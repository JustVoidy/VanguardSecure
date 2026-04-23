"""
Unified event persistence: writes to SQLite always, Redis when available.
Reading prefers Redis (fast) and falls back to SQLite.
"""

import ipaddress
import uuid
from collections import deque
from datetime import datetime, timedelta
from functools import lru_cache

from app.database import redis_client, SessionLocal
from app.models.event import Event, EventRecord

_EVENTS_KEY   = "events:timeline"
_EVENT_PREFIX = "event:"

# Rolling window of all scored flow timestamps (attack + benign).
# Used for fps / total_scored metrics without needing DB writes for benign flows.
_scored_timestamps: deque = deque()
_scored_flows: deque = deque()     # (timestamp, src_ip, dst_ip, protocol)
_flow_scores:  deque = deque(maxlen=20)  # latest per-flow model probabilities (0–1)


def record_flow_score(prob: float) -> None:
    """Append the raw model probability for the most recent flow."""
    _flow_scores.append(round(prob * 100, 1))


def recent_flow_scores() -> list[float]:
    """Last ≤20 per-flow confidence percentages, oldest first."""
    return list(_flow_scores)


def record_scored_flow(src_ip: str, dst_ip: str, protocol: str = "") -> None:
    now = datetime.now()
    _scored_timestamps.append(now)
    _scored_flows.append((now, src_ip, dst_ip, protocol.upper()))
    cutoff = now - timedelta(seconds=60)
    while _scored_timestamps and _scored_timestamps[0] < cutoff:
        _scored_timestamps.popleft()
    while _scored_flows and _scored_flows[0][0] < cutoff:
        _scored_flows.popleft()


def scored_fps() -> float:
    """Flows per second, averaged over the last 10 seconds."""
    cutoff = datetime.now() - timedelta(seconds=10)
    count = sum(1 for t in _scored_timestamps if t >= cutoff)
    return round(count / 10, 2)


def scored_total() -> int:
    """Total flows scored in the last 60 seconds."""
    return len(_scored_timestamps)


def scored_active_flows() -> int:
    """Unique (src, dst) pairs scored in the last 60 seconds."""
    return len({(s, d) for _, s, d, _ in _scored_flows})


def scored_syn_fps() -> float:
    """TCP flows per second (10s avg)."""
    cutoff = datetime.now() - timedelta(seconds=10)
    count = sum(1 for ts, _, _, p in _scored_flows if p == "TCP" and ts >= cutoff)
    return round(count / 10, 2)


def scored_udp_fps() -> float:
    """UDP flows per second (10s avg)."""
    cutoff = datetime.now() - timedelta(seconds=10)
    count = sum(1 for ts, _, _, p in _scored_flows if p == "UDP" and ts >= cutoff)
    return round(count / 10, 2)


def top_source_ips(n: int = 10) -> list[tuple[str, int]]:
    """Most frequent source IPs in the last 60 seconds."""
    from collections import Counter
    return Counter(s for _, s, _, _ in _scored_flows if s).most_common(n)


def save_event(event: Event) -> None:
    db = SessionLocal()
    try:
        db.add(EventRecord(
            event_type=event.event_type,
            source_ip=event.source_ip,
            dest_ip=event.dest_ip,
            threat_score=event.threat_score,
            severity=event.severity,
            timestamp=event.timestamp,
        ))
        db.commit()
    except Exception as exc:
        db.rollback()
        print(f"[event_store] SQLite write failed: {exc}")
    finally:
        db.close()

    if redis_client is not None:
        try:
            eid = str(uuid.uuid4())
            ts  = event.timestamp.timestamp()
            pipe = redis_client.pipeline()
            pipe.hset(f"{_EVENT_PREFIX}{eid}", mapping={
                "event_type":   event.event_type,
                "source_ip":    event.source_ip,
                "dest_ip":      event.dest_ip or "",
                "threat_score": str(event.threat_score),
                "severity":     event.severity,
                "timestamp":    str(ts),
            })
            pipe.zadd(_EVENTS_KEY, {eid: ts})
            pipe.execute()
        except Exception as exc:
            print(f"[event_store] Redis write failed: {exc}")


def recent_events(window_seconds: int = 60) -> list[Event]:
    if redis_client is not None:
        try:
            now_ts = datetime.now().timestamp()
            cutoff = now_ts - window_seconds
            ids    = redis_client.zrangebyscore(_EVENTS_KEY, cutoff, now_ts)
            rows   = []
            for eid in ids:
                raw = redis_client.hgetall(f"{_EVENT_PREFIX}{eid}")
                if not raw:
                    continue
                ts = float(raw.get("timestamp", now_ts))
                rows.append(Event(
                    event_type=raw.get("event_type", ""),
                    source_ip=raw.get("source_ip", ""),
                    dest_ip=raw.get("dest_ip", ""),
                    threat_score=float(raw.get("threat_score", 0)),
                    severity=raw.get("severity", ""),
                    timestamp=datetime.fromtimestamp(ts),
                    id=eid,
                ))
            return rows
        except Exception as exc:
            print(f"[event_store] Redis read failed, falling back to SQLite: {exc}")

    cutoff = datetime.now() - timedelta(seconds=window_seconds)
    db = SessionLocal()
    try:
        records = (
            db.query(EventRecord)
            .filter(EventRecord.timestamp >= cutoff)
            .order_by(EventRecord.timestamp.desc())
            .all()
        )
        return [
            Event(
                event_type=r.event_type,
                source_ip=r.source_ip,
                dest_ip=r.dest_ip or "",
                threat_score=r.threat_score,
                severity=r.severity,
                timestamp=r.timestamp,
                id=str(r.id),
            )
            for r in records
        ]
    finally:
        db.close()


# CIDR → country, sorted most-specific first so sub-ranges override broader ones.
# Sources: IANA, ARIN, RIPE NCC, APNIC, LACNIC, AFRINIC delegation files.
_GEO_CIDRS: list[tuple[ipaddress.IPv4Network, str]] = sorted(
    [
        (ipaddress.ip_network(cidr), cc) for cidr, cc in [
            # ── Private / Special ──────────────────────────────────────────
            ('0.0.0.0/8',       'LAN'),   # "This" network
            ('10.0.0.0/8',      'LAN'),   # RFC 1918
            ('100.64.0.0/10',   'LAN'),   # RFC 6598 CGNAT
            ('127.0.0.0/8',     'LAN'),   # Loopback
            ('169.254.0.0/16',  'LAN'),   # Link-local
            ('172.16.0.0/12',   'LAN'),   # RFC 1918
            ('192.168.0.0/16',  'LAN'),   # RFC 1918
            ('198.18.0.0/15',   'LAN'),   # Benchmarking
            ('240.0.0.0/4',     'LAN'),   # Reserved
            # ── China (CNNIC / APNIC) ──────────────────────────────────────
            ('36.0.0.0/8',      'CHN'), ('42.0.0.0/8',   'CHN'),
            ('58.0.0.0/7',      'CHN'),                           # 58–59
            ('60.0.0.0/8',      'CHN'), ('61.0.0.0/8',   'CHN'),
            ('101.0.0.0/8',     'CHN'), ('103.0.0.0/8',  'CHN'),
            ('106.0.0.0/8',     'CHN'), ('110.0.0.0/7',  'CHN'), # 110–111
            ('112.0.0.0/6',  'CHN'),  # 112–115
            ('116.0.0.0/6',  'CHN'),  # 116–119
            ('120.0.0.0/6',  'CHN'),  # 120–123
            ('124.0.0.0/7',  'CHN'),  # 124–125
            # ── Russia (RIPE NCC → RU) ─────────────────────────────────────
            ('46.0.0.0/8',      'RUS'),
            ('77.72.0.0/13',    'RUS'), ('77.88.0.0/13',  'RUS'),
            ('87.224.0.0/12',   'RUS'),
            ('89.108.0.0/14',   'RUS'), ('91.108.0.0/14', 'RUS'),
            ('95.24.0.0/13',    'RUS'),
            ('176.0.0.0/10',    'RUS'), ('178.128.0.0/10','RUS'),
            # ── USA (ARIN) ─────────────────────────────────────────────────
            ('3.0.0.0/8',   'USA'), ('4.0.0.0/8',   'USA'), ('8.0.0.0/8',  'USA'),
            ('9.0.0.0/8',   'USA'), ('12.0.0.0/8',  'USA'), ('16.0.0.0/8', 'USA'),
            ('17.0.0.0/8',  'USA'), ('18.0.0.0/8',  'USA'), ('20.0.0.0/8', 'USA'),
            ('23.0.0.0/8',  'USA'), ('24.0.0.0/8',  'USA'), ('34.0.0.0/8', 'USA'),
            ('35.0.0.0/8',  'USA'), ('38.0.0.0/8',  'USA'), ('40.0.0.0/8', 'USA'),
            ('44.0.0.0/8',  'USA'), ('45.0.0.0/8',  'USA'), ('47.0.0.0/8', 'USA'),
            ('52.0.0.0/8',  'USA'), ('54.0.0.0/8',  'USA'), ('63.0.0.0/8', 'USA'),
            ('64.0.0.0/6',  'USA'),  # 64–67
            ('68.0.0.0/6',  'USA'),  # 68–71
            ('72.0.0.0/5',  'USA'),  # 72–79
            ('97.0.0.0/8',  'USA'), ('98.0.0.0/7',  'USA'),  # 98–99
            ('104.0.0.0/8', 'USA'), ('107.0.0.0/8', 'USA'), ('108.0.0.0/8','USA'),
            ('162.0.0.0/8', 'USA'), ('164.0.0.0/8', 'USA'), ('166.0.0.0/8','USA'),
            ('170.0.0.0/8', 'USA'), ('184.0.0.0/8', 'USA'), ('198.0.0.0/7','USA'),
            ('204.0.0.0/6', 'USA'),  # 204–207
            ('208.0.0.0/5', 'USA'),  # 208–215
            ('216.0.0.0/8', 'USA'),
            # ── India (IRINN / APNIC) ──────────────────────────────────────
            ('14.96.0.0/11',    'IND'), ('49.32.0.0/11',  'IND'),
            ('117.192.0.0/10',  'IND'), ('122.160.0.0/11','IND'),
            ('182.64.0.0/10',   'IND'), ('183.0.0.0/10',  'IND'),
            ('220.224.0.0/12',  'IND'),
            # ── Brazil (LACNIC) ───────────────────────────────────────────
            ('177.0.0.0/8', 'BRA'), ('179.0.0.0/8', 'BRA'), ('186.0.0.0/8','BRA'),
            ('187.0.0.0/8', 'BRA'), ('189.0.0.0/8', 'BRA'), ('191.0.0.0/8','BRA'),
            ('200.0.0.0/7',     'BRA'),  # 200–201
            # ── Europe (RIPE NCC, broad — RU-specific sub-ranges above win) ─
            ('5.0.0.0/8',   'EUR'), ('31.0.0.0/8',  'EUR'), ('37.0.0.0/8', 'EUR'),
            ('77.0.0.0/8',  'EUR'), ('78.0.0.0/7',  'EUR'),  # 78–79
            ('80.0.0.0/4',  'EUR'),  # 80–95
            ('176.0.0.0/8', 'EUR'), ('178.0.0.0/8', 'EUR'), ('185.0.0.0/8','EUR'),
            ('188.0.0.0/8', 'EUR'), ('193.0.0.0/8', 'EUR'), ('194.0.0.0/7','EUR'),
            ('212.0.0.0/7', 'EUR'), ('217.0.0.0/8', 'EUR'),
            # ── Japan (JPNIC / APNIC) ─────────────────────────────────────
            ('126.0.0.0/8', 'JPN'), ('133.0.0.0/8', 'JPN'),
            ('150.0.0.0/8', 'JPN'), ('153.0.0.0/8', 'JPN'),
            # ── South Korea (KISA / APNIC) ────────────────────────────────
            ('175.192.0.0/10',  'KOR'),
            ('211.0.0.0/8', 'KOR'), ('218.0.0.0/7', 'KOR'),  # 218–219
            ('221.0.0.0/8', 'KOR'), ('222.0.0.0/8', 'KOR'),
        ]
    ],
    key=lambda x: x[0].prefixlen,
    reverse=True,  # longest prefix wins
)


@lru_cache(maxsize=4096)
def ip_to_country(ip: str) -> str:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return 'OTH'
    for net, cc in _GEO_CIDRS:
        if addr in net:
            return cc
    return 'OTH'


def latest_events(limit: int = 50) -> list[Event]:
    """For the dashboard events list — most recent N events regardless of age."""
    if redis_client is not None:
        try:
            ids = redis_client.zrevrangebyscore(_EVENTS_KEY, "+inf", "-inf", start=0, num=limit)
            rows = []
            for eid in ids:
                raw = redis_client.hgetall(f"{_EVENT_PREFIX}{eid}")
                if not raw:
                    continue
                ts = float(raw.get("timestamp", 0))
                rows.append(Event(
                    event_type=raw.get("event_type", ""),
                    source_ip=raw.get("source_ip", ""),
                    dest_ip=raw.get("dest_ip", ""),
                    threat_score=float(raw.get("threat_score", 0)),
                    severity=raw.get("severity", ""),
                    timestamp=datetime.fromtimestamp(ts) if ts else datetime.now(),
                    id=eid,
                ))
            return rows
        except Exception:
            pass

    db = SessionLocal()
    try:
        records = (
            db.query(EventRecord)
            .order_by(EventRecord.timestamp.desc())
            .limit(limit)
            .all()
        )
        return [
            Event(
                event_type=r.event_type,
                source_ip=r.source_ip,
                dest_ip=r.dest_ip or "",
                threat_score=r.threat_score,
                severity=r.severity,
                timestamp=r.timestamp,
                id=str(r.id),
            )
            for r in records
        ]
    finally:
        db.close()
