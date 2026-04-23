"""
Unified event persistence: writes to SQLite always, Redis when available.
Reading prefers Redis (fast) and falls back to SQLite.
"""

import uuid
from collections import deque
from datetime import datetime, timedelta

from app.database import redis_client, SessionLocal
from app.models.event import Event, EventRecord

_EVENTS_KEY   = "events:timeline"
_EVENT_PREFIX = "event:"

# Rolling window of all scored flow timestamps (attack + benign).
# Used for fps / total_scored metrics without needing DB writes for benign flows.
_scored_timestamps: deque = deque()
_scored_flows: deque = deque()  # (timestamp, src_ip, dst_ip, protocol)


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
