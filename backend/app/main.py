import asyncio
import json
import os
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path

from dotenv import load_dotenv
load_dotenv(Path(__file__).resolve().parent.parent.parent / ".env")

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from app.database import Base, engine, redis_client
from app.services.event_store import (
    recent_events as _recent_events_from_store,
    scored_fps, scored_total, scored_active_flows,
    scored_syn_fps, scored_udp_fps, top_source_ips, ip_to_country,
    recent_flow_scores,
    _EVENTS_KEY, _EVENT_PREFIX,
)
from app.routes import auth, dashboard, inference, mitigation, notifications, profile, capture_control

app = FastAPI(title="NetShield API")

_cors_origins = os.environ.get("CORS_ORIGINS", "*").split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

Base.metadata.create_all(bind=engine)

app.include_router(auth.router,          prefix="/auth",         tags=["Auth"])
app.include_router(dashboard.router,     prefix="/dashboard",    tags=["Dashboard"])
app.include_router(mitigation.router,    prefix="/mitigation",   tags=["Mitigation"])
app.include_router(notifications.router, prefix="/notifications", tags=["Notifications"])
app.include_router(profile.router,       prefix="/profile",      tags=["Profile"])
app.include_router(inference.router,        prefix="",              tags=["Inference"])
app.include_router(capture_control.router, prefix="/capture",      tags=["Capture"])


# ── WebSocket clients ─────────────────────────────────────────────────────────

_ai_clients:  list[WebSocket] = []
_net_clients: list[WebSocket] = []
_WINDOW = 60

def _recent_events():
    return _recent_events_from_store(window_seconds=_WINDOW)


def _ai_payload(rows) -> str:
    threat = "LOW"
    for e in rows:
        s = e.threat_score or 0
        if e.severity in ("CRITICAL", "HIGH") or s >= 0.9:
            threat = "HIGH"; break
        elif s >= 0.7:
            threat = "MEDIUM"
    return json.dumps({
        "threat_level":   threat,
        "total_alerts":   len(rows),
        "total_scored":   scored_total(),
        "fps":            scored_fps(),
        "recent_scores":  recent_flow_scores(),
    })


_prev_net_bytes: int = 0
_prev_net_time:  float = 0.0

def _net_payload() -> str:
    global _prev_net_bytes, _prev_net_time
    import psutil, time as _time
    ctr   = psutil.net_io_counters()
    total = ctr.bytes_sent + ctr.bytes_recv
    now   = _time.monotonic()
    dt    = now - _prev_net_time if _prev_net_time else 1.0
    bw    = max(0, (total - _prev_net_bytes) / dt) if _prev_net_bytes else 0
    _prev_net_bytes = total
    _prev_net_time  = now

    top = top_source_ips(10)
    from collections import Counter
    country_counts: Counter = Counter()
    for ip, cnt in top:
        country_counts[ip_to_country(ip)] += cnt
    top5 = country_counts.most_common(5)
    max_count = top5[0][1] if top5 else 1
    countries = [{"country": cc, "count": n, "pct": round(n / max_count * 100, 1)} for cc, n in top5]
    return json.dumps({
        "total_bw":     bw,
        "active_flows": scored_active_flows(),
        "top_ips":      [{"ip": ip, "count": c} for ip, c in top],
        "countries":    countries,
        "syn_rate":     scored_syn_fps(),
        "udp_rate":     scored_udp_fps(),
    })


async def _broadcast(clients: list, msg: str):
    dead = []
    for ws in clients:
        try:
            await ws.send_text(msg)
        except Exception:
            dead.append(ws)
    for ws in dead:
        clients.remove(ws)


@app.websocket("/ws/ai")
async def ws_ai(ws: WebSocket):
    await ws.accept()
    _ai_clients.append(ws)
    try:
        await ws.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        if ws in _ai_clients:
            _ai_clients.remove(ws)


@app.websocket("/ws/net")
async def ws_net(ws: WebSocket):
    await ws.accept()
    _net_clients.append(ws)
    try:
        await ws.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        if ws in _net_clients:
            _net_clients.remove(ws)


# ── background tasks (run in the main uvicorn event loop) ─────────────────────

async def _ws_broadcast_loop():
    stats_path = os.path.join(os.path.dirname(__file__), "../../../live_stats.json")
    while True:
        try:
            rows = _recent_events()
            ai   = _ai_payload(rows)
            net  = _net_payload()
            await _broadcast(_ai_clients, ai)
            await _broadcast(_net_clients, net)
            try:
                with open(stats_path, "w") as f:
                    f.write(ai)
            except Exception:
                pass
        except Exception as e:
            print(f"[broadcast] {e}")
        await asyncio.sleep(1)


def _prune_worker():
    while True:
        try:
            if redis_client is not None:
                cutoff  = (datetime.now() - timedelta(hours=24)).timestamp()
                old_ids = redis_client.zrangebyscore(_EVENTS_KEY, "-inf", cutoff)
                if old_ids:
                    pipe = redis_client.pipeline()
                    for eid in old_ids:
                        pipe.delete(f"{_EVENT_PREFIX}{eid}")
                    pipe.zremrangebyscore(_EVENTS_KEY, "-inf", cutoff)
                    pipe.execute()
                    print(f"[cleanup] Pruned {len(old_ids)} old events from Redis.")
        except Exception as e:
            print(f"[cleanup] {e}")
        time.sleep(3600)


@app.on_event("startup")
async def startup_event():
    threading.Thread(target=_prune_worker, daemon=True).start()
    asyncio.create_task(_ws_broadcast_loop())


@app.get("/")
def root():
    return {"message": "NetShield API running"}


@app.get("/health")
def health():
    return {"status": "ok"}
