import asyncio
import json
import os
import threading
import time
from collections import Counter
from datetime import datetime, timedelta

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from app.database import Base, SessionLocal, engine
from app.models import user
from app.models.event import Event
from app.routes import auth, dashboard, inference, mitigation, notifications, profile

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
app.include_router(inference.router,     prefix="",              tags=["Inference"])


# ── WebSocket clients ─────────────────────────────────────────────────────────

_ai_clients:  list[WebSocket] = []
_net_clients: list[WebSocket] = []
_WINDOW = 60


def _recent_events():
    try:
        db     = SessionLocal()
        cutoff = datetime.now() - timedelta(seconds=_WINDOW)
        rows   = db.query(Event).filter(Event.timestamp >= cutoff).all()
        db.close()
        return rows
    except Exception:
        return []


def _ai_payload(rows) -> str:
    threat = "LOW"
    for e in rows:
        if e.severity in ("CRITICAL", "HIGH") or (e.threat_score or 0) >= 0.9:
            threat = "HIGH"; break
        elif (e.threat_score or 0) >= 0.7:
            threat = "MEDIUM"
    one_sec_ago = datetime.now() - timedelta(seconds=1)
    fps = sum(1 for e in rows if e.timestamp >= one_sec_ago)
    return json.dumps({"threat_level": threat, "total_alerts": len(rows),
                       "total_scored": len(rows), "fps": fps})


def _net_payload(rows) -> str:
    import psutil
    ctr = psutil.net_io_counters()
    top = Counter(e.source_ip for e in rows if e.source_ip).most_common(10)
    return json.dumps({
        "total_bw":     ctr.bytes_sent + ctr.bytes_recv,
        "active_flows": len({(e.source_ip, e.dest_ip) for e in rows}),
        "top_ips":      [{"ip": ip, "count": c} for ip, c in top],
        "countries":    [],
        "syn_rate":     sum(1 for e in rows if e.event_type and "SYN" in e.event_type),
        "udp_rate":     sum(1 for e in rows if e.event_type and "UDP" in e.event_type),
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


# ── background threads ────────────────────────────────────────────────────────

def _ws_broadcast_worker():
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    async def _loop():
        import os
        stats_path = os.path.join(os.path.dirname(__file__), "../../../live_stats.json")
        while True:
            rows = _recent_events()
            ai   = _ai_payload(rows)
            net  = _net_payload(rows)
            await _broadcast(_ai_clients, ai)
            await _broadcast(_net_clients, net)
            try:
                open(stats_path, "w").write(ai)
            except Exception:
                pass
            await asyncio.sleep(1)

    loop.run_until_complete(_loop())


def _prune_worker():
    while True:
        try:
            db      = SessionLocal()
            cutoff  = datetime.now() - timedelta(hours=24)
            deleted = db.query(Event).filter(Event.timestamp < cutoff).delete()
            if deleted:
                print(f"[cleanup] Pruned {deleted} old events.")
            db.commit()
            db.close()
        except Exception as e:
            print(f"[cleanup] {e}")
        time.sleep(3600)


@app.on_event("startup")
async def startup_event():
    threading.Thread(target=_prune_worker,        daemon=True).start()
    threading.Thread(target=_ws_broadcast_worker, daemon=True).start()


@app.get("/")
def root():
    return {"message": "NetShield API running"}


@app.get("/health")
def health():
    return {"status": "ok"}
