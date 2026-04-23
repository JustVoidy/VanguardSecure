from fastapi import APIRouter
from datetime import datetime
import json
import os

from app.database import redis_client
from app.services.event_store import latest_events

router = APIRouter()


@router.get("/kpis")
def get_kpis():
    data = None
    if redis_client:
        try:
            cached = redis_client.get("netshield:live_stats")
            if cached:
                data = json.loads(cached)
        except Exception:
            pass
    if not data:
        stats_path = os.path.join(os.path.dirname(__file__), "../../../live_stats.json")
        if os.path.exists(stats_path):
            try:
                with open(stats_path, "r") as f:
                    data = json.load(f)
            except Exception:
                pass
    if data:
        return {
            "threat_level":     data.get("threat_level", "NORMAL"),
            "attacks_detected": data.get("total_alerts", 0),
            "flow_rate":        f"{data.get('fps', 0)} flows/s",
            "total_scored":     data.get("total_scored", 0),
            "model_confidence": "99.9%" if data.get("threat_level") == "HIGH" else "95.0%",
        }
    return {
        "threat_level":     "OFFLINE",
        "attacks_detected": 0,
        "flow_rate":        "0 flows/s",
        "total_scored":     0,
        "model_confidence": "N/A",
    }


@router.get("/charts")
def get_charts():
    stats_path = os.path.join(os.path.dirname(__file__), "../../../live_stats.json")
    fps = 0
    if os.path.exists(stats_path):
        try:
            with open(stats_path, "r") as f:
                fps = json.load(f).get("fps", 0)
        except Exception:
            pass
    return {"traffic": [fps] * 20, "attacks": [0] * 20}


@router.get("/events")
def get_events():
    events = latest_events(limit=50)
    if not events:
        return [{
            "type": "System Monitor",
            "src":  "localhost",
            "sev":  "NORMAL",
            "time": datetime.now().strftime("%H:%M:%S"),
            "col":  "#007aff",
        }]
    return [
        {
            "type":  e.event_type,
            "src":   e.source_ip,
            "dst":   e.dest_ip,
            "sev":   e.severity,
            "score": f"{e.threat_score * 100:.1f}%",
            "time":  e.timestamp.strftime("%H:%M:%S"),
            "col":   "#ff2d55" if e.severity in ("HIGH", "CRITICAL") else "#ff9500",
        }
        for e in events
    ]
