from fastapi import APIRouter
from datetime import datetime

from app.services.event_store import latest_events

router = APIRouter()


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
