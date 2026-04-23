from fastapi import APIRouter
import random
from datetime import datetime

router = APIRouter()

_ALERTS = [
    "Multiple failed login attempts detected",
    "Suspicious traffic spike detected",
    "New IP added to block list",
    "Model confidence dropped below threshold",
    "Port scanning behaviour detected",
    "UDP flood signature matched",
    "SYN flood mitigation triggered",
]

@router.get("/")
def get_notifications():
    return [
        {
            "message": random.choice(_ALERTS),
            "level":   random.choice(["info", "warning", "critical"]),
            "time":    datetime.now().strftime("%H:%M:%S"),
        }
        for _ in range(5)
    ]