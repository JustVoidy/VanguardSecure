from fastapi import APIRouter
import random
from datetime import datetime

router = APIRouter()

@router.get("/")
def get_notifications():

    alerts = [

        "Multiple failed login attempts",

        "Suspicious traffic spike detected",

        "New IP added to block list",

        "Model confidence dropped",

        "Port scanning behaviour detected"

    ]

    levels = ["info","warning","critical"]

    return [

        {

            "message": random.choice(alerts),

            "level": random.choice(levels),

            "time": datetime.now().strftime("%H:%M:%S")

        }

        for _ in range(5)

    ]