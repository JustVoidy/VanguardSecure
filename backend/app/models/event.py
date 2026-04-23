from dataclasses import dataclass, field
from datetime import datetime

from sqlalchemy import Column, Float, Integer, String, DateTime
from app.database import Base


class EventRecord(Base):
    __tablename__ = "events"

    id          = Column(Integer, primary_key=True, autoincrement=True)
    event_type  = Column(String)
    source_ip   = Column(String)
    dest_ip     = Column(String)
    threat_score = Column(Float)
    severity    = Column(String)
    timestamp   = Column(DateTime, default=datetime.now)


@dataclass
class Event:
    event_type:   str
    source_ip:    str
    dest_ip:      str
    threat_score: float
    severity:     str
    timestamp:    datetime = field(default_factory=datetime.now)
    id:           str = field(default="")
