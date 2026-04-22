from sqlalchemy import Column, Integer, String, Float, DateTime
from datetime import datetime
from app.database import Base

class Event(Base):
    __tablename__ = "events"

    id         = Column(Integer, primary_key=True, index=True)
    event_type = Column(String(64))
    source_ip  = Column(String(45), index=True)
    dest_ip    = Column(String(45))
    threat_score = Column(Float)
    severity   = Column(String(16), index=True)
    timestamp  = Column(DateTime, default=datetime.now, index=True)

