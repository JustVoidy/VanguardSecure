from fastapi import APIRouter, HTTPException, Depends
from app.utils.jwt_utils import verify_token
from pydantic import BaseModel
from typing import List, Optional
from sqlalchemy.orm import Session
from pathlib import Path
import json
from app.database import SessionLocal
from app.models.event import Event
from app.services.predictor import predictor  # may be None if model files absent

_CONFIG_PATH = Path(__file__).resolve().parent.parent.parent.parent / "config" / "settings.json"

def _alert_threshold() -> float:
    try:
        return float(json.loads(_CONFIG_PATH.read_text()).get("alert_threshold", 0.80))
    except Exception:
        return 0.80

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

router = APIRouter()

class FlowData(BaseModel):
    flow_key: Optional[List] = None
    vector: List[float]

class BatchFlowData(BaseModel):
    flows: List[FlowData]

@router.post("/predict")
async def predict_flow(data: FlowData, db: Session = Depends(get_db)):
    if predictor is None:
        raise HTTPException(status_code=503, detail="Model service not initialized")
    
    try:
        score = predictor.predict(data.vector)
        threshold = _alert_threshold()
        is_attack = score >= threshold

        if is_attack:
            new_event = Event(
                event_type="DDoS Threat",
                source_ip=str(data.flow_key[0]) if data.flow_key else "Unknown",
                dest_ip=str(data.flow_key[1]) if data.flow_key else "Unknown",
                threat_score=score,
                severity="CRITICAL" if score > 0.9 else "HIGH"
            )
            db.add(new_event)
            db.commit()

        return {
            "attack_probability": score,
            "is_attack": is_attack,
            "threat_level": "HIGH" if score > 0.9 else "MEDIUM" if score >= threshold else "NORMAL"
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ── Event ingestion (called by capture.py after remote model scoring) ─────────

class IngestedEvent(BaseModel):
    flow_key: Optional[List] = None
    attack_probability: float
    is_attack: bool
    threat_level: Optional[str] = None

class IngestPayload(BaseModel):
    events: List[IngestedEvent]

@router.post("/events/ingest")
async def ingest_events(data: IngestPayload, db: Session = Depends(get_db), _: dict = Depends(verify_token)):
    """
    Receive pre-scored attack events from capture.py and persist them.
    The model runs remotely; this endpoint just stores the results for the
    frontend dashboard to display.
    """
    stored = 0
    for evt in data.events:
        if not evt.is_attack:
            continue
        score = evt.attack_probability
        new_event = Event(
            event_type="DDoS Threat",
            source_ip=str(evt.flow_key[0]) if evt.flow_key else "Unknown",
            dest_ip=str(evt.flow_key[2]) if evt.flow_key and len(evt.flow_key) > 2 else "Unknown",
            threat_score=score,
            severity="CRITICAL" if score > 0.9 else "HIGH",
        )
        db.add(new_event)
        stored += 1
    db.commit()
    return {"status": "ok", "stored": stored}


# ── Local model endpoints (used when model files are present locally) ──────────

@router.post("/predict_batch")
async def predict_batch(data: BatchFlowData, db: Session = Depends(get_db)):
    if predictor is None:
        raise HTTPException(status_code=503, detail="Model service not initialized")
    
    try:
        vectors = [f.vector for f in data.flows]
        scores = predictor.predict_batch(vectors)
        threshold = _alert_threshold()

        results = []
        for i, score in enumerate(scores):
            is_attack = score >= threshold
            results.append({
                "flow_key": data.flows[i].flow_key,
                "attack_probability": score,
                "is_attack": is_attack
            })

            if is_attack:
                new_event = Event(
                    event_type="DDoS Flow Detected",
                    source_ip=str(data.flows[i].flow_key[0]) if data.flows[i].flow_key else "Unknown",
                    dest_ip=str(data.flows[i].flow_key[1]) if data.flows[i].flow_key else "Unknown",
                    threat_score=score,
                    severity="CRITICAL" if score > 0.9 else "HIGH"
                )
                db.add(new_event)
        
        db.commit()
        return {"predictions": results}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
