from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, field_validator
from typing import List, Optional
from pathlib import Path
import json

from app.models.event import Event
from app.services.predictor import predictor
from app.services.event_store import save_event, record_scored_flow, record_flow_score

_CONFIG_PATH = Path(__file__).resolve().parent.parent.parent.parent / "config" / "settings.json"

EXPECTED_FEATURES = 47

IDX_SYN = 38  # position of SYN Flag Count in SCAPY_FEATURES
IDX_ACK = 42  # position of ACK Flag Count in SCAPY_FEATURES


def _alert_threshold() -> float:
    try:
        return float(json.loads(_CONFIG_PATH.read_text()).get("alert_threshold", 0.85))
    except Exception:
        return 0.85


def _attack_type(features: list, protocol: str) -> str:
    if protocol == "TCP" and features[IDX_SYN] > 5 and features[IDX_ACK] < 2:
        return "TCP SYN FLOOD"
    if protocol == "UDP":
        return "UDP FLOOD"
    return "DDoS ATTACK"


router = APIRouter()


class FlowMeta(BaseModel):
    src_ip:      str
    dst_ip:      str
    src_port:    int
    dst_port:    int
    protocol:    str
    duration:    float
    fwd_packets: int
    bwd_packets: int


class PredictRequest(BaseModel):
    features:  List[float]
    flow_meta: FlowMeta

    @field_validator("features")
    @classmethod
    def check_length(cls, v):
        if len(v) != EXPECTED_FEATURES:
            raise ValueError(f"Expected {EXPECTED_FEATURES} features, got {len(v)}")
        return v


class PredictResponse(BaseModel):
    probability: float
    is_attack:   bool
    attack_type: str
    label:       str
    threshold:   float
    flow_meta:   FlowMeta


@router.post("/predict", response_model=PredictResponse)
def predict_flow(data: PredictRequest):
    if predictor is None:
        raise HTTPException(status_code=503, detail="Model service not initialized")

    threshold = _alert_threshold()
    try:
        prob = predictor.predict(data.features)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    is_attack   = prob >= threshold
    attack_type = _attack_type(data.features, data.flow_meta.protocol) if is_attack else "BENIGN"

    record_scored_flow(data.flow_meta.src_ip, data.flow_meta.dst_ip, data.flow_meta.protocol)
    record_flow_score(prob)

    if is_attack:
        save_event(Event(
            event_type=attack_type,
            source_ip=data.flow_meta.src_ip,
            dest_ip=data.flow_meta.dst_ip,
            threat_score=prob,
            severity="CRITICAL" if prob > 0.9 else "HIGH",
        ))

    return PredictResponse(
        probability=round(prob, 6),
        is_attack=is_attack,
        attack_type=attack_type,
        label="ATTACK" if is_attack else "BENIGN",
        threshold=threshold,
        flow_meta=data.flow_meta,
    )


class BatchFlowData(BaseModel):
    features:  List[float]
    flow_meta: Optional[FlowMeta] = None


class PredictBatchRequest(BaseModel):
    flows: List[BatchFlowData]


@router.post("/predict_batch")
def predict_batch(data: PredictBatchRequest):
    if predictor is None:
        raise HTTPException(status_code=503, detail="Model service not initialized")

    threshold = _alert_threshold()
    try:
        scores = predictor.predict_batch([f.features for f in data.flows])
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    results = []
    for flow, score in zip(data.flows, scores):
        is_attack = score >= threshold
        meta      = flow.flow_meta
        atype     = _attack_type(flow.features, meta.protocol if meta else "TCP") if is_attack else "BENIGN"

        if meta:
            record_scored_flow(meta.src_ip, meta.dst_ip, meta.protocol if meta else "")
            record_flow_score(score)
        if is_attack and meta:
            save_event(Event(
                event_type=atype,
                source_ip=meta.src_ip,
                dest_ip=meta.dst_ip,
                threat_score=score,
                severity="CRITICAL" if score > 0.9 else "HIGH",
            ))

        results.append({
            "probability": round(score, 6),
            "is_attack":   is_attack,
            "attack_type": atype,
            "label":       "ATTACK" if is_attack else "BENIGN",
        })

    return {"predictions": results}


@router.get("/predict/health")
def predict_health():
    if predictor is None:
        raise HTTPException(status_code=503, detail="Model not loaded")
    return {"status": "ok", "message": "DDoS detection model is ready", "threshold": _alert_threshold()}


@router.get("/predict/info")
def predict_info():
    return {
        "expected_features": EXPECTED_FEATURES,
        "alert_threshold":   _alert_threshold(),
    }
