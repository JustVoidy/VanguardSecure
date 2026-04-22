"""
DDoS Detection — Inference Server
==================================
FastAPI server that loads the trained FFNN model and exposes a /predict
endpoint. Receives 47-feature flow vectors from capture.py and returns
attack probability, label, and attack type.

Usage:
    pip install fastapi uvicorn tensorflow scikit-learn joblib numpy
    uvicorn server:app --host 0.0.0.0 --port 8000

    # Or directly:
    python server.py

Notes:
    - Place ddos_ffnn.keras, ddos_scaler.pkl, ddos_features.pkl
      in the same directory as this script (output of trainer.py)
    - The /predict endpoint is designed to receive requests from capture.py
"""

import json
import os
import warnings
from pathlib import Path
from typing import Dict, List, Any

import joblib
import numpy as np
import uvicorn
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, field_validator

os.environ.setdefault("TF_CPP_MIN_LOG_LEVEL", "2")
import tensorflow as tf

warnings.filterwarnings("ignore")

# ─────────────────────────────────────────────────────────────────────────────
# CONSTANTS — must match trainer.py exactly
# ─────────────────────────────────────────────────────────────────────────────

MODEL_PATH   = "ddos_ffnn.keras"
SCALER_PATH  = "ddos_scaler.pkl"
FEATURE_PATH = "ddos_features.pkl"

_CONFIG_PATH = Path(__file__).resolve().parent.parent / "config" / "settings.json"

def _load_threshold() -> float:
    try:
        return float(json.loads(_CONFIG_PATH.read_text()).get("alert_threshold", 0.85))
    except Exception:
        return 0.85

ALERT_THRESHOLD = _load_threshold()
EXPECTED_FEATURES = 47

SCAPY_FEATURES = [
    "Total Fwd Packets", "Total Backward Packets",
    "Total Length of Fwd Packets", "Total Length of Bwd Packets",
    "Fwd Packet Length Max", "Fwd Packet Length Min", "Fwd Packet Length Mean", "Fwd Packet Length Std",
    "Bwd Packet Length Max", "Bwd Packet Length Min", "Bwd Packet Length Mean", "Bwd Packet Length Std",
    "Min Packet Length", "Max Packet Length", "Packet Length Mean", "Packet Length Std", "Packet Length Variance",
    "Flow Bytes/s", "Flow Packets/s", "Fwd Packets/s", "Bwd Packets/s",
    "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max", "Flow IAT Min",
    "Fwd IAT Total", "Fwd IAT Mean", "Fwd IAT Std", "Fwd IAT Max", "Fwd IAT Min",
    "Bwd IAT Total", "Bwd IAT Mean", "Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min",
    "Fwd Header Length", "Bwd Header Length",
    "FIN Flag Count", "SYN Flag Count", "RST Flag Count", "PSH Flag Count", "ACK Flag Count", "URG Flag Count",
    "Destination Port", "Init_Win_bytes_forward", "Init_Win_bytes_backward", "Down/Up Ratio",
]

# Feature indices for attack type heuristics
IDX_SYN = SCAPY_FEATURES.index("SYN Flag Count")
IDX_ACK = SCAPY_FEATURES.index("ACK Flag Count")

# ─────────────────────────────────────────────────────────────────────────────
# APP + MODEL LOADING
# ─────────────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="DDoS Detection API",
    description="FFNN-based DDoS detection — receives flow features from capture.py",
    version="1.0.0",
)

# Loaded once at startup, reused for every request
_model  = None
_scaler = None


@app.on_event("startup")
def load_model():
    global _model, _scaler

    for path in [MODEL_PATH, SCALER_PATH, FEATURE_PATH]:
        if not os.path.exists(path):
            raise RuntimeError(
                f"Required file not found: {path}\n"
                f"Run trainer.py first to generate model artifacts."
            )

    print(f"[*] Loading model from {MODEL_PATH} ...")
    _model  = tf.keras.models.load_model(MODEL_PATH)
    _scaler = joblib.load(SCALER_PATH)
    print(f"[*] Model loaded. Ready to accept requests.")


# ─────────────────────────────────────────────────────────────────────────────
# REQUEST / RESPONSE SCHEMAS
# ─────────────────────────────────────────────────────────────────────────────

class FlowMeta(BaseModel):
    src_ip:      str
    dst_ip:      str
    src_port:    int
    dst_port:    int
    protocol:    str           # "TCP" or "UDP"
    duration:    float
    fwd_packets: int
    bwd_packets: int


class PredictRequest(BaseModel):
    features:  List[float]     # exactly 47 floats
    flow_meta: FlowMeta

    @field_validator("features")
    @classmethod
    def check_feature_length(cls, v):
        if len(v) != EXPECTED_FEATURES:
            raise ValueError(
                f"Expected {EXPECTED_FEATURES} features, got {len(v)}"
            )
        return v


class PredictResponse(BaseModel):
    probability: float
    is_attack:   bool
    attack_type: str            # "TCP SYN FLOOD", "UDP FLOOD", or "BENIGN"
    label:       str            # "ATTACK" or "BENIGN"
    threshold:   float
    flow_meta:   FlowMeta


# ─────────────────────────────────────────────────────────────────────────────
# INFERENCE LOGIC
# ─────────────────────────────────────────────────────────────────────────────

def classify_attack_type(features: List[float], protocol: str) -> str:
    """
    Use flow features and protocol to give a more specific attack label.
    This runs after the model already determined it IS an attack.
    """
    syn_count = features[IDX_SYN]
    ack_count = features[IDX_ACK]

    if protocol == "TCP" and syn_count > 5 and ack_count < 2:
        return "TCP SYN FLOOD"
    elif protocol == "UDP":
        return "UDP FLOOD"
    else:
        return "DDoS ATTACK"


def run_inference(features: List[float], protocol: str, threshold: float) -> dict:
    """
    Apply preprocessing and run the model.
    Preprocessing must match trainer.py exactly: log1p → StandardScaler
    """
    x = np.array(features, dtype=np.float32)

    # Step 1: log1p (same as trainer.py)
    x = np.log1p(np.clip(x, 0, None))

    # Step 2: StandardScaler (fitted during training)
    x = _scaler.transform(x.reshape(1, -1))

    # Step 3: Model inference
    prob = float(_model.predict(x, verbose=0).flatten()[0])

    is_attack   = prob >= threshold
    attack_type = classify_attack_type(features, protocol) if is_attack else "BENIGN"

    return {
        "probability": round(prob, 6),
        "is_attack":   is_attack,
        "attack_type": attack_type,
        "label":       "ATTACK" if is_attack else "BENIGN",
        "threshold":   threshold,
    }


# ─────────────────────────────────────────────────────────────────────────────
# ENDPOINTS
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    """Health check — also confirms model is loaded."""
    if _model is None or _scaler is None:
        raise HTTPException(status_code=503, detail="Model not loaded yet")
    return {
        "status":  "ok",
        "message": "DDoS detection server is running",
        "model":   MODEL_PATH,
        "threshold": ALERT_THRESHOLD,
    }


@app.post("/predict", response_model=PredictResponse)
def predict(request: PredictRequest):
    """
    Receive a completed flow's 47 features from capture.py,
    run inference, and return the result.
    """
    if _model is None or _scaler is None:
        raise HTTPException(status_code=503, detail="Model not loaded")

    try:
        result = run_inference(
            features=request.features,
            protocol=request.flow_meta.protocol,
            threshold=ALERT_THRESHOLD,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Inference error: {str(e)}")

    # Log every attack on the server side
    if result["is_attack"]:
        meta = request.flow_meta
        print(
            f"🚨 {result['attack_type']} | "
            f"{meta.src_ip}:{meta.src_port} → {meta.dst_ip}:{meta.dst_port} "
            f"({meta.protocol}) | "
            f"confidence: {result['probability']:.2%} | "
            f"pkts: {meta.fwd_packets}↑ {meta.bwd_packets}↓ | "
            f"duration: {meta.duration}s"
        )

    return PredictResponse(**result, flow_meta=request.flow_meta)


@app.get("/info")
def info():
    """Return model and feature configuration info."""
    return {
        "expected_features": EXPECTED_FEATURES,
        "feature_names":     SCAPY_FEATURES,
        "alert_threshold":   ALERT_THRESHOLD,
        "model_path":        MODEL_PATH,
    }


# ─────────────────────────────────────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    uvicorn.run(
        "server:app",
        host="0.0.0.0",
        port=8001,
        reload=False,
    )
