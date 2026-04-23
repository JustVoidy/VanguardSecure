from fastapi import APIRouter, Depends
from pydantic import BaseModel
from typing import List
from pathlib import Path
import json

from app.utils.jwt_utils import verify_token

router = APIRouter()

_CONFIG_PATH = Path(__file__).resolve().parent.parent.parent.parent / "config" / "settings.json"

_DEFAULTS = {
    "ddos":      [],
    "rates":     [],
    "blacklist": [],
    "whitelist": [],
    "rules":     [],
}

_CAPTURE_DEFAULTS = {
    "alert_threshold":    0.85,
    "min_packets":        5,
    "flow_window":        5.0,
    "min_flow_duration":  0.5,
    "sampling_rate":      1.0,
    "interface":          "eth0",
}


class CaptureConfig(BaseModel):
    alert_threshold:   float = 0.85
    min_packets:       int   = 5
    flow_window:       float = 5.0
    min_flow_duration: float = 0.5
    sampling_rate:     float = 1.0
    interface:         str   = "eth0"


class Settings(BaseModel):
    ddos:      list
    rates:     list
    blacklist: List[str]
    whitelist: List[str]
    rules:     list


def _load() -> dict:
    try:
        raw = json.loads(_CONFIG_PATH.read_text())
        return {
            "ddos":      raw.get("mitigation_ddos",      _DEFAULTS["ddos"]),
            "rates":     raw.get("mitigation_rates",     _DEFAULTS["rates"]),
            "blacklist": raw.get("mitigation_blacklist", _DEFAULTS["blacklist"]),
            "whitelist": raw.get("mitigation_whitelist", _DEFAULTS["whitelist"]),
            "rules":     raw.get("mitigation_rules",     _DEFAULTS["rules"]),
        }
    except Exception:
        return dict(_DEFAULTS)


def _save(settings: dict):
    try:
        raw = json.loads(_CONFIG_PATH.read_text())
    except Exception:
        raw = {}
    raw["mitigation_ddos"]      = settings["ddos"]
    raw["mitigation_rates"]     = settings["rates"]
    raw["mitigation_blacklist"] = settings["blacklist"]
    raw["mitigation_whitelist"] = settings["whitelist"]
    raw["mitigation_rules"]     = settings["rules"]
    _CONFIG_PATH.write_text(json.dumps(raw, indent=2))


@router.get("/")
def get_settings():
    return _load()


@router.post("/")
def save_settings(settings: Settings, _: dict = Depends(verify_token)):
    data = settings.dict()
    _save(data)
    return {"message": "saved", "data": data}


@router.get("/capture-config")
def get_capture_config():
    try:
        raw = json.loads(_CONFIG_PATH.read_text())
    except Exception:
        raw = {}
    return {
        "alert_threshold":   raw.get("alert_threshold",   _CAPTURE_DEFAULTS["alert_threshold"]),
        "min_packets":       raw.get("min_packets_to_score", _CAPTURE_DEFAULTS["min_packets"]),
        "flow_window":       raw.get("flow_timeout",       _CAPTURE_DEFAULTS["flow_window"]),
        "min_flow_duration": raw.get("min_flow_duration",  _CAPTURE_DEFAULTS["min_flow_duration"]),
        "sampling_rate":     raw.get("sampling_rate",      _CAPTURE_DEFAULTS["sampling_rate"]),
        "interface":         raw.get("interface",          _CAPTURE_DEFAULTS["interface"]),
    }


@router.post("/capture-config")
def save_capture_config(cfg: CaptureConfig, _: dict = Depends(verify_token)):
    try:
        raw = json.loads(_CONFIG_PATH.read_text())
    except Exception:
        raw = {}
    raw["alert_threshold"]    = cfg.alert_threshold
    raw["min_packets_to_score"] = cfg.min_packets
    raw["flow_timeout"]       = cfg.flow_window
    raw["min_flow_duration"]  = cfg.min_flow_duration
    raw["sampling_rate"]      = cfg.sampling_rate
    raw["interface"]          = cfg.interface
    _CONFIG_PATH.write_text(json.dumps(raw, indent=2))
    return {"message": "saved"}
