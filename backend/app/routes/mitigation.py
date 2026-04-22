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
