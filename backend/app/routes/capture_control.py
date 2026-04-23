import os
import signal
import subprocess
import sys
from pathlib import Path

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

router = APIRouter()

_capture_proc: subprocess.Popen | None = None
_capture_iface: str = ""

CAPTURE_SCRIPT = str(Path(__file__).resolve().parents[3] / "scripts" / "capture.py")
VENV_PYTHON    = str(Path(__file__).resolve().parents[3] / ".venv" / "bin" / "python")
PYTHON         = VENV_PYTHON if Path(VENV_PYTHON).exists() else sys.executable

# Wrapper created by setup-capture-sudo.sh — avoids sudo TTY requirement
_WRAPPER = "/usr/local/bin/netshield-capture"


def _build_cmd(iface: str, server_url: str, window: float) -> list[str]:
    args = ["--iface", iface, "--server", server_url, "--window", str(window)]
    if os.geteuid() == 0:
        # Already root — no sudo needed
        return [PYTHON, CAPTURE_SCRIPT] + args
    if Path(_WRAPPER).exists():
        return ["sudo", _WRAPPER] + args
    return ["sudo", PYTHON, CAPTURE_SCRIPT] + args


class StartRequest(BaseModel):
    iface: str = "eth0"
    server_url: str = "http://localhost:8000"
    window: float = 5.0


@router.post("/start")
def start_capture(req: StartRequest):
    global _capture_proc, _capture_iface

    if _capture_proc and _capture_proc.poll() is None:
        return {"status": "already_running", "iface": _capture_iface}

    if not Path(CAPTURE_SCRIPT).exists():
        raise HTTPException(status_code=500, detail=f"capture.py not found at {CAPTURE_SCRIPT}")

    cmd = _build_cmd(req.iface, req.server_url, req.window)

    try:
        _capture_proc  = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        _capture_iface = req.iface
        # Give the process a moment to fail fast (e.g. sudo password required)
        import time; time.sleep(0.5)
        if _capture_proc.poll() is not None:
            out = _capture_proc.stdout.read().decode(errors="replace")
            _capture_proc  = None
            _capture_iface = ""
            raise HTTPException(status_code=500,
                detail=f"Capture process exited immediately. Output: {out.strip()}")
        return {"status": "started", "iface": req.iface, "pid": _capture_proc.pid}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/stop")
def stop_capture():
    global _capture_proc, _capture_iface

    if not _capture_proc or _capture_proc.poll() is not None:
        _capture_proc  = None
        _capture_iface = ""
        return {"status": "not_running"}

    try:
        os.kill(_capture_proc.pid, signal.SIGTERM)
        _capture_proc.wait(timeout=5)
    except Exception:
        try:
            _capture_proc.kill()
        except Exception:
            pass
    finally:
        _capture_proc  = None
        _capture_iface = ""

    return {"status": "stopped"}


@router.get("/status")
def capture_status():
    running = bool(_capture_proc and _capture_proc.poll() is None)
    return {"running": running, "iface": _capture_iface if running else ""}
