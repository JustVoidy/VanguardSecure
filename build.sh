#!/usr/bin/env bash
# NetShield Desktop — full build pipeline
# Produces: dist/capture (binary) + frontend/dist/<platform> (Electron installer)
# Usage: ./build.sh [--skip-capture] [--skip-electron]

set -e

SKIP_CAPTURE=0
SKIP_ELECTRON=0
for arg in "$@"; do
  [[ "$arg" == "--skip-capture"  ]] && SKIP_CAPTURE=1
  [[ "$arg" == "--skip-electron" ]] && SKIP_ELECTRON=1
done

# ── 1. Python capture binary ──────────────────────────────────────────────────
if [[ $SKIP_CAPTURE -eq 0 ]]; then
  echo "==> Building capture binary (PyInstaller)..."

  # Activate venv
  if [[ -f ".venv/bin/activate" ]]; then
    source .venv/bin/activate
  else
    echo "ERROR: .venv not found. Run: python -m venv .venv && pip install -r requirements.txt"
    exit 1
  fi

  pip install pyinstaller --quiet
  pyinstaller capture.spec --distpath dist --workpath build_pyinstaller --noconfirm

  echo "==> Capture binary: dist/capture"
fi

# ── 2. Electron app ───────────────────────────────────────────────────────────
if [[ $SKIP_ELECTRON -eq 0 ]]; then
  echo "==> Building Electron app..."
  cd frontend

  npm install
  npm run electron:build

  echo "==> Electron output: frontend/dist/"
  cd ..
fi

echo ""
echo "Build complete."
echo "  Capture binary : dist/capture"
echo "  Electron app   : frontend/dist/<platform>/"
