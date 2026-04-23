#!/usr/bin/env bash
# NetShield Desktop — full build pipeline
# Produces: dist/capture (binary) + frontend/dist/<platform> (Electron installer)
# Usage: ./build.sh [--skip-capture] [--skip-electron]

set -euo pipefail

SKIP_CAPTURE=0
SKIP_ELECTRON=0
for arg in "$@"; do
  [[ "$arg" == "--skip-capture"  ]] && SKIP_CAPTURE=1
  [[ "$arg" == "--skip-electron" ]] && SKIP_ELECTRON=1
done

# Print the failed step and line number on any error
trap 'echo ""; echo "ERROR: build failed at line $LINENO — check output above." >&2' ERR

# ── 1. Python capture binary ──────────────────────────────────────────────────
if [[ $SKIP_CAPTURE -eq 0 ]]; then
  echo "==> Building capture binary (PyInstaller)..."

  if [[ ! -f ".venv/bin/activate" ]]; then
    echo "ERROR: .venv not found. Run: python -m venv .venv && pip install -r requirements.txt" >&2
    exit 1
  fi

  # shellcheck disable=SC1091
  source .venv/bin/activate

  pip install pyinstaller
  pyinstaller capture.spec --distpath dist --workpath build_pyinstaller --noconfirm --clean

  echo "==> Capture binary: dist/capture"
fi

# ── 2. Electron app ───────────────────────────────────────────────────────────
if [[ $SKIP_ELECTRON -eq 0 ]]; then
  echo "==> Building Electron app..."

  # electron-builder bundles dist/capture as an extraResource; it must exist
  if [[ ! -e "dist/capture" ]]; then
    echo "ERROR: dist/capture not found. Run without --skip-capture first (or build the binary manually)." >&2
    exit 1
  fi

  pushd frontend > /dev/null
  npm ci
  npm run electron:build
  popd > /dev/null

  echo "==> Electron output: frontend/dist/"
fi

echo ""
echo "Build complete."
echo "  Capture binary : dist/capture"
echo "  Electron app   : frontend/dist/<platform>/"
