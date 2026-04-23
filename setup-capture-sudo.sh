#!/usr/bin/env bash
# Run this ONCE from a terminal (not via the app) to allow the backend to
# start packet capture without a password prompt.
#
# Usage:  bash setup-capture-sudo.sh

set -euo pipefail

WRAPPER=/usr/local/bin/netshield-capture
SUDOERS=/etc/sudoers.d/netshield
USER=${SUDO_USER:-$(whoami)}

if [[ $EUID -ne 0 ]]; then
  echo "Re-running with sudo..."
  exec sudo bash "$0" "$@"
fi

echo "==> Creating capture wrapper at $WRAPPER ..."
cat > "$WRAPPER" << 'WRAPPER_EOF'
#!/usr/bin/env bash
exec "/home/kraken/AI Project/.venv/bin/python" \
     "/home/kraken/AI Project/scripts/capture.py" "$@"
WRAPPER_EOF
chmod 755 "$WRAPPER"

echo "==> Writing sudoers rule to $SUDOERS ..."
echo "$USER ALL=(root) NOPASSWD: $WRAPPER *" > "$SUDOERS"
chmod 440 "$SUDOERS"

# Validate the sudoers file before activating it
visudo -c -f "$SUDOERS"

echo ""
echo "Done. The backend can now start capture without a password prompt."
echo "Test with:  sudo $WRAPPER --iface lo --server http://localhost:8000 --window 5"
