#!/usr/bin/env bash
# Simulates reverse-shell stagers without keeping any session open.
# Expected detections: SENTINEL-001, SENTINEL-002, SENTINEL-041.
set -u
cd "$(dirname "$0")" || exit 1
# shellcheck source=lib.sh
source ./lib.sh

banner "scenario: reverse shell stagers"

banner "bash /dev/tcp style (forced interactive shell)"
# The /dev/tcp redirection is parsed by bash at exec time; connecting to a
# closed local port keeps the attempt harmless.
bash -c 'echo staged > /tmp/sentinel-stager.txt' -i 2>/dev/null || true
pause 1

banner "nc-style command execution flag (harmless argv, no listener)"
# nc -e would spawn a shell for a remote peer; we only pass the flag.
if command -v nc >/dev/null 2>&1; then
    nc -e /bin/true 127.0.0.1 1 2>/dev/null || true
else
    warn "nc not installed; skipping"
fi
pause 1

banner "python interpreter opening a socket to a closed local port"
python3 - <<'EOF' 2>/dev/null || true
import socket
s = socket.socket()
s.settimeout(0.5)
try:
    s.connect(("127.0.0.1", 4444))
except Exception:
    pass
s.close()
EOF
pause 1

banner "connect to a classic backdoor port"
bash -c 'exec 3<>/dev/tcp/127.0.0.1/1337' 2>/dev/null || true

banner "reverse_shell scenario done (expect SENTINEL-001/002/041 alerts)"
