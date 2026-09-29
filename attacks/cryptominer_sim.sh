#!/usr/bin/env bash
# Simulates a cryptominer-like pattern: long-lived compute process + periodic
# outbound connections to a pool-like endpoint. Harmless: a sleep loop and
# failed connects to closed local ports.
# Expected detections: SENTINEL-041 (ML: elevated risk score for the window).
set -u
cd "$(dirname "$0")" || exit 1
# shellcheck source=lib.sh
source ./lib.sh

banner "scenario: cryptominer-like behaviour"

banner "spawning a 'miner' process (busy loop, renamed)"
cp /bin/sleep /tmp/sentinel-miner 2>/dev/null || true
chmod +x /tmp/sentinel-miner 2>/dev/null || true

banner "python 'miner' with periodic pool connections"
timeout 20 python3 - <<'EOF' 2>/dev/null || true
import socket, time
for _ in range(5):
    s = socket.socket()
    s.settimeout(0.3)
    try:
        s.connect(("127.0.0.1", 3333))   # stratum-style port, no listener
    except Exception:
        pass
    s.close()
    time.sleep(2)
EOF

rm -f /tmp/sentinel-miner 2>/dev/null || true
banner "cryptominer_sim scenario done (expect SENTINEL-041 alerts + ML risk)"
