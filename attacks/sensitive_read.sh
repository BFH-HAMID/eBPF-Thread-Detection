#!/usr/bin/env bash
# Simulates credential harvesting and cross-namespace file access.
# Expected detections: SENTINEL-010 (as non-root), SENTINEL-011, SENTINEL-012, SENTINEL-042.
set -u
cd "$(dirname "$0")" || exit 1
# shellcheck source=lib.sh
source ./lib.sh

banner "scenario: sensitive file access"

banner "reading /etc/shadow (drop privileges if we are root)"
read_shadow() { cat /etc/shadow >/dev/null 2>&1 || true; }
if [ "$(id -u)" = "0" ]; then
    if id -u nobody >/dev/null 2>&1; then
        su -s /bin/sh nobody -c "cat /etc/shadow" >/dev/null 2>&1 || true
    else
        read_shadow
    fi
else
    read_shadow
fi
pause 1

banner "probing for SSH private keys"
for key in /root/.ssh/id_rsa /root/.ssh/id_ed25519 "$HOME/.ssh/id_rsa"; do
    cat "$key" >/dev/null 2>&1 || true
done
pause 1

banner "cross-namespace access via /proc/1/root"
cat /proc/1/root/etc/hostname >/dev/null 2>&1 || true
pause 1

banner "host enumeration reads"
for f in /etc/passwd /etc/hosts /proc/cpuinfo /proc/net/tcp; do
    cat "$f" >/dev/null 2>&1 || true
done

banner "sensitive_read scenario done (expect SENTINEL-010/011/012/042 alerts)"
