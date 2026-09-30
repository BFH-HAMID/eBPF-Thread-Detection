#!/usr/bin/env bash
# Boot a specific kernel version under virtme-ng and run the detection gate
# inside the guest (Phase 5 kernel matrix). Used by .github/workflows/kernel-matrix.yml.
#
# Usage: sudo bash scripts/ci/kernel-matrix-test.sh <kernel-version, e.g. 5.15>
set -uo pipefail
KVER="${1:?usage: kernel-matrix-test.sh <kernel-version>}"
cd "$(dirname "$0")/../.." || exit 2

echo "== kernel matrix gate for ${KVER} =="
uname -a

# Prefer virtme-ng with an explicit image; fall back to -r (version lookup).
KIMG="$(ls -1 /boot/vmlinuz-*"${KVER}"* 2>/dev/null | sort -V | tail -1 || true)"
if [ -n "$KIMG" ]; then
    echo "booting $KIMG"
    exec vng --kimg "$KIMG" -- scripts/ci/detect-test.sh
else
    echo "no /boot/vmlinuz-*${KVER}* found; trying vng -r ${KVER}"
    exec vng -r "$KVER" -- scripts/ci/detect-test.sh
fi
