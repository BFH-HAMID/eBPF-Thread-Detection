#!/usr/bin/env bash
# Phase 3 detection gate: run the agent on a real kernel, replay the attack
# scenarios, and fail unless every expected rule fires. Used by CI (sudo) and
# by the virtme-ng kernel matrix.
#
# Usage: sudo bash scripts/ci/detect-test.sh
set -uo pipefail

cd "$(dirname "$0")/../.." || exit 2
mkdir -p target/ci-logs
OUT="$(mktemp /tmp/sentinel-detect-XXXXXX.jsonl)"
AGENT_LOG="target/ci-logs/detect-agent.log"

cleanup() {
    if [ -n "${AGENT_PID:-}" ]; then
        kill -INT "$AGENT_PID" 2>/dev/null || true
        wait "$AGENT_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT

# Make sure tracefs is available (some runners need the mount).
for p in /sys/kernel/tracing /sys/kernel/debug/tracing; do
    if [ ! -d "$p/events" ]; then
        mkdir -p "$p" 2>/dev/null || true
        mount -t tracefs tracefs "$p" 2>/dev/null || true
    fi
done

echo "== starting agent (output: $OUT) =="
./target/release/sentinel --rules rules/ --emit-events >"$OUT" 2>"$AGENT_LOG" &
AGENT_PID=$!
sleep 5

if ! kill -0 "$AGENT_PID" 2>/dev/null; then
    echo "!! agent died during startup:"
    cat "$AGENT_LOG"
    exit 1
fi

echo "== running attack suite =="
FAILURES=0
bash attacks/run_all.sh --assert "$OUT" || FAILURES=$?

echo "== agent summary =="
sleep 2
kill -INT "$AGENT_PID" 2>/dev/null || true
wait "$AGENT_PID" 2>/dev/null || true
AGENT_PID=""
grep '"kind":"summary"' "$OUT" || true
grep '"kind":"alert"' "$OUT" | head -30 || true

if [ "$FAILURES" -ne 0 ]; then
    echo "!! $FAILURES expected detections missing"
    echo "---- agent log ----"
    cat "$AGENT_LOG"
    exit 1
fi
echo "== all expected detections observed =="
