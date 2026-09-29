#!/usr/bin/env bash
# Run every attack scenario. With --assert <jsonl>, also verify detections.
#
# Usage:
#   sudo ./run_all.sh
#   sudo ./run_all.sh --assert /tmp/sentinel.jsonl
set -u
cd "$(dirname "$0")" || exit 1
# shellcheck source=lib.sh
source ./lib.sh

ASSERT_FILE=""
if [ "${1:-}" = "--assert" ]; then
    ASSERT_FILE="${2:-}"
    if [ -z "$ASSERT_FILE" ] || [ ! -f "$ASSERT_FILE" ]; then
        echo "usage: $0 [--assert <sentinel-jsonl>]" >&2
        exit 2
    fi
fi

SCENARIOS=(
    "reverse_shell.sh:SENTINEL-001 SENTINEL-002 SENTINEL-041"
    "sensitive_read.sh:SENTINEL-010 SENTINEL-011 SENTINEL-012"
    "privilege_escalation.sh:SENTINEL-021 SENTINEL-022"
    "container_escape.sh:SENTINEL-030 SENTINEL-032 SENTINEL-033 SENTINEL-034"
    "cryptominer_sim.sh:SENTINEL-041"
)

FAILURES=0
for entry in "${SCENARIOS[@]}"; do
    script="${entry%%:*}"
    expected="${entry#*:}"
    banner "=== $script ==="
    bash "./$script"
    if [ -n "$ASSERT_FILE" ]; then
        # Give the ingest pipeline a moment to flush.
        sleep 2
        assert_rules "$ASSERT_FILE" $expected || FAILURES=$((FAILURES + $?))
    fi
    pause 2
done

if [ -n "$ASSERT_FILE" ]; then
    if [ "$FAILURES" -gt 0 ]; then
        warn "$FAILURES expected detections missing"
        exit 1
    fi
    banner "all expected detections observed"
fi
