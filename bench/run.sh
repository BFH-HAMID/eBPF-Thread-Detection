#!/usr/bin/env bash
# Minimal overhead/loss benchmark driver. See bench/README.md.
#
# Usage: sudo ./run.sh --workload exec-flood --duration 60
set -euo pipefail

WORKLOAD="exec-flood"
DURATION=60
AGENT_PID="${AGENT_PID:-}"

while [ $# -gt 0 ]; do
    case "$1" in
        --workload) WORKLOAD="$2"; shift 2 ;;
        --duration) DURATION="$2"; shift 2 ;;
        *) echo "usage: $0 [--workload exec-flood|open-flood] [--duration SECS]" >&2; exit 2 ;;
    esac
done

if [ -z "$AGENT_PID" ]; then
    AGENT_PID="$(pgrep -n -f 'target/release/sentinel' || true)"
fi

cpu_ticks() {
    # utime + stime for a pid
    awk '{print $14 + $15}' "/proc/$1/stat" 2>/dev/null || echo 0
}

TICKS_BEFORE=$(cpu_ticks "$AGENT_PID")
START=$(date +%s)

case "$WORKLOAD" in
    exec-flood)
        END=$((START + DURATION))
        COUNT=0
        while [ "$(date +%s)" -lt "$END" ]; do
            for _ in $(seq 1 100); do
                /bin/true
                COUNT=$((COUNT + 1))
            done
        done
        echo "syscalls generated (approx): $COUNT"
        ;;
    open-flood)
        END=$((START + DURATION))
        COUNT=0
        while [ "$(date +%s)" -lt "$END" ]; do
            for _ in $(seq 1 100); do
                cat /etc/hostname >/dev/null 2>&1 || true
                COUNT=$((COUNT + 1))
            done
        done
        echo "opens generated (approx): $COUNT"
        ;;
    *)
        echo "unknown workload: $WORKLOAD" >&2
        exit 2
        ;;
esac

END_TS=$(date +%s)
TICKS_AFTER=$(cpu_ticks "$AGENT_PID")
ELAPSED=$((END_TS - START + 1))

echo "workload=$WORKLOAD duration=${ELAPSED}s"
if [ -n "$AGENT_PID" ]; then
    # 100 ticks/sec (USER_HZ) -> % of one core
    CPU_PCT=$(awk -v a="$TICKS_BEFORE" -v b="$TICKS_AFTER" -v t="$ELAPSED" \
        'BEGIN { printf "%.1f", (b - a) / (100 * t) * 100 }')
    echo "agent cpu: ${CPU_PCT}% (of one core, pid=$AGENT_PID)"
else
    echo "agent cpu: unknown (agent not running; set AGENT_PID)"
fi
echo "check the agent's summary line for events= and dropped= to compute the drop rate"
