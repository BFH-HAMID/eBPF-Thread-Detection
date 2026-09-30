#!/usr/bin/env bash
# Scrape the agent's Prometheus endpoint and print a markdown metrics table.
# Usage: bench/collect_metrics.sh [host:port]   (default 127.0.0.1:9095)
set -u
ADDR="${1:-127.0.0.1:9095}"
URL="http://${ADDR}/metrics"

DATA="$(curl -fsS --max-time 5 "$URL")" || {
    echo "!! cannot scrape $URL (is the agent running with --metrics-addr?)" >&2
    exit 1
}

echo "| metric | value |"
echo "|---|---|"
echo "$DATA" | awk '
    /^sentinel_/ {
        printf "| `%s` | %s |\n", $1, $2
    }
'
