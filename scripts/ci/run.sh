#!/usr/bin/env bash
# CI step wrapper: run a command, capture its output, and on failure emit
# GitHub annotations (readable via the Checks API) plus a machine-collected
# error file that the diagnostics step posts to the PR.
#
# Usage: scripts/ci/run.sh <step-name> <command...>
set -uo pipefail

NAME="$1"; shift
mkdir -p target/ci-logs
LOG="target/ci-logs/${NAME//[^a-zA-Z0-9_.-]/_}.log"

"$@" >"$LOG" 2>&1
code=$?

# Show the output in the job console.
cat "$LOG"

# Extract errors / tails into annotations + target/ci-errors.log.
python3 scripts/ci/annotate.py "$NAME" "$LOG" "$code" || true

exit "$code"
