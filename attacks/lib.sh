#!/usr/bin/env bash
# Shared helpers for attack scenarios. Source, don't execute.
set -u

RED='\033[0;31m'
GRN='\033[0;32m'
NC='\033[0m'

banner() {
    echo -e "${GRN}[*] $*${NC}"
}

warn() {
    echo -e "${RED}[!] $*${NC}"
}

pause() {
    sleep "${1:-2}"
}

# Assert that a JSONL stream contains alerts for the given rule ids.
# Usage: assert_rules <jsonl-file> <rule-id> [<rule-id>...]
assert_rules() {
    local file="$1"; shift
    local missing=0
    for id in "$@"; do
        if grep -q "\"rule_id\":\"$id\"" "$file"; then
            echo -e "${GRN}[PASS]${NC} $id detected"
        else
            echo -e "${RED}[FAIL]${NC} $id NOT detected"
            missing=$((missing + 1))
        fi
    done
    return "$missing"
}
