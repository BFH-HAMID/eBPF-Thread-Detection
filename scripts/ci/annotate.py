#!/usr/bin/env python3
"""Turn a CI step log into GitHub Actions annotations + a collected error file.

Why: job logs are not always retrievable via API; annotations ARE (see
`gh api .../check-runs/<id>/annotations`). Compiler errors are parsed out of
`cargo --message-format=json` records; anything else falls back to a tail
annotation.

Usage: annotate.py <step-name> <log-file> <exit-code>
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

MAX_ANNOTATIONS = 10
MAX_MSG = 1800
ERRORS_FILE = Path("target/ci-errors.log")


def emit(kind: str, message: str, file: str | None = None, line: int | None = None) -> None:
    message = message.replace("\r", "").replace("\n", "%0A")[:MAX_MSG]
    location = ""
    if file:
        location = f" file={file}"
        if line:
            location += f",line={line}"
    print(f"::{kind}{location}::{message}")


def main() -> int:
    name, log_path, code = sys.argv[1], sys.argv[2], int(sys.argv[3])
    log = Path(log_path).read_text(errors="replace")

    ERRORS_FILE.parent.mkdir(parents=True, exist_ok=True)
    with ERRORS_FILE.open("a") as out:
        out.write(f"\n## step `{name}` (exit {code})\n```\n")
        out.write(log[-12_000:])
        out.write("\n```\n")

    if code == 0:
        return 0

    # 1. Structured compiler errors from cargo JSON lines.
    found = 0
    tails: list[str] = []
    for line in log.splitlines():
        if found >= MAX_ANNOTATIONS:
            break
        line = line.strip()
        if not line.startswith("{"):
            tails.append(line)
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            tails.append(line)
            continue
        msg = rec.get("message") or {}
        if rec.get("reason") != "compiler-message" or msg.get("level") != "error":
            continue
        rendered = msg.get("message", "")
        spans = msg.get("spans") or []
        primary = next((s for s in spans if s.get("is_primary")), None)
        if primary:
            emit(
                "error",
                f"[{name}] {rendered}",
                file=primary.get("file_name"),
                line=primary.get("line_start"),
            )
        else:
            emit("error", f"[{name}] {rendered}")
        found += 1

    # 2. Fallback tail annotation for non-cargo failures (fmt, tests, shell).
    if found < MAX_ANNOTATIONS:
        tail = "\n".join(tails[-25:]) or log.splitlines()[-1] if log else "(empty log)"
        emit("error", f"[{name}] exit {code}; output tail: {tail}")

    # 3. Human-facing summary (visible in the run UI).
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_path:
        with open(summary_path, "a") as s:
            s.write(f"\n### ❌ `{name}` failed (exit {code})\n\n```\n")
            s.write("\n".join(tails[-40:])[-4000:])
            s.write("\n```\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
