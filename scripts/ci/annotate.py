#!/usr/bin/env python3
"""Turn a CI step log into GitHub Actions annotations + a collected error file.

Why: job logs are not always retrievable via API; annotations ARE (see
`gh api .../check-runs/<id>/annotations`). Compiler errors are found either
as cargo JSON records (`--message-format=json`) or by scanning plain-text
output for `error[...]`/`error:` blocks with their `-->` locations.

Usage: annotate.py <step-name> <log-file> <exit-code>
"""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

MAX_ANNOTATIONS = 10
MAX_MSG = 1800
ERRORS_FILE = Path("target/ci-errors.log")
ANSI = re.compile(r"\x1b\[[0-9;]*m")
# Plain-text compiler/clippy errors: "error[E0433]: ...", "error: ...".
ERR_LINE = re.compile(r"^error(?:\[E\d+\])?: ")
LOC_LINE = re.compile(r"^\s+--> ([^:\n]+):(\d+)")


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
    raw = Path(log_path).read_text(errors="replace")
    log = ANSI.sub("", raw)

    ERRORS_FILE.parent.mkdir(parents=True, exist_ok=True)
    with ERRORS_FILE.open("a") as out:
        out.write(f"\n## step `{name}` (exit {code})\n```\n")
        out.write(log[-12_000:])
        out.write("\n```\n")

    if code == 0:
        return 0

    lines = log.splitlines()
    found = 0

    # 1. Structured compiler errors from cargo JSON lines.
    tails: list[str] = []
    for line in lines:
        if found >= MAX_ANNOTATIONS:
            break
        s = line.strip()
        if not s.startswith("{"):
            tails.append(line)
            continue
        try:
            rec = json.loads(s)
        except json.JSONDecodeError:
            tails.append(line)
            continue
        msg = rec.get("message") or {}
        if rec.get("reason") != "compiler-message" or msg.get("level") != "error":
            continue
        rendered = msg.get("message", "")
        spans = msg.get("spans") or []
        primary = next((sp for sp in spans if sp.get("is_primary")), None)
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

    # 2. Plain-text `error:` blocks (rustc/clippy without JSON), with `-->` loc.
    if found < MAX_ANNOTATIONS:
        i = 0
        while i < len(lines) and found < MAX_ANNOTATIONS:
            if ERR_LINE.match(lines[i]):
                block = [lines[i]]
                file = line_no = None
                j = i + 1
                while j < len(lines) and j < i + 25 and not ERR_LINE.match(lines[j]):
                    block.append(lines[j])
                    m = LOC_LINE.match(lines[j])
                    if m and file is None:
                        file, line_no = m.group(1), int(m.group(2))
                    if lines[j].strip() == "" and len(block) > 3:
                        break
                    j += 1
                emit("error", f"[{name}] " + "\n".join(block), file=file, line=line_no)
                found += 1
                i = j
                continue
            i += 1

    # 3. Panic / assertion failures (test binaries).
    if found < MAX_ANNOTATIONS:
        for i, line in enumerate(lines):
            if found >= MAX_ANNOTATIONS:
                break
            if "panicked at" in line or "assertion failed" in line:
                ctx = "\n".join(lines[i : min(i + 8, len(lines))])
                emit("error", f"[{name}] test failure: {ctx}")
                found += 1

    # 4. Fallback tail annotation so every failure is at least visible.
    if found == 0:
        tail = "\n".join(lines[-25:]) or "(empty log)"
        emit("error", f"[{name}] exit {code}; output tail: {tail}")

    # 5. Human-facing summary (visible in the run UI).
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_path:
        with open(summary_path, "a") as s:
            s.write(f"\n### ❌ `{name}` failed (exit {code})\n\n```\n")
            s.write("\n".join(tails[-40:])[-4000:] if tails else log[-3000:])
            s.write("\n```\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
