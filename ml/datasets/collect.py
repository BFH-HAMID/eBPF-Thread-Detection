#!/usr/bin/env python3
"""Collect windowed feature datasets from sentinel JSONL output.

Reads the agent's JSON lines stream (``--emit-events``), recomputes the same
windowed features as ``agent/src/features.rs`` (single source of truth:
``FeatureVector``) and writes an ``.npz`` dataset for training.

Usage:
    python3 ml/datasets/collect.py events.jsonl -o ml/data/baseline.npz
    sudo ./sentinel --emit-events | python3 ml/datasets/collect.py - -o /tmp/ds.npz

Columns are exported both as a numpy matrix and a JSON schema so trainers and
the agent cannot silently drift apart.
"""

from __future__ import annotations

import argparse
import json
import math
import sys
from collections import defaultdict
from pathlib import Path

import numpy as np

# Must match `agent/src/features.rs::FeatureVector` field order (and
# `FEATURE_COLUMNS` in `agent/src/ml.rs`).
FEATURE_COLUMNS = [
    "exec_count",
    "open_count",
    "net_connect_count",
    "sys_event_count",
    "distinct_dst_ips",
    "distinct_dst_ports",
    "distinct_file_paths",
    "file_path_entropy",
    "distinct_comms",
    "dns_count",
    "distinct_dns_queries",
]


def shannon_entropy(byte_counts: dict[int, int]) -> float:
    total = sum(byte_counts.values())
    if total == 0:
        return 0.0
    return -sum(
        (n / total) * math.log2(n / total) for n in byte_counts.values() if n > 0
    )


class Window:
    __slots__ = (
        "exec_count",
        "open_count",
        "net_connect_count",
        "sys_event_count",
        "dst_ips",
        "dst_ports",
        "file_paths",
        "path_chars",
        "comms",
        "dns_count",
        "dns_queries",
    )

    def __init__(self) -> None:
        self.exec_count = 0
        self.open_count = 0
        self.net_connect_count = 0
        self.sys_event_count = 0
        self.dst_ips: set[str] = set()
        self.dst_ports: set[int] = set()
        self.file_paths: set[str] = set()
        self.path_chars: dict[int, int] = defaultdict(int)
        self.comms: set[str] = set()
        self.dns_count = 0
        self.dns_queries: set[str] = set()

    def observe(self, data: dict) -> None:
        evt_type = data.get("evt_type", "")
        header = data.get("header", {})
        comm = header.get("comm", "")
        if comm:
            self.comms.add(comm)
        if evt_type == "execve":
            self.exec_count += 1
            self._record_path(data.get("filename", ""))
        elif evt_type == "openat":
            self.open_count += 1
            self._record_path(data.get("filename", ""))
        elif evt_type == "connect":
            self.net_connect_count += 1
            addr = data.get("addr", "")
            if addr:
                self.dst_ips.add(addr)
            self.dst_ports.add(int(data.get("port", 0)))
        elif evt_type in ("accept", "bind"):
            self.net_connect_count += 1
        elif evt_type == "dns":
            self.dns_count += 1
            query = data.get("query", "")
            if query:
                self.dns_queries.add(query)
        else:
            self.sys_event_count += 1

    def _record_path(self, path: str) -> None:
        if not path:
            return
        self.file_paths.add(path)
        for b in path.encode("utf-8", "replace"):
            self.path_chars[b] += 1

    def to_row(self) -> list[float]:
        return [
            float(self.exec_count),
            float(self.open_count),
            float(self.net_connect_count),
            float(self.sys_event_count),
            float(len(self.dst_ips)),
            float(len(self.dst_ports)),
            float(len(self.file_paths)),
            float(shannon_entropy(self.path_chars)),
            float(len(self.comms)),
            float(self.dns_count),
            float(len(self.dns_queries)),
        ]


def process(lines, window_secs: int) -> tuple[np.ndarray, list[str]]:
    """Group events per ``tgid`` key and split them into fixed windows by the
    event count boundary approximation (timestamp bucketing)."""
    buckets: dict[str, dict[int, Window]] = defaultdict(lambda: defaultdict(Window))
    for raw in lines:
        try:
            obj = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if obj.get("kind") != "event":
            continue
        data = obj.get("data", {})
        header = data.get("header", {})
        tgid = header.get("tgid", 0)
        ts_ns = header.get("timestamp_ns", 0)
        bucket = int(ts_ns // (window_secs * 1_000_000_000))
        buckets[f"tgid:{tgid}"][bucket].observe(data)

    rows: list[list[float]] = []
    keys: list[str] = []
    for key, windows in buckets.items():
        for _, window in sorted(windows.items()):
            rows.append(window.to_row())
            keys.append(key)
    return np.asarray(rows, dtype=np.float32), keys


def process_sequences(lines) -> dict[str, list[str]]:
    """Per-key event-type token sequences for the n-gram (LSTM) model.

    Tokens are plain ``evt_type`` names in arrival order — the same vocabulary
    the agent's ``SequenceScorer`` sees. Sequences are truncated to 4096
    tokens per key (keeps datasets bounded).
    """
    seqs: dict[str, list[str]] = defaultdict(list)
    for raw in lines:
        try:
            obj = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if obj.get("kind") != "event":
            continue
        data = obj.get("data", {})
        header = data.get("header", {})
        key = f"tgid:{header.get('tgid', 0)}"
        tok = data.get("evt_type", "")
        if tok and len(seqs[key]) < 4096:
            seqs[key].append(tok)
    return seqs


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("input", help="JSONL file from the agent, or '-' for stdin")
    ap.add_argument("-o", "--output", type=Path, required=True)
    ap.add_argument("--window-secs", type=int, default=60)
    ap.add_argument(
        "--sequences-out",
        type=Path,
        default=None,
        help="also write per-key evt_type token sequences (JSONL) for the LSTM",
    )
    args = ap.parse_args()

    stream = sys.stdin if args.input == "-" else open(args.input, encoding="utf-8")
    with stream:
        if args.sequences_out:
            raw = list(stream)
            seqs = process_sequences(iter(raw))
            matrix, keys = process(iter(raw), args.window_secs)
        else:
            seqs = {}
            matrix, keys = process(stream, args.window_secs)

    if matrix.size == 0 and not seqs:
        print("no events collected; dataset is empty", file=sys.stderr)
        return 1

    args.output.parent.mkdir(parents=True, exist_ok=True)
    np.savez(
        args.output,
        features=matrix if matrix.size else np.zeros((0, len(FEATURE_COLUMNS)), np.float32),
        columns=np.asarray(FEATURE_COLUMNS),
        keys=np.asarray(keys),
    )
    schema = args.output.with_suffix(".schema.json")
    schema.write_text(
        json.dumps(
            {
                "columns": FEATURE_COLUMNS,
                "window_secs": args.window_secs,
                "rows": int(matrix.shape[0]),
            },
            indent=2,
        )
    )
    print(f"wrote {matrix.shape[0]} rows x {matrix.shape[1]} cols -> {args.output}")

    if args.sequences_out:
        args.sequences_out.parent.mkdir(parents=True, exist_ok=True)
        with open(args.sequences_out, "w", encoding="utf-8") as out:
            for key, tokens in seqs.items():
                out.write(json.dumps({"key": key, "tokens": tokens}) + "\n")
        print(f"wrote {len(seqs)} token sequences -> {args.sequences_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
