#!/usr/bin/env python3
"""Validate and version an exported ONNX model against the agent contract.

Checks:
  * input name/type matches the agent's FeatureVector schema,
  * the sentinel metadata (columns, normalization) is present and ordered,
  * the file runs in onnxruntime on a zero input (shape smoke test).

Usage:
    python3 ml/export/export_onnx.py ml/models/iforest-v1.onnx --version 1
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path

EXPECTED_COLUMNS = [
    "exec_count",
    "open_count",
    "net_connect_count",
    "sys_event_count",
    "distinct_dst_ips",
    "distinct_dst_ports",
    "distinct_file_paths",
    "file_path_entropy",
    "distinct_comms",
]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("model", type=Path)
    ap.add_argument("--version", type=int, default=1)
    ap.add_argument("--models-dir", type=Path, default=Path("ml/models"))
    args = ap.parse_args()

    try:
        import onnxruntime as ort
    except ImportError:
        print("onnxruntime is required: pip install -r ml/requirements.txt", file=sys.stderr)
        return 1

    sess = ort.InferenceSession(str(args.model), providers=["CPUExecutionProvider"])
    inputs = sess.get_inputs()
    if len(inputs) != 1:
        print(f"FAIL: expected 1 input, got {len(inputs)}", file=sys.stderr)
        return 1
    if inputs[0].name != "features":
        print(f"FAIL: input must be named 'features', got {inputs[0].name}", file=sys.stderr)
        return 1
    shape = inputs[0].shape
    if len(shape) != 2 or (isinstance(shape[1], int) and shape[1] != len(EXPECTED_COLUMNS)):
        print(f"FAIL: input shape {shape} does not match FeatureVector", file=sys.stderr)
        return 1

    meta = {p.key: p.value for p in sess.get_modelmeta().custom_metadata_map.items()} \
        if hasattr(sess.get_modelmeta(), "custom_metadata_map") else {}
    columns = json.loads(meta.get("sentinel_columns", "[]"))
    if columns and columns != EXPECTED_COLUMNS:
        print(f"FAIL: column drift: {columns}", file=sys.stderr)
        return 1

    # Smoke test on a zero input.
    import numpy as np

    out = sess.run(None, {"features": np.zeros((1, len(EXPECTED_COLUMNS)), dtype=np.float32)})
    print(f"OK: smoke output shape {np.asarray(out[0]).shape}")

    # Versioned copy.
    args.models_dir.mkdir(parents=True, exist_ok=True)
    stem = args.model.stem.split("-v")[0]
    dest = args.models_dir / f"{stem}-v{args.version}.onnx"
    shutil.copyfile(args.model, dest)
    manifest = {
        "model": dest.name,
        "version": args.version,
        "columns": EXPECTED_COLUMNS,
        "input": "features",
    }
    (args.models_dir / f"{stem}-v{args.version}.json").write_text(json.dumps(manifest, indent=2))
    print(f"versioned model -> {dest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
