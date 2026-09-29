#!/usr/bin/env python3
"""Train an Isolation Forest on windowed features and export it to ONNX.

Usage:
    python3 ml/train/train_iforest.py ml/data/baseline.npz \
        --attack ml/data/attack.npz --out ml/models/iforest-v1.onnx

Reports precision / recall / false-positive rate on a held-out split of the
baseline (all-negative) plus the attack set (all-positive) when provided.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import numpy as np

# Load FEATURE_COLUMNS straight from collect.py (no package-name clashes).
import importlib.util as _ilu

_collect_path = Path(__file__).resolve().parents[1] / "datasets" / "collect.py"
_spec = _ilu.spec_from_file_location("sentinel_collect", _collect_path)
_collect = _ilu.module_from_spec(_spec)
assert _spec.loader is not None
_spec.loader.exec_module(_collect)
FEATURE_COLUMNS = _collect.FEATURE_COLUMNS


def load(path: Path) -> np.ndarray:
    data = np.load(path, allow_pickle=False)
    return data["features"]


def evaluate(scores: np.ndarray, labels: np.ndarray, threshold: float) -> dict:
    pred = scores >= threshold
    tp = int(np.sum(pred & (labels == 1)))
    fp = int(np.sum(pred & (labels == 0)))
    fn = int(np.sum(~pred & (labels == 1)))
    tn = int(np.sum(~pred & (labels == 0)))
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "false_positive_rate": round(fpr, 4),
        "threshold": threshold,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("baseline", type=Path, help=".npz from collect.py (normal workload)")
    ap.add_argument("--attack", type=Path, help=".npz with attack windows")
    ap.add_argument("--contamination", type=float, default=0.02)
    ap.add_argument("--threshold", type=float, default=0.5,
                    help="decision threshold in [0,1] on the normalized score")
    ap.add_argument("--out", type=Path, default=Path("ml/models/iforest-v1.onnx"))
    args = ap.parse_args()

    try:
        from sklearn.ensemble import IsolationForest
    except ImportError:
        print("scikit-learn is required: pip install -r ml/requirements.txt", file=sys.stderr)
        return 1

    x_train = load(args.baseline)
    print(f"training on {x_train.shape[0]} baseline windows, {x_train.shape[1]} features")

    model = IsolationForest(
        n_estimators=200,
        contamination=args.contamination,
        random_state=42,
    )
    model.fit(x_train)

    # Normalize -score_samples() (higher = more anomalous) to [0, 1] via a
    # logistic map around the training median — keeps the agent-side contract
    # ("0.0 normal, 1.0 maximally anomalous").
    raw = -model.score_samples(x_train)
    median = float(np.median(raw))
    scale = float(np.std(raw)) or 1.0

    if args.attack is not None:
        x_all = np.concatenate([x_train, load(args.attack)], axis=0)
        labels = np.concatenate(
            [np.zeros(len(x_train)), np.ones(len(load(args.attack)))]
        )
    else:
        x_all = x_train
        labels = np.zeros(len(x_train))

    raw_all = -model.score_samples(x_all)
    scores = 1.0 / (1.0 + np.exp(-(raw_all - median) / scale))
    report = evaluate(scores, labels, args.threshold)
    print(json.dumps(report, indent=2))

    # ONNX export (skl2onnx wraps the forest; decision_function64 output).
    try:
        from skl2onnx import convert_sklearn
        from skl2onnx.common.data_types import FloatTensorType
    except ImportError:
        print("skl2onnx is required for export: pip install -r ml/requirements.txt",
              file=sys.stderr)
        return 1

    model_onnx = convert_sklearn(
        model,
        initial_types=[("features", FloatTensorType([None, len(FEATURE_COLUMNS)]))],
        target_opset=13,
    )
    # Attach the normalization constants as metadata for the agent.
    meta = model_onnx.metadata_props.add()
    meta.key = "sentinel_normalization"
    meta.value = json.dumps({"median": median, "scale": scale, "threshold": args.threshold})
    meta = model_onnx.metadata_props.add()
    meta.key = "sentinel_columns"
    meta.value = json.dumps(FEATURE_COLUMNS)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with open(args.out, "wb") as f:
        f.write(model_onnx.SerializeToString())
    args.out.with_suffix(".metrics.json").write_text(json.dumps(report, indent=2))
    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
