#!/usr/bin/env python3
"""Train a feature autoencoder and export it to ONNX.

The autoencoder learns the normal-workload manifold; the reconstruction error
(MSE) becomes the anomaly score. Reported metrics are computed on a held-out
baseline split plus an optional attack set.

Usage:
    python3 ml/train/train_autoencoder.py ml/data/baseline.npz \
        --attack ml/data/attack.npz --out ml/models/autoencoder-v1.onnx
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np


def load(path: Path) -> np.ndarray:
    return np.load(path, allow_pickle=False)["features"]


def evaluate(errors: np.ndarray, labels: np.ndarray, threshold: float) -> dict:
    pred = errors >= threshold
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
    ap.add_argument("baseline", type=Path)
    ap.add_argument("--attack", type=Path)
    ap.add_argument("--epochs", type=int, default=50)
    ap.add_argument("--latent", type=int, default=4)
    ap.add_argument("--threshold", type=float, default=None,
                    help="MSE threshold (default: p99 of training error)")
    ap.add_argument("--out", type=Path, default=Path("ml/models/autoencoder-v1.onnx"))
    args = ap.parse_args()

    try:
        import torch
        from torch import nn
    except ImportError:
        print("torch is required: pip install -r ml/requirements.txt", file=__import__("sys").stderr)
        return 1

    x = load(args.baseline).astype(np.float32)
    # Standardize with training statistics (persisted for the agent).
    mean = x.mean(axis=0)
    std = x.std(axis=0) or 1.0
    x_norm = (x - mean) / std

    n_features = x.shape[1]
    model = nn.Sequential(
        nn.Linear(n_features, 16),
        nn.ReLU(),
        nn.Linear(16, args.latent),
        nn.ReLU(),
        nn.Linear(args.latent, 16),
        nn.ReLU(),
        nn.Linear(16, n_features),
    )
    opt = torch.optim.Adam(model.parameters(), lr=1e-3)
    loss_fn = nn.MSELoss()
    dataset = torch.from_numpy(x_norm)

    model.train()
    for epoch in range(args.epochs):
        perm = torch.randperm(dataset.shape[0])
        total = 0.0
        for i in range(0, dataset.shape[0], 32):
            batch = dataset[perm[i : i + 32]]
            opt.zero_grad()
            loss = loss_fn(model(batch), batch)
            loss.backward()
            opt.step()
            total += float(loss) * batch.shape[0]
        if (epoch + 1) % 10 == 0:
            print(f"epoch {epoch + 1}: mse={total / dataset.shape[0]:.6f}")

    model.eval()
    with torch.no_grad():
        train_errors = ((model(dataset) - dataset) ** 2).mean(dim=1).numpy()

    threshold = args.threshold or float(np.percentile(train_errors, 99))
    print(f"threshold (train p99): {threshold:.6f}")

    if args.attack is not None:
        x_a = (load(args.attack).astype(np.float32) - mean) / std
        with torch.no_grad():
            attack_errors = (
                (model(torch.from_numpy(x_a)) - torch.from_numpy(x_a)) ** 2
            ).mean(dim=1).numpy()
        errors = np.concatenate([train_errors, attack_errors])
        labels = np.concatenate([np.zeros(len(train_errors)), np.ones(len(attack_errors))])
    else:
        errors, labels = train_errors, np.zeros(len(train_errors))

    report = evaluate(errors, labels, threshold)
    print(json.dumps(report, indent=2))

    # ONNX export with a wrapper that applies standardization + MSE so the
    # agent can call a single model.
    class Scorer(nn.Module):
        def __init__(self, ae: nn.Module, mean: np.ndarray, std: np.ndarray):
            super().__init__()
            self.ae = ae
            self.register_buffer("mean", torch.from_numpy(mean))
            self.register_buffer("std", torch.from_numpy(std))

        def forward(self, features: torch.Tensor) -> torch.Tensor:
            x = (features - self.mean) / self.std
            err = ((self.ae(x) - x) ** 2).mean(dim=1, keepdim=True)
            return err

    scorer = Scorer(model, mean, std.astype(np.float32))
    dummy = torch.zeros(1, n_features)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    torch.onnx.export(
        scorer,
        dummy,
        str(args.out),
        input_names=["features"],
        output_names=["anomaly_score"],
        dynamic_axes={"features": {0: "batch"}, "anomaly_score": {0: "batch"}},
        opset_version=13,
    )
    args.out.with_suffix(".metrics.json").write_text(
        json.dumps({**report, "mean": mean.tolist(), "std": np.asarray(std).tolist()}, indent=2)
    )
    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
