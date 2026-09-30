#!/usr/bin/env python3
"""Train a syscall n-gram LSTM (next-token) and export it to ONNX.

The model learns event-type sequences of *normal* workloads (one-class).
Anomaly score = mean next-token negative log-likelihood over a sequence; the
exported ONNX graph computes exactly that from a token-id tensor, so the agent
(`agent/src/ml.rs::SequenceScorer`) only has to feed ids and compare the scalar.

Usage:
    python3 ml/train/train_ngram_lstm.py ml/data/baseline.seqs.jsonl \
        --attack ml/data/attack.seqs.jsonl \
        --out ml/models/ngram-lstm-v1.onnx

Outputs (next to --out):
    <stem>.onnx       exported scorer (input: ids [1,T] int64 → score f32)
    <stem>.vocab.json token → id map (the agent loads this alongside the model)
    <stem>.metrics.json precision / recall / FPR + threshold

Requires: numpy + torch (see ml/requirements.txt). ONNX export needs
`onnx` (or torch's built-in exporter fallback).
"""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path

import numpy as np

PAD, UNK = 0, 1
SPECIALS = ["<pad>", "<unk>"]


def load_sequences(path: Path) -> list[list[str]]:
    seqs = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            tokens = obj.get("tokens", [])
            if len(tokens) >= 4:
                seqs.append(tokens)
    return seqs


def build_vocab(seqs: list[list[str]], min_freq: int) -> dict[str, int]:
    counts: Counter[str] = Counter(t for s in seqs for t in s)
    vocab = {tok: i for i, tok in enumerate(SPECIALS)}
    for tok, n in sorted(counts.items()):
        if n >= min_freq and tok not in vocab:
            vocab[tok] = len(vocab)
    return vocab


def encode(seqs: list[list[str]], vocab: dict[str, int]) -> list[np.ndarray]:
    unk = vocab["<unk>"]
    return [
        np.asarray([vocab.get(t, unk) for t in s], dtype=np.int64) for s in seqs
    ]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("baseline", type=Path, help="baseline sequences (JSONL)")
    ap.add_argument("--attack", type=Path, default=None, help="attack sequences (JSONL)")
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--epochs", type=int, default=12)
    ap.add_argument("--batch-size", type=int, default=32)
    ap.add_argument("--embed-dim", type=int, default=32)
    ap.add_argument("--hidden-dim", type=int, default=64)
    ap.add_argument("--max-len", type=int, default=128)
    ap.add_argument("--min-freq", type=int, default=1)
    ap.add_argument("--lr", type=float, default=1e-3)
    ap.add_argument("--seed", type=int, default=7)
    args = ap.parse_args()

    import torch
    from torch import nn

    torch.manual_seed(args.seed)

    base_seqs = load_sequences(args.baseline)
    if not base_seqs:
        print("no baseline sequences (need >= 4 tokens each)", flush=True)
        return 1
    vocab = build_vocab(base_seqs, args.min_freq)
    base = encode(base_seqs, vocab)
    attack = encode(load_sequences(args.attack), vocab) if args.attack else []

    class NextTokenLSTM(nn.Module):
        def __init__(self, vocab_size: int, embed: int, hidden: int):
            super().__init__()
            self.emb = nn.Embedding(vocab_size, embed, padding_idx=PAD)
            self.lstm = nn.LSTM(embed, hidden, batch_first=True)
            self.head = nn.Linear(hidden, vocab_size)

        def forward(self, ids):  # ids: [B, T]
            x, _ = self.lstm(self.emb(ids))
            return self.head(x)  # [B, T, V]

        def seq_nll(self, ids):  # [B, T] -> [B] mean NLL of next tokens
            logits = self.forward(ids[:, :-1])
            tgt = ids[:, 1:]
            loss = nn.functional.cross_entropy(
                logits.reshape(-1, logits.shape[-1]),
                tgt.reshape(-1),
                ignore_index=PAD,
                reduction="none",
            ).reshape(tgt.shape)
            mask = (tgt != PAD).float()
            return (loss * mask).sum(1) / mask.sum(1).clamp(min=1.0)

    vocab_size = len(vocab)
    model = NextTokenLSTM(vocab_size, args.embed_dim, args.hidden_dim)
    opt = torch.optim.Adam(model.parameters(), lr=args.lr)

    def batches(seqs, shuffle=True):
        idx = np.arange(len(seqs))
        if shuffle:
            np.random.shuffle(idx)
        for start in range(0, len(seqs), args.batch_size):
            chunk = [seqs[i] for i in idx[start : start + args.batch_size]]
            T = min(args.max_len, max(len(s) for s in chunk))
            arr = np.full((len(chunk), T), PAD, dtype=np.int64)
            for r, s in enumerate(chunk):
                s = s[:T]
                arr[r, : len(s)] = s
            yield torch.from_numpy(arr)

    model.train()
    for epoch in range(args.epochs):
        total, n = 0.0, 0
        for ids in batches(base):
            opt.zero_grad()
            loss = model.seq_nll(ids).mean()
            loss.backward()
            nn.utils.clip_grad_norm_(model.parameters(), 5.0)
            opt.step()
            total += float(loss) * ids.shape[0]
            n += ids.shape[0]
        print(f"epoch {epoch + 1}/{args.epochs} loss={total / max(n, 1):.4f}", flush=True)

    model.eval()

    @torch.no_grad()
    def score(seqs) -> np.ndarray:
        out = []
        for ids in batches(seqs, shuffle=False):
            out.append(model.seq_nll(ids).numpy())
        return np.concatenate(out) if out else np.zeros(0)

    base_scores = score(base)
    # Threshold: 99th percentile of baseline (≈1% FPR target on train data).
    threshold = float(np.quantile(base_scores, 0.99)) if len(base_scores) else 0.0

    metrics: dict = {
        "model": "ngram-lstm",
        "vocab_size": vocab_size,
        "baseline_sequences": len(base),
        "threshold": threshold,
        "baseline_fpr_at_threshold": float((base_scores >= threshold).mean())
        if len(base_scores)
        else 0.0,
    }
    if attack:
        atk_scores = score(attack)
        tp = int((atk_scores >= threshold).sum())
        fn = int((atk_scores < threshold).sum())
        fp = int((base_scores >= threshold).sum())
        tn = int((base_scores < threshold).sum())
        precision = tp / max(tp + fp, 1)
        recall = tp / max(tp + fn, 1)
        metrics.update(
            {
                "attack_sequences": len(attack),
                "true_positives": tp,
                "false_negatives": fn,
                "false_positives": fp,
                "true_negatives": tn,
                "precision": precision,
                "recall": recall,
                "false_positive_rate": fp / max(fp + tn, 1),
            }
        )
        print(
            f"P={precision:.3f} R={recall:.3f} FPR={fp / max(fp + tn, 1):.3f} "
            f"@ threshold={threshold:.4f}"
        )

    # ---- ONNX export: ids [1,T] -> mean NLL f32 -------------------------
    class Scorer(nn.Module):
        def __init__(self, inner):
            super().__init__()
            self.inner = inner

        def forward(self, ids):
            return self.inner.seq_nll(ids)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    scorer = Scorer(model).eval()
    dummy = torch.zeros((1, 8), dtype=torch.int64)
    exported = False
    try:
        torch.onnx.export(
            scorer,
            (dummy,),
            str(args.out),
            input_names=["ids"],
            output_names=["score"],
            dynamic_axes={"ids": {1: "T"}, "score": {0: "batch"}},
            opset_version=17,
        )
        exported = True
    except Exception as exc:  # noqa: BLE001 - exporter differences across torch versions
        print(f"torch.onnx.export failed ({exc}); trying onnxscript dynamo exporter")
        try:
            onnx_prog = torch.onnx.export(scorer, (dummy,), dynamo=True)
            onnx_prog.save(str(args.out))
            exported = True
        except Exception as exc2:  # noqa: BLE001
            print(f"ONNX export failed: {exc2}")

    vocab_path = args.out.with_suffix(".vocab.json")
    vocab_path.write_text(json.dumps(vocab, indent=2))
    metrics_path = args.out.with_suffix(".metrics.json")
    metrics_path.write_text(json.dumps(metrics, indent=2))
    print(f"wrote {args.out} (onnx={exported}), {vocab_path.name}, {metrics_path.name}")
    return 0 if exported else 2


if __name__ == "__main__":
    raise SystemExit(main())
