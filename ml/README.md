# Sentinel ML pipeline

Python training pipeline for anomaly detection on top of the agent's
windowed features. Models are exported to ONNX and consumed by the agent
(`agent/src/ml.rs`) via the `ort` crate.

```
ml/
├── datasets/
│   └── collect.py          # JSONL (agent output) -> windowed feature dataset
├── train/
│   ├── train_iforest.py    # Isolation Forest (sklearn -> ONNX via skl2onnx)
│   ├── train_autoencoder.py# autoencoder (PyTorch -> ONNX)
│   └── train_ngram_lstm.py # (Phase 4) syscall n-gram sequence model
└── export/
    └── export_onnx.py      # validate + version exported models
```

## Workflow

1. **Collect a baseline** from normal workloads:

   ```shell
   sudo ./target/release/sentinel --emit-events > /tmp/workload.jsonl
   # run nginx/postgres/CI workload...
   python3 ml/datasets/collect.py /tmp/workload.jsonl -o ml/data/baseline.npz
   ```

2. **Inject attacks** (`attacks/`) and collect again → `ml/data/attack.npz`.

3. **Train** (in order of complexity):

   ```shell
   python3 ml/train/train_iforest.py ml/data/baseline.npz --attack ml/data/attack.npz
   python3 ml/train/train_autoencoder.py ml/data/baseline.npz --attack ml/data/attack.npz
   ```

   Each trainer reports precision / recall / false-positive rate on a held-out
   split and writes `ml/models/<name>-v<N>.onnx` + metadata JSON.

4. **Export/validate**: `python3 ml/export/export_onnx.py ml/models/model.onnx`
   checks the input signature matches the agent's [`FeatureVector`] schema.

5. **Sequence data**: `collect.py --sequences-out ml/data/baseline.seqs.jsonl`
   writes per-key `evt_type` token sequences for the LSTM.

6. **Train the n-gram LSTM** (next-token model, mean-NLL scoring):

   ```shell
   python3 ml/train/train_ngram_lstm.py ml/data/baseline.seqs.jsonl        --attack ml/data/attack.seqs.jsonl --out ml/models/ngram-lstm-v1.onnx
   ```

   This writes `<stem>.onnx` (ids `[1,T] int64` → `score f32`), `<stem>.vocab.json`
   and `<stem>.metrics.json` (precision / recall / FPR + threshold).

7. **Run**: `sentinel --model ml/models/iforest-v1.onnx` for window models, or
   feed the LSTM export the same way — the agent's `OnnxScorer` scores feature
   vectors; `SequenceScorer` keeps per-process token history and scores windows
   of events. Risk alerts fire at/above `--risk-threshold` as `{"kind":"risk"}`.

## Model plan

| Model | Signal | Tradeoff | State |
|---|---|---|---|
| Isolation Forest | point anomalies in feature space | cheap, interpretable, weak on sequences | shipped (`train_iforest.py`, `OnnxScorer`) |
| Autoencoder | reconstruction error on feature vectors | catches multivariate drift, needs threshold tuning | shipped (`train_autoencoder.py`, `OnnxScorer`) |
| n-gram LSTM | event-type sequence anomalies | best recall on slow attacks, heaviest to run | shipped (`train_ngram_lstm.py`, `SequenceScorer`) |

Model contract for the agent: the exported graph maps one input tensor to a
single `f32` **anomaly score, higher = worse**. Window models take
`[1, N_FEATURES]` float features (column order = `FEATURE_COLUMNS`); the
sequence model takes `[1, T]` int64 token ids and returns mean next-token NLL.

Rules stay the high-confidence layer; ML only supplies a risk score for the
gaps (`docs/architecture.md`).

## Requirements

See `requirements.txt`. Python ≥ 3.10.
