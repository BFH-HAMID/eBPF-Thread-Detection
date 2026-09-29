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

5. **Run**: `sentinel --model ml/models/iforest-v1.onnx` (Phase 4).

## Model plan

| Model | Signal | Tradeoff |
|---|---|---|
| Isolation Forest | point anomalies in feature space | cheap, interpretable, weak on sequences |
| Autoencoder | reconstruction error on feature vectors | catches multivariate drift, needs tuning of the threshold |
| n-gram LSTM | syscall-sequence anomalies | best recall on slow attacks, heaviest to run |

Rules stay the high-confidence layer; ML only supplies a risk score for the
gaps (`docs/architecture.md`).

## Requirements

See `requirements.txt`. Python ≥ 3.10.
