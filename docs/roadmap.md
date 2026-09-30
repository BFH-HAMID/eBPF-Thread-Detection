# Roadmap (~20 weeks)

Status: ✅ done · 🚧 in progress · ⬜ planned

## Phase 1 — Foundations (weeks 1–3) ✅

- ✅ Workspace: `bpf/` (Aya eBPF), `agent/` (Aya userspace), `bpf/common/` ABI.
- ✅ `execve` + `openat` tracing through a ring buffer to stdout (JSON lines).
- ✅ Also shipped ahead of schedule: `connect`, `ptrace`, `mount`, `setns`,
  `unshare`, `capset`, `pivot_root` tracepoints.
- ✅ Drop-counter map + loss accounting (`DROPPED` → `dropped` metric).
- ✅ Read Falco / Tetragon / Tracee design notes (`docs/architecture.md`).
- ⬜ Verifier-pitfalls blog post draft (`docs/blog/verifier-pitfalls.md`).

## Phase 2 — Core tracing (weeks 4–8) ✅

- ✅ Syscalls from the roadmap list (see above).
- ✅ `accept4` + `bind` syscall tracepoints (peer/local addresses via shared
  `parse_sockaddr`; accept peer address is filled at syscall *exit* and is a
  documented gap until CO-RE).
- ✅ `cgroup_skb` egress/ingress: per-cgroup byte counters (`BYTE_STATS`) and
  DNS query capture (UDP/53 wire-format QNAME → userspace label decoding).
  CO-RE `fentry/tcp_v4_connect` 4-tuple tracking remains optional future work.
- ✅ Container enrichment v2: container id + pod UID from cgroup paths,
  pod name/namespace via the Kubernetes API (`k8s` feature, in-cluster
  service account, TTL cache).
- ✅ In-kernel uid-range filter (`CONFIG` map, `--min-uid/--max-uid`) —
  checked before any ring-buffer reservation.
- 🚧 Loss/overhead benchmark (`bench/collect_metrics.sh` scrapes the
  Prometheus endpoint); fill the results table early.

## Phase 3 — Rule engine (weeks 9–11) 🚧

- ✅ YAML rules + boolean condition language (`agent/src/rules.rs`).
- ✅ Default rules with MITRE ATT&CK tags (`rules/*.yaml`).
- ✅ Attack test suite (`attacks/`).
- ✅ CI assertions: `scripts/ci/detect-test.sh` runs the agent + the attack
  suite with `--assert` in the `detection` CI job (GH runners support BPF).
- 🚧 Virtme-ng kernel coverage: `kernel-matrix.yml` boots 5.10/5.15/6.1/6.6
  and runs the same gate via `scripts/ci/kernel-matrix-test.sh`
  (experimental, `continue-on-error`).
- ⬜ Run `attacks/run_all.sh --assert` under virtme-ng kernels
  and fail the build on missing detections (`.github/workflows/kernel-matrix.yml`).

## Phase 4 — ML anomaly detection (weeks 12–16) 🚧

- ✅ Windowed feature extraction (`agent/src/features.rs`,
  `ml/datasets/collect.py`).
- ✅ Dataset collection from agent JSONL (baseline + attack injection).
- 🚧 Isolation Forest trainer with precision/recall/FPR reporting
  (`ml/train/train_iforest.py`).
- 🚧 Autoencoder (`ml/train/train_autoencoder.py`).
- ✅ n-gram LSTM over event-type sequences (`ml/train/train_ngram_lstm.py`:
  next-token model, mean-NLL scoring, ONNX export + vocab, P/R/FPR report).
- ✅ ONNX inference in the agent (`ort` 2.0-rc.13) behind `--model`:
  `OnnxScorer` for IsolationForest/AE window models, `SequenceScorer` for
  the LSTM; risk alerts flow through the sinks at `--risk-threshold`.
- ✅ Combination story: rules = high-confidence alerts, ML = risk score for gaps.

## Phase 5 — Production polish (weeks 17–20) 🚧

- 🚧 DaemonSet + Helm chart (`deploy/`).
- ✅ Prometheus metrics (`agent/src/metrics.rs`: zero-dependency HTTP thread
  on `--metrics-addr`, `/metrics` + `/healthz`, byte counters aggregated
  from the per-cgroup map).
- ✅ Graceful degradation under load: bounded ingest batches (MAX_BATCH=256),
  in-kernel uid filtering, non-fatal telemetry paths (k8s/metrics/cgroup_skb
  failures degrade instead of dying).
- ✅ Tamper resistance: execve-heartbeat silence detection, `DROPPED`
  monotonicity, program `prog_id` identity via fdinfo (`agent/src/tamper.rs`).
- 🚧 Kernel matrix testing: 5.10 / 5.15 / 6.1 / 6.6 (virtme-ng, weekly +
  manual; experimental until stable).
- ⬜ CPU overhead vs. Falco on identical workloads (`bench/README.md`).

## Stand-out items (parallel tracks)

- 🚧 Deep write-ups in `docs/blog/` (verifier pitfalls, escape-technique postmortem).
- ⬜ Upstream contribution to `aya-rs/aya`, `cilium/ebpf` or Tetragon.
- ✅ Clear threat model (`docs/threat-model.md`).
- 🚧 Numbers: CPU overhead, events/sec, drop rate (`bench/`).
