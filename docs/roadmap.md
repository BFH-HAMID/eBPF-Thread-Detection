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

## Phase 2 — Core tracing (weeks 4–8) 🚧

- ✅ Syscalls from the roadmap list (see above).
- ⬜ Network tracing: CO-RE `tcp_connect`/`accept`, DNS query names, per-cgroup
  byte counters (`bpf/src/network.rs` has the plan).
- ⬜ Container enrichment v2: cgroup id → containerd/CRI → K8s pod/namespace
  (`agent/src/enrich.rs` currently parses `/proc` cgroup paths).
- ⬜ In-kernel filtering (uid/comm allowlists in a config map) to cut volume.
- 🚧 Loss/overhead benchmark (`bench/`); fill the results table early.

## Phase 3 — Rule engine (weeks 9–11) 🚧

- ✅ YAML rules + boolean condition language (`agent/src/rules.rs`).
- ✅ Default rules with MITRE ATT&CK tags (`rules/*.yaml`).
- ✅ Attack test suite (`attacks/`).
- ⬜ CI assertions: run `attacks/run_all.sh --assert` under virtme-ng kernels
  and fail the build on missing detections (`.github/workflows/kernel-matrix.yml`).

## Phase 4 — ML anomaly detection (weeks 12–16) 🚧

- ✅ Windowed feature extraction (`agent/src/features.rs`,
  `ml/datasets/collect.py`).
- ✅ Dataset collection from agent JSONL (baseline + attack injection).
- 🚧 Isolation Forest trainer with precision/recall/FPR reporting
  (`ml/train/train_iforest.py`).
- 🚧 Autoencoder (`ml/train/train_autoencoder.py`).
- ⬜ n-gram LSTM over syscall sequences.
- ⬜ ONNX inference in the agent (`ort` crate) behind `--model`.
- ✅ Combination story: rules = high-confidence alerts, ML = risk score for gaps.

## Phase 5 — Production polish (weeks 17–20) ⬜

- 🚧 DaemonSet + Helm chart (`deploy/`).
- ⬜ Prometheus metrics (the `Metrics` counters already exist).
- ⬜ Graceful degradation under load (bounded batches exist; add shedding).
- ⬜ Tamper resistance: detach/map-tamper detection (`docs/threat-model.md`).
- ⬜ Kernel matrix testing: 5.10 / 5.15 / 6.1 / 6.6 (virtme-ng CI).
- ⬜ CPU overhead vs. Falco on identical workloads (`bench/README.md`).

## Stand-out items (parallel tracks)

- 🚧 Deep write-ups in `docs/blog/` (verifier pitfalls, escape-technique postmortem).
- ⬜ Upstream contribution to `aya-rs/aya`, `cilium/ebpf` or Tetragon.
- ✅ Clear threat model (`docs/threat-model.md`).
- 🚧 Numbers: CPU overhead, events/sec, drop rate (`bench/`).
