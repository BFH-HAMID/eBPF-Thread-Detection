# Sentinel — eBPF runtime threat detection

**Sentinel** is a runtime security agent for Linux hosts and containers: eBPF
probes written in Rust ([Aya](https://aya-rs.dev)) stream syscall activity into
a userspace daemon that evaluates Falco-style YAML rules, extracts windowed
features for ML anomaly scoring, and emits JSON alerts tagged with
[MITRE ATT&CK](https://attack.mitre.org) techniques.

> **Status: Phase 1 complete** — full syscall tracing pipeline (execve, openat,
> connect, ptrace, mount, setns, unshare, capset, pivot_root) from kernel probe
> to JSON alerts, with a working rule engine and attack test suite. See
> [`docs/roadmap.md`](docs/roadmap.md) for what's next.

## Why

Container escapes, reverse shells and cryptominers all leave syscall-level
footprints. Detection engines like Falco and Tetragon prove the approach;
Sentinel is a from-scratch implementation (Rust + Aya end-to-end) built to be
understood, measured and extended — with honest numbers and an explicit
[threat model](docs/threat-model.md).

## Quickstart

Prerequisites:

```shell
rustup toolchain install stable
rustup toolchain install nightly --component rust-src
cargo install bpf-linker
```

Build & run (root is needed to load eBPF; `cargo run` is already wrapped in
`sudo -E` via `.cargo/config.toml`):

```shell
cargo build --release -p sentinel
sudo ./target/release/sentinel --rules rules/ --emit-events
```

In another terminal, fire an attack scenario:

```shell
attacks/reverse_shell.sh
```

Alerts appear as JSON lines on stdout:

```json
{"kind":"alert","data":{"schema_version":1,"rule_id":"SENTINEL-001","rule_name":"Interactive shell with reverse-shell arguments","priority":"CRITICAL","tags":["mitre/TA0002","mitre/T1059.004"],"output":"possible reverse shell: bash spawned with bash -i /dev/tcp/10.0.0.1/4444", "...":"..."}}
```

Ctrl-C prints a loss summary (`events=… alerts=… dropped=…`) — the numbers the
[benchmarks](bench/README.md) track.

Validate rules without loading eBPF (CI-friendly):

```shell
cargo build -p sentinel && ./target/debug/sentinel --rules rules/ --dry-run
```

## Status

| Roadmap phase | State |
|---|---|
| 1. Foundations (execve/openat, ring buffer, rules skeleton) | done |
| 2. Core tracing (accept/bind, DNS on the wire, per-cgroup bytes, K8s enrichment, in-kernel uid filter) | done |
| 3. Rule engine (YAML + MITRE rules + attack suite; CI detection gate) | done |
| 4. ML (window features, IsolationForest/AE ONNX, LSTM n-gram, in-agent `ort` inference, risk alerts) | done |
| 5. Production polish (Prometheus, tamper watchdog, kernel matrix, degradation) | mostly done — Falco overhead comparison outstanding |

Useful flags beyond the quickstart:

```shell
# ML scoring + risk alerts at/above 0.6 + metrics + capture uid 1000+ only
sudo ./target/release/sentinel --rules rules/ \
    --model ml/models/ngram-lstm-v1.onnx --risk-threshold 0.6 \
    --metrics-addr 0.0.0.0:9095 --min-uid 1000

curl -s localhost:9095/metrics   # Prometheus text format
```

Kubernetes enrichment (pod name/namespace) activates automatically when the
pod runs with a service account (see `deploy/`).

## Layout

```
├── bpf/                  # kernel-side programs (Aya eBPF, CO-RE-ready)
│   ├── common/           # shared #[repr(C)] event ABI (sentinel-common)
│   └── src/              # syscalls.rs, container.rs, network.rs, util.rs
├── agent/                # userspace daemon (sentinel)
│   └── src/              # loader, ingest, enrich, rules, features, ml, sink
├── ml/                   # Python training: datasets, IsolationForest/AE, ONNX
├── rules/                # default rules + MITRE ATT&CK tags
├── attacks/              # attack scenarios + detection assertions
├── deploy/               # Dockerfile, DaemonSet, Helm chart
├── bench/                # overhead / event-loss benchmarks
├── docs/                 # architecture, threat model, roadmap, blog posts
└── .github/workflows/    # CI (fmt/clippy/tests/build) + kernel matrix
```

Design details in [`docs/architecture.md`](docs/architecture.md).

## Testing

```shell
cargo test --workspace --exclude sentinel-ebpf   # unit tests (no eBPF needed)
python3 -m py_compile ml/**/*.py                 # training pipeline syntax
attacks/run_all.sh                                # attack scenarios (needs agent)
```

CI runs fmt/clippy/unit tests and a full eBPF build on GitHub Actions;
`.github/workflows/kernel-matrix.yml` boots 5.10/5.15/6.1/6.6 under virtme-ng.

## What makes it stand out

- **Numbers**: event-loss accounting (`DROPPED` map), CPU overhead and
  events/sec in [`bench/`](bench/README.md).
- **Write-ups**: verifier pitfalls and escape-technique postmortems in
  [`docs/blog/`](docs/blog/verifier-pitfalls.md).
- **Honest scope**: [`docs/threat-model.md`](docs/threat-model.md) says exactly
  what is and isn't detected.
- **Upstream**: bugs fixed in Aya flow back to `aya-rs/aya`.

## License

MIT — see [LICENSE](LICENSE). eBPF objects carry a `Dual MIT/GPL` license
section, as required for GPL-kernel-helper use.
