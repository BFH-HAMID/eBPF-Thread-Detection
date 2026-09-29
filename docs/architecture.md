# Sentinel architecture

```mermaid
flowchart LR
    subgraph kernel [Kernel - eBPF / Aya]
        TP[syscalls/sys_enter_* tracepoints]
        RB[(EVENTS ring buffer)]
        DR[DROPPED counter map]
        TP -->|ExecveEvent FileEvent NetEvent MountEvent SyscallEvent| RB
        TP -->|reserve fails| DR
    end

    subgraph agent [Userspace agent - agent/src]
        LOADER[loader: load + attach]
        INGEST[ingest: async ring reader + batching]
        ENRICH[enrich: cgroup / container id]
        RULES[rules: YAML engine]
        FEAT[features: sliding windows]
        ML[ml: ONNX scorer]
        SINK[sink: JSON / stdout / OTLP]
        LOADER --> INGEST --> ENRICH --> RULES --> SINK
        ENRICH --> FEAT --> ML --> SINK
    end

    subgraph ext [External]
        YAML[(rules/*.yaml)]
        ONNX[(ml/models/*.onnx)]
        ATTK[attacks/ scenarios]
    end

    RB --> INGEST
    YAML --> RULES
    ONNX --> ML
    ATTK -.->|test traffic| kernel
```

## Kernel side (`bpf/`)

* `bpf/common/` (`sentinel-common`) — the event ABI: `#[repr(C)]` structs
  shared verbatim with userspace. Every struct is 8-byte aligned and sized for
  a direct ring-buffer reservation (no BPF stack copies of big events).
* `bpf/src/syscalls.rs` — `execve`, `openat`, `connect`, `ptrace`, `mount`,
  `setns` tracepoints.
* `bpf/src/container.rs` — `unshare`, `capset`, `pivot_root` (escape signals).
* `bpf/src/network.rs` — Phase 2 CO-RE probes (`tcp_connect`, accept, DNS).
* `bpf/src/util.rs` — maps (`EVENTS`, `DROPPED`), header fill, string reads,
  per-type emitters.

Design points:

* **Tracepoints first, CO-RE second.** `syscalls/sys_enter_*` works on any
  `CONFIG_FTRACE_SYSCALLS` kernel without BTF; CO-RE probes land in Phase 2
  where kernel structs are unavoidable.
* **Reserve-then-fill.** Events up to 600 bytes are written straight into
  ring-buffer memory; the 512-byte BPF stack only holds scalars.
* **Loss accounting.** A failed reservation bumps `DROPPED` instead of
  silently discarding — the benchmark's headline number.

## Userspace side (`agent/`)

| Module | Responsibility |
|---|---|
| `loader` | load the embedded eBPF object, attach probes, expose maps |
| `ingest` | async ring-buffer reads (`AsyncFd`), batch drain, decode |
| `event` | ABI decode → owned `Event` + field lookup for rules |
| `enrich` | `/proc/<pid>/cgroup` → container id, ppid (cached) |
| `rules` | YAML rule files + boolean condition language |
| `features` | windowed per-process feature vectors |
| `ml` | anomaly scorer trait; baseline heuristic, ONNX in Phase 4 |
| `sink` | JSON-lines alerts (stdout), metrics counters |

Event flow per record: decode → enrich → rule evaluation (alerts) →
feature window → sinks. A window timer flushes feature vectors into risk
scores independent of the event stream.

## Data contracts

1. **Event ABI** — `bpf/common/src/lib.rs`, decoded by `agent/src/event.rs`.
   Size assertions in the common crate's tests guard against silent drift.
2. **Alert schema** — JSON envelope `{"kind":"alert","data":{...}}` with
   `schema_version` (currently 1).
3. **Feature vector** — `agent/src/features.rs` and `ml/datasets/collect.py`
   must stay in lockstep (column list is asserted in `ml/export/export_onnx.py`).

## Why Rust + Aya

* Kernel and userspace share one type system and one ABI crate — struct drift
  becomes a compile error, not a runtime misparse.
* The verifier-friendly patterns above are expressible directly (const-bounded
  slices, no C preprocessor).
* Upstreamability: fixes flow to `aya-rs/aya` (a stated goal of the project).
