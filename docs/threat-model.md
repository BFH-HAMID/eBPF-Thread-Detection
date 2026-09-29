# Threat model

## What Sentinel is

A **runtime detection** layer for Linux hosts and containers: it observes
syscall activity through eBPF, matches it against curated rules, and scores
windows of behaviour with ML. It reports; it does not block.

## Assets

* Host root (kernel, host filesystem, node credentials).
* Cloud/K8s credentials inside workloads (`/run/secrets/...`, metadata service).
* Workload data reachable via `/proc/*/root`, mounted host paths.

## Adversaries

| Adversary | Capability | Example |
|---|---|---|
| Remote attacker | RCE in a workload | webshell → reverse shell → crypto miner |
| Malicious/compromised workload | container root | escape via `release_agent`, `nsenter`, docker.sock |
| Local user | unprivileged shell | `unshare(CLONE_NEWUSER)` sandbox escape, ptrace injection |
| Supply chain | malicious image | miner stager, credential stealer |

## Detected (high confidence)

* **Execution**: shell interpreters with reverse-shell argv, netcat-style
  `-e`/`-c`, escape tooling (`nsenter`, `ctr`, `capsh`).
* **Credential access**: reads of shadow/sudoers/SSH keys/cloud credentials,
  `/proc/<pid>/root` cross-namespace access, metadata-service connects.
* **Privilege escalation**: ptrace memory writes/attach, `unshare(CLONE_NEWUSER)`,
  unexpected `capset`.
* **Container escape**: `setns`/`pivot_root` outside runtimes, host block
  devices or `docker.sock` access, cgroup `release_agent` writes, cgroup mounts.
* **C2 patterns**: shells opening sockets, connections to classic backdoor
  ports, interpreter-driven egress.

## Explicitly NOT detected (today)

* **Kernel exploits / rootkits**: eBPF sees syscalls from the *compromised*
  kernel's perspective; a kernel-level adversary can disable or spoof the
  probes (mitigations below, not elimination).
* **Fileless malice that stays inside allowed syscalls** (e.g. pure compute
  malware) — only the ML risk score can drift on this, with false positives.
* **Encrypted payload contents** — we see `connect()` metadata, not TLS data.
  DNS payload parsing lands in Phase 2.
* **Historical activity** — detection is streaming-only; no forensics.
* **Non-syscall channels**: DMA, GPU, firmware, physical access.
* **Userspace tampering with the agent binary** itself.
* **32-bit compat syscall tables** — `ia32` tracepoints are not attached yet.
* **Post-exploitation living-off-the-land** with only benign syscalls
  (e.g. `curl | sh` of a "legit" binary) — rule gaps, partially covered by ML.

## Trust boundaries

```text
[ workload ] --syscalls--> [ kernel tracepoints ] --ring--> [ agent ] --JSON--> [ log pipeline ]
                                ^                                 |
                                |                                 v
                        attacker with kernel               rules/ + models
                        access can tamper                  (mounted read-only)
```

The agent runs privileged (CAP_BPF/PERFMON/SYS_RESOURCE). Compromise of the
agent = compromise of the node; hence: read-only rootfs, dropped caps, no
network listeners by default.

## Tamper resistance (Phase 5 plan)

* Detect BPF program detachment (periodic `bpf_prog_get_next_id` /
  `bpf_link` introspection against the expected set).
* Detect map modification (checksum of pinned map ids + `DROPPED` monotonicity
  checks — an attacker resetting it is itself a signal).
* Self-detection: rules for `ptrace`/`kill` against the agent's own pid.

## Residual risk statement

Sentinel raises the cost of post-exploitation and container escape; it does
not provide prevention, and a patient adversary with kernel-level access wins.
Deploy it *alongside* seccomp/AppArmor/SELinux, image scanning, and least
privilege — never as the only control.
