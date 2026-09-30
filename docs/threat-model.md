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
  DNS *queries* are captured on the wire (names/types, not record data).
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

## Tamper resistance (Phase 5, implemented — detection, not prevention)

Root can always win against a userspace daemon; the design goal is that
tampering becomes *loud* (`{"kind":"tamper",...}` through every sink and the
`sentinel_tamper_alerts_total` counter). Three independent signals:

* **Probe silence** — a heartbeat thread execs `/bin/true` every 15 s; if the
  execve stream goes quiet for >30 s, the probes or the ring path are dead
  (covers silent link detachments).
* **Map modification** — `DROPPED` is monotonic by construction; a *decrease*
  means the map was wiped or replaced.
* **Program identity** — each probe's `prog_id` is recorded from
  `/proc/self/fdinfo/<fd>` at startup and re-checked every 15 s; an fd swap
  shows up as `prog_id_changed`.

Known limit: `aya`'s public API has no kernel-wide program enumeration
(`bpf_prog_get_next_id` is crate-private), so "detach and replace with a
forged event stream" is only caught by the heartbeat *if* the forged stream
loses execves. Self-detection of `ptrace`/`kill` against the agent's own pid
is covered by the existing ptrace rules plus agent-side pid filtering.

## Residual risk statement

Sentinel raises the cost of post-exploitation and container escape; it does
not provide prevention, and a patient adversary with kernel-level access wins.
Deploy it *alongside* seccomp/AppArmor/SELinux, image scanning, and least
privilege — never as the only control.
