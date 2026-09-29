# Attack scenarios

Executable test scenarios used to validate detections locally and (Phase 3) in
CI. Each script is self-contained, prints what it does, and is safe to run on a
disposable VM — **not** on production hosts.

| Script | Simulates | Expected detections |
|---|---|---|
| `reverse_shell.sh` | Reverse shell stagers (bash /dev/tcp, nc -e, python) | SENTINEL-001, 002, 003, 004, 041 |
| `sensitive_read.sh` | Credential harvesting, /proc/<pid>/root access | SENTINEL-010, 011, 012, 042 |
| `privilege_escalation.sh` | ptrace injection, unshare(CLONE_NEWUSER), capset | SENTINEL-020, 021, 022 |
| `container_escape.sh` | nsenter, setns, mount host paths, release_agent | SENTINEL-030 – 035 |
| `cryptominer_sim.sh` | Miner-like exec + outbound connect pattern | SENTINEL-041 (+ ML risk score) |

Usage (with the agent already running in another terminal):

```shell
cd attacks
sudo ./run_all.sh            # runs every scenario with pauses
# or individually:
./reverse_shell.sh
```

To assert detections automatically (Phase 3 harness):

```shell
sudo ./target/release/sentinel --rules rules/ --emit-events > /tmp/sentinel.jsonl &
sudo attacks/run_all.sh --assert /tmp/sentinel.jsonl
```

The `--assert` flag is wired in `attacks/run_all.sh` and greps the JSONL stream
for the expected rule ids listed above; CI fails if any are missing.
