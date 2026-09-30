# Benchmarks

Numbers are what make this project credible. Three measurements, taken early
and re-run at every phase:

| Metric | What | How |
|---|---|---|
| **Event loss** | events dropped in-kernel vs. processed | `DROPPED` map counter vs. agent's `events` count (both in the summary line) |
| **CPU overhead** | agent CPU vs. a Falco baseline | `bench/run.sh` compares idle vs. traced workload `/proc/<pid>/stat` deltas |
| **Throughput** | events/sec sustained at <0.1% loss | synthetic `execve`/`openat` flood generator |

## Quick run

```shell
# terminal 1
sudo ./target/release/sentinel --emit-events > /tmp/sentinel.jsonl

# terminal 2
sudo bench/run.sh --workload exec-flood --duration 60
```

`run.sh` prints a summary like:

```text
workload=exec-flood duration=60s
syscalls generated (approx): 482113
agent events:                482109
dropped in-kernel:           0
drop rate:                   0.000%
agent cpu:                   4.2%   (of one core)
```

## Methodology notes

* Run 3× and report medians; pin the workload to one CPU (`taskset -c 2`) to
  reduce noise.
* The ring buffer is 16 MiB by default (`--ring-buf-mib`); loss under burst is
  dominated by ring size vs. userspace scheduling — that's the point of the
  `dropped` counter.
* Kernel matrix: 5.10 / 5.15 / 6.1 / 6.6 (see `.github/workflows/kernel-matrix.yml`).
* Falco comparison: same node, same workload, `falco --modern-bpf`, CPU from
  `pidstat -p $(pgrep falco) 1`.

## Results

| Date | Kernel | Workload | Events/s | Drop rate | Agent CPU | Falco CPU |
|---|---|---|---|---|---|---|
| _TBD_ | 6.6.x | exec-flood | | | | |

Fill this table from `run.sh` output; it goes into `docs/blog/` posts too.
