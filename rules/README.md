# Sentinel rule format

Rules are YAML files loaded from the `rules/` directory (`sentinel --rules DIR`).
Each file contains a list of rules (or a top-level `rules:` key with a list).

## Schema

```yaml
- id: SENTINEL-001          # stable identifier (required, unique)
  name: Reverse shell       # short title (required)
  description: |            # optional, what/why
    Interactive shell spawned with reverse-shell style arguments.
  priority: critical        # debug|info|notice|warning|error|critical
  condition: >              # required, condition language below
    evt.type = execve and proc.name in (sh, bash) and exec.argv contains "-i"
  tags: [mitre/TA0002, mitre/T1059.004]   # optional
  output: "possible reverse shell: %proc.name %exec.argv"  # optional
```

`output` supports `%field` placeholders (e.g. `%proc.name`) substituted from the
event; unknown fields are left as-is.

## Condition language

```text
expr      := or_expr
or_expr   := and_expr ("or" and_expr)*
and_expr  := unary ("and" unary)*
unary     := "not" unary | "(" expr ")" | predicate
predicate := field op value
           | field "in" "(" value ("," value)* ")"
           | field "exists"
           | field                          # truthy (exists and non-empty)
op        := "=" | "==" | "!=" | "<" | "<=" | ">" | ">="
           | "contains" | "startswith" | "endswith"
value     := bare-word | "quoted string" | integer
```

Notes:

* `and` binds tighter than `or`; use parentheses to disambiguate.
* Missing fields never match (except `not (...)`, `!=` follows the same rule:
  a missing field makes the whole predicate false — write `not X` explicitly).
* `=` coerces between `"4444"` and `4444`.
* Comparisons are case-sensitive.

## Field reference

| Field | Available on | Type | Meaning |
|---|---|---|---|
| `evt.type` | all | str | `execve`, `openat`, `connect`, `ptrace`, `mount`, `setns`, `unshare`, `capset`, `pivot_root` |
| `evt.timestamp_ns` | all | int | monotonic ns at probe time |
| `proc.pid` | all | int | thread id (tid) |
| `proc.tgid` | all | int | process id |
| `proc.ppid` | all | int | parent process id (enrichment) |
| `proc.uid`, `proc.gid` | all | int | credentials at probe time |
| `proc.name` | all | str | `comm` (16 bytes, truncated) |
| `container` | all | bool | event came from a container workload |
| `container.id` | containers | str | container id from cgroup path |
| `exec.path` | execve | str | execve `filename` |
| `exec.argv` | execve | str | first 4 argv entries (63 chars each), space-joined |
| `file.path` | openat | str | opened path |
| `file.flags` | openat | int | `openat` flags (O_*) |
| `file.mode` | openat | int | mode argument |
| `net.addr` | connect | str | destination IP (empty for AF_UNIX) |
| `net.port` | connect | int | destination port (host order) |
| `net.family` | connect | str | `inet`, `inet6`, `unix`, `other` |
| `net.fd` | connect | int | socket fd |
| `mount.source`, `mount.target`, `mount.fstype` | mount | str | mount(2) strings |
| `mount.flags` | mount | int | MS_* flags |
| `sys.arg0` | ptrace, setns, unshare | int | request / fd / flags |
| `sys.arg1` | ptrace, setns | int | target pid / nstype |
| `sys.arg2` | ptrace | int | addr |
| `sys.path`, `sys.path2` | pivot_root | str | `new_root`, `put_old` |

## Examples

```yaml
condition: evt.type = execve and proc.name = curl and exec.argv contains "http://"
condition: evt.type = openat and file.path in (/etc/shadow, /etc/sudoers)
condition: evt.type = openat and file.path startswith /proc/ and file.path contains /root
condition: evt.type = connect and net.port in (4444, 1337, 31337) and proc.name in (sh, bash)
condition: evt.type = mount and mount.fstype in (cgroup, cgroup2) and container
condition: evt.type = unshare and sys.arg0 in (268435456, 268566528)   # CLONE_NEWUSER(+NS)
```

## Testing rules

`cargo test -p sentinel` covers the parser/evaluator. To validate a rule
against real traffic:

```shell
sudo ./target/release/sentinel --rules rules/ --emit-events | \
  python3 ml/datasets/collect.py --stdin --emit-events
```

or replay an attack scenario from `attacks/` and watch the alert stream.
