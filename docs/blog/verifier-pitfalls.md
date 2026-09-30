# Notes toward: "Verifier pitfalls: building a 600-byte event pipeline in Rust eBPF"

> Status: outline. This post will document the traps hit while building
> Sentinel's ring-buffer pipeline with Aya — the ones that only surface as
> `R3 invalid mem access` at 2 a.m.

## Draft outline

1. **The 512-byte stack is a lie detector**
   Building a fat event (`ExecveEvent`, 560 bytes) on the stack "works" until
   LLVM spills one local too many. The fix: reserve the ring-buffer slot first
   and fill it in place (`bpf_ringbuf_reserve` → field writes → `submit`).

2. **Dynamic slice indexing is the verifier's enemy**
   `&mut buf[offset..]` with a runtime `offset` (joining argv strings) dies
   with "unbounded memory access". The escape: fixed `ARG_SLOT_LEN = 64` slots
   with constant slice bounds — see `bpf/src/util.rs::read_argv`.

3. **Pointer chains in user memory**
   `execve`'s `argv` is `char **`: one `bpf_probe_read_user` for the slot
   pointer, another for the string. Each hop needs its own NULL check or the
   verifier rejects the path; each hop is also a chance to truncate sanely.

4. **Tracepoint layouts without CO-RE**
   `sys_enter_*` args start at offset 16 on 64-bit (`trace_entry` + `long id`).
   Spelled as a const with a comment pointing at the format file — and a
   reminder that 32-bit compat is a different table entirely.

5. **Ring buffer sizing math**
   `max_entries` for `BPF_MAP_TYPE_RINGBUF` is a *byte* size and must be a
   power-of-two multiple of the page size. The loss metric (`DROPPED`) exists
   because silent loss is the default behavior.

6. **`#[map]` statics, `no_std`, and edition 2024**
   `#[unsafe(link_section)]`, panic handlers, and why `bpf-linker` failures
   look like cargo errors.

## One-liner for the résumé

> Built an eBPF runtime-detection agent in Rust (Aya); wrote up the verifier
> constraints that shape its event ABI.
