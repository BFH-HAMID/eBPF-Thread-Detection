//! Network probes (Phase 2): `tcp_connect`, `accept`, DNS parsing, bytes in/out.
//!
//! These need CO-RE (BTF-based relocation of `struct sock`, `struct inet_sock`,
//! ...) because they attach to kernel functions rather than syscall
//! tracepoints. The plan:
//!
//! 1. Generate `struct sock` / `inet_sock` / `sockaddr` bindings from
//!    `/sys/kernel/btf/vmlinux` with `aya-bindgen` (checked into
//!    `bpf/src/vmlinux.rs` per-arch).
//! 2. `fentry/tcp_v4_connect` + `fentry/tcp_v6_connect` → [`sentinel_common::NetEvent`]
//!    with the *resolved* 4-tuple and the owning cgroup id.
//! 3. `fentry/tcp_sendmsg` / `tcp_recvmsg` (or `cgroup_skb`) → per-cgroup
//!    byte counters (per-CPU array, aggregated in userspace).
//! 4. `uprobe` on `getaddrparse`/`res_nsend` or skb parsing on port 53 for
//!    DNS query names.
//!
//! The connect syscalls themselves are already covered in
//! [`crate::syscalls`] (`sys_enter_connect`), which keeps Phase 1 free of
//! CO-RE while this module lands.
#![allow(dead_code)]

/// Placeholder so the module is linked and documented; replaced by real
/// probes in Phase 2.
pub const PHASE: u32 = 2;

/// Direction tag for future byte counters.
pub const DIR_EGRESS: u32 = 0;
pub const DIR_INGRESS: u32 = 1;
