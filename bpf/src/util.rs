//! Shared probe-side plumbing: maps, header fill, user-memory string reads and
//! the per-event-type ring-buffer emitters.
//!
//! Ring-buffer pattern: reserve an `ExecveEvent`-sized slot first, then fill it
//! *in place* (the reserved memory is not on the 512-byte BPF stack, so large
//! events stay verifier-friendly), then submit. On reservation failure the
//! drop counter is bumped — userspace exposes it as the `dropped` metric.

use aya_ebpf::{
    EbpfContext as _,
    helpers::{bpf_ktime_get_ns, bpf_probe_read_user_str_bytes},
    macros::map,
    maps::{Array, RingBuf},
    programs::TracePointContext,
};
use sentinel_common::{
    DnsEvent, EVENT_EXECVE, EVENT_MOUNT, EVENT_OPENAT, ExecveEvent, FileEvent, FilterConfig,
    MountEvent, NetEvent, SyscallEvent, TASK_COMM_LEN,
};

/// Size of the events ring buffer, in bytes. Must be a power-of-two multiple of
/// the page size. Userspace may override it at load time via
/// `EbpfLoader::map_max_entries("EVENTS", ...)` (see `agent/src/loader.rs`).
pub const EVENTS_RINGBUF_BYTES: u32 = 1 << 24; // 16 MiB

/// All captured events flow through this ring buffer.
#[map]
pub static EVENTS: RingBuf = RingBuf::with_byte_size(EVENTS_RINGBUF_BYTES, 0);

/// Monotonic count of events lost because the ring buffer was full.
///
/// Approximate under concurrent updates (plain increments, no atomics — good
/// enough for a loss metric, and cheap in verifier terms).
#[map]
pub static DROPPED: Array<u64> = Array::with_max_entries(1, 0);

/// In-kernel capture filter (uid range), written by userspace at startup.
/// Checked before any ring-buffer reservation so filtered events are nearly
/// free — the eBPF analogue of Falco's `base_syscalls` / Tetragon selectors.
#[map]
pub static CONFIG: Array<FilterConfig> = Array::with_max_entries(1, 0);

/// Whether events from `uid` should be captured. A missing config entry means
/// "capture everything".
#[inline(always)]
pub fn should_capture(uid: u32) -> bool {
    match CONFIG.get(0) {
        Some(cfg) => uid >= cfg.min_uid && uid <= cfg.max_uid,
        None => true,
    }
}

/// Tracepoint `syscalls/sys_enter_*` layout on 64-bit kernels:
///
/// ```text
/// struct trace_event_raw_sys_enter {
///     struct trace_entry ent;   /* 8 bytes */
///     long id;                  /* 8 bytes */
///     unsigned long args[6];    /* starts at offset 16 */
/// };
/// ```
pub const SYS_ENTER_ARG0: usize = 16;

/// Byte offset of syscall argument `n` (0..=5) inside a `sys_enter` tracepoint.
#[inline(always)]
pub const fn sys_enter_arg(n: usize) -> usize {
    SYS_ENTER_ARG0 + n * 8
}

/// Read syscall argument `n` from a `sys_enter` tracepoint context.
#[inline(always)]
pub fn sys_arg(ctx: &TracePointContext, n: usize) -> u64 {
    // SAFETY: `sys_enter_arg(n)` points into the tracepoint buffer, which the
    // kernel guarantees to be readable for `args[0..6]`.
    unsafe { ctx.read_at::<u64>(sys_enter_arg(n)) }.unwrap_or(0)
}

/// Read the common `EventHeader` fields for the current task.
#[inline(always)]
pub fn header(ctx: &impl aya_ebpf::EbpfContext, event_type: u32) -> sentinel_common::EventHeader {
    sentinel_common::EventHeader {
        event_type,
        pid: ctx.pid(),
        tgid: ctx.tgid(),
        uid: ctx.uid(),
        gid: ctx.gid(),
        // Parent pid resolution needs `task_struct` access (CO-RE); filled in
        // by userspace enrichment for now.
        ppid: 0,
        timestamp_ns: unsafe { bpf_ktime_get_ns() as u64 },
        comm: ctx.command().unwrap_or([0; TASK_COMM_LEN]),
    }
}

/// Copy a NUL-terminated user string into `dst` (zero-padded, truncated).
#[inline(always)]
pub fn read_user_str(dst: &mut [u8], user_ptr: u64) {
    if user_ptr == 0 {
        return;
    }
    // SAFETY: the helper only reads user memory and bounds the copy to `dst`.
    let _ = unsafe { bpf_probe_read_user_str_bytes(user_ptr as *const u8, dst) };
}

/// Read the first [`sentinel_common::ARG_SLOTS`] entries of a user `char **argv`
/// array into fixed slots. Constant-bounded slices only — no dynamic indexing,
/// so the verifier stays happy.
#[inline(always)]
pub fn read_argv(dst: &mut [u8; sentinel_common::ARGV_BUF_LEN], argv_ptr: u64) {
    if argv_ptr == 0 {
        return;
    }
    // SAFETY: `argv_ptr` is a user `char **`; the helper bails on fault.
    let arg = |index: u64| -> u64 {
        unsafe { aya_ebpf::helpers::bpf_probe_read_user((argv_ptr + index * 8) as *const u64) }
            .unwrap_or(0)
    };
    let p0 = arg(0);
    if p0 == 0 {
        return;
    }
    read_user_str(&mut dst[0..sentinel_common::ARG_SLOT_LEN - 1], p0);
    let p1 = arg(1);
    if p1 == 0 {
        return;
    }
    read_user_str(
        &mut dst[sentinel_common::ARG_SLOT_LEN..2 * sentinel_common::ARG_SLOT_LEN - 1],
        p1,
    );
    let p2 = arg(2);
    if p2 == 0 {
        return;
    }
    read_user_str(
        &mut dst[2 * sentinel_common::ARG_SLOT_LEN..3 * sentinel_common::ARG_SLOT_LEN - 1],
        p2,
    );
    let p3 = arg(3);
    if p3 == 0 {
        return;
    }
    read_user_str(
        &mut dst[3 * sentinel_common::ARG_SLOT_LEN..4 * sentinel_common::ARG_SLOT_LEN - 1],
        p3,
    );
}

#[inline(always)]
fn bump_dropped() {
    if let Some(counter) = DROPPED.get_ptr_mut(0) {
        // SAFETY: the map value is valid for the lifetime of the program.
        unsafe { *counter = (*counter).wrapping_add(1) };
    }
}

/// Zero `*p` (including nested arrays) directly inside ring-buffer memory.
#[inline(always)]
unsafe fn zero<T>(p: *mut T) {
    // SAFETY: `p` points at a reserved ring-buffer slot of size `size_of::<T>()`.
    unsafe {
        core::ptr::write_bytes(p.cast::<u8>(), 0, core::mem::size_of::<T>());
    }
}

/// Emit an [`ExecveEvent`]. `argv_ptr` is the `char **argv` user pointer; the
/// first [`sentinel_common::ARG_SLOTS`] entries are captured.
#[inline(always)]
pub fn emit_execve(ctx: &impl aya_ebpf::EbpfContext, filename_ptr: u64, argv_ptr: u64) {
    if !should_capture(ctx.uid()) {
        return;
    }
    let Some(mut entry) = EVENTS.reserve::<ExecveEvent>(0) else {
        bump_dropped();
        return;
    };
    let e = entry.as_mut_ptr();
    // SAFETY: the ring buffer slot is exclusively owned until `submit(0)`.
    unsafe {
        zero(e);
        (*e).header = header(ctx, EVENT_EXECVE);
        read_user_str(&mut (*e).filename, filename_ptr);
        read_argv(&mut (*e).argv, argv_ptr);
    }
    entry.submit(0);
}

/// Emit a [`FileEvent`] (openat-style file access).
#[inline(always)]
pub fn emit_file(
    ctx: &impl aya_ebpf::EbpfContext,
    filename_ptr: u64,
    dirfd: i32,
    flags: u32,
    mode: u32,
) {
    if !should_capture(ctx.uid()) {
        return;
    }
    let Some(mut entry) = EVENTS.reserve::<FileEvent>(0) else {
        bump_dropped();
        return;
    };
    let e = entry.as_mut_ptr();
    // SAFETY: exclusive ring-buffer slot until submit.
    unsafe {
        zero(e);
        (*e).header = header(ctx, EVENT_OPENAT);
        read_user_str(&mut (*e).filename, filename_ptr);
        (*e).dirfd = dirfd;
        (*e).flags = flags;
        (*e).mode = mode;
    }
    entry.submit(0);
}

/// Emit a [`NetEvent`] (`event_type` selects connect/accept/bind semantics).
#[inline(always)]
pub fn emit_net(
    ctx: &impl aya_ebpf::EbpfContext,
    event_type: u32,
    fd: i32,
    family: u16,
    port: u16,
    addr: [u8; 16],
    addrlen: u32,
) {
    if !should_capture(ctx.uid()) {
        return;
    }
    let Some(mut entry) = EVENTS.reserve::<NetEvent>(0) else {
        bump_dropped();
        return;
    };
    let e = entry.as_mut_ptr();
    // SAFETY: exclusive ring-buffer slot until submit.
    unsafe {
        zero(e);
        (*e).header = header(ctx, event_type);
        (*e).fd = fd;
        (*e).family = family;
        (*e).port = port;
        (*e).addr = addr;
        (*e).addrlen = addrlen;
    }
    entry.submit(0);
}

/// Parse a user `struct sockaddr` (v4 or v6) into `(family, port, addr, addrlen)`.
/// Used by `connect` and `bind`. Any other family reports the family only.
#[inline(always)]
pub fn parse_sockaddr(sa_ptr: u64, addrlen: u32) -> (u16, u16, [u8; 16], u32) {
    let mut family: u16 = 0;
    let mut port: u16 = 0;
    let mut addr = [0u8; 16];
    if sa_ptr == 0 {
        return (family, port, addr, addrlen);
    }
    // SAFETY: `sa_ptr` is a user pointer valid for `addrlen` bytes; the helper
    // bails out safely on fault.
    family = unsafe { aya_ebpf::helpers::bpf_probe_read_user(sa_ptr as *const u16) }.unwrap_or(0);
    match family {
        sentinel_common::AF_INET => {
            // struct sockaddr_in { family: u16, port: be16, addr: [u8; 4], ..8 }
            #[repr(C)]
            struct SockAddrIn {
                _family: u16,
                port: u16,
                addr: [u8; 4],
                _zero: [u8; 8],
            }
            if let Ok(sin) =
                (unsafe { aya_ebpf::helpers::bpf_probe_read_user(sa_ptr as *const SockAddrIn) })
            {
                port = u16::from_be(sin.port);
                addr[..4].copy_from_slice(&sin.addr);
            }
        }
        sentinel_common::AF_INET6 => {
            // struct sockaddr_in6 { family: u16, port: be16, flowinfo: u32,
            //                       addr: [u8; 16], scope_id: u32 }
            #[repr(C)]
            struct SockAddrIn6 {
                _family: u16,
                port: u16,
                _flowinfo: u32,
                addr: [u8; 16],
                _scope_id: u32,
            }
            if let Ok(sin6) =
                (unsafe { aya_ebpf::helpers::bpf_probe_read_user(sa_ptr as *const SockAddrIn6) })
            {
                port = u16::from_be(sin6.port);
                addr.copy_from_slice(&sin6.addr);
            }
        }
        _ => {}
    }
    (family, port, addr, addrlen)
}

/// Emit a [`DnsEvent`] (from the cgroup_skb egress program). `qname_raw` is
/// the raw wire-format QNAME + QTYPE/QCLASS tail; `qname_len` how many bytes
/// were captured.
#[inline(always)]
pub fn emit_dns(
    ctx: &impl aya_ebpf::EbpfContext,
    qname_raw: &[u8; 128],
    qname_len: u16,
    dst_port: u16,
    family: u16,
    server: [u8; 16],
) {
    if !should_capture(ctx.uid()) {
        return;
    }
    let Some(mut entry) = EVENTS.reserve::<DnsEvent>(0) else {
        bump_dropped();
        return;
    };
    let e = entry.as_mut_ptr();
    // SAFETY: exclusive ring-buffer slot until submit.
    unsafe {
        zero(e);
        (*e).header = header(ctx, sentinel_common::EVENT_DNS);
        (*e).qname_raw = *qname_raw;
        (*e).qname_len = qname_len;
        (*e).dst_port = dst_port;
        (*e).family = family;
        (*e).server = server;
    }
    entry.submit(0);
}

/// Emit a [`MountEvent`].
#[inline(always)]
pub fn emit_mount(
    ctx: &impl aya_ebpf::EbpfContext,
    source_ptr: u64,
    target_ptr: u64,
    fstype_ptr: u64,
    flags: u64,
) {
    if !should_capture(ctx.uid()) {
        return;
    }
    let Some(mut entry) = EVENTS.reserve::<MountEvent>(0) else {
        bump_dropped();
        return;
    };
    let e = entry.as_mut_ptr();
    // SAFETY: exclusive ring-buffer slot until submit.
    unsafe {
        zero(e);
        (*e).header = header(ctx, EVENT_MOUNT);
        read_user_str(&mut (*e).source, source_ptr);
        read_user_str(&mut (*e).target, target_ptr);
        read_user_str(&mut (*e).fstype, fstype_ptr);
        (*e).flags = flags;
    }
    entry.submit(0);
}

/// Emit a [`SyscallEvent`] for ptrace/setns/unshare/capset/pivot_root.
#[inline(always)]
pub fn emit_sys(
    ctx: &impl aya_ebpf::EbpfContext,
    event_type: u32,
    arg0: u64,
    arg1: u64,
    arg2: u64,
    path_ptr: u64,
    path2_ptr: u64,
) {
    if !should_capture(ctx.uid()) {
        return;
    }
    let Some(mut entry) = EVENTS.reserve::<SyscallEvent>(0) else {
        bump_dropped();
        return;
    };
    let e = entry.as_mut_ptr();
    // SAFETY: exclusive ring-buffer slot until submit.
    unsafe {
        zero(e);
        (*e).header = header(ctx, event_type);
        (*e).arg0 = arg0;
        (*e).arg1 = arg1;
        (*e).arg2 = arg2;
        read_user_str(&mut (*e).path, path_ptr);
        read_user_str(&mut (*e).path2, path2_ptr);
    }
    entry.submit(0);
}
