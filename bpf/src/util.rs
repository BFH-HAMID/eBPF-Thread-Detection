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
    EVENT_CONNECT, EVENT_EXECVE, EVENT_MOUNT, EVENT_OPENAT, ExecveEvent, FileEvent, MountEvent,
    NetEvent, SyscallEvent, TASK_COMM_LEN,
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

#[inline(always)]
fn header(ctx: &TracePointContext, event_type: u32) -> sentinel_common::EventHeader {
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
pub fn emit_execve(ctx: &TracePointContext, filename_ptr: u64, argv_ptr: u64) {
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
    ctx: &TracePointContext,
    filename_ptr: u64,
    dirfd: i32,
    flags: u32,
    mode: u32,
) {
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

/// Emit a [`NetEvent`] (connect).
#[inline(always)]
pub fn emit_net(
    ctx: &TracePointContext,
    fd: i32,
    family: u16,
    port: u16,
    addr: [u8; 16],
    addrlen: u32,
) {
    let Some(mut entry) = EVENTS.reserve::<NetEvent>(0) else {
        bump_dropped();
        return;
    };
    let e = entry.as_mut_ptr();
    // SAFETY: exclusive ring-buffer slot until submit.
    unsafe {
        zero(e);
        (*e).header = header(ctx, EVENT_CONNECT);
        (*e).fd = fd;
        (*e).family = family;
        (*e).port = port;
        (*e).addr = addr;
        (*e).addrlen = addrlen;
    }
    entry.submit(0);
}

/// Emit a [`MountEvent`].
#[inline(always)]
pub fn emit_mount(
    ctx: &TracePointContext,
    source_ptr: u64,
    target_ptr: u64,
    fstype_ptr: u64,
    flags: u64,
) {
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
    ctx: &TracePointContext,
    event_type: u32,
    arg0: u64,
    arg1: u64,
    arg2: u64,
    path_ptr: u64,
    path2_ptr: u64,
) {
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
