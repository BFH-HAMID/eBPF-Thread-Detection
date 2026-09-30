//! Syscall tracepoints: execve, openat, connect, accept4, bind, ptrace, mount,
//! setns.
//!
//! All probes attach to `syscalls/sys_enter_*` tracepoints, which are available
//! on any kernel with `CONFIG_FTRACE_SYSCALLS=y` — no BTF/CO-RE required for
//! this phase. Argument layout: [`crate::util::sys_enter_arg`].

use aya_ebpf::{macros::tracepoint, programs::TracePointContext};
use sentinel_common::{EVENT_ACCEPT, EVENT_BIND, EVENT_CONNECT, EVENT_PTRACE, EVENT_SETNS};

use crate::util::{
    emit_execve, emit_file, emit_mount, emit_net, emit_sys, parse_sockaddr, sys_arg,
};

/// `execve(filename, argv, envp)`.
#[tracepoint(category = "syscalls", name = "sys_enter_execve")]
pub fn sys_enter_execve(ctx: TracePointContext) -> u32 {
    emit_execve(&ctx, sys_arg(&ctx, 0), sys_arg(&ctx, 1));
    0
}

/// `openat(dirfd, pathname, flags, mode)`.
#[tracepoint(category = "syscalls", name = "sys_enter_openat")]
pub fn sys_enter_openat(ctx: TracePointContext) -> u32 {
    emit_file(
        &ctx,
        sys_arg(&ctx, 1),
        sys_arg(&ctx, 0) as i32,
        sys_arg(&ctx, 2) as u32,
        sys_arg(&ctx, 3) as u32,
    );
    0
}

/// `connect(fd, uservaddr, addrlen)`.
///
/// Address parsing is done in-kernel from `struct sockaddr`:
/// AF_INET → `sockaddr_in`, AF_INET6 → `sockaddr_in6`, anything else is
/// reported with the family only (e.g. AF_UNIX).
#[tracepoint(category = "syscalls", name = "sys_enter_connect")]
pub fn sys_enter_connect(ctx: TracePointContext) -> u32 {
    let fd = sys_arg(&ctx, 0) as i32;
    let sa_ptr = sys_arg(&ctx, 1);
    let addrlen = sys_arg(&ctx, 2) as u32;
    let (family, port, addr, addrlen) = parse_sockaddr(sa_ptr, addrlen);
    emit_net(&ctx, EVENT_CONNECT, fd, family, port, addr, addrlen);
    0
}

/// `accept4(fd, upeer_sockaddr, upeer_addrlen, flags)`.
///
/// Emitted at syscall *entry*: the peer address is still empty here (the kernel
/// fills it in on the way out; capturing it needs `sys_exit_accept4` with its
/// own layout, or CO-RE). The accept signal itself — a listening socket taking
/// a connection — is what the rules use.
#[tracepoint(category = "syscalls", name = "sys_enter_accept4")]
pub fn sys_enter_accept4(ctx: TracePointContext) -> u32 {
    let fd = sys_arg(&ctx, 0) as i32;
    emit_net(&ctx, EVENT_ACCEPT, fd, 0, 0, [0u8; 16], 0);
    0
}

/// `bind(fd, umyaddr, addrlen)` — listening-socket setup (reverse-shell
/// listeners, privileged-port binds).
#[tracepoint(category = "syscalls", name = "sys_enter_bind")]
pub fn sys_enter_bind(ctx: TracePointContext) -> u32 {
    let fd = sys_arg(&ctx, 0) as i32;
    let sa_ptr = sys_arg(&ctx, 1);
    let addrlen = sys_arg(&ctx, 2) as u32;
    let (family, port, addr, addrlen) = parse_sockaddr(sa_ptr, addrlen);
    emit_net(&ctx, EVENT_BIND, fd, family, port, addr, addrlen);
    0
}

/// `ptrace(request, pid, addr, data)` — process injection / debugging signal.
#[tracepoint(category = "syscalls", name = "sys_enter_ptrace")]
pub fn sys_enter_ptrace(ctx: TracePointContext) -> u32 {
    emit_sys(
        &ctx,
        EVENT_PTRACE,
        sys_arg(&ctx, 0),
        sys_arg(&ctx, 1),
        sys_arg(&ctx, 2),
        0,
        0,
    );
    0
}

/// `mount(source, target, fstype, flags, data)` — container-escape classic.
#[tracepoint(category = "syscalls", name = "sys_enter_mount")]
pub fn sys_enter_mount(ctx: TracePointContext) -> u32 {
    emit_mount(
        &ctx,
        sys_arg(&ctx, 0),
        sys_arg(&ctx, 1),
        sys_arg(&ctx, 2),
        sys_arg(&ctx, 3),
    );
    0
}

/// `setns(fd, nstype)` — namespace hopping.
#[tracepoint(category = "syscalls", name = "sys_enter_setns")]
pub fn sys_enter_setns(ctx: TracePointContext) -> u32 {
    emit_sys(
        &ctx,
        EVENT_SETNS,
        sys_arg(&ctx, 0),
        sys_arg(&ctx, 1),
        0,
        0,
        0,
    );
    0
}
