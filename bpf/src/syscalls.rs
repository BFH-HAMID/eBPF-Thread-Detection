//! Syscall tracepoints: execve, openat, connect, ptrace, mount, setns.
//!
//! All probes attach to `syscalls/sys_enter_*` tracepoints, which are available
//! on any kernel with `CONFIG_FTRACE_SYSCALLS=y` — no BTF/CO-RE required for
//! this phase. Argument layout: [`crate::util::sys_enter_arg`].

use aya_ebpf::{macros::tracepoint, programs::TracePointContext};
use sentinel_common::{AF_INET, AF_INET6, EVENT_PTRACE, EVENT_SETNS};

use crate::util::{emit_execve, emit_file, emit_mount, emit_net, emit_sys, sys_arg};

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

    let mut family: u16 = 0;
    let mut port: u16 = 0;
    let mut addr = [0u8; 16];

    if sa_ptr != 0 {
        // SAFETY: `uservaddr` is a user pointer valid for `addrlen` bytes; the
        // helper bails out safely on fault.
        let read_family =
            unsafe { aya_ebpf::helpers::bpf_probe_read_user(sa_ptr as *const u16) };
        family = read_family.unwrap_or(0);
        match family {
            AF_INET => {
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
            AF_INET6 => {
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
                if let Ok(sin6) = (unsafe {
                    aya_ebpf::helpers::bpf_probe_read_user(sa_ptr as *const SockAddrIn6)
                }) {
                    port = u16::from_be(sin6.port);
                    addr.copy_from_slice(&sin6.addr);
                }
            }
            _ => {}
        }
    }

    emit_net(&ctx, fd, family, port, addr, addrlen);
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
