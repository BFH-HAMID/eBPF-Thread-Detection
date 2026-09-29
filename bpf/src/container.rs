//! Container-escape signal probes: namespace, capability and root-fs changes.
//!
//! These attach to plain syscall tracepoints (no CO-RE needed). The heavier
//! cgroup-scoped detectors (cgroup attach/detach, `release_agent` writes,
//! `/proc/*/root` access) are Phase 2/3 work — see `docs/roadmap.md`.

use aya_ebpf::{macros::tracepoint, programs::TracePointContext};
use aya_log_ebpf::debug;
use sentinel_common::{EVENT_CAPSET, EVENT_PIVOT_ROOT, EVENT_UNSHARE};

use crate::util::{emit_sys, sys_arg};

/// `unshare(flags)` — creates namespaces (CLONE_NEWNS/NEWUSER/NEWPID/...).
#[tracepoint(category = "syscalls", name = "sys_enter_unshare")]
pub fn sys_enter_unshare(ctx: TracePointContext) -> u32 {
    emit_sys(&ctx, EVENT_UNSHARE, sys_arg(&ctx, 0), 0, 0, 0, 0);
    0
}

/// `capset(header, data)` — capability set changes (CAP_SYS_ADMIN abuse).
#[tracepoint(category = "syscalls", name = "sys_enter_capset")]
pub fn sys_enter_capset(ctx: TracePointContext) -> u32 {
    emit_sys(&ctx, EVENT_CAPSET, sys_arg(&ctx, 0), 0, 0, 0, 0);
    0
}

/// `pivot_root(new_root, put_old)` — root-fs swap, the container-escape
/// finale. Both paths are captured because this event is rare and high-signal.
#[tracepoint(category = "syscalls", name = "sys_enter_pivot_root")]
pub fn sys_enter_pivot_root(ctx: TracePointContext) -> u32 {
    debug!(
        &ctx,
        "pivot_root: new_root={:x} put_old={:x}",
        sys_arg(&ctx, 0),
        sys_arg(&ctx, 1)
    );
    emit_sys(
        &ctx,
        EVENT_PIVOT_ROOT,
        sys_arg(&ctx, 0),
        sys_arg(&ctx, 1),
        0,
        sys_arg(&ctx, 0),
        sys_arg(&ctx, 1),
    );
    0
}
