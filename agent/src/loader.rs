//! eBPF program loading and attachment.

use anyhow::{Context as _, Result, bail};
use aya::{
    Ebpf,
    maps::MapData,
    programs::TracePoint,
};
use log::info;

/// Every `(program name, tracepoint category, tracepoint name)` triple the
/// agent attaches. Program names must match the `#[tracepoint]` fn names in
/// `bpf/src/`.
pub const PROBES: &[(&str, &str, &str)] = &[
    ("sys_enter_execve", "syscalls", "sys_enter_execve"),
    ("sys_enter_openat", "syscalls", "sys_enter_openat"),
    ("sys_enter_connect", "syscalls", "sys_enter_connect"),
    ("sys_enter_ptrace", "syscalls", "sys_enter_ptrace"),
    ("sys_enter_mount", "syscalls", "sys_enter_mount"),
    ("sys_enter_setns", "syscalls", "sys_enter_setns"),
    ("sys_enter_unshare", "syscalls", "sys_enter_unshare"),
    ("sys_enter_capset", "syscalls", "sys_enter_capset"),
    ("sys_enter_pivot_root", "syscalls", "sys_enter_pivot_root"),
];

/// Links are owned by the loaded [`Ebpf`] programs (`attach` returns only an
/// id); dropping the `Ebpf` detaches everything, which is what we want for
/// graceful shutdown.
pub struct Attached;

/// Load and attach all probes declared in [`PROBES`].
pub fn attach_all(ebpf: &mut Ebpf) -> Result<Attached> {
    for &(prog, category, name) in PROBES {
        let program: &mut TracePoint = match ebpf.program_mut(prog) {
            Some(p) => p
                .try_into()
                .with_context(|| format!("{prog} is not a tracepoint program"))?,
            None => bail!("eBPF program {prog} not found in object (build mismatch?)"),
        };
        program
            .load()
            .with_context(|| format!("loading {prog}"))?;
        program
            .attach(category, name)
            .with_context(|| format!("attaching {prog} to {category}/{name}"))?;
        info!("attached {prog} -> {category}/{name}");
    }
    Ok(Attached)
}

/// Take the `EVENTS` ring buffer map out of a loaded object.
pub fn take_events_ring(ebpf: &mut Ebpf) -> Result<aya::maps::ring_buf::RingBuf<MapData>> {
    let map = ebpf
        .take_map("EVENTS")
        .context("EVENTS map not found in eBPF object")?;
    aya::maps::ring_buf::RingBuf::try_from(map).context("EVENTS map is not a ring buffer")
}

/// Take the `DROPPED` counter map out of a loaded object.
pub fn take_dropped_counter(ebpf: &mut Ebpf) -> Result<aya::maps::Array<MapData, u64>> {
    let map = ebpf
        .take_map("DROPPED")
        .context("DROPPED map not found in eBPF object")?;
    aya::maps::Array::try_from(map).context("DROPPED map is not an array")
}
