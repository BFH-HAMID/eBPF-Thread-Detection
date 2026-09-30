//! eBPF program loading and attachment.

use anyhow::{Context as _, Result, bail};
use aya::{
    Ebpf,
    maps::MapData,
    programs::{CgroupSkb, CgroupSkbAttachType, TracePoint, links::CgroupAttachMode},
};
use log::info;
use sentinel_common::{ByteStats, FilterConfig};

/// Every `(program name, tracepoint category, tracepoint name)` triple the
/// agent attaches. Program names must match the `#[tracepoint]` fn names in
/// `bpf/src/`.
pub const PROBES: &[(&str, &str, &str)] = &[
    ("sys_enter_execve", "syscalls", "sys_enter_execve"),
    ("sys_enter_openat", "syscalls", "sys_enter_openat"),
    ("sys_enter_connect", "syscalls", "sys_enter_connect"),
    ("sys_enter_accept4", "syscalls", "sys_enter_accept4"),
    ("sys_enter_bind", "syscalls", "sys_enter_bind"),
    ("sys_enter_ptrace", "syscalls", "sys_enter_ptrace"),
    ("sys_enter_mount", "syscalls", "sys_enter_mount"),
    ("sys_enter_setns", "syscalls", "sys_enter_setns"),
    ("sys_enter_unshare", "syscalls", "sys_enter_unshare"),
    ("sys_enter_capset", "syscalls", "sys_enter_capset"),
    ("sys_enter_pivot_root", "syscalls", "sys_enter_pivot_root"),
];

/// The two `cgroup_skb` programs (byte counters + DNS capture), attached to
/// the root cgroup so all containers on the node are covered.
pub const CGROUP_SKB: &[(&str, CgroupSkbAttachType)] = &[
    ("cgroup_skb_egress", CgroupSkbAttachType::Egress),
    ("cgroup_skb_ingress", CgroupSkbAttachType::Ingress),
];

/// Links are owned by the loaded [`Ebpf`] programs (`attach` returns only an
/// id); dropping the `Ebpf` detaches everything, which is what we want for
/// graceful shutdown.
pub struct Attached;

/// Load and attach all probes declared in [`PROBES`] plus the cgroup_skb
/// programs (best-effort: cgroup attach failure is a warning, not fatal —
/// e.g. on cgroup-v1 hosts without a unified hierarchy).
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

    if let Err(err) = attach_cgroup_skb(ebpf) {
        log::warn!("cgroup_skb programs not attached (byte/DNS telemetry off): {err:#}");
    }
    Ok(Attached)
}

/// Attach `cgroup_skb_{egress,ingress}` to the root cgroup.
pub fn attach_cgroup_skb(ebpf: &mut Ebpf) -> Result<()> {
    let cgroup = std::fs::File::open("/sys/fs/cgroup")
        .context("opening /sys/fs/cgroup (unified hierarchy required)")?;
    for &(prog, attach_type) in CGROUP_SKB {
        let program: &mut CgroupSkb = match ebpf.program_mut(prog) {
            Some(p) => p
                .try_into()
                .with_context(|| format!("{prog} is not a cgroup_skb program"))?,
            None => bail!("eBPF program {prog} not found in object"),
        };
        program.load().with_context(|| format!("loading {prog}"))?;
        program
            .attach(
                cgroup.try_clone().context("cloning cgroup fd")?,
                attach_type,
                CgroupAttachMode::default(),
            )
            .with_context(|| format!("attaching {prog}"))?;
        info!("attached {prog} -> root cgroup ({attach_type:?})");
    }
    Ok(())
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

/// Take the `BYTE_STATS` per-cgroup map out of a loaded object (Phase 2).
pub fn take_byte_stats(
    ebpf: &mut Ebpf,
) -> Result<aya::maps::HashMap<MapData, u64, ByteStats>> {
    let map = ebpf
        .take_map("BYTE_STATS")
        .context("BYTE_STATS map not found in eBPF object")?;
    aya::maps::HashMap::try_from(map).context("BYTE_STATS map is not a hash map")
}

/// Write the uid-range capture filter into the in-kernel `CONFIG` map.
/// Missing map (older objects) is fine — the probes then capture everything.
pub fn set_filter(ebpf: &mut Ebpf, min_uid: u32, max_uid: u32) -> Result<()> {
    let Some(map) = ebpf.take_map("CONFIG") else {
        log::warn!("CONFIG map not found; in-kernel uid filtering disabled");
        return Ok(());
    };
    let mut config: aya::maps::Array<MapData, FilterConfig> =
        aya::maps::Array::try_from(map).context("CONFIG map is not an array")?;
    config
        .set(0, FilterConfig { min_uid, max_uid }, 0)
        .context("writing CONFIG[0]")?;
    info!("in-kernel filter: uid range [{min_uid}, {max_uid}]");
    Ok(())
}

/// Record program identities (fdinfo `prog_id`) for the tamper watchdog.
/// Called after `attach_all`, while programs are still in the `Ebpf`.
pub fn probe_identities(ebpf: &Ebpf) -> Vec<crate::tamper::ProbeRecord> {
    use std::os::fd::AsRawFd as _;

    let mut out = Vec::new();
    for &(prog, _, _) in PROBES {
        let Some(p) = ebpf.program(prog) else {
            continue;
        };
        let Ok(fd) = p.fd() else {
            continue;
        };
        let raw = std::os::fd::AsFd::as_fd(fd).as_raw_fd();
        if let Some(prog_id) = crate::tamper::read_fdinfo_id(raw) {
            out.push(crate::tamper::ProbeRecord {
                name: prog.to_string(),
                fd: raw,
                prog_id,
            });
        }
    }
    out
}
