//! `sentinel-common` — the event ABI shared by the eBPF probes (`sentinel-ebpf`)
//! and the userspace agent (`sentinel`).
//!
//! Everything in this crate is `no_std` and `#[repr(C)]`. The eBPF side writes
//! these structs into a ring buffer; the userspace side decodes them from raw
//! bytes. Field order and sizes are part of the ABI — change them only together
//! with the decoder in `agent/src/event.rs`.
//!
//! Size notes (64-bit): every event starts with a 48-byte [`EventHeader`]. All
//! structs are 8-byte aligned so they can be reserved directly inside a
//! `BPF_MAP_TYPE_RINGBUF` entry.

#![no_std]

/// Length of the kernel `comm` field (`TASK_COMM_LEN`).
pub const TASK_COMM_LEN: usize = 16;

/// Maximum length (including trailing NUL) of a captured path string.
pub const MAX_PATH_LEN: usize = 256;

/// Maximum length (including trailing NUL) of a captured secondary string
/// (mount source, fstype, put_old, ...).
pub const MAX_ARGV_LEN: usize = 128;

/// Number of `argv` entries captured from `execve`.
pub const ARG_SLOTS: usize = 4;

/// Bytes per argv slot (including trailing NUL). Longer args are truncated.
pub const ARG_SLOT_LEN: usize = 64;

/// Total size of the argv slots buffer: `ARG_SLOTS * ARG_SLOT_LEN`.
pub const ARGV_BUF_LEN: usize = ARG_SLOTS * ARG_SLOT_LEN;

/// Maximum length (including trailing NUL) of a captured file-system type name.
pub const MAX_FSTYPE_LEN: usize = 32;

// ---------------------------------------------------------------------------
// Event type tags (first u32 of every event, i.e. `EventHeader::event_type`)
// ---------------------------------------------------------------------------

pub const EVENT_EXECVE: u32 = 1;
pub const EVENT_OPENAT: u32 = 2;
pub const EVENT_CONNECT: u32 = 3;
pub const EVENT_PTRACE: u32 = 4;
pub const EVENT_MOUNT: u32 = 5;
pub const EVENT_SETNS: u32 = 6;
pub const EVENT_UNSHARE: u32 = 7;
pub const EVENT_CAPSET: u32 = 8;
pub const EVENT_PIVOT_ROOT: u32 = 9;
pub const EVENT_ACCEPT: u32 = 10;
pub const EVENT_BIND: u32 = 11;
pub const EVENT_DNS: u32 = 12;

/// Stable name for an event type tag. Used by the rule engine (`evt.type=`).
pub const fn event_type_name(event_type: u32) -> &'static str {
    match event_type {
        EVENT_EXECVE => "execve",
        EVENT_OPENAT => "openat",
        EVENT_CONNECT => "connect",
        EVENT_PTRACE => "ptrace",
        EVENT_MOUNT => "mount",
        EVENT_SETNS => "setns",
        EVENT_UNSHARE => "unshare",
        EVENT_CAPSET => "capset",
        EVENT_PIVOT_ROOT => "pivot_root",
        EVENT_ACCEPT => "accept",
        EVENT_BIND => "bind",
        EVENT_DNS => "dns",
        _ => "unknown",
    }
}

// Linux address families (uapi `bits/socket.h`).
pub const AF_UNSPEC: u16 = 0;
pub const AF_UNIX: u16 = 1;
pub const AF_INET: u16 = 2;
pub const AF_INET6: u16 = 10;

// ---------------------------------------------------------------------------
// Event structs
// ---------------------------------------------------------------------------

/// Common prefix of every event.
///
/// Layout: 6 × u32 (24 bytes) + u64 (8) + comm (16) = 48 bytes.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct EventHeader {
    /// One of the `EVENT_*` constants.
    pub event_type: u32,
    /// Thread id (kernel `pid`, i.e. `gettid()`).
    pub pid: u32,
    /// Process id (kernel `tgid`, i.e. `getpid()`).
    pub tgid: u32,
    pub uid: u32,
    pub gid: u32,
    /// Parent process id. Populated by userspace enrichment for now (the eBPF
    /// side leaves it 0); see `agent/src/enrich.rs`.
    pub ppid: u32,
    /// `bpf_ktime_get_ns()` at probe time (CLOCK_MONOTONIC).
    pub timestamp_ns: u64,
    /// `bpf_get_current_comm()`, NUL-padded.
    pub comm: [u8; TASK_COMM_LEN],
}

/// `execve(2)` — emitted from `syscalls/sys_enter_execve`.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct ExecveEvent {
    pub header: EventHeader,
    /// `filename` argument, NUL-padded, possibly truncated.
    pub filename: [u8; MAX_PATH_LEN],
    /// First [`ARG_SLOTS`] `argv` entries, one per [`ARG_SLOT_LEN`]-byte slot,
    /// NUL-padded. Userspace joins the slots for `exec.argv`.
    pub argv: [u8; ARGV_BUF_LEN],
}

/// `openat(2)` / `openat2(2)` style file access — emitted from
/// `syscalls/sys_enter_openat`.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct FileEvent {
    pub header: EventHeader,
    /// `pathname` argument (resolved relative to `dirfd` by the kernel).
    pub filename: [u8; MAX_PATH_LEN],
    /// Directory fd (`AT_FDCWD` = -100).
    pub dirfd: i32,
    /// `flags` argument (O_* bits).
    pub flags: u32,
    /// `mode` argument.
    pub mode: u32,
    pub _reserved: u32,
}

/// `connect(2)` — emitted from `syscalls/sys_enter_connect`.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct NetEvent {
    pub header: EventHeader,
    /// Socket fd being connected.
    pub fd: i32,
    /// `AF_*` address family from `struct sockaddr`.
    pub family: u16,
    /// Destination port, host byte order.
    pub port: u16,
    /// IPv4 address in the first 4 bytes, IPv6 in all 16. Zero for other families.
    pub addr: [u8; 16],
    /// `addrlen` argument.
    pub addrlen: u32,
    pub _reserved: u32,
}

/// `mount(2)` — emitted from `syscalls/sys_enter_mount`.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct MountEvent {
    pub header: EventHeader,
    /// `flags` argument (MS_* bits).
    pub flags: u64,
    /// `source` argument.
    pub source: [u8; MAX_ARGV_LEN],
    /// `target` argument.
    pub target: [u8; MAX_PATH_LEN],
    /// `fstype` argument ("proc", "cgroup", "hostpath", ...).
    pub fstype: [u8; MAX_FSTYPE_LEN],
}

/// Generic syscall event used for the remaining traced syscalls:
/// `ptrace`, `setns`, `unshare`, `capset`, `pivot_root`.
///
/// Numeric arguments land in `arg0..arg2`; the primary string argument (if
/// any) lands in `path`, the secondary in `path2`.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct SyscallEvent {
    pub header: EventHeader,
    /// First syscall argument (request / fd / flags / header pointer / ...).
    pub arg0: u64,
    /// Second syscall argument.
    pub arg1: u64,
    /// Third syscall argument.
    pub arg2: u64,
    /// Primary string argument (`pivot_root(new_root, put_old)` → `new_root`).
    pub path: [u8; MAX_PATH_LEN],
    /// Secondary string argument (`put_old` for `pivot_root`).
    pub path2: [u8; MAX_ARGV_LEN],
}

/// DNS query observed on the wire by the `cgroup_skb` egress program
/// (UDP destination port 53). Emitted from `bpf/src/network.rs`.
///
/// The query name is captured in **wire format** (length-prefixed labels,
/// followed by the QTYPE/QCLASS tail) — label walking happens in userspace
/// (`agent/src/event.rs`), keeping the probe to fixed-range copies that the
/// verifier checks trivially. Long names are truncated.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct DnsEvent {
    pub header: EventHeader,
    /// Raw QNAME + QTYPE/QCLASS tail, truncated to 128 bytes.
    pub qname_raw: [u8; 128],
    /// Bytes of `qname_raw` that were actually captured.
    pub qname_len: u16,
    /// Destination port (53 for classic DNS).
    pub dst_port: u16,
    /// Address family of the DNS server (`AF_INET` / `AF_INET6`).
    pub family: u16,
    pub _pad: u16,
    /// DNS server address (IPv4 in first 4 bytes, IPv6 in all 16).
    pub server: [u8; 16],
}

/// In-kernel capture filter. Written by userspace into the `CONFIG` map at
/// startup; checked by every emitter before reserving ring-buffer space.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct FilterConfig {
    /// Only capture events from uids in `[min_uid, max_uid]`.
    pub min_uid: u32,
    pub max_uid: u32,
}

impl FilterConfig {
    pub const CAPTURE_ALL: FilterConfig = FilterConfig {
        min_uid: 0,
        max_uid: u32::MAX,
    };
}

/// Per-cgroup byte counters aggregated by the `cgroup_skb` programs in a
/// `BPF_MAP_TYPE_HASH` keyed by cgroup id. Userspace reads and resets them.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct ByteStats {
    /// Bytes received (ingress hook).
    pub ingress: u64,
    /// Bytes sent (egress hook).
    pub egress: u64,
}

// ---------------------------------------------------------------------------
// FFI safety for the userspace decoder (`aya::Pod` marks plain-old-data)
// ---------------------------------------------------------------------------

#[cfg(feature = "user")]
unsafe impl aya::Pod for EventHeader {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for ExecveEvent {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for FileEvent {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for NetEvent {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for MountEvent {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for SyscallEvent {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for DnsEvent {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for FilterConfig {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for ByteStats {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_sizes_are_abi_stable() {
        // The decoder checks `bytes.len() == size_of::<T>()`; these sizes are
        // part of the ABI and must not drift silently.
        assert_eq!(core::mem::size_of::<EventHeader>(), 48);
        assert_eq!(core::mem::size_of::<ExecveEvent>(), 560);
        assert_eq!(core::mem::size_of::<FileEvent>(), 320);
        assert_eq!(core::mem::size_of::<NetEvent>(), 80);
        assert_eq!(core::mem::size_of::<MountEvent>(), 472);
        assert_eq!(core::mem::size_of::<SyscallEvent>(), 456);
        assert_eq!(core::mem::size_of::<DnsEvent>(), 200);
        assert_eq!(core::mem::size_of::<FilterConfig>(), 8);
        assert_eq!(core::mem::size_of::<ByteStats>(), 16);
    }

    #[test]
    fn events_are_eight_byte_aligned() {
        // Ring buffer reservations only guarantee 8-byte alignment.
        assert!(core::mem::align_of::<ExecveEvent>() <= 8);
        assert!(core::mem::align_of::<FileEvent>() <= 8);
        assert!(core::mem::align_of::<NetEvent>() <= 8);
        assert!(core::mem::align_of::<MountEvent>() <= 8);
        assert!(core::mem::align_of::<SyscallEvent>() <= 8);
        assert!(core::mem::align_of::<DnsEvent>() <= 8);
    }
}
