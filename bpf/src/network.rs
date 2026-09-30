//! Network probes (Phase 2): `cgroup_skb` byte counters + DNS query capture.
//!
//! `cgroup_skb/egress` and `cgroup_skb/ingress` run for every packet that
//! crosses a cgroup boundary (i.e. per container/pod on the node). Two jobs:
//!
//! 1. **Bytes in/out per cgroup** — a `BPF_MAP_TYPE_HASH` keyed by cgroup id
//!    (`bpf_skb_cgroup_id`) accumulates [`sentinel_common::ByteStats`]. The
//!    agent reads and resets it into the metrics snapshot.
//! 2. **DNS query capture** — UDP packets with destination port 53 get their
//!    raw QNAME captured into a [`sentinel_common::DnsEvent`] (labels are
//!    decoded in userspace). This catches DNS-based C2 and exfiltration even
//!    when no socket API is used.
//!
//! Deeper 4-tuple connect tracking (`fentry/tcp_v4_connect` on `struct sock`)
//! still wants CO-RE + `vmlinux` bindings; the syscall-level `connect`/
//! `accept4`/`bind` tracepoints in [`crate::syscalls`] cover the common cases
//! without BTF.

use aya_ebpf::{
    EbpfContext as _,
    bindings::__sk_buff,
    helpers::bpf_skb_cgroup_id,
    macros::{cgroup_skb, map},
    maps::HashMap,
    programs::SkBuffContext,
};
use sentinel_common::{AF_INET, AF_INET6, ByteStats};

use crate::util::emit_dns;

/// UDP protocol number (IPv4 `protocol` / IPv6 `nexthdr`).
pub const UDP_PROTO: u8 = 17;
/// Classic DNS port.
pub const DNS_PORT: u16 = 53;

/// Per-cgroup byte counters, keyed by cgroup id. Written from both hooks;
/// drained by userspace for the metrics endpoint.
#[map]
pub static BYTE_STATS: HashMap<u64, ByteStats> = HashMap::with_max_entries(4096, 0);

/// Bytes of raw QNAME (plus QTYPE/QCLASS tail) captured per DNS event.
const QNAME_RAW_CAP: usize = 128;
/// Max bytes of a packet header we inspect (v4 header + udp + dns + qname cap).
const HEAD_CAP: usize = 160;

/// `cgroup_skb` egress: byte accounting + DNS query capture. Always returns 1
/// (observe only — the detector must never drop traffic).
#[cgroup_skb]
pub fn cgroup_skb_egress(ctx: SkBuffContext) -> i32 {
    account_bytes(&ctx, true);
    try_dns(&ctx);
    1
}

/// `cgroup_skb` ingress: byte accounting only (DNS queries leave the node).
#[cgroup_skb]
pub fn cgroup_skb_ingress(ctx: SkBuffContext) -> i32 {
    account_bytes(&ctx, false);
    1
}

#[inline(always)]
fn account_bytes(ctx: &SkBuffContext, egress: bool) {
    // SAFETY: `ctx.as_ptr()` is a valid `__sk_buff` for the program's lifetime;
    // the helper returns the cgroup id of the skb (0 if unavailable).
    let cgroup_id = unsafe { bpf_skb_cgroup_id(ctx.as_ptr().cast::<__sk_buff>()) } as u64;
    let len = ctx.len() as u64;
    match BYTE_STATS.get_ptr_mut(&cgroup_id) {
        // SAFETY: map value is valid while the program runs; non-atomic += is
        // fine for a loss-tolerant counter.
        Some(stats) => unsafe {
            if egress {
                (*stats).egress = (*stats).egress.saturating_add(len);
            } else {
                (*stats).ingress = (*stats).ingress.saturating_add(len);
            }
        },
        None => {
            let stats = ByteStats {
                ingress: if egress { 0 } else { len },
                egress: if egress { len } else { 0 },
            };
            let _ = BYTE_STATS.insert(&cgroup_id, &stats, 0);
        }
    }
}

/// If the packet is a UDP query to port 53, capture the raw QNAME.
///
/// Packet layout assumptions: IPv4 without exotic IHL, or IPv6 without
/// extension headers (documented limitation). All copies are fixed-bounded —
/// no label walking in-kernel.
#[inline(always)]
fn try_dns(ctx: &SkBuffContext) {
    let mut head = [0u8; HEAD_CAP];
    let Ok(n) = ctx.load_bytes(0, &mut head) else {
        return;
    };
    if n < 28 {
        return;
    }

    let mut udp_off = 0usize;
    let mut family: u16 = 0;
    let mut server = [0u8; 16];
    match head[0] >> 4 {
        4 => {
            let ihl = ((head[0] & 0x0f) as usize) * 4;
            // need: ip hdr + udp hdr + dns hdr + 1 qname byte
            if ihl < 20 || n < ihl + 25 {
                return;
            }
            if head[9] != UDP_PROTO {
                return;
            }
            udp_off = ihl;
            family = AF_INET;
            server[..4].copy_from_slice(&head[16..20]);
        }
        6 => {
            if n < 65 {
                return;
            }
            if head[6] != UDP_PROTO {
                return; // extension headers unsupported (documented)
            }
            udp_off = 40;
            family = AF_INET6;
            server.copy_from_slice(&head[24..40]);
        }
        _ => return,
    }

    let dport = u16::from_be_bytes([head[udp_off + 2], head[udp_off + 3]]);
    if dport != DNS_PORT {
        return;
    }

    let qname_off = udp_off + 8 + 12; // udp hdr + dns header
    let avail = n - qname_off;
    let take = if avail >= QNAME_RAW_CAP {
        QNAME_RAW_CAP
    } else {
        avail
    };

    let mut raw = [0u8; QNAME_RAW_CAP];
    // Fixed-bounded copy: `k < take <= n - qname_off <= HEAD_CAP`.
    for k in 0..QNAME_RAW_CAP {
        if k >= take {
            break;
        }
        raw[k] = head[qname_off + k];
    }

    emit_dns(ctx, &raw, take as u16, dport, family, server);
}
