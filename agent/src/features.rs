//! Windowed feature extraction (Phase 4 groundwork).
//!
//! Features are aggregated per key (process tgid or container id) over fixed
//! sliding windows and flushed as [`FeatureVector`]s for the ML pipeline.
//! The training side (`ml/datasets/collect.py`) consumes exactly this schema.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use crate::event::Event;

/// Feature vector for one window of one key. Keep in sync with
/// `ml/datasets/collect.py`.
#[derive(Debug, Clone, Serialize)]
pub struct FeatureVector {
    pub key: String,
    pub window_secs: u64,
    pub exec_count: u64,
    pub open_count: u64,
    pub net_connect_count: u64,
    pub sys_event_count: u64,
    pub distinct_dst_ips: u64,
    pub distinct_dst_ports: u64,
    pub distinct_file_paths: u64,
    /// Shannon entropy (bits/byte) over the characters of accessed paths —
    /// high entropy often means key/keystore-style access or encoded names.
    pub file_path_entropy: f64,
    pub distinct_comms: u64,
    /// DNS queries observed (cgroup_skb capture).
    pub dns_count: u64,
    /// Distinct queried names — high with low connect count smells like C2.
    pub distinct_dns_queries: u64,
}

#[derive(Debug, Default)]
struct Window {
    exec_count: u64,
    open_count: u64,
    net_connect_count: u64,
    sys_event_count: u64,
    dst_ips: BTreeSet<String>,
    dst_ports: BTreeSet<u16>,
    file_paths: BTreeSet<String>,
    path_chars: BTreeMap<u8, u64>,
    comms: BTreeSet<String>,
    dns_count: u64,
    dns_queries: BTreeSet<String>,
}

impl Window {
    fn to_vector(&self, key: &str, window_secs: u64) -> FeatureVector {
        FeatureVector {
            key: key.to_string(),
            window_secs,
            exec_count: self.exec_count,
            open_count: self.open_count,
            net_connect_count: self.net_connect_count,
            sys_event_count: self.sys_event_count,
            distinct_dst_ips: self.dst_ips.len() as u64,
            distinct_dst_ports: self.dst_ports.len() as u64,
            distinct_file_paths: self.file_paths.len() as u64,
            file_path_entropy: shannon_entropy(&self.path_chars),
            distinct_comms: self.comms.len() as u64,
            dns_count: self.dns_count,
            distinct_dns_queries: self.dns_queries.len() as u64,
        }
    }
}

fn shannon_entropy(counts: &BTreeMap<u8, u64>) -> f64 {
    let total: u64 = counts.values().sum();
    if total == 0 {
        return 0.0;
    }
    counts
        .values()
        .filter(|&&n| n > 0)
        .map(|&n| {
            let p = n as f64 / total as f64;
            -p * p.log2()
        })
        .sum()
}

/// Aggregates events into per-key sliding windows.
pub struct FeatureExtractor {
    window_secs: u64,
    windows: BTreeMap<String, Window>,
}

impl FeatureExtractor {
    pub fn new(window_secs: u64) -> Self {
        Self {
            window_secs: window_secs.max(1),
            windows: BTreeMap::new(),
        }
    }

    /// Record one event. `key` is the aggregation key (`tgid` or
    /// `container:<id>`), chosen by the caller.
    pub fn observe(&mut self, key: &str, event: &Event) {
        let w = self.windows.entry(key.to_string()).or_default();
        w.comms.insert(event.header().comm.clone());
        match event {
            Event::Execve { filename, .. } => {
                w.exec_count += 1;
                record_path(w, filename);
            }
            Event::Openat { filename, .. } => {
                w.open_count += 1;
                record_path(w, filename);
            }
            Event::Connect { addr, port, .. } => {
                w.net_connect_count += 1;
                if !addr.is_empty() {
                    w.dst_ips.insert(addr.clone());
                }
                w.dst_ports.insert(*port);
            }
            Event::Accept { .. } | Event::Bind { .. } => {
                w.net_connect_count += 1;
            }
            Event::Dns { query, .. } => {
                w.dns_count += 1;
                if !query.is_empty() {
                    w.dns_queries.insert(query.clone());
                }
            }
            Event::Ptrace { .. }
            | Event::Mount { .. }
            | Event::Setns { .. }
            | Event::Unshare { .. }
            | Event::Capset { .. }
            | Event::PivotRoot { .. } => {
                w.sys_event_count += 1;
            }
        }
    }

    /// Flush all open windows (call once per window boundary).
    pub fn flush(&mut self) -> Vec<FeatureVector> {
        let windows = std::mem::take(&mut self.windows);
        windows
            .into_iter()
            .map(|(key, w)| w.to_vector(&key, self.window_secs))
            .collect()
    }
}

fn record_path(w: &mut Window, path: &str) {
    w.file_paths.insert(path.to_string());
    for b in path.bytes() {
        *w.path_chars.entry(b).or_insert(0) += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::Header;

    fn hdr() -> Header {
        Header {
            event_type: 1,
            evt_type: "execve".into(),
            pid: 1,
            tgid: 1,
            uid: 0,
            gid: 0,
            ppid: 0,
            timestamp_ns: 0,
            comm: "bash".into(),
        }
    }

    #[test]
    fn windows_aggregate_counts() {
        let mut fx = FeatureExtractor::new(60);
        fx.observe(
            "tgid:1",
            &Event::Execve {
                header: hdr(),
                filename: "/bin/sh".into(),
                argv: "sh".into(),
            },
        );
        fx.observe(
            "tgid:1",
            &Event::Connect {
                header: hdr(),
                fd: 3,
                family: 2,
                family_name: "inet".into(),
                port: 4444,
                addr: "10.0.0.1".into(),
            },
        );
        let vectors = fx.flush();
        assert_eq!(vectors.len(), 1);
        let v = &vectors[0];
        assert_eq!(v.exec_count, 1);
        assert_eq!(v.net_connect_count, 1);
        assert_eq!(v.distinct_dst_ips, 1);
        assert_eq!(v.distinct_dst_ports, 1);
        assert_eq!(v.distinct_comms, 1);
        assert!(v.file_path_entropy > 0.0);
    }

    #[test]
    fn empty_windows_have_zero_entropy() {
        assert_eq!(shannon_entropy(&BTreeMap::new()), 0.0);
    }
}
