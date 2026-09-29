//! Event enrichment: pid → parent, container id.
//!
//! Phase 1 reads `/proc/<pid>/cgroup` and `/proc/<pid>/status` per process.
//! Phase 2 adds containerd/CRI lookups and the Kubernetes API
//! (cgroup id → container id → pod/namespace), with an LRU cache.

use std::{
    collections::HashMap,
    fs,
    time::{Duration, Instant},
};

use serde::Serialize;

/// Enrichment result attached to every event before rule evaluation.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Enrichment {
    pub container_id: Option<String>,
    pub cgroup: Option<String>,
}

/// Extract a container id from a cgroup path.
///
/// Handles the common systemd/cri spellings:
/// * `.../docker-<64hex>.scope`
/// * `.../cri-containerd-<64hex>.scope`
/// * `.../crio-<64hex>.scope`
/// * `.../docker/<64hex>/...`
/// * any bare 64-hex path component (fallback)
pub fn container_id_from_cgroup(cgroup_path: &str) -> Option<String> {
    const HEX64: usize = 64;

    fn is_hex64(s: &str) -> bool {
        s.len() == HEX64 && s.bytes().all(|b| b.is_ascii_hexdigit())
    }

    for part in cgroup_path.split(['/', ':', '.', '-']) {
        if is_hex64(part) {
            return Some(part.to_string());
        }
    }
    None
}

/// Read the first `cgroup` path of `pid` from procfs.
pub fn read_cgroup(pid: u32) -> Option<String> {
    let text = fs::read_to_string(format!("/proc/{pid}/cgroup")).ok()?;
    // v2: `0::/path`; v1: many lines. Take the longest path — that's where
    // the container runtime drops the workload.
    text.lines()
        .filter_map(|line| line.split_once("::").map(|(_, path)| path))
        .max_by_key(|path| path.len())
        .map(|path| path.to_string())
}

/// Read `PPid` of `pid` from `/proc/<pid>/status`.
pub fn read_ppid(pid: u32) -> Option<u32> {
    let text = fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("PPid:") {
            return rest.trim().parse().ok();
        }
    }
    None
}

const CACHE_TTL: Duration = Duration::from_secs(5);

/// Per-tgid enrichment cache (procfs reads dominate otherwise).
pub struct Enricher {
    cache: HashMap<u32, (Instant, Enrichment)>,
}

impl Default for Enricher {
    fn default() -> Self {
        Self::new()
    }
}

impl Enricher {
    pub fn new() -> Self {
        Self {
            cache: HashMap::new(),
        }
    }

    pub fn enrich(&mut self, tgid: u32) -> Enrichment {
        if let Some((at, cached)) = self.cache.get(&tgid) {
            if at.elapsed() < CACHE_TTL {
                return cached.clone();
            }
        }
        let enrichment = self.compute(tgid);
        self.cache.insert(tgid, (Instant::now(), enrichment.clone()));
        // Bounded cache: drop everything on overflow (rare; cheap).
        if self.cache.len() > 4096 {
            self.cache.clear();
        }
        enrichment
    }

    fn compute(&self, tgid: u32) -> Enrichment {
        let cgroup = read_cgroup(tgid);
        let container_id = cgroup
            .as_deref()
            .and_then(container_id_from_cgroup);
        Enrichment {
            container_id,
            cgroup,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_docker_scope() {
        let cg = "/system.slice/docker-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef.scope";
        assert_eq!(
            container_id_from_cgroup(cg).as_deref(),
            Some("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
        );
    }

    #[test]
    fn extracts_containerd_scope() {
        let cg = "/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-poddeadbeef.slice/cri-containerd-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.scope";
        assert_eq!(
            container_id_from_cgroup(cg).as_deref(),
            Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        );
    }

    #[test]
    fn extracts_docker_cgroup_v1() {
        let cg = "/docker/0d1b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef";
        assert_eq!(
            container_id_from_cgroup(cg).as_deref(),
            Some("0d1b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef")
        );
    }

    #[test]
    fn ignores_non_container_cgroups() {
        assert_eq!(container_id_from_cgroup("/user.slice/user-1000.slice"), None);
        assert_eq!(container_id_from_cgroup("/system.slice/sshd.service"), None);
    }
}
