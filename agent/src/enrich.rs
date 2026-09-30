//! Event enrichment: pid → parent, container id, pod metadata.
//!
//! Reads `/proc/<pid>/cgroup` and `/proc/<pid>/status` per process. Phase 2
//! adds the Kubernetes layer: pod UID is parsed out of the cgroup path and
//! resolved to pod name/namespace through the API server (in-cluster service
//! account) when the `k8s` feature is enabled. Lookups are cached.

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
    pub pod_uid: Option<String>,
    pub pod_name: Option<String>,
    pub pod_namespace: Option<String>,
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

/// Extract a Kubernetes pod UID from a cgroup path.
///
/// Handles the systemd slice spelling
/// `kubepods-<class>-pod<uid_with_underscores>.slice` and the cgroupfs
/// spelling `kubepods/<class>/pod<uid>`. UID characters `:` become `_`.
pub fn pod_uid_from_cgroup(cgroup_path: &str) -> Option<String> {
    // Look for `pod<36-char-uuid>` with `-`/`_`/`:` separators normalized.
    for (i, w) in cgroup_path.match_indices("pod") {
        let start = i + w.len();
        let rest = &cgroup_path[start..];
        if rest.len() < 36 {
            continue;
        }
        let cand = &rest[..36];
        let shaped = cand.chars().enumerate().all(|(j, c)| match j {
            8 | 13 | 18 | 23 => c == '-' || c == '_',
            _ => c.is_ascii_hexdigit(),
        });
        if shaped {
            return Some(cand.replace('_', "-").to_lowercase());
        }
    }
    None
}

/// Pod identity resolved from the Kubernetes API.
#[derive(Debug, Clone, Default, Serialize)]
pub struct PodMeta {
    pub uid: String,
    pub name: String,
    pub namespace: String,
}

/// Reads the first `cgroup` path of `pid` from procfs.
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

/// Pod-metadata cache entry lifetime (pod identity does not change).
const POD_TTL: Duration = Duration::from_secs(600);

/// Kubernetes API client (in-cluster service account). Created at startup
/// when the `k8s` feature is enabled and credentials exist; every failure is
/// non-fatal — enrichment simply degrades to cgroup-derived fields.
#[cfg(feature = "k8s")]
pub mod k8s {
    use super::PodMeta;
    use std::{fs, time::Duration};

    pub struct K8sClient {
        token: String,
        ca: reqwest::Certificate,
        base: String,
    }

    impl K8sClient {
        /// Read the in-cluster service account (token + CA) and API host.
        pub fn from_cluster() -> Option<Self> {
            let token = fs::read_to_string("/var/run/secrets/kubernetes.io/serviceaccount/token")
                .ok()?
                .trim()
                .to_string();
            let ca_pem =
                fs::read("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt").ok()?;
            let ca = reqwest::Certificate::from_pem(&ca_pem).ok()?;
            let host = std::env::var("KUBERNETES_SERVICE_HOST").ok()?;
            let port =
                std::env::var("KUBERNETES_SERVICE_PORT").unwrap_or_else(|_| "443".into());
            Some(Self {
                token,
                ca,
                base: format!("https://{host}:{port}"),
            })
        }

        /// Resolve pod name/namespace by UID via a field-selected list.
        /// Returns `None` on any error (auth, RBAC, connectivity).
        pub fn lookup_pod(&self, uid: &str) -> Option<PodMeta> {
            let client = reqwest::blocking::Client::builder()
                .add_root_certificate(self.ca.clone())
                .timeout(Duration::from_secs(2))
                .build()
                .ok()?;
            let url = format!(
                "{}/api/v1/pods?fieldSelector={}",
                self.base,
                // metadata.uid is a supported field selector for pods.
                urlencoding_lite(uid)
            );
            let resp = client
                .get(&url)
                .bearer_auth(&self.token)
                .send()
                .ok()?;
            let json: serde_json::Value = resp.json().ok()?;
            let item = json.get("items")?.as_array()?.first()?;
            Some(PodMeta {
                uid: uid.to_string(),
                name: item.get("metadata")?.get("name")?.as_str()?.to_string(),
                namespace: item
                    .get("metadata")?
                    .get("namespace")?
                    .as_str()?
                    .to_string(),
            })
        }
    }

    /// Minimal percent-encoding for the fieldSelector value.
    fn urlencoding_lite(uid: &str) -> String {
        format!("metadata.uid%3D{}", uid.replace('%', "%25"))
    }
}

/// Per-tgid enrichment cache (procfs reads dominate otherwise).
pub struct Enricher {
    cache: HashMap<u32, (Instant, Enrichment)>,
    pod_cache: HashMap<String, (Instant, Option<PodMeta>)>,
    #[cfg(feature = "k8s")]
    k8s: Option<k8s::K8sClient>,
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
            pod_cache: HashMap::new(),
            #[cfg(feature = "k8s")]
            k8s: k8s::K8sClient::from_cluster(),
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

    fn compute(&mut self, tgid: u32) -> Enrichment {
        let cgroup = read_cgroup(tgid);
        let container_id = cgroup
            .as_deref()
            .and_then(container_id_from_cgroup);
        let pod_uid = cgroup.as_deref().and_then(pod_uid_from_cgroup);

        let (pod_name, pod_namespace) = match &pod_uid {
            Some(uid) => match self.lookup_pod(uid) {
                Some(meta) => (Some(meta.name), Some(meta.namespace)),
                None => (None, None),
            },
            None => (None, None),
        };

        Enrichment {
            container_id,
            cgroup,
            pod_uid,
            pod_name,
            pod_namespace,
        }
    }

    fn lookup_pod(&mut self, uid: &str) -> Option<PodMeta> {
        if let Some((at, cached)) = self.pod_cache.get(uid) {
            if at.elapsed() < POD_TTL {
                return cached.clone();
            }
        }
        #[cfg(feature = "k8s")]
        let meta = self.k8s.as_ref().and_then(|k| k.lookup_pod(uid));
        #[cfg(not(feature = "k8s"))]
        let meta: Option<PodMeta> = None;

        self.pod_cache
            .insert(uid.to_string(), (Instant::now(), meta.clone()));
        if self.pod_cache.len() > 1024 {
            self.pod_cache.clear();
        }
        meta
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

    #[test]
    fn extracts_pod_uid_from_slice() {
        let cg = "/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-poddeadbeef_dead_beef_dead_beefdeadbeef.slice/cri-containerd-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.scope";
        assert_eq!(
            pod_uid_from_cgroup(cg).as_deref(),
            Some("deadbeef-dead-beef-dead-beefdeadbeef")
        );
    }

    #[test]
    fn extracts_pod_uid_with_underscores() {
        // containerd writes `:`-containing uids as `_`-separated groups.
        let cg = "/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod12345678_1234_1234_1234_123456789abc.slice";
        assert_eq!(
            pod_uid_from_cgroup(cg).as_deref(),
            Some("12345678-1234-1234-1234-123456789abc")
        );
    }

    #[test]
    fn extracts_pod_uid_cgroupfs() {
        let cg = "/kubepods/burstable/podf00dbaad-f00d-baad-f00d-baadf00dbaad";
        assert_eq!(
            pod_uid_from_cgroup(cg).as_deref(),
            Some("f00dbaad-f00d-baad-f00d-baadf00dbaad")
        );
    }
}
