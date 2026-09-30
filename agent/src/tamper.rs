//! Tamper resistance (Phase 5): detect — not prevent — interference with the
//! detector itself. Root can always win against a userspace daemon; the point
//! is that tampering becomes *loud*.
//!
//! Three independent signals, checked on a timer by the ingest loop:
//!
//! 1. **Probe silence** — a heartbeat thread execs `/bin/true` on a fixed
//!    period. If the `execve` probe (or the ring path) dies, the last-seen
//!    execve timestamp goes stale and we raise `probe_silent`.
//! 2. **Map modification** — the kernel-side `DROPPED` counter is monotonic
//!    by construction. A *decrease* means the map was wiped or replaced:
//!    `dropped_decreased`.
//! 3. **Program identity** — each attached program's `prog_id` (from
//!    `/proc/self/fdinfo/<fd>`) is recorded at startup. A later mismatch
//!    means the fd was swapped for a foreign program: `prog_id_changed`.
//!
//! Known limit (documented in `docs/threat-model.md`): `aya` exposes no
//! kernel-wide program-id enumeration (`bpf_prog_get_next_id` is crate-
//! private), so silent *link* detachments are covered only by signal (1).

use std::{
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};

use serde::Serialize;

/// A tamper finding, emitted through the sinks as `{"kind":"tamper",...}`.
#[derive(Debug, Clone, Serialize)]
pub struct TamperFinding {
    /// `probe_silent` | `dropped_decreased` | `prog_id_changed`.
    pub kind: String,
    pub detail: String,
    pub timestamp_ns: u64,
}

/// One attached program's identity.
#[derive(Debug, Clone)]
pub struct ProbeRecord {
    pub name: String,
    pub fd: i32,
    pub prog_id: u32,
}

/// Parse `prog_id:` out of `/proc/<pid>/fdinfo/<fd>` (works for bpf prog,
/// map and link fds alike).
pub fn read_fdinfo_id(fd: i32) -> Option<u32> {
    read_fdinfo_id_in(&PathBuf::from("/proc/self/fdinfo"), fd)
}

fn read_fdinfo_id_in(dir: &std::path::Path, fd: i32) -> Option<u32> {
    let text = std::fs::read_to_string(dir.join(fd.to_string())).ok()?;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("prog_id:") {
            return rest.trim().parse().ok();
        }
    }
    None
}

/// Periodic watchdog state. `check` is cheap and runs inside the ingest loop.
pub struct Watchdog {
    pub probes: Vec<ProbeRecord>,
    last_dropped: u64,
    last_execve_ns: Arc<AtomicU64>,
    /// Skip the silence check when the uid filter excludes the heartbeat.
    silence_check: bool,
    warmed_up: bool,
}

/// Heartbeat period: the watchdog fires after 2× this without an execve.
pub const HEARTBEAT_PERIOD: Duration = Duration::from_secs(15);

impl Watchdog {
    pub fn new(
        probes: Vec<ProbeRecord>,
        last_execve_ns: Arc<AtomicU64>,
        silence_check: bool,
    ) -> Self {
        Self {
            probes,
            last_dropped: 0,
            last_execve_ns,
            silence_check,
            warmed_up: false,
        }
    }

    /// Run all checks; returns findings (empty = healthy).
    pub fn check(&mut self, dropped_now: u64, now_ns: u64) -> Vec<TamperFinding> {
        let mut out = Vec::new();

        // Warmup: give the pipeline one heartbeat period to see real execves.
        if !self.warmed_up {
            if self.last_execve_ns.load(Ordering::Relaxed) == 0 {
                return Vec::new;
            }
            self.warmed_up = true;
        }

        if self.silence_check {
            let last = self.last_execve_ns.load(Ordering::Relaxed);
            let limit = (2 * HEARTBEAT_PERIOD.as_nanos()) as u64;
            if last == 0 || now_ns.saturating_sub(last) > limit {
                out.push(TamperFinding {
                    kind: "probe_silent".into(),
                    detail: format!(
                        "no execve seen for >{}s although the heartbeat fires every {}s — \
                         probe detached or ring path broken",
                        limit / 1_000_000_000,
                        HEARTBEAT_PERIOD.as_secs()
                    ),
                    timestamp_ns: now_ns,
                });
            }
        }

        if dropped_now < self.last_dropped {
            out.push(TamperFinding {
                kind: "dropped_decreased".into(),
                detail: format!(
                    "DROPPED went from {} to {} — the map was wiped or replaced",
                    self.last_dropped, dropped_now
                ),
                timestamp_ns: now_ns,
            });
        }
        self.last_dropped = dropped_now;

        for probe in &self.probes {
            match read_fdinfo_id(probe.fd) {
                Some(id) if id == probe.prog_id => {}
                Some(id) => out.push(TamperFinding {
                    kind: "prog_id_changed".into(),
                    detail: format!(
                        "probe {} fd {} now refers to prog_id {} (was {}) — fd swapped",
                        probe.name, probe.fd, id, probe.prog_id
                    ),
                    timestamp_ns: now_ns,
                }),
                None => out.push(TamperFinding {
                    kind: "prog_id_changed".into(),
                    detail: format!(
                        "probe {} fd {} is gone from fdinfo — program closed or replaced",
                        probe.name, probe.fd
                    ),
                    timestamp_ns: now_ns,
                }),
            }
        }
        out
    }
}

/// Spawn the `/bin/true` heartbeat thread. `stop` ends it (best-effort; the
/// process exit kills it anyway).
pub fn spawn_heartbeat(stop: Arc<AtomicBool>) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        while !stop.load(Ordering::Relaxed) {
            let _ = std::process::Command::new("/bin/true").status();
            std::thread::sleep(HEARTBEAT_PERIOD);
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_prog_id_from_fdinfo() {
        let dir = std::env::temp_dir().join(format!("sentinel-fdinfo-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("7"), "pos:\t0\nflags:\t02000000\nprog_id:\t4242\n").unwrap();
        assert_eq!(read_fdinfo_id_in(&dir, 7), Some(4242));
        assert_eq!(read_fdinfo_id_in(&dir, 8), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn watchdog_detects_drop_decrease_and_silence() {
        let seen = Arc::new(AtomicU64::new(1));
        let mut wd = Watchdog::new(vec![], seen.clone(), true);
        // warmup passes only once an execve has been seen
        assert!(wd.check(5, 1_000_000_000).is_empty());
        // dropped decrease
        let f = wd.check(2, 2_000_000_000);
        assert!(f.iter().any(|x| x.kind == "dropped_decreased"));
        // silence: now far beyond last execve
        let far = 1_000_000_000 + (10 * HEARTBEAT_PERIOD.as_nanos()) as u64;
        let f = wd.check(2, far);
        assert!(f.iter().any(|x| x.kind == "probe_silent"));
    }
}
