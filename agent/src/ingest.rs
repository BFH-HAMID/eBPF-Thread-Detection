//! Ring-buffer ingestion: async read → decode → enrich → features → rules →
//! sinks, with batching per wakeup and loss accounting.
//!
//! The ring buffer is consumed through `tokio::io::unix::AsyncFd`; each wakeup
//! drains every available record into a batch (capped to bound latency) before
//! running the pipeline, so userspace keeps up under bursty load.

use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use anyhow::{Context as _, Result};
use aya::maps::{MapData, ring_buf::RingBuf};
use log::{debug, info, warn};
use tokio::io::{Interest, unix::AsyncFd};

use crate::{
    enrich::{Enricher, Enrichment},
    event::{Event, EventContext, decode},
    features::FeatureExtractor,
    ml::{AnomalyScorer, RiskScore},
    rules::{RuleEngine, render_output},
    sink::{Alert, Metrics, Sink},
    tamper::{TamperFinding, Watchdog},
};

/// Max records drained per wakeup before yielding back to the runtime.
const MAX_BATCH: usize = 256;

/// Everything one event flows through.
pub struct Pipeline {
    pub engine: RuleEngine,
    pub sinks: Vec<Box<dyn Sink>>,
    pub features: FeatureExtractor,
    pub scorer: Box<dyn AnomalyScorer>,
    pub enricher: Enricher,
    pub metrics: Arc<Metrics>,
    /// Score at/above which a window becomes a `risk` alert on the sinks.
    pub risk_threshold: f32,
    /// Last-seen execve timestamp (monotonic ns) for the tamper heartbeat.
    pub last_execve_ns: Arc<AtomicU64>,
}

impl Pipeline {
    /// Decode one raw record and push it through the pipeline.
    pub fn handle_raw(&mut self, bytes: &[u8], dropped: &aya::maps::Array<MapData, u64>) {
        self.metrics
            .events
            .fetch_add(1, Ordering::Relaxed);

        let Some(event) = decode(bytes) else {
            self.metrics
                .decode_errors
                .fetch_add(1, Ordering::Relaxed);
            warn!("failed to decode {}-byte record", bytes.len());
            return;
        };
        self.handle(event, dropped);
    }

    /// Run a decoded event through enrichment, features, rules and sinks.
    pub fn handle(&mut self, event: Event, dropped: &aya::maps::Array<MapData, u64>) {
        if matches!(event, Event::Execve { .. }) {
            // Wall-clock ns — the same clock the tamper watchdog compares on.
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0);
            self.last_execve_ns.store(now, Ordering::Relaxed);
        }

        let enrichment: Enrichment = self.enricher.enrich(event.header().tgid);
        let container_id = enrichment.container_id.clone();

        // Rule evaluation.
        let ctx = EventContext {
            event: event.clone(),
            enrichment,
        };
        for compiled in self.engine.evaluate(&ctx) {
            let output = render_output(&compiled.rule.output, &ctx);
            let alert = Alert::from_match(
                &compiled.rule,
                output,
                event.clone(),
                container_id.clone(),
            );
            self.metrics.alerts.fetch_add(1, Ordering::Relaxed);
            for sink in &mut self.sinks {
                sink.emit_alert(&alert);
            }
        }

        // Feature extraction, keyed per process; container-level keying comes
        // with Phase 4 baselines.
        let key = format!("tgid:{}", event.header().tgid);
        self.features.observe(&key, &event);

        for sink in &mut self.sinks {
            sink.emit_event(&event);
        }

        // Keep the kernel-side drop counter visible in the metrics snapshot.
        if let Ok(dropped) = dropped.get(&0, 0) {
            self.metrics
                .dropped_reported
                .store(dropped, Ordering::Relaxed);
        }
    }

    /// Emit a tamper finding through the sinks and count it.
    pub fn handle_tamper(&mut self, finding: &TamperFinding) {
        warn!("TAMPER [{}]: {}", finding.kind, finding.detail);
        self.metrics.tamper_alerts.fetch_add(1, Ordering::Relaxed);
        for sink in &mut self.sinks {
            sink.emit_tamper(finding);
        }
    }

    /// Flush feature windows into risk scores (called on the window timer).
    /// Scores at/above [`Pipeline::risk_threshold`] are emitted as `risk`
    /// lines through the sinks and counted in the metrics.
    pub fn flush_windows(&mut self) -> Vec<RiskScore> {
        let scores: Vec<RiskScore> = self
            .features
            .flush()
            .into_iter()
            .filter_map(|fv| {
                match self.scorer.score(&fv) {
                    Ok(score) => Some(RiskScore {
                        model_id: self.scorer.model_id().to_string(),
                        score,
                        key: fv.key.clone(),
                        window_secs: fv.window_secs,
                    }),
                    Err(err) => {
                        warn!("scoring failed for {}: {err:#}", fv.key);
                        None
                    }
                }
            })
            .collect();
        for risk in &scores {
            if risk.score >= self.risk_threshold {
                self.metrics.risk_alerts.fetch_add(1, Ordering::Relaxed);
                for sink in &mut self.sinks {
                    sink.emit_risk(risk);
                }
            }
        }
        scores
    }
}

/// Drain the ring buffer into `pipeline` until shutdown.
/// Drain the ring buffer into `pipeline` until shutdown.
///
/// `watchdog` (Phase 5 tamper checks) and `byte_stats` (per-cgroup counters
/// from the `cgroup_skb` programs) are serviced on the same timer ticks.
pub async fn run(
    ring: RingBuf<MapData>,
    mut pipeline: Pipeline,
    dropped: aya::maps::Array<MapData, u64>,
    window: Duration,
    mut watchdog: Option<Watchdog>,
    byte_stats: Option<aya::maps::HashMap<MapData, u64, sentinel_common::ByteStats>>,
) -> Result<()> {
    let mut ring = AsyncFd::with_interest(ring, Interest::READABLE)
        .context("registering ring buffer with tokio")?;
    let mut window_timer = tokio::time::interval(window);
    window_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut tamper_timer = tokio::time::interval(Duration::from_secs(15));
    tamper_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    info!("ingest loop started");
    loop {
        tokio::select! {
            ready = ring.readable_mut() => {
                let mut guard = ready.context("ring buffer readable")?;
                {
                    let rb = guard.get_inner_mut();
                    let mut batch: Vec<Vec<u8>> = Vec::new();
                    while batch.len() < MAX_BATCH {
                        let Some(item) = rb.next() else { break };
                        batch.push(item.to_vec());
                    }
                    let n = batch.len();
                    for bytes in &batch {
                        pipeline.handle_raw(bytes, &dropped);
                    }
                    if n == MAX_BATCH {
                        debug!("batch limit reached ({n} records); yielding");
                    }
                }
                guard.clear_ready();
            }
            _ = window_timer.tick() => {
                // Aggregate per-cgroup byte counters into the metrics totals.
                if let Some(stats) = &byte_stats {
                    let (mut ingress, mut egress) = (0u64, 0u64);
                    for (_k, v) in stats.iter().flatten() {
                        ingress = ingress.saturating_add(v.ingress);
                        egress = egress.saturating_add(v.egress);
                    }
                    pipeline
                        .metrics
                        .bytes_ingress
                        .store(ingress, Ordering::Relaxed);
                    pipeline.metrics.bytes_egress.store(egress, Ordering::Relaxed);
                }
                for risk in pipeline.flush_windows() {
                    debug!(
                        "window {}: risk={:.3} model={}",
                        risk.key, risk.score, risk.model_id
                    );
                }
            }
            _ = tamper_timer.tick() => {
                if let Some(wd) = watchdog.as_mut() {
                    let dropped_now = dropped.get(&0, 0).unwrap_or(0);
                    let now_ns = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_nanos() as u64)
                        .unwrap_or(0);
                    for finding in wd.check(dropped_now, now_ns) {
                        pipeline.handle_tamper(&finding);
                    }
                }
            }
        }
    }
}
