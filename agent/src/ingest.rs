//! Ring-buffer ingestion: async read → decode → enrich → features → rules →
//! sinks, with batching per wakeup and loss accounting.
//!
//! The ring buffer is consumed through `tokio::io::unix::AsyncFd`; each wakeup
//! drains every available record into a batch (capped to bound latency) before
//! running the pipeline, so userspace keeps up under bursty load.

use std::{sync::Arc, time::Duration};

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
}

impl Pipeline {
    /// Decode one raw record and push it through the pipeline.
    pub fn handle_raw(&mut self, bytes: &[u8], dropped: &aya::maps::Array<MapData, u64>) {
        self.metrics
            .events
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let Some(event) = decode(bytes) else {
            self.metrics
                .decode_errors
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            warn!("failed to decode {}-byte record", bytes.len());
            return;
        };
        self.handle(event, dropped);
    }

    /// Run a decoded event through enrichment, features, rules and sinks.
    pub fn handle(&mut self, event: Event, dropped: &aya::maps::Array<MapData, u64>) {
        let Enrichment { container_id, .. } = self.enricher.enrich(event.header().tgid);

        // Rule evaluation.
        let ctx = EventContext {
            event: event.clone(),
            container_id: container_id.clone(),
        };
        for compiled in self.engine.evaluate(&ctx) {
            let output = render_output(&compiled.rule.output, &ctx);
            let alert = Alert::from_match(
                &compiled.rule,
                output,
                event.clone(),
                container_id.clone(),
            );
            self.metrics
                .alerts
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
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
                .store(dropped, std::sync::atomic::Ordering::Relaxed);
        }
    }

    /// Flush feature windows into risk scores (called on the window timer).
    pub fn flush_windows(&mut self) -> Vec<RiskScore> {
        self.features
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
            .collect()
    }
}

/// Drain the ring buffer into `pipeline` until shutdown.
pub async fn run(
    ring: RingBuf<MapData>,
    mut pipeline: Pipeline,
    dropped: aya::maps::Array<MapData, u64>>,
    window: Duration,
) -> Result<()> {
    let mut ring = AsyncFd::with_interest(ring, Interest::READABLE)
        .context("registering ring buffer with tokio")?;
    let mut window_timer = tokio::time::interval(window);
    window_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

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
                for risk in pipeline.flush_windows() {
                    debug!(
                        "window {}: risk={:.3} model={}",
                        risk.key, risk.score, risk.model_id
                    );
                }
            }
        }
    }
}
