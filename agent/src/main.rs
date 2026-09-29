//! Sentinel agent entry point.
//!
//! Wires: loader → ingest pipeline (decode → enrich → features → rules →
//! sinks) with graceful shutdown on Ctrl-C and a final loss summary.

use std::{path::PathBuf, sync::Arc, time::Duration};

use anyhow::{Context as _, Result};
use clap::Parser;
use log::{info, warn};
use sentinel::{
    enrich::Enricher,
    features::FeatureExtractor,
    ingest::{self, Pipeline},
    loader,
    ml::BaselineScorer,
    rules::RuleEngine,
    sink::{Metrics, StdoutJsonSink},
};

#[derive(Debug, Parser)]
#[command(
    name = "sentinel",
    about = "Runtime threat detection on eBPF (Aya): syscall tracing, rules and ML risk scores"
)]
struct Opt {
    /// Directory containing YAML rule files
    #[clap(short, long, default_value = "rules")]
    rules: PathBuf,

    /// Also emit every raw event as JSON lines (default: alerts only)
    #[clap(long)]
    emit_events: bool,

    /// EVENTS ring buffer size in MiB (rounded up to a power-of-two multiple
    /// of the page size by the kernel)
    #[clap(long, default_value_t = 16)]
    ring_buf_mib: u32,

    /// Feature window length in seconds
    #[clap(long, default_value_t = 60)]
    window_secs: u64,

    /// Validate rules and exit without loading eBPF (CI / lint friendly)
    #[clap(long)]
    dry_run: bool,
}

fn bump_memlock() {
    // Needed for kernels without memcg-based BPF accounting (see
    // https://lwn.net/Articles/837122/).
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        warn!("failed to lift RLIMIT_MEMLOCK (continuing): errno unsafe to query here");
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    let opt = Opt::parse();

    let engine = RuleEngine::from_dir(&opt.rules)
        .with_context(|| format!("loading rules from {}", opt.rules.display()))?;
    info!("loaded {} rules", engine.rules.len());

    if opt.dry_run {
        println!(
            "{{\"kind\":\"dry_run\",\"data\":{{\"rules\":{}}}}}",
            engine.rules.len()
        );
        return Ok(());
    }

    bump_memlock();

    // Load the eBPF object (embedded at build time by `agent/build.rs`), with
    // the ring buffer sized from the CLI.
    let ring_bytes = (opt.ring_buf_mib.max(1)) * 1024 * 1024;
    let mut loader = aya::EbpfLoader::new();
    loader.map_max_entries("EVENTS", ring_bytes);
    let mut ebpf = loader
        .load(aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/sentinel")))
        .context("loading eBPF object")?;

    // eBPF-side log stream (debug! from probes).
    match aya_log::EbpfLogger::init(&mut ebpf) {
        Err(e) => warn!("failed to initialize eBPF logger: {e}"),
        Ok(logger) => {
            let mut logger =
                tokio::io::unix::AsyncFd::with_interest(logger, tokio::io::Interest::READABLE)?;
            tokio::task::spawn(async move {
                loop {
                    let mut guard = logger.readable_mut().await.unwrap();
                    guard.get_inner_mut().flush();
                    guard.clear_ready();
                }
            });
        }
    }

    loader::attach_all(&mut ebpf).context("attaching probes")?;

    let ring = loader::take_events_ring(&mut ebpf)?;
    let dropped = loader::take_dropped_counter(&mut ebpf)?;

    let metrics = Arc::new(Metrics::default());
    let pipeline = Pipeline {
        engine,
        sinks: vec![Box::new(StdoutJsonSink {
            emit_events: opt.emit_events,
        })],
        features: FeatureExtractor::new(opt.window_secs),
        scorer: Box::new(BaselineScorer::default()),
        enricher: Enricher::new(),
        metrics: metrics.clone(),
    };

    info!(
        "sentinel is live: {} probes attached, ring buffer {} MiB, window {}s",
        loader::PROBES.len(),
        opt.ring_buf_mib,
        opt.window_secs
    );

    let window = Duration::from_secs(opt.window_secs);
    tokio::select! {
        res = ingest::run(ring, pipeline, dropped, window) => {
            res.context("ingest loop")?;
        }
        _ = tokio::signal::ctrl_c() => {
            info!("Ctrl-C received, shutting down");
        }
    }

    // Final summary: the numbers reviewers care about.
    let snap = metrics.snapshot();
    let verdict = if snap.dropped_reported > 0 {
        format!("{} events dropped in-kernel", snap.dropped_reported)
    } else {
        "no event loss observed".to_string()
    };
    info!(
        "summary: events={} alerts={} decode_errors={} dropped={} ({})",
        snap.events, snap.alerts, snap.decode_errors, snap.dropped_reported, verdict
    );
    println!(
        "{{\"kind\":\"summary\",\"data\":{}}}",
        serde_json::to_string(&snap)?
    );
    Ok(())
}
