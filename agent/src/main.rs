//! Sentinel agent entry point.
//!
//! Wires: loader → ingest pipeline (decode → enrich → features → rules →
//! sinks) with graceful shutdown on Ctrl-C and a final loss summary.

use std::{
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64},
    },
    time::Duration,
};

use anyhow::{Context as _, Result};
use clap::Parser;
use log::{info, warn};
use sentinel::{
    enrich::Enricher,
    features::FeatureExtractor,
    ingest::{self, Pipeline},
    loader,
    metrics,
    ml::{AnomalyScorer, BaselineScorer},
    rules::RuleEngine,
    sink::{Metrics, StdoutJsonSink},
    tamper::{self, Watchdog},
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

    /// ONNX model for per-window anomaly scoring (Isolation Forest /
    /// autoencoder export from `ml/`). Without it the baseline scorer runs.
    #[clap(long)]
    model: Option<PathBuf>,

    /// Risk score at/above which a window is emitted as a `risk` alert.
    #[clap(long, default_value_t = 0.6)]
    risk_threshold: f32,

    /// Prometheus metrics listen address (Phase 5).
    #[clap(long, default_value = "0.0.0.0:9095")]
    metrics_addr: String,

    /// Disable the Prometheus metrics endpoint.
    #[clap(long)]
    no_metrics: bool,

    /// In-kernel capture filter: minimum uid (inclusive).
    #[clap(long, default_value_t = 0)]
    min_uid: u32,

    /// In-kernel capture filter: maximum uid (inclusive).
    #[clap(long, default_value_t = u32::MAX)]
    max_uid: u32,
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
    loader::set_filter(&mut ebpf, opt.min_uid, opt.max_uid).context("writing CONFIG filter")?;

    let ring = loader::take_events_ring(&mut ebpf)?;
    let dropped = loader::take_dropped_counter(&mut ebpf)?;
    let byte_stats = match loader::take_byte_stats(&mut ebpf) {
        Ok(m) => Some(m),
        Err(err) => {
            warn!("BYTE_STATS map unavailable (byte telemetry off): {err:#}");
            None
        }
    };

    let metrics = Arc::new(Metrics::default());

    // Phase 5: Prometheus endpoint (unless disabled).
    let _metrics_server = if opt.no_metrics {
        None
    } else {
        match metrics::start(&opt.metrics_addr, metrics.clone()) {
            Ok(server) => {
                info!("metrics endpoint on http://{}/metrics", server.addr);
                Some(server)
            }
            Err(err) => {
                warn!("metrics endpoint failed to start: {err:#}");
                None
            }
        }
    };

    // Phase 4: scorer selection — ONNX model if provided, baseline otherwise.
    let scorer: Box<dyn AnomalyScorer> = match &opt.model {
        Some(path) => {
            #[cfg(feature = "onnx")]
            {
                let s = sentinel::ml::OnnxScorer::load(path)
                    .context("loading ONNX model")?;
                info!("ONNX scorer: {}", s.model_id());
                Box::new(s)
            }
            #[cfg(not(feature = "onnx"))]
            {
                let _ = path;
                anyhow::bail!("--model requires the `onnx` feature");
            }
        }
        None => {
            info!("no --model given; using the baseline scorer");
            Box::new(BaselineScorer::default())
        }
    };

    // Phase 5: tamper watchdog + heartbeat.
    let last_execve_ns = Arc::new(AtomicU64::new(0));
    let stop_heartbeat = Arc::new(AtomicBool::new(false));
    let _heartbeat = tamper::spawn_heartbeat(stop_heartbeat.clone());
    let silence_check = opt.min_uid == 0; // heartbeat execs run as root
    let watchdog = Watchdog::new(
        loader::probe_identities(&ebpf),
        last_execve_ns.clone(),
        silence_check,
    );

    let pipeline = Pipeline {
        engine,
        sinks: vec![Box::new(StdoutJsonSink {
            emit_events: opt.emit_events,
        })],
        features: FeatureExtractor::new(opt.window_secs),
        scorer,
        enricher: Enricher::new(),
        metrics: metrics.clone(),
        risk_threshold: opt.risk_threshold,
        last_execve_ns,
    };

    info!(
        "sentinel is live: {} probes attached, ring buffer {} MiB, window {}s, risk threshold {:.2}",
        loader::PROBES.len(),
        opt.ring_buf_mib,
        opt.window_secs,
        opt.risk_threshold
    );

    let window = Duration::from_secs(opt.window_secs);
    tokio::select! {
        res = ingest::run(ring, pipeline, dropped, window, Some(watchdog), byte_stats) => {
            res.context("ingest loop")?;
        }
        _ = tokio::signal::ctrl_c() => {
            info!("Ctrl-C received, shutting down");
        }
    }
    stop_heartbeat.store(true, std::sync::atomic::Ordering::Relaxed);

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
