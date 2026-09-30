//! Prometheus metrics endpoint (Phase 5).
//!
//! Zero-dependency `std::net::TcpListener` on a dedicated thread — one
//! request path (`GET /metrics`, `GET /healthz`), Prometheus text format.
//! Counters come from the shared [`Metrics`] snapshot; byte totals are added
//! by the ingest loop from the in-kernel per-cgroup `BYTE_STATS` map.

use std::{
    io::{BufRead, BufReader, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    sync::Arc,
    time::Duration,
};

use crate::sink::Metrics;

/// Handle for the serving thread (kept so callers can hold ownership).
pub struct MetricsServer {
    pub addr: SocketAddr,
}

/// Start serving `/metrics` on `addr` (e.g. `0.0.0.0:9095`).
pub fn start(addr: &str, metrics: Arc<Metrics>) -> anyhow::Result<MetricsServer> {
    let listener = TcpListener::bind(addr)?;
    let local = listener.local_addr()?;
    std::thread::Builder::new()
        .name("sentinel-metrics".into())
        .spawn(move || {
            for stream in listener.incoming() {
                match stream {
                    Ok(stream) => {
                        let metrics = metrics.clone();
                        std::thread::spawn(move || {
                            let _ = handle(stream, &metrics);
                        });
                    }
                    Err(_) => std::thread::sleep(Duration::from_millis(50)),
                }
            }
        })?;
    Ok(MetricsServer { addr: local })
}

fn handle(mut stream: TcpStream, metrics: &Metrics) -> std::io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    let mut line = String::new();
    {
        let mut reader = BufReader::new(&stream);
        reader.read_line(&mut line)?;
    }
    let path = line.split_whitespace().nth(1).unwrap_or("/");
    let (status, body, ctype) = match path {
        "/metrics" => ("200 OK", render(metrics), "text/plain; version=0.0.4"),
        "/healthz" => ("200 OK", "ok\n".to_string(), "text/plain"),
        _ => ("404 Not Found", "not found\n".to_string(), "text/plain"),
    };
    let resp = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(resp.as_bytes())?;
    stream.flush()
}

/// Prometheus text exposition of the metrics snapshot.
pub fn render(metrics: &Metrics) -> String {
    let s = metrics.snapshot();
    let mut out = String::with_capacity(1024);
    let counter = |out: &mut String, name: &str, help: &str, v: u64| {
        out.push_str(&format!("# HELP {name} {help}\n# TYPE {name} counter\n{name} {v}\n"));
    };
    counter(&mut out, "sentinel_events_total", "Events consumed from the ring buffer", s.events);
    counter(&mut out, "sentinel_alerts_total", "Rule-based alerts emitted", s.alerts);
    counter(&mut out, "sentinel_risk_alerts_total", "ML risk alerts emitted", s.risk_alerts);
    counter(&mut out, "sentinel_tamper_alerts_total", "Tamper findings emitted", s.tamper_alerts);
    counter(&mut out, "sentinel_decode_errors_total", "Records that failed to decode", s.decode_errors);
    counter(&mut out, "sentinel_dropped_total", "Events dropped in-kernel (ring buffer full)", s.dropped_reported);
    counter(&mut out, "sentinel_bytes_ingress_total", "Bytes seen at cgroup ingress", s.bytes_ingress);
    counter(&mut out, "sentinel_bytes_egress_total", "Bytes seen at cgroup egress", s.bytes_egress);
    out.push_str("# HELP sentinel_up Sentinel agent liveness.\n# TYPE sentinel_up gauge\nsentinel_up 1\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    #[test]
    fn renders_prometheus_text() {
        let m = Metrics::default();
        m.events.store(7, std::sync::atomic::Ordering::Relaxed);
        let text = render(&m);
        assert!(text.contains("sentinel_events_total 7"));
        assert!(text.contains("# TYPE sentinel_alerts_total counter"));
        assert!(text.contains("sentinel_up 1"));
    }

    #[test]
    fn serves_over_tcp() {
        let m = Arc::new(Metrics::default());
        let server = start("127.0.0.1:0", m).unwrap();
        let mut stream = TcpStream::connect(server.addr).unwrap();
        stream
            .write_all(b"GET /metrics HTTP/1.1\r\nHost: x\r\n\r\n")
            .unwrap();
        let mut body = String::new();
        stream.read_to_string(&mut body).unwrap();
        assert!(body.contains("sentinel_events_total"));
    }
}
