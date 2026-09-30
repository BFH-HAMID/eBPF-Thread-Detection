//! Output sinks: stdout/JSON today; webhook and OTLP are roadmap items
//! (`docs/roadmap.md`). Alerts, risk scores, tamper findings and (optionally)
//! raw events go through [`Sink`]. Prometheus scrapes [`Metrics`] directly
//! (`crate::metrics`).

use std::{io::Write, sync::atomic::{AtomicU64, Ordering}};

use serde::Serialize;

use crate::{event::Event, ml::RiskScore, rules::Rule, tamper::TamperFinding};

/// Counters shared across the ingest pipeline, the metrics endpoint and the
/// periodic summary.
#[derive(Debug, Default)]
pub struct Metrics {
    pub events: AtomicU64,
    pub alerts: AtomicU64,
    pub risk_alerts: AtomicU64,
    pub tamper_alerts: AtomicU64,
    pub decode_errors: AtomicU64,
    pub dropped_reported: AtomicU64,
    pub bytes_ingress: AtomicU64,
    pub bytes_egress: AtomicU64,
}

impl Metrics {
    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            events: self.events.load(Ordering::Relaxed),
            alerts: self.alerts.load(Ordering::Relaxed),
            risk_alerts: self.risk_alerts.load(Ordering::Relaxed),
            tamper_alerts: self.tamper_alerts.load(Ordering::Relaxed),
            decode_errors: self.decode_errors.load(Ordering::Relaxed),
            dropped_reported: self.dropped_reported.load(Ordering::Relaxed),
            bytes_ingress: self.bytes_ingress.load(Ordering::Relaxed),
            bytes_egress: self.bytes_egress.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize)]
pub struct MetricsSnapshot {
    pub events: u64,
    pub alerts: u64,
    pub risk_alerts: u64,
    pub tamper_alerts: u64,
    pub decode_errors: u64,
    pub dropped_reported: u64,
    pub bytes_ingress: u64,
    pub bytes_egress: u64,
}

/// A rule match, ready for output.
#[derive(Debug, Clone, Serialize)]
pub struct Alert {
    /// Bump when the alert schema changes; consumers should key on it.
    pub schema_version: u32,
    pub rule_id: String,
    pub rule_name: String,
    pub description: String,
    pub priority: String,
    pub tags: Vec<String>,
    pub output: String,
    pub event: Event,
    pub container_id: Option<String>,
}

impl Alert {
    pub fn from_match(rule: &Rule, output: String, event: Event, container_id: Option<String>) -> Self {
        Self {
            schema_version: 1,
            rule_id: rule.id.clone(),
            rule_name: rule.name.clone(),
            description: rule.description.clone(),
            priority: rule.priority.as_str().to_string(),
            tags: rule.tags.clone(),
            output,
            event,
            container_id,
        }
    }
}

/// Destination for alerts and events.
pub trait Sink: Send {
    fn emit_alert(&mut self, alert: &Alert);
    fn emit_event(&mut self, event: &Event);
    fn emit_risk(&mut self, risk: &RiskScore);
    fn emit_tamper(&mut self, finding: &TamperFinding);
}

/// JSON-lines to stdout (`{"schema_version":1,...}` per line).
///
/// `kind` is prepended as a small envelope so downstream consumers can
/// multiplex alerts and raw events on one stream.
pub struct StdoutJsonSink {
    pub emit_events: bool,
}

impl Sink for StdoutJsonSink {
    fn emit_alert(&mut self, alert: &Alert) {
        write_json_line("alert", alert);
    }

    fn emit_event(&mut self, event: &Event) {
        if self.emit_events {
            write_json_line("event", event);
        }
    }

    fn emit_risk(&mut self, risk: &RiskScore) {
        write_json_line("risk", risk);
    }

    fn emit_tamper(&mut self, finding: &TamperFinding) {
        write_json_line("tamper", finding);
    }
}

fn write_json_line(kind: &str, value: &impl Serialize) {
    // Serialize once, wrap in a one-key envelope without re-serializing the
    // payload (keeps allocation low and output stable).
    let Ok(payload) = serde_json::to_string(value) else {
        return;
    };
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    let _ = writeln!(out, "{{\"kind\":\"{kind}\",\"data\":{payload}}}");
    let _ = out.flush();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::Header;

    #[test]
    fn alert_is_serializable() {
        let alert = Alert::from_match(
            &Rule {
                id: "R1".into(),
                name: "test".into(),
                description: "d".into(),
                priority: crate::rules::Priority::Warning,
                condition: "evt.type = execve".into(),
                tags: vec!["t1".into()],
                output: "out".into(),
            },
            "rendered".into(),
            Event::Capset {
                header: Header {
                    event_type: 8,
                    evt_type: "capset".into(),
                    pid: 1,
                    tgid: 1,
                    uid: 0,
                    gid: 0,
                    ppid: 0,
                    timestamp_ns: 0,
                    comm: "x".into(),
                },
            },
            None,
        );
        let json = serde_json::to_string(&alert).unwrap();
        assert!(json.contains("\"rule_id\":\"R1\""));
        assert!(json.contains("\"schema_version\":1"));
    }
}
