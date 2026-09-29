//! ML anomaly scoring (Phase 4).
//!
//! Rules produce high-confidence alerts; an [`AnomalyScorer`] adds a risk
//! score for the gaps. The planned scorer runs ONNX models exported by
//! `ml/export/` (Isolation Forest → autoencoder → n-gram sequence model)
//! through the `ort` crate.
//!
//! Phase 1 ships the trait and a deterministic baseline scorer so the
//! pipeline (features → score → sink) is wired end-to-end and testable.

use serde::Serialize;

use crate::features::FeatureVector;

/// Anomaly score for a feature vector. Convention: higher = more anomalous,
/// with `0.0` = perfectly normal and `1.0` = maximal anomaly.
pub trait AnomalyScorer: Send {
    fn score(&mut self, features: &FeatureVector) -> anyhow::Result<f32>;
    /// Model identifier for the alert metadata ("baseline", "iforest-v3", ...).
    fn model_id(&self) -> &str;
}

/// Deterministic, dependency-free baseline scorer.
///
/// Heuristics (each contributes to the score, clamped to [0, 1]):
/// * exec rate per window,
/// * number of distinct destination IPs/ports,
/// * file-path entropy,
/// * privileged + network combo is handled by rules, not here.
///
/// Replaced by ONNX models in Phase 4; kept as a fallback when no model file
/// is present ("graceful degradation under load" — Phase 5).
pub struct BaselineScorer {
    pub max_exec_per_window: f64,
}

impl Default for BaselineScorer {
    fn default() -> Self {
        Self {
            max_exec_per_window: 50.0,
        }
    }
}

impl AnomalyScorer for BaselineScorer {
    fn score(&mut self, features: &FeatureVector) -> anyhow::Result<f32> {
        let exec_score = (features.exec_count as f64 / self.max_exec_per_window).min(1.0);
        let net_score = ((features.distinct_dst_ips as f64) / 16.0).min(1.0);
        let port_score = ((features.distinct_dst_ports as f64) / 16.0).min(1.0);
        // Path entropy for typical workloads sits around 3-4 bits/byte.
        let entropy_score = (features.file_path_entropy / 5.0).min(1.0);
        let score = 0.35 * exec_score + 0.25 * net_score + 0.15 * port_score + 0.25 * entropy_score;
        Ok(score as f32)
    }

    fn model_id(&self) -> &str {
        "baseline-v1"
    }
}

/// Risk record attached to a flushed feature window.
#[derive(Debug, Clone, Serialize)]
pub struct RiskScore {
    pub model_id: String,
    pub score: f32,
    pub key: String,
    pub window_secs: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn features(exec_count: u64, ips: u64, entropy: f64) -> FeatureVector {
        FeatureVector {
            key: "tgid:1".into(),
            window_secs: 60,
            exec_count,
            open_count: 0,
            net_connect_count: 0,
            sys_event_count: 0,
            distinct_dst_ips: ips,
            distinct_dst_ports: 0,
            distinct_file_paths: 0,
            file_path_entropy: entropy,
            distinct_comms: 1,
        }
    }

    #[test]
    fn baseline_scores_are_bounded() {
        let mut scorer = BaselineScorer::default();
        let quiet = scorer.score(&features(0, 0, 0.0)).unwrap();
        assert_eq!(quiet, 0.0);

        let loud = scorer.score(&features(1000, 1000, 10.0)).unwrap();
        assert!(loud <= 1.0);
        assert!(loud > 0.5);
    }
}
