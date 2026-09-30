//! ML anomaly scoring (Phase 4).
//!
//! Rules produce high-confidence alerts; an [`AnomalyScorer`] adds a risk
//! score for the gaps. ONNX models exported by `ml/export/` and
//! `ml/train/train_ngram_lstm.py` run in-agent through the `ort` crate:
//!
//! * feature-vector models (Isolation Forest, autoencoder) → [`OnnxScorer`]
//! * syscall n-gram sequence model (LSTM) → [`SequenceScorer`]
//!
//! The deterministic [`BaselineScorer`] stays as the fallback when no model
//! file is present ("graceful degradation under load" — Phase 5).

use serde::Serialize;

use crate::features::FeatureVector;

/// Anomaly score for a feature vector. Convention: higher = more anomalous,
/// with `0.0` = perfectly normal and `1.0` = maximal anomaly.
pub trait AnomalyScorer: Send {
    fn score(&mut self, features: &FeatureVector) -> anyhow::Result<f32>;
    /// Model identifier for the alert metadata ("baseline", "iforest-v3", ...).
    fn model_id(&self) -> &str;
}

/// Column order of [`FeatureVector::to_array`]. Must stay in lock-step with
/// `FEATURE_COLUMNS` in `ml/datasets/collect.py`.
pub const FEATURE_COLUMNS: &[&str] = &[
    "exec_count",
    "open_count",
    "net_connect_count",
    "sys_event_count",
    "distinct_dst_ips",
    "distinct_dst_ports",
    "distinct_file_paths",
    "file_path_entropy",
    "distinct_comms",
    "dns_count",
    "distinct_dns_queries",
];

impl FeatureVector {
    /// Dense column-ordered array for model input.
    pub fn to_array(&self) -> Vec<f32> {
        vec![
            self.exec_count as f32,
            self.open_count as f32,
            self.net_connect_count as f32,
            self.sys_event_count as f32,
            self.distinct_dst_ips as f32,
            self.distinct_dst_ports as f32,
            self.distinct_file_paths as f32,
            self.file_path_entropy as f32,
            self.distinct_comms as f32,
            self.dns_count as f32,
            self.distinct_dns_queries as f32,
        ]
    }
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

/// ONNX feature-vector scorer (Isolation Forest / autoencoder exports).
///
/// Contract: the model maps a `[1, N_FEATURES]` f32 tensor to a single
/// anomaly score (higher = worse) — `ml/export/export_onnx.py` wraps both
/// model families into exactly this shape.
#[cfg(feature = "onnx")]
pub struct OnnxScorer {
    session: ort::session::Session,
    id: String,
}

#[cfg(feature = "onnx")]
impl OnnxScorer {
    pub fn load(path: &std::path::Path) -> anyhow::Result<Self> {
        let env = ort::init().map_err(|e| anyhow::anyhow!("ort init: {e}"))?;
        let session = ort::session::Session::builder(&env)
            .map_err(|e| anyhow::anyhow!("ort session builder: {e}"))?
            .commit_from_file(path)
            .map_err(|e| anyhow::anyhow!("loading {}: {e}", path.display()))?;
        let id = format!(
            "onnx:{}",
            path.file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| "model".into())
        );
        Ok(Self { session, id })
    }
}

#[cfg(feature = "onnx")]
impl AnomalyScorer for OnnxScorer {
    fn score(&mut self, features: &FeatureVector) -> anyhow::Result<f32> {
        let cols = features.to_array();
        let input = ort::value::Tensor::<f32>::from_array(([1usize, cols.len()], cols))
            .map_err(|e| anyhow::anyhow!("tensor: {e}"))?;
        let outputs = self
            .session
            .run(ort::inputs![input])
            .map_err(|e| anyhow::anyhow!("inference: {e}"))?;
        let (_shape, data) = outputs[0]
            .try_extract_tensor::<f32>()
            .map_err(|e| anyhow::anyhow!("extract: {e}"))?;
        Ok(data.first().copied().unwrap_or(0.0))
    }

    fn model_id(&self) -> &str {
        &self.id
    }
}

/// N-gram (LSTM) sequence scorer: keeps a short token history per key and
/// scores the window against a next-token model (mean NLL over the sequence,
/// squashed to [0, 1]).
///
/// Tokens are `evt.type` ids from a vocabulary JSON (`{"<token>": id, ...}`)
/// exported next to the model by `ml/train/train_ngram_lstm.py`.
#[cfg(feature = "onnx")]
pub struct SequenceScorer {
    session: ort::session::Session,
    vocab: std::collections::HashMap<String, i64>,
    unk: i64,
    /// Max sequence length fed to the model (dynamic axis, capped here).
    max_len: usize,
    history: std::collections::HashMap<String, std::collections::VecDeque<i64>>,
    id: String,
}

#[cfg(feature = "onnx")]
impl SequenceScorer {
    pub fn load(
        model: &std::path::Path,
        vocab: &std::path::Path,
        max_len: usize,
    ) -> anyhow::Result<Self> {
        let env = ort::init().map_err(|e| anyhow::anyhow!("ort init: {e}"))?;
        let session = ort::session::Session::builder(&env)
            .map_err(|e| anyhow::anyhow!("ort session builder: {e}"))?
            .commit_from_file(model)
            .map_err(|e| anyhow::anyhow!("loading {}: {e}", model.display()))?;
        let raw = std::fs::read_to_string(vocab)?;
        let vocab: std::collections::HashMap<String, i64> = serde_json::from_str(&raw)?;
        Ok(Self {
            session,
            vocab,
            unk: 0,
            max_len: max_len.clamp(8, 256),
            history: std::collections::HashMap::new(),
            id: format!(
                "ngram-lstm:{}",
                model
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_else(|| "model".into())
            ),
        })
    }

    /// Feed one event token for `key`; returns a score once `min_len` tokens
    /// of history exist (mean NLL, squashed through `1 - exp(-x)`).
    pub fn observe(&mut self, key: &str, token: &str, min_len: usize) -> Option<f32> {
        let id = *self.vocab.get(token).unwrap_or(&self.unk);
        let hist = self.history.entry(key.to_string()).or_default();
        hist.push_back(id);
        while hist.len() > self.max_len {
            hist.pop_front();
        }
        if hist.len() < min_len {
            return None;
        }
        let seq: Vec<i64> = hist.iter().copied().collect();
        self.score_seq(&seq).ok()
    }

    fn score_seq(&mut self, seq: &[i64]) -> anyhow::Result<f32> {
        let input = ort::value::Tensor::<i64>::from_array(([1usize, seq.len()], seq.to_vec()))
            .map_err(|e| anyhow::anyhow!("tensor: {e}"))?;
        let outputs = self
            .session
            .run(ort::inputs![input])
            .map_err(|e| anyhow::anyhow!("inference: {e}"))?;
        let (_shape, data) = outputs[0]
            .try_extract_tensor::<f32>()
            .map_err(|e| anyhow::anyhow!("extract: {e}"))?;
        let nll = data.first().copied().unwrap_or(0.0);
        Ok((1.0 - (-nll.max(0.0)).exp()).clamp(0.0, 1.0))
    }

    pub fn model_id(&self) -> &str {
        &self.id
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
            dns_count: 0,
            distinct_dns_queries: 0,
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
