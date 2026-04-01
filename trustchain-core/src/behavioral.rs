//! Behavioral change detection and selective scamming analysis (Layer 5.1-5.2).
//!
//! Provides the **derivative component** of the trust PID controller:
//! - **P (proportional):** current recency score — already exists.
//! - **I (integral):** MeritRank epoch decay over full history — already exists.
//! - **D (derivative):** rate-of-change detection — **this module**.
//!
//! Two detection mechanisms:
//! - **Behavioral change** (L5.1): rolling-window failure rate vs baseline, flags
//!   sudden worsening (or improving) behavior.
//! - **Selective targeting** (L5.2): compares failure rates toward new vs established
//!   peers, flags agents that exploit newcomers while maintaining good standing
//!   with established agents.
//!
//! All functions are stateless utilities operating on quality slices, not on
//! block stores. The caller partitions interactions and passes pre-extracted
//! quality values.
//!
//! Research: Olfati-Saber et al. 2007 (PID control, consensus stability),
//! Hoffman et al. 2009 (value imbalance attack), Olariu et al. 2024
//! (cross-segment farming), trust-model-gaps §5.

use serde::{Deserialize, Serialize};

// ─── Types ──────────────────────────────────────────────────────────────────

/// Configuration for behavioral change detection.
///
/// All fields are immutable after construction. Use `Default` for
/// research-validated parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehavioralConfig {
    /// Number of most recent interactions for the "recent" window. Default: 10.
    pub recent_window: usize,
    /// Number of interactions for the baseline window. Default: 30.
    pub baseline_window: usize,
    /// Threshold for anomalous change magnitude. Default: 0.3 (30% spike).
    pub anomaly_threshold: f64,
    /// Multiplier for selective scamming detection. Default: 2.0.
    /// If `failure_rate_to_new >= multiplier × failure_rate_to_established`, flag.
    pub selective_targeting_multiplier: f64,
    /// Minimum sample size per partition for selective targeting. Default: 3.
    pub selective_min_samples: usize,
}

impl Default for BehavioralConfig {
    fn default() -> Self {
        Self {
            recent_window: 10,
            baseline_window: 30,
            anomaly_threshold: 0.3,
            selective_targeting_multiplier: 2.0,
            selective_min_samples: 3,
        }
    }
}

/// Result of rolling-window behavioral change detection (Layer 5.1).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehavioralAnalysis {
    /// Failure rate in the recent window \[0.0, 1.0\].
    pub recent_failure_rate: f64,
    /// Failure rate in the baseline window \[0.0, 1.0\].
    pub baseline_failure_rate: f64,
    /// Change magnitude: `recent_failure_rate - baseline_failure_rate`.
    /// Positive = worsening behavior, negative = improving.
    pub change_magnitude: f64,
    /// True if `change_magnitude >= anomaly_threshold`.
    pub is_anomalous: bool,
}

/// Result of selective targeting / scamming detection (Layer 5.2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelectiveTargetingResult {
    /// Failure rate toward new/infrequent counterparties.
    pub failure_rate_to_new: f64,
    /// Failure rate toward established counterparties.
    pub failure_rate_to_established: f64,
    /// True if selective targeting detected.
    pub is_selective: bool,
}

// ─── Functions ──────────────────────────────────────────────────────────────

/// Compute failure rate: fraction of quality values below 0.5.
///
/// Returns 0.0 for empty slices.
pub fn failure_rate(qualities: &[f64]) -> f64 {
    if qualities.is_empty() {
        return 0.0;
    }
    let failures = qualities.iter().filter(|&&q| q < 0.5).count();
    failures as f64 / qualities.len() as f64
}

/// Detect behavioral change using rolling window vs baseline.
///
/// Splits the quality history (oldest first) into:
/// - **recent:** last `config.recent_window` entries.
/// - **baseline:** the `config.baseline_window` entries immediately before recent.
///
/// If there are fewer than `recent_window + 1` entries, there is insufficient
/// history and the result is not anomalous (magnitude 0.0).
///
/// # Research
///
/// PID derivative component (Olfati-Saber et al. 2007). Without rate-of-change
/// detection, an agent that suddenly turns malicious after 40 good interactions
/// won't trigger suspicion until recency decay catches up (~20 interactions).
pub fn detect_behavioral_change(
    qualities: &[f64],
    config: &BehavioralConfig,
) -> BehavioralAnalysis {
    let len = qualities.len();

    // Need at least recent_window + 1 entries to have any baseline.
    if len <= config.recent_window {
        let rate = failure_rate(qualities);
        return BehavioralAnalysis {
            recent_failure_rate: rate,
            baseline_failure_rate: rate,
            change_magnitude: 0.0,
            is_anomalous: false,
        };
    }

    let recent_start = len - config.recent_window;
    let recent = &qualities[recent_start..];

    let baseline_end = recent_start;
    let baseline_start = baseline_end.saturating_sub(config.baseline_window);
    let baseline = &qualities[baseline_start..baseline_end];

    let recent_rate = failure_rate(recent);
    let baseline_rate = failure_rate(baseline);
    let change = recent_rate - baseline_rate;

    BehavioralAnalysis {
        recent_failure_rate: recent_rate,
        baseline_failure_rate: baseline_rate,
        change_magnitude: change,
        is_anomalous: change >= config.anomaly_threshold,
    }
}

/// Detect selective targeting: different failure rates toward new vs established peers.
///
/// The caller provides pre-partitioned quality slices:
/// - `qualities_to_new`: quality of interactions with new/infrequent peers.
/// - `qualities_to_established`: quality of interactions with established peers.
///
/// Flags selective targeting when:
/// 1. Both partitions have at least `config.selective_min_samples` entries, AND
/// 2. `failure_rate_to_new >= config.selective_targeting_multiplier × max(failure_rate_to_established, 0.01)`, AND
/// 3. `failure_rate_to_new >= config.anomaly_threshold` (absolute floor).
///
/// The `max(rate, 0.01)` floor prevents flagging when both rates are near-zero.
///
/// # Research
///
/// Hoffman et al. 2009 (value imbalance attack), Olariu et al. 2024
/// (cross-segment farming), trust-model-gaps §5.
pub fn detect_selective_targeting(
    qualities_to_new: &[f64],
    qualities_to_established: &[f64],
    config: &BehavioralConfig,
) -> SelectiveTargetingResult {
    let rate_new = failure_rate(qualities_to_new);
    let rate_est = failure_rate(qualities_to_established);

    let is_selective = qualities_to_new.len() >= config.selective_min_samples
        && qualities_to_established.len() >= config.selective_min_samples
        && rate_new >= config.selective_targeting_multiplier * rate_est.max(0.01)
        && rate_new >= config.anomaly_threshold;

    SelectiveTargetingResult {
        failure_rate_to_new: rate_new,
        failure_rate_to_established: rate_est,
        is_selective,
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_defaults() {
        let c = BehavioralConfig::default();
        assert_eq!(c.recent_window, 10);
        assert_eq!(c.baseline_window, 30);
        assert!((c.anomaly_threshold - 0.3).abs() < 1e-12);
        assert!((c.selective_targeting_multiplier - 2.0).abs() < 1e-12);
        assert_eq!(c.selective_min_samples, 3);
    }

    // ── failure_rate ──

    #[test]
    fn test_failure_rate_empty() {
        assert!((failure_rate(&[]) - 0.0).abs() < 1e-12);
    }

    #[test]
    fn test_failure_rate_all_good() {
        assert!((failure_rate(&[1.0, 0.8, 0.6]) - 0.0).abs() < 1e-12);
    }

    #[test]
    fn test_failure_rate_all_bad() {
        assert!((failure_rate(&[0.1, 0.2, 0.3]) - 1.0).abs() < 1e-12);
    }

    #[test]
    fn test_failure_rate_mixed() {
        // 2 failures out of 4
        assert!((failure_rate(&[0.9, 0.1, 0.9, 0.1]) - 0.5).abs() < 1e-12);
    }

    #[test]
    fn test_failure_rate_boundary() {
        // 0.5 is NOT a failure (< 0.5 is failure)
        assert!((failure_rate(&[0.5]) - 0.0).abs() < 1e-12);
        assert!((failure_rate(&[0.49]) - 1.0).abs() < 1e-12);
    }

    // ── detect_behavioral_change ──

    #[test]
    fn test_behavioral_change_insufficient_history() {
        let c = BehavioralConfig::default(); // window=10
                                             // Only 10 entries — not enough for recent + baseline
        let qualities: Vec<f64> = vec![0.1; 10];
        let result = detect_behavioral_change(&qualities, &c);
        assert!(!result.is_anomalous);
        assert!((result.change_magnitude - 0.0).abs() < 1e-12);
    }

    #[test]
    fn test_behavioral_change_stable() {
        let c = BehavioralConfig::default();
        // 40 entries all good quality
        let qualities: Vec<f64> = vec![0.8; 40];
        let result = detect_behavioral_change(&qualities, &c);
        assert!((result.recent_failure_rate - 0.0).abs() < 1e-12);
        assert!((result.baseline_failure_rate - 0.0).abs() < 1e-12);
        assert!((result.change_magnitude - 0.0).abs() < 1e-12);
        assert!(!result.is_anomalous);
    }

    #[test]
    fn test_behavioral_change_worsening() {
        let c = BehavioralConfig::default();
        // 30 good (baseline) then 10 bad (recent)
        let mut qualities: Vec<f64> = vec![0.9; 30];
        qualities.extend(vec![0.1; 10]);
        let result = detect_behavioral_change(&qualities, &c);
        assert!((result.recent_failure_rate - 1.0).abs() < 1e-12);
        assert!((result.baseline_failure_rate - 0.0).abs() < 1e-12);
        assert!((result.change_magnitude - 1.0).abs() < 1e-12);
        assert!(result.is_anomalous);
    }

    #[test]
    fn test_behavioral_change_improving() {
        let c = BehavioralConfig::default();
        // 30 bad (baseline) then 10 good (recent)
        let mut qualities: Vec<f64> = vec![0.1; 30];
        qualities.extend(vec![0.9; 10]);
        let result = detect_behavioral_change(&qualities, &c);
        assert!((result.recent_failure_rate - 0.0).abs() < 1e-12);
        assert!((result.baseline_failure_rate - 1.0).abs() < 1e-12);
        // change = 0.0 - 1.0 = -1.0 (negative = improving)
        assert!((result.change_magnitude - (-1.0)).abs() < 1e-12);
        // is_anomalous checks change >= threshold (positive worsening only)
        assert!(!result.is_anomalous);
    }

    #[test]
    fn test_behavioral_change_below_threshold() {
        let c = BehavioralConfig::default(); // threshold=0.3
                                             // Baseline: 30 entries, 10% failure → 3 bad
        let mut qualities: Vec<f64> = vec![0.9; 27];
        qualities.extend(vec![0.1; 3]);
        // Recent: 10 entries, 20% failure → 2 bad
        qualities.extend(vec![0.9; 8]);
        qualities.extend(vec![0.1; 2]);
        let result = detect_behavioral_change(&qualities, &c);
        // change = 0.2 - 0.1 = 0.1, below 0.3 threshold
        assert!((result.change_magnitude - 0.1).abs() < 1e-12);
        assert!(!result.is_anomalous);
    }

    #[test]
    fn test_behavioral_change_exactly_at_threshold() {
        let c = BehavioralConfig::default(); // threshold=0.3
                                             // Baseline: 30 entries, 0 failures
        let mut qualities: Vec<f64> = vec![0.9; 30];
        // Recent: 10 entries, 3 failures = 30%
        qualities.extend(vec![0.9; 7]);
        qualities.extend(vec![0.1; 3]);
        let result = detect_behavioral_change(&qualities, &c);
        assert!((result.change_magnitude - 0.3).abs() < 1e-12);
        assert!(result.is_anomalous); // >= threshold
    }

    // ── detect_selective_targeting ──

    #[test]
    fn test_selective_targeting_not_flagged() {
        let c = BehavioralConfig::default();
        // Equal failure rates
        let to_new = vec![0.9, 0.1, 0.9, 0.1, 0.9]; // 40% failure
        let to_est = vec![0.9, 0.1, 0.9, 0.1, 0.9]; // 40% failure
        let result = detect_selective_targeting(&to_new, &to_est, &c);
        assert!(!result.is_selective);
    }

    #[test]
    fn test_selective_targeting_flagged() {
        let c = BehavioralConfig::default();
        // 80% failure to new, 10% to established
        let to_new = vec![0.1, 0.1, 0.1, 0.1, 0.9]; // 4/5 = 0.8
        let to_est = vec![0.9, 0.9, 0.9, 0.9, 0.1]; // 1/5 = 0.2
        let result = detect_selective_targeting(&to_new, &to_est, &c);
        assert!((result.failure_rate_to_new - 0.8).abs() < 1e-12);
        assert!((result.failure_rate_to_established - 0.2).abs() < 1e-12);
        // 0.8 >= 2.0 * 0.2 = 0.4 → true, AND 0.8 >= 0.3 → true
        assert!(result.is_selective);
    }

    #[test]
    fn test_selective_targeting_insufficient_samples() {
        let c = BehavioralConfig::default(); // min_samples=3
                                             // Only 2 interactions with new peers
        let to_new = vec![0.1, 0.1];
        let to_est = vec![0.9, 0.9, 0.9, 0.9, 0.9];
        let result = detect_selective_targeting(&to_new, &to_est, &c);
        assert!(!result.is_selective);
    }

    #[test]
    fn test_selective_targeting_both_high_failure() {
        let c = BehavioralConfig::default();
        // Both fail equally — not selective, just generally bad
        let to_new = vec![0.1, 0.1, 0.1, 0.1]; // 100% failure
        let to_est = vec![0.1, 0.1, 0.1, 0.1]; // 100% failure
        let result = detect_selective_targeting(&to_new, &to_est, &c);
        // 1.0 >= 2.0 * 1.0 = 2.0 → false
        assert!(!result.is_selective);
    }

    #[test]
    fn test_selective_targeting_new_low_established_zero() {
        let c = BehavioralConfig::default();
        // 40% failure to new, 0% to established
        let to_new = vec![0.1, 0.1, 0.9, 0.9, 0.9]; // 2/5 = 0.4
        let to_est = vec![0.9, 0.9, 0.9]; // 0% failure
        let result = detect_selective_targeting(&to_new, &to_est, &c);
        // 0.4 >= 2.0 * max(0.0, 0.01) = 0.02 → true, AND 0.4 >= 0.3 → true
        assert!(result.is_selective);
    }
}
