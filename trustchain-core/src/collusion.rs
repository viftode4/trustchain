//! Collusion ring detection signals (Layer 5.3).
//!
//! Detects coordination among agents that artificially inflate each other's
//! trust scores through reciprocal fake transactions. Colluders form dense
//! clusters in the interaction graph with sparse connections to the honest
//! network.
//!
//! Detection signals (MVP — Session 6):
//! - **Reciprocity anomaly:** peer pairs giving each other near-perfect ratings
//!   (suspiciously symmetric).
//! - **Peer concentration:** fraction of interactions going to top-N peers.
//!
//! Deferred signals (future sessions):
//! - **Cluster density:** ego-network internal density (requires full graph traversal).
//! - **External connection ratio:** connections outside the cluster.
//! - **Temporal burst:** interactions clustered in time.
//!
//! All functions are stateless utilities operating on pre-computed metrics,
//! not on block stores. The caller computes graph metrics and passes them
//! as simple numeric values.
//!
//! Research: negative-feedback-punishment §4 (Sun et al. 2012, frequency analysis),
//! negative-feedback-punishment §4.3 (Hooi et al. 2016, FRAUDAR camouflage resistance).

use serde::{Deserialize, Serialize};

// ─── Types ──────────────────────────────────────────────────────────────────

/// Configuration for collusion ring detection.
///
/// All fields are immutable after construction. Use `Default` for
/// research-validated parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollusionConfig {
    /// Minimum internal density to flag as suspicious. Default: 0.6.
    pub min_cluster_density: f64,
    /// Maximum external connection ratio before clearing suspicion. Default: 0.3.
    pub max_external_ratio: f64,
    /// Minimum interactions with a single peer to assess reciprocity. Default: 3.
    pub reciprocity_min_interactions: usize,
    /// Threshold for reciprocity anomaly: `|avg_given - avg_received| < threshold`
    /// while both are >= 0.9. Default: 0.05.
    pub reciprocity_symmetry_threshold: f64,
    /// Threshold for peer concentration flag. Default: 0.8.
    pub concentration_threshold: f64,
    /// Number of top peers for concentration check. Default: 3.
    pub concentration_top_n: usize,
}

impl Default for CollusionConfig {
    fn default() -> Self {
        Self {
            min_cluster_density: 0.6,
            max_external_ratio: 0.3,
            reciprocity_min_interactions: 3,
            reciprocity_symmetry_threshold: 0.05,
            concentration_threshold: 0.8,
            concentration_top_n: 3,
        }
    }
}

/// Collusion signal bundle returned by detection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollusionSignals {
    /// Ego-network internal density \[0.0, 1.0\].
    /// Fraction of possible edges that exist among the target's peers.
    /// 0.0 when not computed (deferred).
    pub cluster_density: f64,
    /// Fraction of the target's peers with connections outside the cluster.
    /// 0.0 when not computed (deferred).
    pub external_connection_ratio: f64,
    /// Whether interactions with peers are temporally clustered.
    /// `false` when not computed (deferred).
    pub temporal_burst: bool,
    /// Whether the target has reciprocity anomalies: peer pairs giving
    /// each other near-perfect ratings (both >= 0.9, difference < threshold).
    pub reciprocity_anomaly: bool,
    /// Fraction of interactions going to top-N peers \[0.0, 1.0\].
    pub peer_concentration: f64,
}

// ─── Functions ──────────────────────────────────────────────────────────────

/// Check if any peer pair shows a reciprocity anomaly.
///
/// A reciprocity anomaly means suspiciously symmetric high-quality ratings:
/// both parties consistently give each other near-perfect scores.
///
/// Each entry in `pairs` is `(avg_quality_given, avg_quality_received, interaction_count)`.
///
/// Returns `true` if any pair satisfies ALL of:
/// 1. `interaction_count >= config.reciprocity_min_interactions`
/// 2. Both `avg_quality_given >= 0.9` and `avg_quality_received >= 0.9`
/// 3. `|avg_quality_given - avg_quality_received| < config.reciprocity_symmetry_threshold`
///
/// The `>= 0.9` floor ensures only near-perfect mutual ratings are flagged,
/// not pairs that happen to be symmetrically mediocre.
///
/// # Research
///
/// Sun et al. 2012: observed mutual interaction frequency >> expected under
/// null model indicates collusion.
pub fn has_reciprocity_anomaly(pairs: &[(f64, f64, usize)], config: &CollusionConfig) -> bool {
    pairs.iter().any(|&(given, received, count)| {
        count >= config.reciprocity_min_interactions
            && given >= 0.9
            && received >= 0.9
            && (given - received).abs() < config.reciprocity_symmetry_threshold
    })
}

/// Compute peer concentration: fraction of interactions going to top-N peers.
///
/// `counts` must be sorted descending (most interactions first).
/// Returns 0.0 when `total_interactions` is 0 or `counts` is empty.
/// Result is clamped to \[0.0, 1.0\].
pub fn peer_concentration(counts: &[usize], total_interactions: usize, top_n: usize) -> f64 {
    if total_interactions == 0 || counts.is_empty() {
        return 0.0;
    }
    let top_sum: usize = counts.iter().take(top_n).sum();
    (top_sum as f64 / total_interactions as f64).clamp(0.0, 1.0)
}

/// Detect collusion signals from pre-computed metrics.
///
/// This is the main entry point. It assembles a `CollusionSignals` bundle
/// from pre-computed graph metrics and chain analysis results.
///
/// # Arguments
///
/// * `cluster_density` — ego-network density (pass 0.0 if not computed).
/// * `external_ratio` — external connection ratio (pass 0.0 if not computed).
/// * `temporal_burst` — temporal clustering flag (pass `false` if not computed).
/// * `reciprocity_pairs` — `(avg_given, avg_received, count)` per peer.
/// * `peer_interaction_counts` — sorted descending: interactions per peer.
/// * `total_interactions` — total interaction count.
/// * `config` — detection thresholds.
pub fn detect_collusion(
    cluster_density: f64,
    external_ratio: f64,
    temporal_burst: bool,
    reciprocity_pairs: &[(f64, f64, usize)],
    peer_interaction_counts: &[usize],
    total_interactions: usize,
    config: &CollusionConfig,
) -> CollusionSignals {
    let reciprocity_anomaly = has_reciprocity_anomaly(reciprocity_pairs, config);
    let concentration = peer_concentration(
        peer_interaction_counts,
        total_interactions,
        config.concentration_top_n,
    );

    CollusionSignals {
        cluster_density,
        external_connection_ratio: external_ratio,
        temporal_burst,
        reciprocity_anomaly,
        peer_concentration: concentration,
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_defaults() {
        let c = CollusionConfig::default();
        assert!((c.min_cluster_density - 0.6).abs() < 1e-12);
        assert!((c.max_external_ratio - 0.3).abs() < 1e-12);
        assert_eq!(c.reciprocity_min_interactions, 3);
        assert!((c.reciprocity_symmetry_threshold - 0.05).abs() < 1e-12);
        assert!((c.concentration_threshold - 0.8).abs() < 1e-12);
        assert_eq!(c.concentration_top_n, 3);
    }

    // ── has_reciprocity_anomaly ──

    #[test]
    fn test_reciprocity_anomaly_symmetric_high() {
        let c = CollusionConfig::default();
        // Both give ~0.95, 5 interactions → flagged
        let pairs = vec![(0.95, 0.96, 5)];
        assert!(has_reciprocity_anomaly(&pairs, &c));
    }

    #[test]
    fn test_reciprocity_anomaly_asymmetric() {
        let c = CollusionConfig::default();
        // One gives 0.9, other gives 0.3 → not symmetric
        let pairs = vec![(0.9, 0.3, 5)];
        assert!(!has_reciprocity_anomaly(&pairs, &c));
    }

    #[test]
    fn test_reciprocity_anomaly_insufficient_count() {
        let c = CollusionConfig::default(); // min=3
                                            // Symmetric high but only 2 interactions
        let pairs = vec![(0.95, 0.95, 2)];
        assert!(!has_reciprocity_anomaly(&pairs, &c));
    }

    #[test]
    fn test_reciprocity_anomaly_low_scores() {
        let c = CollusionConfig::default();
        // Symmetric but mediocre (both 0.3) → not flagged (below 0.9)
        let pairs = vec![(0.3, 0.3, 5)];
        assert!(!has_reciprocity_anomaly(&pairs, &c));
    }

    #[test]
    fn test_reciprocity_anomaly_empty() {
        let c = CollusionConfig::default();
        assert!(!has_reciprocity_anomaly(&[], &c));
    }

    #[test]
    fn test_reciprocity_anomaly_one_clean_one_suspicious() {
        let c = CollusionConfig::default();
        // First pair clean, second suspicious
        let pairs = vec![(0.5, 0.9, 5), (0.92, 0.93, 4)];
        assert!(has_reciprocity_anomaly(&pairs, &c));
    }

    // ── peer_concentration ──

    #[test]
    fn test_peer_concentration_empty() {
        assert!((peer_concentration(&[], 0, 3) - 0.0).abs() < 1e-12);
    }

    #[test]
    fn test_peer_concentration_diverse() {
        // 6 peers: [10, 8, 7, 6, 5, 4], total = 40
        // Top-3 = 10 + 8 + 7 = 25 → 25/40 = 0.625
        let counts = vec![10, 8, 7, 6, 5, 4];
        let result = peer_concentration(&counts, 40, 3);
        assert!(
            (result - 0.625).abs() < 1e-12,
            "expected 0.625, got {result}"
        );
    }

    #[test]
    fn test_peer_concentration_monopoly() {
        // 3 peers: [50, 1, 1], total = 52
        // Top-3 = 52 → 52/52 = 1.0
        let counts = vec![50, 1, 1];
        let result = peer_concentration(&counts, 52, 3);
        assert!((result - 1.0).abs() < 1e-12, "expected 1.0, got {result}");
    }

    #[test]
    fn test_peer_concentration_fewer_peers_than_top_n() {
        // 2 peers but top_n=3
        let counts = vec![10, 5];
        let result = peer_concentration(&counts, 15, 3);
        assert!((result - 1.0).abs() < 1e-12, "expected 1.0, got {result}");
    }

    // ── detect_collusion ──

    #[test]
    fn test_detect_collusion_clean() {
        let c = CollusionConfig::default();
        let pairs = vec![(0.7, 0.5, 4), (0.6, 0.8, 3)];
        let counts = vec![5, 4, 3, 2, 1];
        let result = detect_collusion(0.0, 0.0, false, &pairs, &counts, 15, &c);
        assert!(!result.reciprocity_anomaly);
        // Top-3 = 5+4+3 = 12/15 = 0.8
        assert!((result.peer_concentration - 0.8).abs() < 1e-12);
        assert!(!result.temporal_burst);
    }

    #[test]
    fn test_detect_collusion_reciprocity_flagged() {
        let c = CollusionConfig::default();
        let pairs = vec![(0.95, 0.96, 5)];
        let counts = vec![5];
        let result = detect_collusion(0.0, 0.0, false, &pairs, &counts, 5, &c);
        assert!(result.reciprocity_anomaly);
        assert!((result.peer_concentration - 1.0).abs() < 1e-12);
    }

    #[test]
    fn test_detect_collusion_passthrough_metrics() {
        let c = CollusionConfig::default();
        // cluster_density and external_ratio are passed through unchanged
        let result = detect_collusion(0.75, 0.05, true, &[], &[], 0, &c);
        assert!((result.cluster_density - 0.75).abs() < 1e-12);
        assert!((result.external_connection_ratio - 0.05).abs() < 1e-12);
        assert!(result.temporal_burst);
    }
}
