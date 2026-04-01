//! Correlation-based delegation penalty for trust violation amplification.
//!
//! Implements Ethereum PoS-style correlation penalty (Buterin et al. 2020) and
//! supply chain liability (Management Science 2024) for delegation trees.
//!
//! Key insight: correlated failures across a delegation tree are more dangerous
//! than isolated failures and should be punished super-linearly. A delegator
//! who delegates to many agents that all fail simultaneously is likely running
//! a coordinated attack, not just unlucky.
//!
//! Two penalty mechanisms:
//! - **Tree correlation**: `base_penalty × multiplier × (failed/total)` — penalizes
//!   correlated failures across the delegation tree.
//! - **Delegator propagation**: `worker_penalty × propagation_factor` — delegators
//!   bear partial responsibility for their delegates' failures.
//!
//! These are stateless utilities operating on penalty values, not on block stores.
//!
//! Research: Ethereum PoS correlation penalty (Buterin et al. 2020),
//! Management Science 2024 (supply chain liability, 0.3–0.5 range).

use serde::{Deserialize, Serialize};

// ─── Types ──────────────────────────────────────────────────────────────────

/// Configuration for correlation-based delegation penalties.
///
/// All fields are immutable after construction. Use `Default` for
/// research-validated parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationConfig {
    /// Ethereum-inspired multiplier for correlated failures. Default: 3.0.
    /// Higher values punish correlated failures more severely.
    pub correlation_multiplier: f64,
    /// Fraction of worker penalty propagated to delegator. Default: 0.4.
    /// Research range: 0.3–0.5 (Management Science 2024).
    pub delegator_propagation: f64,
}

impl Default for CorrelationConfig {
    fn default() -> Self {
        Self {
            correlation_multiplier: 3.0,
            delegator_propagation: 0.4,
        }
    }
}

// ─── Functions ──────────────────────────────────────────────────────────────

/// Compute correlation penalty for a delegation tree.
///
/// Formula: `base_penalty × correlation_multiplier × (failed_count / total_in_tree)`
///
/// When many delegates fail simultaneously, each individual penalty is amplified
/// by the fraction that failed. A single failure in a tree of 10 produces a
/// small correlation factor (0.1); all 10 failing produces maximum amplification.
///
/// Returns 0.0 when `total_in_tree` is 0 or `failed_count` is 0.
/// Result is clamped to \[0.0, 1.0\].
///
/// # Research
///
/// Ethereum PoS: `correlation_penalty = 3 × fraction_slashed_in_window`.
/// Applied at day 18 of 36-day exit period. If 33.4%+ of stake slashed,
/// penalty approaches 100%.
pub fn delegation_tree_penalty(
    failed_count: usize,
    total_in_tree: usize,
    base_penalty: f64,
    config: &CorrelationConfig,
) -> f64 {
    if total_in_tree == 0 || failed_count == 0 {
        return 0.0;
    }
    let fraction = failed_count as f64 / total_in_tree as f64;
    (base_penalty * config.correlation_multiplier * fraction).clamp(0.0, 1.0)
}

/// Compute the penalty propagated from a worker to its delegator.
///
/// Formula: `worker_penalty × delegator_propagation`
///
/// Creates incentive for careful delegation: delegators bear partial
/// responsibility for their delegates' quality/liveness failures.
///
/// Returns 0.0 when `worker_penalty` is 0.0 or negative.
/// Result is clamped to \[0.0, 1.0\].
///
/// # Research
///
/// Management Science 2024: without indirect liability, agents hire the
/// cheapest subcontractor regardless of quality. The 0.3–0.5 weight creates
/// incentive structure where delegators check worker trust before delegating.
pub fn delegator_penalty(worker_penalty: f64, config: &CorrelationConfig) -> f64 {
    if worker_penalty <= 0.0 {
        return 0.0;
    }
    (worker_penalty * config.delegator_propagation).clamp(0.0, 1.0)
}

/// Compute the total correlation-adjusted penalty for a delegator given
/// the penalty and failure status of all delegates in their tree.
///
/// This is the main entry point. It:
/// 1. Sums individual delegate penalties propagated to the delegator.
/// 2. Computes the correlation fraction (failed / total).
/// 3. Applies the Ethereum-style correlation multiplier.
///
/// The result represents how much the delegator's trust should be penalized
/// due to delegate failures. Higher when failures are correlated (many delegates
/// failing simultaneously).
///
/// Each entry in `delegate_penalties` is `(individual_penalty, is_failed)`.
/// `is_failed` = true if the delegate has any active violation.
///
/// Returns 0.0 when the list is empty or no delegates have failed.
/// Result is clamped to \[0.0, 1.0\].
pub fn compute_delegator_correlation_penalty(
    delegate_penalties: &[(f64, bool)],
    config: &CorrelationConfig,
) -> f64 {
    if delegate_penalties.is_empty() {
        return 0.0;
    }

    let total = delegate_penalties.len();
    let failed_count = delegate_penalties
        .iter()
        .filter(|(_, failed)| *failed)
        .count();

    if failed_count == 0 {
        return 0.0;
    }

    // Sum propagated penalties from failed delegates
    let propagated_sum: f64 = delegate_penalties
        .iter()
        .filter(|(_, failed)| *failed)
        .map(|(penalty, _)| delegator_penalty(*penalty, config))
        .sum();

    // Apply correlation amplification
    let fraction = failed_count as f64 / total as f64;
    let correlation_factor = config.correlation_multiplier * fraction;

    (propagated_sum * correlation_factor).clamp(0.0, 1.0)
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_defaults() {
        let c = CorrelationConfig::default();
        assert!((c.correlation_multiplier - 3.0).abs() < 1e-12);
        assert!((c.delegator_propagation - 0.4).abs() < 1e-12);
    }

    #[test]
    fn test_tree_penalty_single_failure_in_large_tree() {
        let c = CorrelationConfig::default();
        // 1/10 failed, base_penalty = 0.05
        // penalty = 0.05 * 3.0 * 0.1 = 0.015
        let p = delegation_tree_penalty(1, 10, 0.05, &c);
        assert!((p - 0.015).abs() < 1e-12, "1/10 failed → 0.015, got {p}");
    }

    #[test]
    fn test_tree_penalty_all_failures() {
        let c = CorrelationConfig::default();
        // 10/10 failed, base_penalty = 0.5
        // penalty = 0.5 * 3.0 * 1.0 = 1.5, clamped to 1.0
        let p = delegation_tree_penalty(10, 10, 0.5, &c);
        assert!(
            (p - 1.0).abs() < 1e-12,
            "all failed → capped at 1.0, got {p}"
        );
    }

    #[test]
    fn test_tree_penalty_zero_failures() {
        let c = CorrelationConfig::default();
        let p = delegation_tree_penalty(0, 10, 0.5, &c);
        assert!((p - 0.0).abs() < 1e-12, "zero failures → 0.0, got {p}");
    }

    #[test]
    fn test_tree_penalty_empty_tree() {
        let c = CorrelationConfig::default();
        let p = delegation_tree_penalty(0, 0, 0.5, &c);
        assert!((p - 0.0).abs() < 1e-12, "empty tree → 0.0, got {p}");
    }

    #[test]
    fn test_tree_penalty_amplifies_with_fraction() {
        let c = CorrelationConfig::default();
        let p1 = delegation_tree_penalty(1, 10, 0.1, &c); // fraction = 0.1
        let p5 = delegation_tree_penalty(5, 10, 0.1, &c); // fraction = 0.5
        assert!(p5 > p1, "more failures → higher penalty: p1={p1}, p5={p5}");
        // p1 = 0.1 * 3.0 * 0.1 = 0.03
        // p5 = 0.1 * 3.0 * 0.5 = 0.15
        assert!((p1 - 0.03).abs() < 1e-12);
        assert!((p5 - 0.15).abs() < 1e-12);
    }

    #[test]
    fn test_delegator_penalty_40_percent() {
        let c = CorrelationConfig::default();
        let p = delegator_penalty(0.5, &c);
        assert!((p - 0.2).abs() < 1e-12, "0.5 * 0.4 = 0.2, got {p}");
    }

    #[test]
    fn test_delegator_penalty_zero_worker() {
        let c = CorrelationConfig::default();
        let p = delegator_penalty(0.0, &c);
        assert!((p - 0.0).abs() < 1e-12, "zero worker → 0.0, got {p}");
    }

    #[test]
    fn test_delegator_penalty_capped() {
        let c = CorrelationConfig::default();
        // worker_penalty = 3.0, propagated = 3.0 * 0.4 = 1.2, clamped to 1.0
        let p = delegator_penalty(3.0, &c);
        assert!((p - 1.0).abs() < 1e-12, "capped at 1.0, got {p}");
    }

    #[test]
    fn test_custom_config() {
        let c = CorrelationConfig {
            correlation_multiplier: 5.0,
            delegator_propagation: 0.3,
        };
        // 2/4 failed, base = 0.1 → 0.1 * 5.0 * 0.5 = 0.25
        let p = delegation_tree_penalty(2, 4, 0.1, &c);
        assert!((p - 0.25).abs() < 1e-12, "custom config, got {p}");

        let dp = delegator_penalty(1.0, &c);
        assert!((dp - 0.3).abs() < 1e-12, "custom propagation, got {dp}");
    }

    #[test]
    fn test_compute_delegator_empty_list() {
        let c = CorrelationConfig::default();
        let p = compute_delegator_correlation_penalty(&[], &c);
        assert!((p - 0.0).abs() < 1e-12, "empty list → 0.0, got {p}");
    }

    #[test]
    fn test_compute_delegator_no_failures() {
        let c = CorrelationConfig::default();
        let delegates = vec![(0.0, false), (0.0, false), (0.0, false)];
        let p = compute_delegator_correlation_penalty(&delegates, &c);
        assert!((p - 0.0).abs() < 1e-12, "no failures → 0.0, got {p}");
    }

    #[test]
    fn test_compute_delegator_single_failure() {
        let c = CorrelationConfig::default();
        // 1 of 3 delegates failed with penalty 0.05
        // propagated = 0.05 * 0.4 = 0.02
        // correlation_factor = 3.0 * (1/3) = 1.0
        // total = 0.02 * 1.0 = 0.02
        let delegates = vec![(0.05, true), (0.0, false), (0.0, false)];
        let p = compute_delegator_correlation_penalty(&delegates, &c);
        assert!(
            (p - 0.02).abs() < 1e-12,
            "single failure of 3 → 0.02, got {p}"
        );
    }

    #[test]
    fn test_compute_delegator_multiple_failures_amplified() {
        let c = CorrelationConfig::default();
        // 3 of 5 delegates failed with penalty 0.1 each
        // propagated sum = 3 × (0.1 * 0.4) = 0.12
        // correlation_factor = 3.0 * (3/5) = 1.8
        // total = 0.12 * 1.8 = 0.216
        let delegates = vec![
            (0.1, true),
            (0.1, true),
            (0.1, true),
            (0.0, false),
            (0.0, false),
        ];
        let p = compute_delegator_correlation_penalty(&delegates, &c);
        assert!((p - 0.216).abs() < 1e-9, "3/5 failed → 0.216, got {p}");
    }

    #[test]
    fn test_compute_delegator_all_failed_capped() {
        let c = CorrelationConfig::default();
        // 3 of 3 failed with penalty 1.0 each
        // propagated sum = 3 × (1.0 * 0.4) = 1.2
        // correlation_factor = 3.0 * 1.0 = 3.0
        // total = 1.2 * 3.0 = 3.6, clamped to 1.0
        let delegates = vec![(1.0, true), (1.0, true), (1.0, true)];
        let p = compute_delegator_correlation_penalty(&delegates, &c);
        assert!(
            (p - 1.0).abs() < 1e-12,
            "all failed → capped at 1.0, got {p}"
        );
    }
}
