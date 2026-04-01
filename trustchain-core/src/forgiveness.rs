//! Forgiveness and trust recovery after violations.
//!
//! Implements graduated trust recovery with severity-dependent ceilings
//! and asymmetric decay (negative outcomes decay faster than positive).
//!
//! Design principles:
//! - **Generous tit-for-tat** (Axelrod 1984, Nowak & Sigmund 1992): cooperate
//!   with probability p after opponent defects. Forgiveness prevents spiraling
//!   mutual defection in noisy environments.
//! - **Trust scar** (Vasalou et al. 2008): recovery ceiling depends on severity.
//!   Liveness failures can be fully forgiven; fraud leaves a permanent scar.
//! - **Uncertainty, not reduction** (Josang et al. 2007): aged negative ratings
//!   increase uncertainty rather than directly reducing trust. An agent that was
//!   bad 6 months ago is *uncertain*, not necessarily rehabilitated.
//! - **Partner choice over punishment** (Rand et al. 2009): low trust = no jobs =
//!   effective exclusion. Explicit punishment is secondary to market exclusion.
//!
//! Research: Josang, Ismail, Boyd 2007; Axelrod 1984; Vasalou et al. 2008;
//! Nowak & Sigmund 1992; `negative-feedback-punishment.md` §5.

use serde::{Deserialize, Serialize};

use crate::sanctions::ViolationSeverity;

// ─── Types ──────────────────────────────────────────────────────────────────

/// Recovery severity classification for ceiling determination.
///
/// Extends `ViolationSeverity` with `Systemic` for delegation-propagated fraud
/// that allows no recovery (tombstone).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RecoverySeverity {
    /// Timeout, late delivery — full recovery possible.
    Liveness,
    /// Poor quality — partial recovery (trust scar: -25%).
    Quality,
    /// Proven fraud — very limited recovery (trust scar: -75%).
    Fraud,
    /// Delegate fraud propagation — no recovery (tombstone).
    Systemic,
}

impl From<ViolationSeverity> for RecoverySeverity {
    fn from(v: ViolationSeverity) -> Self {
        match v {
            ViolationSeverity::Liveness => RecoverySeverity::Liveness,
            ViolationSeverity::Quality => RecoverySeverity::Quality,
            ViolationSeverity::Byzantine => RecoverySeverity::Fraud,
        }
    }
}

/// Configuration for forgiveness / trust recovery.
///
/// All fields are immutable after construction. Use `Default` for
/// research-validated parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForgivenessConfig {
    /// Decay factor per good interaction. Default: 0.8.
    /// Each good interaction reduces remaining penalty by 20%.
    /// After 10 good interactions: penalty × 0.8^10 ≈ 10.7% of original.
    pub decay_per_good_interaction: f64,
    /// Recovery ceiling for liveness violations. Default: 1.0 (full recovery).
    pub liveness_recovery_ceiling: f64,
    /// Recovery ceiling for quality violations. Default: 0.75 (-25% scar).
    pub quality_recovery_ceiling: f64,
    /// Recovery ceiling for fraud. Default: 0.25 (-75% scar).
    pub fraud_recovery_ceiling: f64,
    /// Speedup factor for negative outcome decay in recency. Default: 1.5.
    /// Negatives age 50% faster than positives.
    pub negative_decay_speedup: f64,
}

impl Default for ForgivenessConfig {
    fn default() -> Self {
        Self {
            decay_per_good_interaction: 0.8,
            liveness_recovery_ceiling: 1.0,
            quality_recovery_ceiling: 0.75,
            fraud_recovery_ceiling: 0.25,
            negative_decay_speedup: 1.5,
        }
    }
}

// ─── Functions ──────────────────────────────────────────────────────────────

/// Get the recovery ceiling for a given severity level.
///
/// The ceiling represents the maximum fraction of pre-violation trust that
/// can be recovered. Returns a value in \[0.0, 1.0\].
///
/// | Severity | Ceiling | Meaning |
/// |----------|---------|---------|
/// | Liveness | 1.0 | Full recovery possible |
/// | Quality | 0.75 | -25% permanent scar |
/// | Fraud | 0.25 | -75% permanent scar |
/// | Systemic | 0.0 | No recovery (tombstone) |
pub fn recovery_ceiling(severity: RecoverySeverity, config: &ForgivenessConfig) -> f64 {
    match severity {
        RecoverySeverity::Liveness => config.liveness_recovery_ceiling,
        RecoverySeverity::Quality => config.quality_recovery_ceiling,
        RecoverySeverity::Fraud => config.fraud_recovery_ceiling,
        RecoverySeverity::Systemic => 0.0,
    }
}

/// Compute the forgiveness-adjusted penalty.
///
/// Formula: `adjusted = initial_penalty × decay^good_interactions`
///
/// The result is further bounded by the recovery ceiling: the adjusted penalty
/// will never drop below `initial_penalty × (1.0 - ceiling)`. This implements
/// the "trust scar" concept from Vasalou et al. (2008).
///
/// Returns 0.0 when `initial_penalty` is 0.0 or negative.
/// Result is clamped to \[0.0, 1.0\].
///
/// # Example
///
/// ```
/// use trustchain_core::forgiveness::*;
/// let config = ForgivenessConfig::default();
/// // Liveness violation, 5 good interactions since:
/// // penalty = 0.01 × 0.8^5 ≈ 0.00328 (approaching full forgiveness)
/// let p = apply_forgiveness(0.01, 5, RecoverySeverity::Liveness, &config);
/// assert!(p < 0.004);
/// ```
pub fn apply_forgiveness(
    initial_penalty: f64,
    good_interactions_since: usize,
    severity: RecoverySeverity,
    config: &ForgivenessConfig,
) -> f64 {
    if initial_penalty <= 0.0 {
        return 0.0;
    }

    let ceiling = recovery_ceiling(severity, config);

    // Systemic: no recovery at all
    if ceiling <= 0.0 {
        return initial_penalty.clamp(0.0, 1.0);
    }

    // Decay penalty by good interactions
    let decayed = initial_penalty
        * config
            .decay_per_good_interaction
            .powi(good_interactions_since as i32);

    // Floor: penalty cannot drop below the scar level
    // scar_floor = initial_penalty × (1.0 - ceiling)
    // e.g., quality ceiling = 0.75 → floor = initial × 0.25
    let scar_floor = initial_penalty * (1.0 - ceiling);

    decayed.max(scar_floor).clamp(0.0, 1.0)
}

/// Compute asymmetric decay weight for recency computation.
///
/// Positive outcomes use standard exponential decay: `λ^age`.
/// Negative outcomes decay faster: `λ^(age × speedup)`.
///
/// This means old negative interactions fade from the recency computation
/// faster than old positive interactions, implementing gradual forgiveness
/// at the recency level.
///
/// # Parameters
///
/// - `base_lambda`: Base decay factor (e.g., 0.95).
/// - `age`: How many interactions ago (0 = most recent).
/// - `is_negative`: Whether this interaction had a negative outcome (quality < 0.5).
/// - `negative_decay_speedup`: How much faster negatives decay. Default: 1.5.
pub fn asymmetric_decay_weight(
    base_lambda: f64,
    age: i32,
    is_negative: bool,
    negative_decay_speedup: f64,
) -> f64 {
    if is_negative {
        base_lambda.powf(age as f64 * negative_decay_speedup)
    } else {
        base_lambda.powi(age)
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_defaults() {
        let c = ForgivenessConfig::default();
        assert!((c.decay_per_good_interaction - 0.8).abs() < 1e-12);
        assert!((c.liveness_recovery_ceiling - 1.0).abs() < 1e-12);
        assert!((c.quality_recovery_ceiling - 0.75).abs() < 1e-12);
        assert!((c.fraud_recovery_ceiling - 0.25).abs() < 1e-12);
        assert!((c.negative_decay_speedup - 1.5).abs() < 1e-12);
    }

    #[test]
    fn test_recovery_ceiling_liveness() {
        let c = ForgivenessConfig::default();
        assert!((recovery_ceiling(RecoverySeverity::Liveness, &c) - 1.0).abs() < 1e-12);
    }

    #[test]
    fn test_recovery_ceiling_quality() {
        let c = ForgivenessConfig::default();
        assert!((recovery_ceiling(RecoverySeverity::Quality, &c) - 0.75).abs() < 1e-12);
    }

    #[test]
    fn test_recovery_ceiling_fraud() {
        let c = ForgivenessConfig::default();
        assert!((recovery_ceiling(RecoverySeverity::Fraud, &c) - 0.25).abs() < 1e-12);
    }

    #[test]
    fn test_recovery_ceiling_systemic() {
        let c = ForgivenessConfig::default();
        assert!((recovery_ceiling(RecoverySeverity::Systemic, &c) - 0.0).abs() < 1e-12);
    }

    #[test]
    fn test_forgiveness_zero_good_interactions() {
        let c = ForgivenessConfig::default();
        // 0 good interactions → no forgiveness, penalty unchanged
        let p = apply_forgiveness(0.05, 0, RecoverySeverity::Quality, &c);
        assert!((p - 0.05).abs() < 1e-12, "no forgiveness → 0.05, got {p}");
    }

    #[test]
    fn test_forgiveness_one_good_interaction() {
        let c = ForgivenessConfig::default();
        // 1 good interaction: 0.05 * 0.8 = 0.04
        // scar floor for quality: 0.05 * 0.25 = 0.0125
        // 0.04 > 0.0125, so decayed wins
        let p = apply_forgiveness(0.05, 1, RecoverySeverity::Quality, &c);
        assert!((p - 0.04).abs() < 1e-12, "1 good → 0.04, got {p}");
    }

    #[test]
    fn test_forgiveness_ten_good_interactions_liveness() {
        let c = ForgivenessConfig::default();
        // Liveness: full recovery possible (ceiling = 1.0, floor = 0.0)
        // 0.01 * 0.8^10 ≈ 0.001074
        let p = apply_forgiveness(0.01, 10, RecoverySeverity::Liveness, &c);
        let expected = 0.01 * 0.8_f64.powi(10);
        assert!(
            (p - expected).abs() < 1e-9,
            "10 good (liveness) → {expected}, got {p}"
        );
    }

    #[test]
    fn test_forgiveness_quality_scar_floor() {
        let c = ForgivenessConfig::default();
        // Quality: ceiling = 0.75, floor = penalty * 0.25
        // Initial = 0.1, floor = 0.025
        // After many good interactions, penalty approaches floor
        // 0.1 * 0.8^50 ≈ 0.0000143 < floor 0.025 → clamped to floor
        let p = apply_forgiveness(0.1, 50, RecoverySeverity::Quality, &c);
        let floor = 0.1 * 0.25;
        assert!(
            (p - floor).abs() < 1e-9,
            "quality scar floor → {floor}, got {p}"
        );
    }

    #[test]
    fn test_forgiveness_fraud_scar_floor() {
        let c = ForgivenessConfig::default();
        // Fraud: ceiling = 0.25, floor = penalty * 0.75
        // Initial = 0.5, floor = 0.375
        let p = apply_forgiveness(0.5, 100, RecoverySeverity::Fraud, &c);
        let floor = 0.5 * 0.75;
        assert!(
            (p - floor).abs() < 1e-9,
            "fraud scar floor → {floor}, got {p}"
        );
    }

    #[test]
    fn test_forgiveness_systemic_no_recovery() {
        let c = ForgivenessConfig::default();
        // Systemic: no recovery regardless of good interactions
        let p = apply_forgiveness(0.8, 1000, RecoverySeverity::Systemic, &c);
        assert!((p - 0.8).abs() < 1e-12, "systemic → no recovery, got {p}");
    }

    #[test]
    fn test_forgiveness_zero_penalty() {
        let c = ForgivenessConfig::default();
        let p = apply_forgiveness(0.0, 10, RecoverySeverity::Quality, &c);
        assert!((p - 0.0).abs() < 1e-12, "zero penalty → 0.0, got {p}");
    }

    #[test]
    fn test_asymmetric_decay_positive_unchanged() {
        // Positive outcome: standard decay λ^age
        let w = asymmetric_decay_weight(0.95, 5, false, 1.5);
        let expected = 0.95_f64.powi(5);
        assert!((w - expected).abs() < 1e-12, "positive → λ^5, got {w}");
    }

    #[test]
    fn test_asymmetric_decay_negative_faster() {
        // Negative outcome: λ^(age * speedup) = 0.95^(5*1.5) = 0.95^7.5
        let w_neg = asymmetric_decay_weight(0.95, 5, true, 1.5);
        let w_pos = asymmetric_decay_weight(0.95, 5, false, 1.5);
        assert!(
            w_neg < w_pos,
            "negative decays faster: neg={w_neg}, pos={w_pos}"
        );
        let expected = 0.95_f64.powf(7.5);
        assert!(
            (w_neg - expected).abs() < 1e-12,
            "negative → 0.95^7.5, got {w_neg}"
        );
    }

    #[test]
    fn test_asymmetric_decay_custom_speedup() {
        // speedup = 2.0: negatives age twice as fast
        let w = asymmetric_decay_weight(0.95, 10, true, 2.0);
        let expected = 0.95_f64.powf(20.0);
        assert!(
            (w - expected).abs() < 1e-12,
            "speedup 2.0 → 0.95^20, got {w}"
        );
    }

    #[test]
    fn test_severity_conversion() {
        assert_eq!(
            RecoverySeverity::from(ViolationSeverity::Liveness),
            RecoverySeverity::Liveness
        );
        assert_eq!(
            RecoverySeverity::from(ViolationSeverity::Quality),
            RecoverySeverity::Quality
        );
        assert_eq!(
            RecoverySeverity::from(ViolationSeverity::Byzantine),
            RecoverySeverity::Fraud
        );
    }
}
