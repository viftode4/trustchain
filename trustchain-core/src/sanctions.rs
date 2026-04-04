//! Graduated sanctions framework for trust violations.
//!
//! Implements Ostrom's Principle #5 (graduated sanctions, 1990) with a
//! Cosmos/Ethereum-inspired severity hierarchy (500x ratio between levels).
//!
//! Three severity levels:
//! - **Liveness**: Timeout, late delivery — 0.0001 penalty (Cosmos downtime slashing).
//! - **Quality**: Poor quality delivery — proportional to quality gap (Ostrom graduated).
//! - **Byzantine**: Proven fraud — 1.0 hard zero (already enforced in `trust.rs`).
//!
//! Sanctions are computed **separately** from the trust score. The trust formula
//! already penalizes bad outcomes via recency decay. Sanctions provide explicit
//! penalty tracking for additional gating (e.g., tier demotion, escrow requirements).
//!
//! Research: negative-feedback-punishment §2.1 (Ostrom 1990, graduated sanctions),
//! negative-feedback-punishment §2.2 (Cosmos slashing model, Cox et al. 2010).

use serde::{Deserialize, Serialize};

// ─── Types ──────────────────────────────────────────────────────────────────

/// Violation severity classification.
///
/// Severity hierarchy preserves ~500x ratio between adjacent levels,
/// inspired by Cosmos staking slashing (500x between downtime and Byzantine).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ViolationSeverity {
    /// Timeout, late delivery, unresponsiveness.
    /// Penalty: 0.0001 per occurrence (auto-recoverable).
    Liveness,
    /// Poor quality, partial delivery, quality below threshold.
    /// Penalty: proportional to quality gap from 0.5 median.
    Quality,
    /// Proven fraud, double-spend.
    /// Penalty: 1.0 (hard zero — already enforced in trust.rs).
    Byzantine,
}

/// Configuration for graduated sanctions.
///
/// All fields are immutable after construction. Use `Default` for
/// research-validated parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SanctionConfig {
    /// Penalty per liveness failure (timeout). Default: 0.0001 (Cosmos-inspired).
    pub liveness_penalty: f64,
    /// Base penalty for quality violations. Default: 0.05.
    /// Actual penalty = base × (0.5 - avg_quality).max(0).
    pub quality_penalty_base: f64,
    /// Penalty for Byzantine (fraud). Default: 1.0 (hard zero).
    pub byzantine_penalty: f64,
    /// Decay factor for forgiveness per epoch. Default: 0.95.
    /// Each epoch reduces accumulated penalties by this factor.
    pub forgiveness_decay: f64,
}

impl Default for SanctionConfig {
    fn default() -> Self {
        Self {
            liveness_penalty: 0.0001,
            quality_penalty_base: 0.05,
            byzantine_penalty: 1.0,
            forgiveness_decay: 0.95,
        }
    }
}

/// A single classified violation with its computed penalty.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Violation {
    /// Severity classification of this violation.
    pub severity: ViolationSeverity,
    /// Computed penalty for this violation.
    pub penalty: f64,
}

/// Result of sanctions computation: cumulative penalties from all violations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SanctionResult {
    /// Cumulative penalty across all violations, clamped to \[0.0, 1.0\].
    pub total_penalty: f64,
    /// Number of classified violations.
    pub violation_count: usize,
    /// Individual violations with their penalties.
    pub violations: Vec<Violation>,
}

// ─── Functions ──────────────────────────────────────────────────────────────

/// Classify observable evidence into the highest-severity applicable violation.
///
/// Priority: Byzantine > Quality > Liveness > None.
///
/// - `fraud == true` → Byzantine
/// - `avg_quality < 0.3` → Quality
/// - `timeout_count > 0` → Liveness
/// - Otherwise → `None`
pub fn classify_violation(
    timeout_count: usize,
    avg_quality: f64,
    fraud: bool,
) -> Option<ViolationSeverity> {
    if fraud {
        Some(ViolationSeverity::Byzantine)
    } else if avg_quality < 0.3 {
        Some(ViolationSeverity::Quality)
    } else if timeout_count > 0 {
        Some(ViolationSeverity::Liveness)
    } else {
        None
    }
}

/// Compute penalty for a single violation type.
///
/// - Liveness: `config.liveness_penalty` (flat per occurrence).
/// - Quality: `config.quality_penalty_base × quality_gap` where
///   `quality_gap = (0.5 - avg_quality).max(0.0)`.
/// - Byzantine: `config.byzantine_penalty` (always 1.0).
pub fn compute_penalty(
    severity: ViolationSeverity,
    config: &SanctionConfig,
    quality_gap: f64,
) -> f64 {
    match severity {
        ViolationSeverity::Liveness => config.liveness_penalty,
        ViolationSeverity::Quality => config.quality_penalty_base * quality_gap.max(0.0),
        ViolationSeverity::Byzantine => config.byzantine_penalty,
    }
}

/// Compute cumulative sanctions from observable trust evidence.
///
/// This is the main entry point. It classifies all applicable violations
/// and sums their penalties (clamped to \[0.0, 1.0\]).
///
/// Multiple violation types can stack:
/// - Byzantine fraud produces a single violation with penalty 1.0.
/// - Quality violations produce one violation proportional to the gap.
/// - Liveness violations produce one violation per timeout.
///
/// The total penalty is capped at 1.0.
pub fn compute_sanctions(
    timeout_count: usize,
    avg_quality: f64,
    fraud: bool,
    config: &SanctionConfig,
) -> SanctionResult {
    let mut violations = Vec::new();
    let mut total = 0.0_f64;

    // Byzantine: proven fraud → hard penalty
    if fraud {
        let penalty = config.byzantine_penalty;
        violations.push(Violation {
            severity: ViolationSeverity::Byzantine,
            penalty,
        });
        total += penalty;
    }

    // Quality: avg_quality below threshold
    if avg_quality < 0.3 {
        let quality_gap = (0.5 - avg_quality).max(0.0);
        let penalty = config.quality_penalty_base * quality_gap;
        violations.push(Violation {
            severity: ViolationSeverity::Quality,
            penalty,
        });
        total += penalty;
    }

    // Liveness: each timeout is a separate liveness failure
    if timeout_count > 0 {
        let penalty = config.liveness_penalty * timeout_count as f64;
        violations.push(Violation {
            severity: ViolationSeverity::Liveness,
            penalty,
        });
        total += penalty;
    }

    SanctionResult {
        total_penalty: total.clamp(0.0, 1.0),
        violation_count: violations.len(),
        violations,
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config_values() {
        let c = SanctionConfig::default();
        assert!((c.liveness_penalty - 0.0001).abs() < 1e-12);
        assert!((c.quality_penalty_base - 0.05).abs() < 1e-12);
        assert!((c.byzantine_penalty - 1.0).abs() < 1e-12);
        assert!((c.forgiveness_decay - 0.95).abs() < 1e-12);
    }

    #[test]
    fn test_classify_byzantine() {
        let v = classify_violation(0, 0.8, true);
        assert_eq!(v, Some(ViolationSeverity::Byzantine));
    }

    #[test]
    fn test_classify_quality() {
        let v = classify_violation(0, 0.2, false);
        assert_eq!(v, Some(ViolationSeverity::Quality));
    }

    #[test]
    fn test_classify_liveness() {
        let v = classify_violation(3, 0.8, false);
        assert_eq!(v, Some(ViolationSeverity::Liveness));
    }

    #[test]
    fn test_classify_none() {
        let v = classify_violation(0, 0.8, false);
        assert_eq!(v, None);
    }

    #[test]
    fn test_classify_byzantine_overrides_quality() {
        // Byzantine takes priority even if quality is also low
        let v = classify_violation(5, 0.1, true);
        assert_eq!(v, Some(ViolationSeverity::Byzantine));
    }

    #[test]
    fn test_penalty_liveness() {
        let c = SanctionConfig::default();
        let p = compute_penalty(ViolationSeverity::Liveness, &c, 0.0);
        assert!((p - 0.0001).abs() < 1e-12);
    }

    #[test]
    fn test_penalty_quality_proportional() {
        let c = SanctionConfig::default();
        // quality = 0.2, gap = 0.5 - 0.2 = 0.3, penalty = 0.05 * 0.3 = 0.015
        let p = compute_penalty(ViolationSeverity::Quality, &c, 0.3);
        assert!(
            (p - 0.015).abs() < 1e-12,
            "quality penalty → 0.015, got {p}"
        );
    }

    #[test]
    fn test_penalty_byzantine() {
        let c = SanctionConfig::default();
        let p = compute_penalty(ViolationSeverity::Byzantine, &c, 0.0);
        assert!((p - 1.0).abs() < 1e-12);
    }

    #[test]
    fn test_sanctions_clean_agent() {
        let c = SanctionConfig::default();
        let r = compute_sanctions(0, 0.85, false, &c);
        assert!((r.total_penalty - 0.0).abs() < 1e-12);
        assert_eq!(r.violation_count, 0);
        assert!(r.violations.is_empty());
    }

    #[test]
    fn test_sanctions_fraud() {
        let c = SanctionConfig::default();
        let r = compute_sanctions(0, 0.85, true, &c);
        assert!((r.total_penalty - 1.0).abs() < 1e-12);
        assert_eq!(r.violation_count, 1);
        assert_eq!(r.violations[0].severity, ViolationSeverity::Byzantine);
    }

    #[test]
    fn test_sanctions_combined_capped() {
        let c = SanctionConfig::default();
        // Fraud (1.0) + quality (0.025) + liveness (0.001) → capped at 1.0
        let r = compute_sanctions(10, 0.0, true, &c);
        assert!((r.total_penalty - 1.0).abs() < 1e-12, "total capped at 1.0");
        assert_eq!(
            r.violation_count, 3,
            "fraud + quality + liveness = 3 violations"
        );
    }

    #[test]
    fn test_sanctions_liveness_scales_with_count() {
        let c = SanctionConfig::default();
        let r = compute_sanctions(100, 0.85, false, &c);
        // 100 timeouts × 0.0001 = 0.01
        assert!(
            (r.total_penalty - 0.01).abs() < 1e-12,
            "100 timeouts → 0.01, got {}",
            r.total_penalty
        );
    }

    #[test]
    fn test_severity_hierarchy_ratio() {
        let c = SanctionConfig::default();
        let liveness = c.liveness_penalty;
        let quality = c.quality_penalty_base;
        let byzantine = c.byzantine_penalty;
        // Quality / Liveness ≈ 500x
        let ql_ratio = quality / liveness;
        assert!(
            (ql_ratio - 500.0).abs() < 1.0,
            "quality/liveness ratio ≈ 500, got {ql_ratio}"
        );
        // Byzantine / Liveness = 10,000x
        let bl_ratio = byzantine / liveness;
        assert!(
            (bl_ratio - 10_000.0).abs() < 1.0,
            "byzantine/liveness ratio = 10000, got {bl_ratio}"
        );
    }
}
