//! Decision-support trust thresholds for risk-adjusted transacting.
//!
//! Three pure functions that answer "should I transact?" given trust evidence:
//!
//! - [`min_trust_threshold`]: Josang & Presti 2004 — minimum trust for a given risk/reward.
//! - [`risk_threshold`]: Composite risk-scaled threshold (Josang + TRAVOS + actuarial).
//! - [`required_deposit`]: Trust-gated escrow (Asgaonkar & Krishnamachari 2019).
//!
//! These are stateless utilities — they operate on trust scores and transaction
//! parameters, not on block stores or chains.

// ─── Constants for risk_threshold formula ───────────────────────────────────

/// Base threshold for a minimal transaction.
const BASE: f64 = 0.1;
/// Weight for log-scaled transaction value.
const V_FACTOR: f64 = 0.25;
/// Weight for log-scaled duration.
const D_FACTOR: f64 = 0.15;
/// Penalty for uncertainty (1.0 - confidence).
const U_PENALTY: f64 = 0.2;
/// Discount for recoverable transactions.
const R_DISCOUNT: f64 = 0.1;
/// Reference value for log scaling ($10 base transaction).
const BASE_VALUE: f64 = 10.0;
/// Reference duration for log scaling (1 hour).
const BASE_DURATION: f64 = 1.0;

// ─── L3.3: Josang Decision Trust Threshold ──────────────────────────────────

/// Minimum trust threshold for a transaction, based on loss/gain analysis.
///
/// Formula: `threshold = loss / (loss + gain)` (Josang & Presti 2004).
///
/// Returns 0.5 (maximum uncertainty) when both values are zero or negative.
/// Result is clamped to \[0.0, 1.0\].
///
/// # Examples
///
/// - Equal risk/reward ($100/$100): threshold = 0.5
/// - High risk ($5000 loss, $1000 gain): threshold ≈ 0.833
/// - Low risk ($5 loss, $100 gain): threshold ≈ 0.048
pub fn min_trust_threshold(transaction_value: f64, expected_gain: f64) -> f64 {
    if transaction_value <= 0.0 && expected_gain <= 0.0 {
        return 0.5;
    }
    let denom = transaction_value + expected_gain;
    if denom <= 0.0 {
        return 0.5;
    }
    (transaction_value / denom).clamp(0.0, 1.0)
}

// ─── L3.4: Risk-Scaled Threshold ────────────────────────────────────────────

/// Composite risk-scaled trust threshold combining value, duration, confidence,
/// and recovery factors.
///
/// Research: `risk-scaled-trust-thresholds.md` §9.6 — synthetic formula combining
/// Josang decision trust + TRAVOS confidence + actuarial risk pricing.
///
/// Formula:
/// ```text
/// threshold = base
///     + v_factor × ln(value / base_value).max(0)
///     + d_factor × ln(duration / base_duration).max(0)
///     + u_penalty × (1 - confidence)
///     - r_discount × recovery_rate
/// ```
///
/// Result is clamped to \[0.05, 0.95\].
///
/// # Parameters
///
/// - `value`: Transaction value (e.g. dollars). Values ≤ `BASE_VALUE` ($10) contribute 0.
/// - `duration_hours`: Expected duration in hours. Durations ≤ 1h contribute 0.
/// - `confidence`: Wilson lower bound confidence \[0.0, 1.0\]. Low confidence = higher threshold.
/// - `recovery_rate`: Fraction of value recoverable on failure \[0.0, 1.0\]. Higher = lower threshold.
pub fn risk_threshold(value: f64, duration_hours: f64, confidence: f64, recovery_rate: f64) -> f64 {
    (BASE
        + V_FACTOR * (value / BASE_VALUE).ln().max(0.0)
        + D_FACTOR * (duration_hours / BASE_DURATION).ln().max(0.0)
        + U_PENALTY * (1.0 - confidence)
        - R_DISCOUNT * recovery_rate)
        .clamp(0.05, 0.95)
}

// ─── L3.5: Trust-Gated Escrow ───────────────────────────────────────────────

/// Required deposit for a transaction based on trust score.
///
/// Formula: `deposit = value × (1 - trust)` (Asgaonkar & Krishnamachari 2019).
///
/// - `trust = 1.0` → 0% deposit (fully trusted).
/// - `trust = 0.0` → 100% deposit (unknown agent).
/// - `trust = 0.5` → 50% deposit.
///
/// Trust score is clamped to \[0.0, 1.0\] before computation.
pub fn required_deposit(transaction_value: f64, trust_score: f64) -> f64 {
    transaction_value * (1.0 - trust_score.clamp(0.0, 1.0))
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Josang threshold (L3.3) ──

    #[test]
    fn test_josang_equal_loss_gain() {
        let t = min_trust_threshold(100.0, 100.0);
        assert!((t - 0.5).abs() < 1e-9, "equal risk/reward → 0.5, got {t}");
    }

    #[test]
    fn test_josang_high_loss() {
        let t = min_trust_threshold(5000.0, 1000.0);
        let expected = 5000.0 / 6000.0;
        assert!(
            (t - expected).abs() < 1e-9,
            "high loss → {expected:.4}, got {t}"
        );
    }

    #[test]
    fn test_josang_low_loss() {
        let t = min_trust_threshold(5.0, 100.0);
        let expected = 5.0 / 105.0;
        assert!(
            (t - expected).abs() < 1e-9,
            "low loss → {expected:.4}, got {t}"
        );
    }

    #[test]
    fn test_josang_zero_gain() {
        // Zero gain means infinite risk → threshold = 1.0 (never trust)
        let t = min_trust_threshold(100.0, 0.0);
        assert!((t - 1.0).abs() < 1e-9, "zero gain → 1.0, got {t}");
    }

    #[test]
    fn test_josang_zero_both() {
        let t = min_trust_threshold(0.0, 0.0);
        assert!((t - 0.5).abs() < 1e-9, "zero both → 0.5, got {t}");
    }

    #[test]
    fn test_josang_negative_values() {
        let t = min_trust_threshold(-10.0, -5.0);
        assert!((t - 0.5).abs() < 1e-9, "negative both → 0.5, got {t}");
    }

    #[test]
    fn test_josang_zero_loss() {
        // Zero loss, positive gain → threshold = 0.0 (always trust)
        let t = min_trust_threshold(0.0, 100.0);
        assert!((t - 0.0).abs() < 1e-9, "zero loss → 0.0, got {t}");
    }

    // ── Risk-scaled threshold (L3.4) ──

    #[test]
    fn test_risk_base_case() {
        // value=10 (base), duration=1h (base), confidence=1.0, recovery=0
        // All log terms = 0, uncertainty = 0, recovery = 0 → exactly BASE
        let t = risk_threshold(10.0, 1.0, 1.0, 0.0);
        assert!((t - 0.1).abs() < 1e-9, "base case → 0.1, got {t}");
    }

    #[test]
    fn test_risk_high_value() {
        let t = risk_threshold(1000.0, 1.0, 1.0, 0.0);
        assert!(t > 0.1, "high value → above base, got {t}");
        // ln(1000/10) = ln(100) ≈ 4.605 → contribution ≈ 0.25 * 4.605 ≈ 1.15
        // total ≈ 0.1 + 1.15 = 1.25, clamped to 0.95
        assert!(
            (t - 0.95).abs() < 1e-9,
            "high value clamps to 0.95, got {t}"
        );
    }

    #[test]
    fn test_risk_long_duration() {
        let t = risk_threshold(10.0, 720.0, 1.0, 0.0);
        assert!(t > 0.1, "long duration → above base, got {t}");
    }

    #[test]
    fn test_risk_low_confidence() {
        let t = risk_threshold(10.0, 1.0, 0.0, 0.0);
        let expected = 0.1 + 0.2; // base + full uncertainty penalty
        assert!(
            (t - expected).abs() < 1e-9,
            "low confidence → {expected}, got {t}"
        );
    }

    #[test]
    fn test_risk_high_recovery() {
        let t = risk_threshold(10.0, 1.0, 1.0, 1.0);
        let expected: f64 = (0.1_f64 - 0.1).max(0.05); // base - full recovery discount, clamped
        assert!(
            (t - expected).abs() < 1e-9,
            "high recovery → {expected}, got {t}"
        );
    }

    #[test]
    fn test_risk_clamp_low() {
        // Very small value, short duration, full confidence, full recovery
        let t = risk_threshold(1.0, 0.5, 1.0, 1.0);
        assert!((t - 0.05).abs() < 1e-9, "should clamp to 0.05, got {t}");
    }

    #[test]
    fn test_risk_clamp_high() {
        // Huge value, long duration, zero confidence
        let t = risk_threshold(1_000_000.0, 10_000.0, 0.0, 0.0);
        assert!((t - 0.95).abs() < 1e-9, "should clamp to 0.95, got {t}");
    }

    // ── Trust-gated escrow (L3.5) ──

    #[test]
    fn test_deposit_zero_trust() {
        let d = required_deposit(1000.0, 0.0);
        assert!(
            (d - 1000.0).abs() < 1e-9,
            "zero trust → full deposit, got {d}"
        );
    }

    #[test]
    fn test_deposit_full_trust() {
        let d = required_deposit(1000.0, 1.0);
        assert!((d - 0.0).abs() < 1e-9, "full trust → no deposit, got {d}");
    }

    #[test]
    fn test_deposit_half_trust() {
        let d = required_deposit(1000.0, 0.5);
        assert!(
            (d - 500.0).abs() < 1e-9,
            "half trust → half deposit, got {d}"
        );
    }

    #[test]
    fn test_deposit_negative_trust_clamped() {
        let d = required_deposit(1000.0, -0.1);
        assert!(
            (d - 1000.0).abs() < 1e-9,
            "negative trust clamped → full deposit, got {d}"
        );
    }

    #[test]
    fn test_deposit_above_one_trust_clamped() {
        let d = required_deposit(1000.0, 1.5);
        assert!(
            (d - 0.0).abs() < 1e-9,
            "trust > 1.0 clamped → no deposit, got {d}"
        );
    }
}
