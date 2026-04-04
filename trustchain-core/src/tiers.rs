//! Trust tier system — progressive unlocking based on trust and history.
//!
//! Prevents cross-segment reputation farming, limits rug-pull damage.
//! Research: risk-scaled-trust-thresholds §9.2 (value-scaled trust tiers),
//! game-theory/market-mechanisms §4 (Rothschild-Stiglitz screening),
//! risk-scaled-trust-thresholds §3 (Armendariz & Morduch 2010, progressive lending).

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::trust::TrustEvidence;

/// Trust tier levels — progressive access to higher-value transactions.
///
/// CRITICAL: Success at Tier N does NOT automatically grant Tier N+1.
/// Must have interactions at Tier N before qualifying for N+1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum TrustTier {
    /// T0: trust >= 0.10, no history required. Max value ~$10.
    Spot,
    /// T1: trust >= 0.25, 5+ successful T0 interactions.
    Basic,
    /// T2: trust >= 0.40, 10+ total interactions including T1.
    Standard,
    /// T3: trust >= 0.55, 20+ total interactions including T2.
    Premium,
    /// T4: trust >= 0.70, 50+ total interactions including T3.
    Enterprise,
}

impl TrustTier {
    /// All tiers in ascending order.
    pub const ALL: [TrustTier; 5] = [
        TrustTier::Spot,
        TrustTier::Basic,
        TrustTier::Standard,
        TrustTier::Premium,
        TrustTier::Enterprise,
    ];
}

/// Requirements to qualify for a given tier.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TierRequirements {
    pub tier: TrustTier,
    pub min_trust: f64,
    pub min_interactions: u64,
    /// Must have history at the tier immediately below.
    pub requires_lower_tier_history: bool,
}

/// Static tier requirements table.
pub fn tier_requirements() -> Vec<TierRequirements> {
    vec![
        TierRequirements {
            tier: TrustTier::Spot,
            min_trust: 0.10,
            min_interactions: 0,
            requires_lower_tier_history: false,
        },
        TierRequirements {
            tier: TrustTier::Basic,
            min_trust: 0.25,
            min_interactions: 5,
            requires_lower_tier_history: true,
        },
        TierRequirements {
            tier: TrustTier::Standard,
            min_trust: 0.40,
            min_interactions: 10,
            requires_lower_tier_history: true,
        },
        TierRequirements {
            tier: TrustTier::Premium,
            min_trust: 0.55,
            min_interactions: 20,
            requires_lower_tier_history: true,
        },
        TierRequirements {
            tier: TrustTier::Enterprise,
            min_trust: 0.70,
            min_interactions: 50,
            requires_lower_tier_history: true,
        },
    ]
}

/// Compute the highest tier an agent qualifies for.
///
/// Uses trust score and interaction count from evidence. Tier history
/// (interactions per tier) is not yet tracked in evidence — for now,
/// we use total interaction count as a proxy.
pub fn compute_tier(evidence: &TrustEvidence) -> TrustTier {
    let reqs = tier_requirements();
    let mut best = TrustTier::Spot;

    for req in &reqs {
        if evidence.trust_score >= req.min_trust
            && evidence.interactions as u64 >= req.min_interactions
        {
            best = req.tier;
        }
    }

    // If trust is below Spot threshold, no tier qualifies.
    if evidence.trust_score < 0.10 {
        return TrustTier::Spot; // Always at least Spot (lowest tier).
    }

    best
}

/// Max transaction value based on trust and history.
///
/// Progressive: 20% growth per successful cycle, capped at 50.
/// Research: Armendariz & Morduch 2010 (microfinance progressive lending).
pub fn max_transaction_value(tier_history: &HashMap<TrustTier, u64>) -> f64 {
    let base = 10.0_f64;
    let rate = 1.2_f64;
    let weighted_successes: f64 = tier_history
        .values()
        .map(|count| *count as f64)
        .sum::<f64>()
        .min(50.0); // cap to prevent overflow
    base * rate.powf(weighted_successes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_tier_no_interactions() {
        let evidence = TrustEvidence {
            trust_score: 0.0,
            interactions: 0,
            ..default_evidence()
        };
        assert_eq!(compute_tier(&evidence), TrustTier::Spot);
    }

    #[test]
    fn test_compute_tier_spot() {
        let evidence = TrustEvidence {
            trust_score: 0.15,
            interactions: 3,
            ..default_evidence()
        };
        assert_eq!(compute_tier(&evidence), TrustTier::Spot);
    }

    #[test]
    fn test_compute_tier_basic() {
        let evidence = TrustEvidence {
            trust_score: 0.30,
            interactions: 6,
            ..default_evidence()
        };
        assert_eq!(compute_tier(&evidence), TrustTier::Basic);
    }

    #[test]
    fn test_compute_tier_standard() {
        let evidence = TrustEvidence {
            trust_score: 0.50,
            interactions: 15,
            ..default_evidence()
        };
        assert_eq!(compute_tier(&evidence), TrustTier::Standard);
    }

    #[test]
    fn test_compute_tier_premium() {
        let evidence = TrustEvidence {
            trust_score: 0.60,
            interactions: 25,
            ..default_evidence()
        };
        assert_eq!(compute_tier(&evidence), TrustTier::Premium);
    }

    #[test]
    fn test_compute_tier_enterprise() {
        let evidence = TrustEvidence {
            trust_score: 0.80,
            interactions: 60,
            ..default_evidence()
        };
        assert_eq!(compute_tier(&evidence), TrustTier::Enterprise);
    }

    #[test]
    fn test_compute_tier_high_trust_low_interactions() {
        // High trust but not enough interactions → capped at lower tier.
        let evidence = TrustEvidence {
            trust_score: 0.90,
            interactions: 4,
            ..default_evidence()
        };
        assert_eq!(compute_tier(&evidence), TrustTier::Spot);
    }

    #[test]
    fn test_max_transaction_value_empty() {
        let history = HashMap::new();
        let max_val = max_transaction_value(&history);
        assert!((max_val - 10.0).abs() < 1e-9, "No history → $10 base");
    }

    #[test]
    fn test_max_transaction_value_growth() {
        let mut history = HashMap::new();
        history.insert(TrustTier::Spot, 10);
        let max_val = max_transaction_value(&history);
        // 10 * 1.2^10 ≈ 61.92
        assert!(
            max_val > 60.0 && max_val < 63.0,
            "10 jobs → ~$62, got {max_val}"
        );
    }

    fn default_evidence() -> TrustEvidence {
        TrustEvidence {
            trust_score: 0.0,
            connectivity: 0.0,
            integrity: 1.0,
            diversity: 0.0,
            recency: 0.0,
            unique_peers: 0,
            interactions: 0,
            fraud: false,
            path_diversity: 0.0,
            audit_count: 0,
            avg_quality: 0.0,
            value_weighted_recency: 0.0,
            timeout_count: 0,
            confidence: 0.0,
            sample_size: 0,
            positive_count: 0,
            beta_reputation: None,
            required_deposit_ratio: 1.0,
            sanction_penalty: 0.0,
            violation_count: 0,
            correlation_penalty: 0.0,
            forgiveness_factor: 1.0,
            good_interactions_since_violation: 0,
            behavioral_change: 0.0,
            behavioral_anomaly: false,
            selective_scamming: false,
            collusion_cluster_density: 0.0,
            collusion_external_ratio: 0.0,
            collusion_temporal_burst: false,
            collusion_reciprocity_anomaly: false,
            requester_trust: None,
            payment_reliability: None,
            rating_fairness: None,
            dispute_rate: None,
        }
    }
}
