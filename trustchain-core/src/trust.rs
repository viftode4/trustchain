//! Unified trust engine combining integrity and netflow scores.
//!
//! Maps to Python's `trust.py`. Blends chain integrity and NetFlow Sybil resistance
//! into a single score, with configurable weights.
//! Delegation-aware: delegated identities inherit trust from their root principal.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::blockstore::BlockStore;
use crate::delegation::{DelegationRecord, DelegationStore};
use crate::error::Result;
#[cfg(feature = "meritrank")]
use crate::meritrank::MeritRankTrust;
use crate::netflow::{CachedNetFlow, NetFlowTrust};
use crate::types::GENESIS_HASH;

/// Default connectivity threshold K: path_diversity / K, capped at 1.0.
pub const DEFAULT_CONNECTIVITY_THRESHOLD: f64 = 3.0;

/// Default diversity threshold M: unique_peers / M, capped at 1.0.
pub const DEFAULT_DIVERSITY_THRESHOLD: f64 = 5.0;

/// Default recency decay factor λ: last ~20 interactions dominate.
pub const DEFAULT_RECENCY_LAMBDA: f64 = 0.95;

/// Trust computation algorithm selection.
#[derive(Debug, Clone)]
pub enum TrustAlgorithm {
    /// Max-flow from seeds.
    NetFlow,
    /// Personalized random walks (MeritRank) — bounded Sybil resistance.
    #[cfg(feature = "meritrank")]
    MeritRank {
        /// Number of random walks per computation.
        num_walks: usize,
    },
}

impl Default for TrustAlgorithm {
    fn default() -> Self {
        #[cfg(feature = "meritrank")]
        {
            TrustAlgorithm::MeritRank { num_walks: 10000 }
        }
        #[cfg(not(feature = "meritrank"))]
        {
            TrustAlgorithm::NetFlow
        }
    }
}

/// Configuration for the weighted-additive trust model.
///
/// Trust = (0.3 × structural + 0.7 × behavioral) × confidence_scale
/// - **structural** = connectivity × integrity (Sybil resistance + chain health)
/// - **behavioral** = recency (quality-weighted track record)
/// - **confidence_scale** = min(interactions / cold_start_threshold, 1.0)
/// - Sybil gate: connectivity < ε → hard zero (unchanged)
#[derive(Debug, Clone)]
pub struct TrustConfig {
    /// K: number of independent paths needed for full connectivity score.
    pub connectivity_threshold: f64,
    /// M: number of unique peers needed for full diversity score.
    pub diversity_threshold: f64,
    /// Which algorithm to use for connectivity computation.
    pub algorithm: TrustAlgorithm,
    /// λ: exponential decay factor for recency (0 < λ < 1). Default 0.95.
    /// Last ~20 interactions dominate when λ=0.95.
    pub recency_lambda: f64,
    /// Number of direct interactions before delegation trust is fully replaced
    /// by direct trust (cold start blending). Default 5.
    pub cold_start_threshold: usize,
    /// Trust budget factor applied to delegation-based trust. Default 0.8.
    pub delegation_factor: f64,
}

impl Default for TrustConfig {
    fn default() -> Self {
        Self {
            connectivity_threshold: DEFAULT_CONNECTIVITY_THRESHOLD,
            diversity_threshold: DEFAULT_DIVERSITY_THRESHOLD,
            algorithm: TrustAlgorithm::default(),
            recency_lambda: DEFAULT_RECENCY_LAMBDA,
            cold_start_threshold: 5,
            delegation_factor: 0.8,
        }
    }
}

/// Backward-compatible alias — maps to TrustConfig.
pub type TrustWeights = TrustConfig;

/// Default z-score for 95% confidence interval (Wilson score).
pub const DEFAULT_WILSON_Z: f64 = 1.96;

/// Evidence bundle returned alongside the trust score.
///
/// Provides interpretable factors explaining *why* a score is what it is.
#[derive(Debug, Clone)]
pub struct TrustEvidence {
    /// The final trust score in [0.0, 1.0].
    pub trust_score: f64,
    /// connectivity = min(path_diversity / K, 1.0).
    pub connectivity: f64,
    /// Chain integrity (fraction of valid hash-linked blocks).
    pub integrity: f64,
    /// diversity = min(unique_peers / M, 1.0).
    pub diversity: f64,
    /// Recency: exponential-decay-weighted outcome quality [0.0, 1.0].
    pub recency: f64,
    /// Number of distinct peers in the target's chain.
    pub unique_peers: usize,
    /// Total interactions (blocks) in the target's chain.
    pub interactions: usize,
    /// Whether the target has committed fraud.
    pub fraud: bool,
    /// Raw max-flow value from seed super-source to target.
    pub path_diversity: f64,
    /// Number of audit blocks (single-player, self-referencing) in the chain.
    pub audit_count: usize,

    // --- Layer 1: Quality signal (trust-differentiation-fixes P0) ---
    /// Average quality across all interactions (continuous 0.0–1.0).
    /// Uses quality > requester_rating > binary outcome fallback chain.
    pub avg_quality: f64,

    // --- Layer 1.4: Value-weighted recency ---
    /// Recency weighted by transaction value (price/avg_price).
    /// Cheap wash-trades contribute negligibly. Research: Olariu et al. 2024.
    pub value_weighted_recency: f64,

    // --- Layer 1.5: Timeout enforcement ---
    /// Number of expired orphan proposals directed at this agent (timeouts).
    /// Each counts as a failure in recency computation.
    pub timeout_count: usize,

    // --- Layer 2.1: Wilson score confidence (Evan Miller 2009, TRAVOS) ---
    /// Wilson lower bound confidence score [0.0, 1.0].
    /// Low for new agents (few interactions), high for established agents.
    pub confidence: f64,
    /// Total interaction count used for confidence computation.
    pub sample_size: u64,
    /// Number of interactions with quality >= 0.5 (positive outcomes).
    pub positive_count: u64,

    // --- Layer 2.3: Beta reputation (Josang & Ismail 2002) ---
    /// Beta reputation score: Bayesian updating with temporal decay.
    /// Unifies cold start + continuous feedback + temporal decay in one model.
    /// `None` when chain is empty.
    pub beta_reputation: Option<f64>,

    // --- Layer 3.5: Trust-gated escrow (Asgaonkar & Krishnamachari 2019) ---
    /// Required deposit ratio: `1.0 - trust_score`.
    /// trust=1.0 → 0% deposit; trust=0.0 → 100% deposit.
    pub required_deposit_ratio: f64,

    // --- Layer 4.1: Graduated sanctions (Ostrom 1990, Cosmos slashing) ---
    /// Cumulative graduated sanction penalty [0.0, 1.0].
    pub sanction_penalty: f64,
    /// Number of active violation classifications.
    pub violation_count: usize,

    // --- Layer 4.2: Correlation penalty (Ethereum PoS, Management Science 2024) ---
    /// Penalty from correlated delegate failures in delegation tree.
    /// 0.0 for non-delegators or no delegate failures.
    pub correlation_penalty: f64,

    // --- Layer 4.4: Forgiveness (Josang 2007, Axelrod 1984, Vasalou 2008) ---
    /// Forgiveness factor applied to sanction penalty [0.0, 1.0].
    /// 1.0 = no forgiveness applied, approaching 0.0 = mostly forgiven.
    pub forgiveness_factor: f64,
    /// Number of consecutive good interactions since the last violation.
    pub good_interactions_since_violation: usize,

    // --- Layer 5.1: Behavioral change detection (Olfati-Saber 2007) ---
    /// Change magnitude: recent_failure_rate - baseline_failure_rate.
    /// Positive = worsening, negative = improving.
    pub behavioral_change: f64,
    /// True if behavioral change exceeds anomaly threshold (30% spike).
    pub behavioral_anomaly: bool,

    // --- Layer 5.2: Selective scamming detection (Hoffman 2009) ---
    /// True if agent shows different failure rates toward new vs established peers.
    pub selective_scamming: bool,

    // --- Layer 5.3: Collusion ring signals (Sun 2012, FRAUDAR) ---
    /// Ego-network internal density [0.0, 1.0]. 0.0 when not computed.
    pub collusion_cluster_density: f64,
    /// Fraction of peers with connections outside the cluster. 0.0 when not computed.
    pub collusion_external_ratio: f64,
    /// Whether interactions with peers are temporally clustered.
    pub collusion_temporal_burst: bool,
    /// Whether the agent has suspiciously symmetric ratings with peers.
    pub collusion_reciprocity_anomaly: bool,

    // --- Layer 6.1: Requester reputation (PeerTrust, Xiong & Liu 2004) ---
    /// Requester-perspective trust score. `None` unless explicitly computed
    /// via `compute_requester_trust()`.
    pub requester_trust: Option<f64>,
    /// Fraction of interactions where requester completed payment.
    pub payment_reliability: Option<f64>,
    /// Agreement between requester's ratings and provider consensus.
    pub rating_fairness: Option<f64>,
    /// Fraction of interactions resulting in disputes.
    pub dispute_rate: Option<f64>,
}

/// Pre-captured delegation context for trust computation.
///
/// This avoids holding a `&dyn DelegationStore` reference in `TrustEngine`,
/// which would make the struct non-`Send` in async contexts with trait objects.
#[derive(Debug, Clone, Default)]
pub struct DelegationContext {
    /// Active delegation where pubkey is the delegate, if any.
    pub active_delegation: Option<DelegationRecord>,
    /// Whether the pubkey has ever been a delegate (active, revoked, or expired).
    pub was_delegate: bool,
    /// All delegations where this pubkey is the delegator (active and revoked).
    pub delegations_as_delegator: Vec<DelegationRecord>,
    /// For walking the chain to root: root delegator pubkey.
    pub root_pubkey: Option<String>,
    /// Active delegation count at the root delegator level (for budget split).
    pub root_active_delegation_count: usize,
    /// Delegation depth (number of hops from root to this delegate).
    pub depth: usize,
}

impl DelegationContext {
    /// Build a `DelegationContext` by querying a `DelegationStore`.
    pub fn from_store(ds: &dyn DelegationStore, pubkey: &str) -> Result<Self> {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        // Check if pubkey is a delegate
        let active_delegation = match ds.get_delegation_by_delegate(pubkey) {
            Ok(Some(d)) if d.is_active(now_ms) => Some(d),
            _ => None,
        };

        let was_delegate = ds.is_delegate(pubkey)?;

        // Walk to root delegator if this is an active delegate
        let (root_pubkey, root_active_delegation_count, depth) =
            if let Some(ref delegation) = active_delegation {
                let mut root = delegation.delegator_pubkey.clone();
                let mut current = delegation.clone();
                let mut depth = 1usize;
                while let Some(ref parent_id) = current.parent_delegation_id {
                    if let Ok(Some(parent)) = ds.get_delegation(parent_id) {
                        root = parent.delegator_pubkey.clone();
                        current = parent;
                        depth += 1;
                    } else {
                        break;
                    }
                }
                let all_delegations = ds.get_delegations_by_delegator(&root)?;
                let active_count = all_delegations
                    .iter()
                    .filter(|d| d.is_active(now_ms))
                    .count()
                    .max(1);
                (Some(root), active_count, depth)
            } else {
                (None, 0, 0)
            };

        // Get delegations where this pubkey is delegator (for fraud propagation)
        let delegations_as_delegator = ds.get_delegations_by_delegator(pubkey)?;

        Ok(Self {
            active_delegation,
            was_delegate,
            delegations_as_delegator,
            root_pubkey,
            root_active_delegation_count,
            depth,
        })
    }
}

/// The unified trust engine.
pub struct TrustEngine<'a, S: BlockStore> {
    store: &'a S,
    seed_nodes: Option<Vec<String>>,
    config: TrustConfig,
    delegation_ctx: Option<DelegationContext>,
    /// Optional finalized checkpoint for verification acceleration.
    checkpoint: Option<crate::consensus::Checkpoint>,
}

impl<'a, S: BlockStore> TrustEngine<'a, S> {
    pub fn new(
        store: &'a S,
        seed_nodes: Option<Vec<String>>,
        config: Option<TrustConfig>,
        delegation_ctx: Option<DelegationContext>,
    ) -> Self {
        Self {
            store,
            seed_nodes,
            config: config.unwrap_or_default(),
            delegation_ctx,
            checkpoint: None,
        }
    }

    /// Builder method: attach a finalized checkpoint for verification acceleration.
    ///
    /// When present and finalized, `compute_chain_integrity()` skips Ed25519
    /// verification of blocks covered by the checkpoint (sequence ≤ checkpoint head),
    /// only verifying blocks after the checkpoint.
    pub fn with_checkpoint(mut self, checkpoint: crate::consensus::Checkpoint) -> Self {
        self.checkpoint = Some(checkpoint);
        self
    }

    /// Compute the blended trust score for an agent.
    ///
    /// Delegation-aware with cold start blending:
    /// - Active delegates blend delegation trust with direct trust as interactions accumulate.
    /// - Expired delegates get 0.0.
    /// - Delegate fraud propagates to delegator.
    ///
    /// Standard (non-delegated):
    /// Trust = (0.3 × structural + 0.7 × behavioral) × confidence_scale
    /// where structural = connectivity × integrity, behavioral = recency.
    /// Sybil gate: hard zero if no path from seeds.
    /// Returns hard zero for agents with proven double-spend fraud.
    pub fn compute_trust(&self, pubkey: &str) -> Result<f64> {
        self.compute_trust_ctx(pubkey, None)
    }

    /// Compute trust with optional context filter.
    ///
    /// When `context` is `Some`, recency and diversity are computed over the
    /// context-filtered chain only. Connectivity (Sybil resistance) always uses
    /// the full graph.
    pub fn compute_trust_ctx(&self, pubkey: &str, context: Option<&str>) -> Result<f64> {
        // Check delegation context
        if let Some(ref ctx) = self.delegation_ctx {
            // Is this an active delegated identity?
            if let Some(ref _delegation) = ctx.active_delegation {
                if let Some(ref root_pubkey) = ctx.root_pubkey {
                    return self.compute_delegated_trust_blended(pubkey, root_pubkey, ctx, context);
                }
            }

            // Was a delegate whose delegation is no longer active -> 0
            if ctx.was_delegate && ctx.active_delegation.is_none() {
                return Ok(0.0);
            }

            // Check if any delegate (active OR revoked) committed fraud
            for d in &ctx.delegations_as_delegator {
                let delegate_frauds = self.store.get_double_spends(&d.delegate_pubkey)?;
                if !delegate_frauds.is_empty() {
                    return Ok(0.0); // Hard zero: delegate fraud = delegator fraud
                }
            }
        }

        self.compute_standard_trust(pubkey, context)
    }

    /// Cold start blending for delegated identities.
    ///
    /// Blends delegation-based trust with emerging direct trust as interactions
    /// accumulate. Once `cold_start_threshold` interactions are reached, direct
    /// trust is used exclusively.
    fn compute_delegated_trust_blended(
        &self,
        pubkey: &str,
        root_pubkey: &str,
        ctx: &DelegationContext,
        context: Option<&str>,
    ) -> Result<f64> {
        let chain = self.get_chain_for_context(pubkey, context)?;
        let direct_interactions = chain.len();

        // Compute delegated trust: root_trust * delegation_factor / active_count.
        // Root trust uses full context — the delegator's overall credibility
        // backs the delegation, not just one interaction type.
        let root_trust = self.compute_standard_trust(root_pubkey, None)?;
        let active_count = ctx.root_active_delegation_count.max(1);
        let depth_factor = if ctx.depth > 1 {
            self.config.delegation_factor.powi(ctx.depth as i32 - 1)
        } else {
            1.0
        };
        let delegated =
            (root_trust * self.config.delegation_factor * depth_factor) / active_count as f64;

        if direct_interactions >= self.config.cold_start_threshold {
            // Enough history — use direct trust only
            return self.compute_standard_trust(pubkey, context);
        }

        // Blend: shift weight from delegation trust to direct trust
        let blend = direct_interactions as f64 / self.config.cold_start_threshold.max(1) as f64;
        let direct = if direct_interactions > 0 {
            self.compute_standard_trust(pubkey, context)?
        } else {
            0.0
        };
        let blended = delegated * (1.0 - blend) + direct * blend;
        Ok(blended.clamp(0.0, 1.0))
    }

    /// Standard trust computation (non-delegated path).
    ///
    /// Trust = (0.3 × structural + 0.7 × behavioral) × confidence_scale
    /// where structural = connectivity × integrity, behavioral = recency.
    /// Sybil gate: hard zero if no path from seeds (connectivity < ε).
    /// Confidence scales linearly from 0 to 1 over cold_start_threshold interactions.
    fn compute_standard_trust(&self, pubkey: &str, context: Option<&str>) -> Result<f64> {
        let evidence = self.compute_standard_trust_evidence(pubkey, context)?;
        Ok(evidence.trust_score)
    }

    /// Get the chain filtered by context, or the full chain if no context.
    fn get_chain_for_context(
        &self,
        pubkey: &str,
        context: Option<&str>,
    ) -> Result<Vec<crate::halfblock::HalfBlock>> {
        match context {
            Some(ctx) => self.store.get_chain_by_context(pubkey, ctx),
            None => self.store.get_chain(pubkey),
        }
    }

    /// Compute trust with full evidence bundle for the standard (non-delegated) path.
    fn compute_standard_trust_evidence(
        &self,
        pubkey: &str,
        context: Option<&str>,
    ) -> Result<TrustEvidence> {
        // Helper: zero-evidence for fraud/failure cases.
        let zero_evidence = |chain: &[crate::halfblock::HalfBlock], fraud: bool| -> TrustEvidence {
            let audit_count = chain.iter().filter(|b| b.is_audit()).count();
            TrustEvidence {
                trust_score: 0.0,
                connectivity: 0.0,
                integrity: 0.0,
                diversity: 0.0,
                recency: 0.0,
                unique_peers: self.count_unique_peers(chain),
                interactions: chain.len(),
                fraud,
                path_diversity: 0.0,
                audit_count,
                avg_quality: Self::compute_avg_quality(chain),
                value_weighted_recency: 0.0,
                timeout_count: 0,
                confidence: 0.0,
                sample_size: 0,
                positive_count: 0,
                beta_reputation: None,
                required_deposit_ratio: 1.0,
                sanction_penalty: if fraud { 1.0 } else { 0.0 },
                violation_count: if fraud { 1 } else { 0 },
                correlation_penalty: if fraud { 1.0 } else { 0.0 },
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
        };

        // Hard zero for proven fraud.
        let frauds = self.store.get_double_spends(pubkey)?;
        if !frauds.is_empty() {
            let chain = self.store.get_chain(pubkey)?;
            return Ok(zero_evidence(&chain, true));
        }

        // Use context-filtered chain for recency and diversity.
        let filtered_chain = self.get_chain_for_context(pubkey, context)?;
        let integrity = self.compute_chain_integrity(pubkey)?;
        let unique_peers = self.count_unique_peers(&filtered_chain);
        let interactions = filtered_chain.len();
        let audit_count = filtered_chain.iter().filter(|b| b.is_audit()).count();
        let diversity = (unique_peers as f64 / self.config.diversity_threshold).min(1.0);
        let avg_quality = Self::compute_avg_quality(&filtered_chain);

        // Layer 1.5: Timeout enforcement — count expired orphan proposals.
        let timeout_count = self.count_timeouts(pubkey, &filtered_chain);

        // Layer 1.4: Value-weighted recency with timeout integration.
        let recency = self.compute_recency_inner(&filtered_chain, timeout_count);
        // Also compute basic (non-timeout) value-weighted recency for reporting.
        let value_weighted_recency = self.compute_recency_inner(&filtered_chain, 0);

        // Layer 2.1: Wilson score confidence.
        let sample_size = interactions as u64;
        let positive_count = filtered_chain
            .iter()
            .filter(|b| Self::extract_quality(&b.transaction) >= 0.5)
            .count() as u64;
        let confidence =
            Self::wilson_lower_bound(positive_count as f64, sample_size as f64, DEFAULT_WILSON_Z);

        // Layer 2.3: Beta reputation (Josang & Ismail 2002).
        let beta_reputation = Self::beta_reputation(&filtered_chain);

        if let Some(ref seeds) = self.seed_nodes {
            if !seeds.is_empty() {
                // Seed nodes get trust = 1.0.
                if seeds.contains(&pubkey.to_string()) {
                    return Ok(TrustEvidence {
                        trust_score: 1.0,
                        connectivity: 1.0,
                        integrity: 1.0,
                        diversity: 1.0,
                        recency: 1.0,
                        unique_peers,
                        interactions,
                        fraud: false,
                        path_diversity: f64::INFINITY,
                        audit_count,
                        avg_quality,
                        value_weighted_recency: 1.0,
                        timeout_count: 0,
                        confidence: 1.0,
                        sample_size,
                        positive_count,
                        beta_reputation,
                        required_deposit_ratio: 0.0,
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
                    });
                }

                // Connectivity always uses full graph (context-independent).
                let path_div = self.compute_path_diversity_score(pubkey)?;

                // Sybil gate: no path from seeds → zero trust.
                if path_div < 1e-10 {
                    return Ok(TrustEvidence {
                        trust_score: 0.0,
                        connectivity: 0.0,
                        integrity,
                        diversity,
                        recency,
                        unique_peers,
                        interactions,
                        fraud: false,
                        path_diversity: path_div,
                        audit_count,
                        avg_quality,
                        value_weighted_recency,
                        timeout_count,
                        confidence,
                        sample_size,
                        positive_count,
                        beta_reputation,
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
                    });
                }

                let connectivity = (path_div / self.config.connectivity_threshold).min(1.0);

                // Layer 2.2: Weighted-additive trust formula.
                // Structural = Sybil resistance × chain health.
                // Behavioral = quality-weighted track record (value-weighted recency).
                // Confidence scales from 0→1 over cold_start_threshold interactions.
                // Research: trust-differentiation-fixes P1, network-ecology-control principle #6.
                let structural = connectivity.min(1.0) * integrity;
                let behavioral = recency;
                let confidence_scale =
                    (interactions as f64 / self.config.cold_start_threshold.max(1) as f64).min(1.0);
                let trust_score =
                    ((0.3 * structural + 0.7 * behavioral) * confidence_scale).clamp(0.0, 1.0);

                // Layer 4.1: Graduated sanctions (Ostrom 1990).
                let sr = crate::sanctions::compute_sanctions(
                    timeout_count,
                    avg_quality,
                    false,
                    &crate::sanctions::SanctionConfig::default(),
                );

                // Layer 4.4: Forgiveness (Josang 2007, Axelrod 1984).
                let good_since = Self::count_good_since_violation(&filtered_chain);
                let forgiveness_severity = sr
                    .violations
                    .first()
                    .map(|v| crate::forgiveness::RecoverySeverity::from(v.severity))
                    .unwrap_or(crate::forgiveness::RecoverySeverity::Liveness);
                let forgiven_penalty = crate::forgiveness::apply_forgiveness(
                    sr.total_penalty,
                    good_since,
                    forgiveness_severity,
                    &crate::forgiveness::ForgivenessConfig::default(),
                );
                let forgiveness_factor = if sr.total_penalty > 1e-12 {
                    forgiven_penalty / sr.total_penalty
                } else {
                    1.0
                };

                // Layer 5.1-5.3: Behavioral detection + collusion signals.
                let (beh, sel, col) = self.compute_layer5_signals(pubkey, &filtered_chain);

                return Ok(TrustEvidence {
                    trust_score,
                    connectivity,
                    integrity,
                    diversity,
                    recency,
                    unique_peers,
                    interactions,
                    fraud: false,
                    path_diversity: path_div,
                    audit_count,
                    avg_quality,
                    value_weighted_recency,
                    timeout_count,
                    confidence,
                    sample_size,
                    positive_count,
                    beta_reputation,
                    required_deposit_ratio: (1.0 - trust_score).clamp(0.0, 1.0),
                    sanction_penalty: forgiven_penalty,
                    violation_count: sr.violation_count,
                    correlation_penalty: 0.0,
                    forgiveness_factor,
                    good_interactions_since_violation: good_since,
                    behavioral_change: beh.change_magnitude,
                    behavioral_anomaly: beh.is_anomalous,
                    selective_scamming: sel.is_selective,
                    collusion_cluster_density: col.cluster_density,
                    collusion_external_ratio: col.external_connection_ratio,
                    collusion_temporal_burst: col.temporal_burst,
                    collusion_reciprocity_anomaly: col.reciprocity_anomaly,
                    requester_trust: None,
                    payment_reliability: None,
                    rating_fairness: None,
                    dispute_rate: None,
                });
            }
        }

        // No seeds configured — no Sybil resistance. Weighted-additive with
        // connectivity=1.0 (no topology to measure). Confidence still scales by interactions.
        let confidence_scale =
            (interactions as f64 / self.config.cold_start_threshold.max(1) as f64).min(1.0);
        let trust_score_no_seeds =
            ((0.3 * integrity + 0.7 * recency) * confidence_scale).clamp(0.0, 1.0);

        // Layer 4.1: Graduated sanctions (Ostrom 1990).
        let sr_no_seeds = crate::sanctions::compute_sanctions(
            timeout_count,
            avg_quality,
            false,
            &crate::sanctions::SanctionConfig::default(),
        );

        // Layer 4.4: Forgiveness (Josang 2007, Axelrod 1984).
        let good_since_ns = Self::count_good_since_violation(&filtered_chain);
        let forgiveness_severity_ns = sr_no_seeds
            .violations
            .first()
            .map(|v| crate::forgiveness::RecoverySeverity::from(v.severity))
            .unwrap_or(crate::forgiveness::RecoverySeverity::Liveness);
        let forgiven_penalty_ns = crate::forgiveness::apply_forgiveness(
            sr_no_seeds.total_penalty,
            good_since_ns,
            forgiveness_severity_ns,
            &crate::forgiveness::ForgivenessConfig::default(),
        );
        let forgiveness_factor_ns = if sr_no_seeds.total_penalty > 1e-12 {
            forgiven_penalty_ns / sr_no_seeds.total_penalty
        } else {
            1.0
        };

        // Layer 5.1-5.3: Behavioral detection + collusion signals.
        let (beh_ns, sel_ns, col_ns) = self.compute_layer5_signals(pubkey, &filtered_chain);

        Ok(TrustEvidence {
            trust_score: trust_score_no_seeds,
            connectivity: 1.0,
            integrity,
            diversity: 1.0,
            recency,
            unique_peers,
            interactions,
            fraud: false,
            path_diversity: 0.0,
            audit_count,
            avg_quality,
            value_weighted_recency,
            timeout_count,
            confidence,
            sample_size,
            positive_count,
            beta_reputation,
            required_deposit_ratio: (1.0 - trust_score_no_seeds).clamp(0.0, 1.0),
            sanction_penalty: forgiven_penalty_ns,
            violation_count: sr_no_seeds.violation_count,
            correlation_penalty: 0.0,
            forgiveness_factor: forgiveness_factor_ns,
            good_interactions_since_violation: good_since_ns,
            behavioral_change: beh_ns.change_magnitude,
            behavioral_anomaly: beh_ns.is_anomalous,
            selective_scamming: sel_ns.is_selective,
            collusion_cluster_density: col_ns.cluster_density,
            collusion_external_ratio: col_ns.external_connection_ratio,
            collusion_temporal_burst: col_ns.temporal_burst,
            collusion_reciprocity_anomaly: col_ns.reciprocity_anomaly,
            requester_trust: None,
            payment_reliability: None,
            rating_fairness: None,
            dispute_rate: None,
        })
    }

    /// Compute Layer 5 signals: behavioral change, selective targeting, collusion.
    ///
    /// Encapsulates all partitioning and chain-loading logic so it can be called
    /// from both seeded and no-seeds paths without duplication.
    fn compute_layer5_signals(
        &self,
        pubkey: &str,
        filtered_chain: &[crate::halfblock::HalfBlock],
    ) -> (
        crate::behavioral::BehavioralAnalysis,
        crate::behavioral::SelectiveTargetingResult,
        crate::collusion::CollusionSignals,
    ) {
        let beh_config = crate::behavioral::BehavioralConfig::default();
        let col_config = crate::collusion::CollusionConfig::default();

        // Extract quality values for behavioral change detection.
        let qualities: Vec<f64> = filtered_chain
            .iter()
            .map(|b| Self::extract_quality(&b.transaction))
            .collect();

        // L5.1: Behavioral change detection.
        let behavioral = crate::behavioral::detect_behavioral_change(&qualities, &beh_config);

        // Build peer interaction counts for L5.2 + L5.3.
        let mut peer_counts: std::collections::HashMap<&str, usize> =
            std::collections::HashMap::new();
        for block in filtered_chain {
            if block.public_key != block.link_public_key {
                *peer_counts.entry(&block.link_public_key).or_insert(0) += 1;
            }
        }

        // L5.2: Selective scamming — partition by counterparty "newness".
        // "established" = appeared >2 times in target's chain.
        let mut qualities_to_new: Vec<f64> = Vec::new();
        let mut qualities_to_established: Vec<f64> = Vec::new();
        for block in filtered_chain {
            if block.public_key == block.link_public_key {
                continue; // skip self-referencing audit blocks
            }
            let q = Self::extract_quality(&block.transaction);
            let count = peer_counts
                .get(block.link_public_key.as_str())
                .copied()
                .unwrap_or(0);
            if count > 2 {
                qualities_to_established.push(q);
            } else {
                qualities_to_new.push(q);
            }
        }
        let selective = crate::behavioral::detect_selective_targeting(
            &qualities_to_new,
            &qualities_to_established,
            &beh_config,
        );

        // L5.3: Collusion signals — reciprocity + concentration from target's chain.
        // Load peer chains for reciprocity check (same pattern as count_timeouts).
        let mut reciprocity_map: std::collections::HashMap<&str, (Vec<f64>, Vec<f64>)> =
            std::collections::HashMap::new();

        // Quality given to each peer (from target's chain).
        for block in filtered_chain {
            if block.public_key == block.link_public_key {
                continue;
            }
            let q = Self::extract_quality(&block.transaction);
            reciprocity_map
                .entry(&block.link_public_key)
                .or_insert_with(|| (Vec::new(), Vec::new()))
                .0
                .push(q);
        }

        // Quality received from each peer (from peer's chain where they interact with target).
        for peer_pk in peer_counts.keys() {
            if let Ok(peer_chain) = self.store.get_chain(peer_pk) {
                for block in &peer_chain {
                    if block.link_public_key == pubkey {
                        let q = Self::extract_quality(&block.transaction);
                        reciprocity_map
                            .entry(peer_pk)
                            .or_insert_with(|| (Vec::new(), Vec::new()))
                            .1
                            .push(q);
                    }
                }
            }
        }

        let reciprocity_pairs: Vec<(f64, f64, usize)> = reciprocity_map
            .values()
            .map(|(given, received)| {
                let avg_given = if given.is_empty() {
                    0.0
                } else {
                    given.iter().sum::<f64>() / given.len() as f64
                };
                let avg_received = if received.is_empty() {
                    0.0
                } else {
                    received.iter().sum::<f64>() / received.len() as f64
                };
                let count = given.len().min(received.len());
                (avg_given, avg_received, count)
            })
            .collect();

        let mut sorted_counts: Vec<usize> = peer_counts.values().copied().collect();
        sorted_counts.sort_unstable_by(|a, b| b.cmp(a));

        let collusion = crate::collusion::detect_collusion(
            0.0,   // cluster_density: deferred (requires ego-network traversal)
            0.0,   // external_ratio: deferred
            false, // temporal_burst: deferred
            &reciprocity_pairs,
            &sorted_counts,
            filtered_chain.len(),
            &col_config,
        );

        (behavioral, selective, collusion)
    }

    /// Inner recency computation with optional virtual negative outcomes (timeouts).
    ///
    /// `extra_negatives` adds virtual quality=0.0 entries with weight 1.0 (latest weight),
    /// representing expired proposals the agent failed to respond to.
    fn compute_recency_inner(
        &self,
        chain: &[crate::halfblock::HalfBlock],
        extra_negatives: usize,
    ) -> f64 {
        if chain.is_empty() && extra_negatives == 0 {
            return 0.5;
        }
        let lambda = self.config.recency_lambda;
        let n = chain.len();
        let avg_price = Self::compute_avg_price(chain);
        let forgiveness_config = crate::forgiveness::ForgivenessConfig::default();
        let mut weighted_sum = 0.0;
        let mut weight_total = 0.0;
        for (k, block) in chain.iter().enumerate() {
            let quality = Self::extract_quality(&block.transaction);
            // Layer 4.4: Asymmetric decay — negative outcomes decay faster.
            let age = (n - 1 - k) as i32;
            let is_negative = quality < 0.5;
            let decay = crate::forgiveness::asymmetric_decay_weight(
                lambda,
                age,
                is_negative,
                forgiveness_config.negative_decay_speedup,
            );
            let price = Self::extract_price(&block.transaction);
            let value_weight = if avg_price > 1e-10 {
                price / avg_price
            } else {
                1.0
            };
            let weight = decay * value_weight;
            weighted_sum += weight * quality;
            weight_total += weight;
        }
        // Add virtual negative outcomes for timeouts (quality=0.0, weight=1.0).
        // These use weight 1.0 (equivalent to most recent entry) to ensure
        // unresponsiveness has immediate impact on trust.
        weight_total += extra_negatives as f64;
        // weighted_sum += 0.0 * extra_negatives (no-op, quality is zero)

        if weight_total < 1e-10 {
            return 0.5;
        }
        (weighted_sum / weight_total).clamp(0.0, 1.0)
    }

    /// Extract quality signal from a block's transaction data.
    ///
    /// Fallback chain (first present value wins):
    ///   1. `quality` field (continuous 0.0–1.0)
    ///   2. `requester_rating` field (continuous 0.0–1.0)
    ///   3. `provider_rating` field (continuous 0.0–1.0)
    ///   4. Binary outcome: "completed"/"success" → 1.0, "failed"/"error" → 0.0
    ///   5. Unknown → 1.0 (backward compat)
    ///
    /// Research: trust-differentiation-fixes P0, reputation-game-theory §3.
    fn extract_quality(transaction: &serde_json::Value) -> f64 {
        // 0. Layer 4.3: Check for sealed rating (commit-reveal protocol).
        // If a verified revealed rating exists, use it.
        if let Some(sealed) = crate::sealed_rating::extract_sealed_rating(transaction) {
            return sealed.clamp(0.0, 1.0);
        }
        // If sealed but not yet revealed (pending), use backward-compat default.
        if transaction.get("rating_commitment").is_some()
            && transaction.get("revealed_rating").is_none()
        {
            return 1.0; // Pending reveal: don't use any quality field
        }

        // 1. Explicit quality field
        if let Some(q) = transaction.get("quality").and_then(|v| v.as_f64()) {
            return q.clamp(0.0, 1.0);
        }
        // 2. Requester's rating of the provider
        if let Some(r) = transaction.get("requester_rating").and_then(|v| v.as_f64()) {
            return r.clamp(0.0, 1.0);
        }
        // 3. Provider's rating of the requester
        if let Some(r) = transaction.get("provider_rating").and_then(|v| v.as_f64()) {
            return r.clamp(0.0, 1.0);
        }
        // 4. Binary outcome (backward compat)
        Self::extract_binary_outcome(transaction)
    }

    /// Extract binary outcome from a block's transaction data.
    ///
    /// "completed" / "success" → 1.0, "failed" / "error" → 0.0.
    /// Missing or unknown → 1.0 (backward compat: assume success).
    fn extract_binary_outcome(transaction: &serde_json::Value) -> f64 {
        match transaction.get("outcome").and_then(|v| v.as_str()) {
            Some("completed") | Some("success") => 1.0,
            Some("failed") | Some("error") => 0.0,
            _ => 1.0, // backward compat: unknown = success
        }
    }

    /// Count consecutive good interactions (quality >= 0.5) since the last violation.
    ///
    /// Scans the chain from most recent backward, counting interactions with
    /// quality >= 0.5 until hitting a violation (quality < 0.3 or failed outcome).
    /// Returns 0 if the most recent interaction is a violation.
    ///
    /// Used for Layer 4.4 forgiveness computation.
    fn count_good_since_violation(chain: &[crate::halfblock::HalfBlock]) -> usize {
        let mut count = 0usize;
        for block in chain.iter().rev() {
            let quality = Self::extract_quality(&block.transaction);
            if quality < 0.3 {
                break; // Hit a violation
            }
            if quality >= 0.5 {
                count += 1;
            }
            // quality in [0.3, 0.5) — not good, not a violation, doesn't break streak
        }
        count
    }

    /// Extract price from a block's transaction, defaulting to 1.0 if absent.
    fn extract_price(transaction: &serde_json::Value) -> f64 {
        transaction
            .get("price")
            .and_then(|v| v.as_f64())
            .unwrap_or(1.0)
            .max(0.0)
    }

    /// Compute average quality across a chain.
    ///
    /// Returns 0.0 for empty chains (no data = no quality evidence).
    fn compute_avg_quality(chain: &[crate::halfblock::HalfBlock]) -> f64 {
        if chain.is_empty() {
            return 0.0;
        }
        let sum: f64 = chain
            .iter()
            .map(|b| Self::extract_quality(&b.transaction))
            .sum();
        sum / chain.len() as f64
    }

    /// Compute average transaction price across a chain.
    ///
    /// Returns 1.0 for empty chains (no data = unit price default).
    /// Research: risk-scaled-trust-thresholds §9.6, Olariu et al. 2024.
    fn compute_avg_price(chain: &[crate::halfblock::HalfBlock]) -> f64 {
        if chain.is_empty() {
            return 1.0;
        }
        let sum: f64 = chain
            .iter()
            .map(|b| Self::extract_price(&b.transaction))
            .sum();
        let avg = sum / chain.len() as f64;
        if avg < 1e-10 {
            1.0
        } else {
            avg
        }
    }

    /// Wilson lower-bound confidence score.
    ///
    /// Returns the lower bound of a Wilson score confidence interval:
    /// high for many positive interactions, low for few or mixed interactions.
    /// z = 1.96 gives 95% confidence interval.
    ///
    /// Research: Evan Miller 2009 "How Not To Sort By Average Rating",
    /// TRAVOS (Teacy et al. 2006): Beta distribution confidence.
    pub fn wilson_lower_bound(positive: f64, total: f64, z: f64) -> f64 {
        if total == 0.0 {
            return 0.0;
        }
        let p = positive / total;
        let d = 1.0 + z * z / total;
        let center = p + z * z / (2.0 * total);
        let spread = z * ((p * (1.0 - p) + z * z / (4.0 * total)) / total).sqrt();
        ((center - spread) / d).max(0.0)
    }

    /// Beta reputation model: continuous Bayesian updating with temporal decay.
    ///
    /// Unifies cold start + continuous feedback + temporal decay in a single model.
    /// Returns `None` for empty chains, `Some(score)` otherwise.
    ///
    /// Parameters: `lambda = 0.95` (temporal decay per interaction).
    /// Prior: `alpha = 1.0, beta = 1.0` (uninformative).
    ///
    /// Research: Josang & Ismail 2002, Josang, Luo, Chen 2008.
    fn beta_reputation(chain: &[crate::halfblock::HalfBlock]) -> Option<f64> {
        if chain.is_empty() {
            return None;
        }
        let lambda = 0.95_f64;
        let mut alpha = 1.0_f64; // prior
        let mut beta_param = 1.0_f64; // prior
        for block in chain {
            let quality = Self::extract_quality(&block.transaction);
            alpha = lambda * alpha + quality;
            beta_param = lambda * beta_param + (1.0 - quality);
        }
        let score = alpha / (alpha + beta_param);
        Some(score.clamp(0.0, 1.0))
    }

    /// Count expired orphan proposals directed at the given pubkey (timeouts).
    ///
    /// Scans counterparties' chains for proposals where `link_public_key == pubkey`
    /// that have `deadline_ms` set, the deadline has passed, and no agreement from
    /// the target agent exists.
    ///
    /// Research: trust-model-gaps §4 "Timeout Enforcement".
    fn count_timeouts(&self, pubkey: &str, chain: &[crate::halfblock::HalfBlock]) -> usize {
        // Collect counterparties from the target's chain.
        let mut counterparties: HashSet<String> = HashSet::new();
        for block in chain {
            if block.public_key != block.link_public_key {
                counterparties.insert(block.link_public_key.clone());
            }
        }

        // Get current time (or latest block timestamp as proxy).
        let now_ms = chain.iter().map(|b| b.timestamp).max().unwrap_or_else(|| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64
        });

        let mut timeout_count = 0usize;

        for cp_pubkey in &counterparties {
            let cp_chain = match self.store.get_chain(cp_pubkey) {
                Ok(c) => c,
                Err(_) => continue,
            };

            for block in &cp_chain {
                // Only look at proposals directed at our target.
                if block.block_type != "proposal" || block.link_public_key != pubkey {
                    continue;
                }

                // Check if deadline_ms exists and has expired.
                let deadline = match block
                    .transaction
                    .get("deadline_ms")
                    .and_then(|v| v.as_u64())
                {
                    Some(d) if d < now_ms => d,
                    _ => continue,
                };

                // Check if the target has a matching agreement.
                let has_agreement = matches!(self.store.get_linked_block(block), Ok(Some(_)));

                if !has_agreement {
                    timeout_count += 1;
                    let _ = deadline; // used in the condition above
                }
            }
        }

        timeout_count
    }

    /// Count unique peers (distinct link_public_keys) in a chain.
    fn count_unique_peers(&self, chain: &[crate::halfblock::HalfBlock]) -> usize {
        let mut peers: HashSet<&str> = HashSet::new();
        for block in chain {
            if block.public_key != block.link_public_key {
                peers.insert(&block.link_public_key);
            }
        }
        peers.len()
    }

    // -----------------------------------------------------------------------
    // Layer 6.1: Requester reputation (PeerTrust, Xiong & Liu 2004)
    // -----------------------------------------------------------------------

    /// Get blocks from counterparties' chains where they record interactions
    /// with `pubkey` as the requester (initiator).
    ///
    /// For each peer that `pubkey` has interacted with, loads the peer's chain
    /// and returns blocks where `link_public_key == pubkey` (the peer's record
    /// about this agent).
    fn get_requester_chain(&self, pubkey: &str) -> Vec<crate::halfblock::HalfBlock> {
        let own_chain = match self.store.get_chain(pubkey) {
            Ok(c) => c,
            Err(_) => return Vec::new(),
        };

        // Collect unique counterparties.
        let mut peers: HashSet<&str> = HashSet::new();
        for block in &own_chain {
            if block.public_key != block.link_public_key {
                peers.insert(&block.link_public_key);
            }
        }

        // Load each peer's chain, filter for blocks referencing pubkey.
        let mut requester_chain = Vec::new();
        for peer_pk in &peers {
            if let Ok(peer_chain) = self.store.get_chain(peer_pk) {
                for block in peer_chain {
                    if block.link_public_key == pubkey {
                        requester_chain.push(block);
                    }
                }
            }
        }
        requester_chain
    }

    /// Fraction of requester-chain interactions with successful outcome.
    ///
    /// Returns 1.0 if the chain is empty (benefit of doubt for new agents).
    fn compute_payment_reliability(chain: &[crate::halfblock::HalfBlock]) -> f64 {
        if chain.is_empty() {
            return 1.0;
        }
        let paid = chain
            .iter()
            .filter(|b| {
                let tx = &b.transaction;
                // Check explicit payment status first.
                if let Some(status) = tx.get("payment_status").and_then(|v| v.as_str()) {
                    return status == "completed" || status == "paid";
                }
                // Fall back to quality >= 0.5 (general success signal).
                Self::extract_quality(tx) >= 0.5
            })
            .count();
        paid as f64 / chain.len() as f64
    }

    /// Agreement between this requester's ratings and consensus (provider avg quality).
    ///
    /// For each provider this requester interacted with, compares the requester's
    /// rating with the provider's average quality across all interactions.
    /// Returns `None` if fewer than 3 providers were rated (insufficient data).
    fn compute_rating_fairness(
        &self,
        _requester_chain: &[crate::halfblock::HalfBlock],
        pubkey: &str,
    ) -> Option<f64> {
        // Get own chain to extract requester's ratings of each provider.
        let own_chain = match self.store.get_chain(pubkey) {
            Ok(c) => c,
            Err(_) => return None,
        };

        // Map provider_pubkey → requester's rating of that provider.
        let mut requester_ratings: HashMap<&str, Vec<f64>> = HashMap::new();
        for block in &own_chain {
            if block.public_key == block.link_public_key {
                continue; // skip audit blocks
            }
            let rating = block
                .transaction
                .get("requester_rating")
                .and_then(|v| v.as_f64())
                .or_else(|| block.transaction.get("quality").and_then(|v| v.as_f64()));
            if let Some(r) = rating {
                requester_ratings
                    .entry(&block.link_public_key)
                    .or_default()
                    .push(r);
            }
        }

        if requester_ratings.len() < 3 {
            return None; // insufficient data
        }

        // For each rated provider, compute consensus (avg quality from provider's chain).
        let mut deviations = Vec::new();
        for (provider_pk, ratings) in &requester_ratings {
            if let Ok(provider_chain) = self.store.get_chain(provider_pk) {
                if provider_chain.is_empty() {
                    continue;
                }
                let consensus = Self::compute_avg_quality(&provider_chain);
                let avg_rating = ratings.iter().sum::<f64>() / ratings.len() as f64;
                deviations.push((avg_rating - consensus).abs());
            }
        }

        if deviations.is_empty() {
            return None;
        }

        let avg_deviation = deviations.iter().sum::<f64>() / deviations.len() as f64;
        Some((1.0 - avg_deviation).clamp(0.0, 1.0))
    }

    /// Fraction of requester-chain interactions resulting in disputes.
    ///
    /// Returns 0.0 if the chain is empty.
    fn compute_dispute_rate(chain: &[crate::halfblock::HalfBlock]) -> f64 {
        if chain.is_empty() {
            return 0.0;
        }
        let disputed = chain
            .iter()
            .filter(|b| {
                let tx = &b.transaction;
                tx.get("outcome")
                    .and_then(|v| v.as_str())
                    .is_some_and(|o| o == "disputed")
                    || tx.get("dispute").and_then(|v| v.as_bool()).unwrap_or(false)
            })
            .count();
        disputed as f64 / chain.len() as f64
    }

    /// Compute trust from the requester (initiator) perspective.
    ///
    /// Uses the same weighted-additive formula but evaluates this agent's
    /// behavior as a requester: payment reliability, rating fairness, dispute rate.
    /// Returns a full `TrustEvidence` with the 4 requester-specific fields populated.
    ///
    /// Research: trust-model-gaps §6, PeerTrust (Xiong & Liu 2004).
    pub fn compute_requester_trust(&self, pubkey: &str) -> Result<TrustEvidence> {
        // Start with standard provider-perspective evidence.
        let mut evidence = self.compute_standard_trust_evidence(pubkey, None)?;

        // Get the requester chain (counterparties' blocks about this agent).
        let requester_chain = self.get_requester_chain(pubkey);

        // Compute requester-perspective recency using counterparties' quality ratings.
        let requester_recency = if requester_chain.is_empty() {
            0.5 // uninformative prior
        } else {
            self.compute_recency_inner(&requester_chain, 0)
        };

        // Requester trust uses same formula: structural from standard + requester behavioral.
        let confidence_scale = (evidence.interactions as f64
            / self.config.cold_start_threshold.max(1) as f64)
            .min(1.0);
        let structural = evidence.connectivity * evidence.integrity;
        let requester_score =
            ((0.3 * structural + 0.7 * requester_recency) * confidence_scale).clamp(0.0, 1.0);

        // Populate the 4 requester-specific fields.
        evidence.requester_trust = Some(requester_score);
        evidence.payment_reliability = Some(Self::compute_payment_reliability(&requester_chain));
        evidence.rating_fairness = self.compute_rating_fairness(&requester_chain, pubkey);
        evidence.dispute_rate = Some(Self::compute_dispute_rate(&requester_chain));

        Ok(evidence)
    }

    /// Compute trust with full evidence bundle (delegation-aware).
    pub fn compute_trust_with_evidence(&self, pubkey: &str) -> Result<TrustEvidence> {
        self.compute_trust_with_evidence_ctx(pubkey, None)
    }

    /// Compute trust with full evidence bundle and optional context filter.
    pub fn compute_trust_with_evidence_ctx(
        &self,
        pubkey: &str,
        context: Option<&str>,
    ) -> Result<TrustEvidence> {
        // Check delegation context
        if let Some(ref ctx) = self.delegation_ctx {
            // Is this an active delegated identity?
            if let Some(ref _delegation) = ctx.active_delegation {
                if let Some(ref root_pubkey) = ctx.root_pubkey {
                    // Root evidence uses full context — delegator's overall trust.
                    let root_evidence = self.compute_standard_trust_evidence(root_pubkey, None)?;
                    // Use cold start blending for the score
                    let blended_score =
                        self.compute_delegated_trust_blended(pubkey, root_pubkey, ctx, context)?;
                    return Ok(TrustEvidence {
                        trust_score: blended_score,
                        connectivity: root_evidence.connectivity,
                        integrity: root_evidence.integrity,
                        diversity: root_evidence.diversity,
                        recency: root_evidence.recency,
                        unique_peers: root_evidence.unique_peers,
                        interactions: root_evidence.interactions,
                        fraud: false,
                        path_diversity: root_evidence.path_diversity,
                        audit_count: root_evidence.audit_count,
                        avg_quality: root_evidence.avg_quality,
                        value_weighted_recency: root_evidence.value_weighted_recency,
                        timeout_count: root_evidence.timeout_count,
                        confidence: root_evidence.confidence,
                        sample_size: root_evidence.sample_size,
                        positive_count: root_evidence.positive_count,
                        beta_reputation: root_evidence.beta_reputation,
                        required_deposit_ratio: root_evidence.required_deposit_ratio,
                        sanction_penalty: root_evidence.sanction_penalty,
                        violation_count: root_evidence.violation_count,
                        correlation_penalty: root_evidence.correlation_penalty,
                        forgiveness_factor: root_evidence.forgiveness_factor,
                        good_interactions_since_violation: root_evidence
                            .good_interactions_since_violation,
                        behavioral_change: root_evidence.behavioral_change,
                        behavioral_anomaly: root_evidence.behavioral_anomaly,
                        selective_scamming: root_evidence.selective_scamming,
                        collusion_cluster_density: root_evidence.collusion_cluster_density,
                        collusion_external_ratio: root_evidence.collusion_external_ratio,
                        collusion_temporal_burst: root_evidence.collusion_temporal_burst,
                        collusion_reciprocity_anomaly: root_evidence.collusion_reciprocity_anomaly,
                        requester_trust: root_evidence.requester_trust,
                        payment_reliability: root_evidence.payment_reliability,
                        rating_fairness: root_evidence.rating_fairness,
                        dispute_rate: root_evidence.dispute_rate,
                    });
                }
            }

            // Was a delegate whose delegation is no longer active -> 0
            if ctx.was_delegate && ctx.active_delegation.is_none() {
                return Ok(TrustEvidence {
                    trust_score: 0.0,
                    connectivity: 0.0,
                    integrity: 0.0,
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
                });
            }

            // Check if any delegate committed fraud
            for d in &ctx.delegations_as_delegator {
                let delegate_frauds = self.store.get_double_spends(&d.delegate_pubkey)?;
                if !delegate_frauds.is_empty() {
                    return Ok(TrustEvidence {
                        trust_score: 0.0,
                        connectivity: 0.0,
                        integrity: 0.0,
                        diversity: 0.0,
                        recency: 0.0,
                        unique_peers: 0,
                        interactions: 0,
                        fraud: true,
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
                        sanction_penalty: 1.0,
                        violation_count: 1,
                        correlation_penalty: 1.0,
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
                    });
                }
            }
        }

        self.compute_standard_trust_evidence(pubkey, context)
    }

    /// Compute chain integrity score (fraction of valid blocks from start).
    ///
    /// When a finalized checkpoint is attached via `with_checkpoint()`, blocks
    /// with sequence ≤ the checkpoint head are trusted (only structural checks,
    /// no Ed25519 verification). Blocks after the checkpoint are fully verified.
    pub fn compute_chain_integrity(&self, pubkey: &str) -> Result<f64> {
        let chain = self.store.get_chain(pubkey)?;
        if chain.is_empty() {
            return Ok(1.0);
        }

        // Determine checkpoint-covered sequence for this pubkey.
        let checkpoint_seq = self
            .checkpoint
            .as_ref()
            .filter(|cp| cp.finalized)
            .and_then(|cp| cp.chain_heads.get(pubkey))
            .copied()
            .unwrap_or(0);

        let total = chain.len() as f64;
        for (i, block) in chain.iter().enumerate() {
            let expected_seq = (i as u64) + 1;
            if block.sequence_number != expected_seq {
                // Tolerate gaps caused by self-signed blocks (checkpoint/audit)
                // that remote peers can't receive via bilateral gossip.
                // Check if the gap is small and the chain is otherwise consistent.
                if i == 0 && block.sequence_number <= 3 {
                    // Missing initial checkpoint/audit blocks — common for remote views.
                    // Treat as valid: integrity covers what we CAN verify.
                    continue;
                }
                // For mid-chain gaps, allow if the gap is 1-2 blocks (likely checkpoints).
                if i > 0 && block.sequence_number <= chain[i - 1].sequence_number + 3 {
                    continue;
                }
                return Ok(i as f64 / total);
            }

            // Verify previous_hash linkage (skip if gap exists from missing blocks).
            if i == 0 {
                // First block we have — if it's not seq=1, we can't verify prev_hash
                // against genesis because intermediate blocks are missing.
                if block.sequence_number == 1 && block.previous_hash != GENESIS_HASH {
                    return Ok(0.0);
                }
            } else {
                // Consecutive blocks: verify hash chain.
                // Only check if sequences are actually consecutive.
                if block.sequence_number == chain[i - 1].sequence_number + 1
                    && block.previous_hash != chain[i - 1].block_hash
                {
                    return Ok(i as f64 / total);
                }
            }

            // Skip Ed25519 verification for blocks covered by the checkpoint.
            if block.sequence_number <= checkpoint_seq {
                continue;
            }

            if !crate::halfblock::verify_block(block).unwrap_or(false) {
                return Ok(i as f64 / total);
            }
        }

        Ok(1.0)
    }

    /// Compute the raw path diversity (max-flow or MeritRank) for Sybil resistance.
    pub fn compute_path_diversity_score(&self, pubkey: &str) -> Result<f64> {
        match &self.seed_nodes {
            Some(seeds) if !seeds.is_empty() => match &self.config.algorithm {
                TrustAlgorithm::NetFlow => {
                    let nf = NetFlowTrust::new(self.store, seeds.clone())?;
                    nf.compute_path_diversity(pubkey)
                }
                #[cfg(feature = "meritrank")]
                TrustAlgorithm::MeritRank { num_walks } => {
                    let mr = MeritRankTrust::new(self.store, seeds.clone(), Some(*num_walks))?;
                    mr.compute_path_diversity(pubkey)
                }
            },
            _ => Ok(0.0),
        }
    }

    /// Compute the path diversity using an external `CachedNetFlow` instance.
    ///
    /// This amortizes graph construction cost across multiple trust queries.
    /// The caller is responsible for providing a `CachedNetFlow` with a compatible store.
    pub fn compute_path_diversity_cached<CS: BlockStore>(
        &self,
        cached: &mut CachedNetFlow<CS>,
        pubkey: &str,
    ) -> Result<f64> {
        cached.compute_path_diversity(pubkey)
    }
}

// ---------------------------------------------------------------------------
// Audit report — summary of a single agent's audit chain
// ---------------------------------------------------------------------------

/// Summary report of an agent's audit chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditReport {
    /// Total blocks in the chain (audit + bilateral).
    pub total_blocks: usize,
    /// Number of audit blocks (self-referencing, single-player).
    pub audit_blocks: usize,
    /// Number of bilateral blocks (proposals + agreements).
    pub bilateral_blocks: usize,
    /// Whether the entire chain passes integrity validation.
    pub integrity_valid: bool,
    /// Integrity score: fraction of valid blocks before first error (0.0-1.0).
    pub integrity_score: f64,
    /// Breakdown of audit blocks by event_type field in transaction JSON.
    pub event_type_breakdown: HashMap<String, usize>,
    /// Timestamp of the first block (ms since epoch), if any.
    pub first_timestamp: Option<u64>,
    /// Timestamp of the last block (ms since epoch), if any.
    pub last_timestamp: Option<u64>,
    /// Total chain length (same as total_blocks, for clarity).
    pub chain_length: usize,
}

impl<S: BlockStore> TrustEngine<'_, S> {
    /// Compute an audit report for the given public key.
    pub fn compute_audit_report(&self, pubkey: &str) -> Result<AuditReport> {
        let chain = self.store.get_chain(pubkey)?;
        let total_blocks = chain.len();

        let mut audit_blocks = 0usize;
        let mut bilateral_blocks = 0usize;
        let mut event_type_breakdown: HashMap<String, usize> = HashMap::new();
        let mut first_timestamp: Option<u64> = None;
        let mut last_timestamp: Option<u64> = None;

        for block in &chain {
            if first_timestamp.is_none() {
                first_timestamp = Some(block.timestamp);
            }
            last_timestamp = Some(block.timestamp);

            if block.block_type == "audit" {
                audit_blocks += 1;
                // Extract event_type from transaction JSON.
                if let Some(et) = block.transaction.get("event_type").and_then(|v| v.as_str()) {
                    *event_type_breakdown.entry(et.to_string()).or_insert(0) += 1;
                } else {
                    *event_type_breakdown
                        .entry("untyped".to_string())
                        .or_insert(0) += 1;
                }
            } else if block.block_type == "proposal" || block.block_type == "agreement" {
                bilateral_blocks += 1;
            }
        }

        // Compute integrity using the existing protocol method logic.
        let mut integrity_valid = true;
        let mut integrity_score = 1.0;

        if !chain.is_empty() {
            let total = chain.len() as f64;
            for (i, block) in chain.iter().enumerate() {
                let expected_seq = (i as u64) + 1;
                if block.sequence_number != expected_seq {
                    integrity_valid = false;
                    integrity_score = i as f64 / total;
                    break;
                }
                let expected_prev = if i == 0 {
                    GENESIS_HASH.to_string()
                } else {
                    chain[i - 1].block_hash.clone()
                };
                if block.previous_hash != expected_prev {
                    integrity_valid = false;
                    integrity_score = i as f64 / total;
                    break;
                }
                if !crate::halfblock::verify_block(block).unwrap_or(false) {
                    integrity_valid = false;
                    integrity_score = i as f64 / total;
                    break;
                }
            }
        }

        Ok(AuditReport {
            total_blocks,
            audit_blocks,
            bilateral_blocks,
            integrity_valid,
            integrity_score,
            event_type_breakdown,
            first_timestamp,
            last_timestamp,
            chain_length: total_blocks,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blockstore::MemoryBlockStore;
    use crate::halfblock::create_half_block;
    use crate::identity::Identity;
    use crate::types::BlockType;

    #[allow(clippy::too_many_arguments)]
    fn create_interaction(
        store: &mut MemoryBlockStore,
        alice: &Identity,
        bob: &Identity,
        alice_seq: u64,
        bob_seq: u64,
        alice_prev: &str,
        bob_prev: &str,
        ts: u64,
    ) -> (String, String) {
        let proposal = create_half_block(
            alice,
            alice_seq,
            &bob.pubkey_hex(),
            0,
            alice_prev,
            BlockType::Proposal,
            serde_json::json!({"service": "test"}),
            Some(ts),
        );
        store.add_block(&proposal).unwrap();

        let agreement = create_half_block(
            bob,
            bob_seq,
            &alice.pubkey_hex(),
            alice_seq,
            bob_prev,
            BlockType::Agreement,
            serde_json::json!({"service": "test"}),
            Some(ts + 1),
        );
        store.add_block(&agreement).unwrap();

        (proposal.block_hash, agreement.block_hash)
    }

    #[test]
    fn test_empty_chain_trust() {
        let store = MemoryBlockStore::new();
        let engine = TrustEngine::new(&store, None, None, None);
        let score = engine.compute_trust("unknown").unwrap();
        // Empty chain: integrity=1.0 (no seeds → integrity only).
        assert!((0.0..=1.0).contains(&score));
    }

    #[test]
    fn test_trust_with_interactions() {
        let mut store = MemoryBlockStore::new();
        let seed = Identity::from_bytes(&[1u8; 32]);
        let agent = Identity::from_bytes(&[2u8; 32]);

        create_interaction(
            &mut store,
            &seed,
            &agent,
            1,
            1,
            GENESIS_HASH,
            GENESIS_HASH,
            1000,
        );

        let engine = TrustEngine::new(&store, Some(vec![seed.pubkey_hex()]), None, None);

        let score = engine.compute_trust(&agent.pubkey_hex()).unwrap();
        assert!(
            score > 0.0,
            "agent with interaction should have positive trust"
        );
        assert!(score <= 1.0);
    }

    #[test]
    fn test_seed_node_high_trust() {
        let mut store = MemoryBlockStore::new();
        let seed = Identity::from_bytes(&[1u8; 32]);
        let agent = Identity::from_bytes(&[2u8; 32]);

        create_interaction(
            &mut store,
            &seed,
            &agent,
            1,
            1,
            GENESIS_HASH,
            GENESIS_HASH,
            1000,
        );

        let engine = TrustEngine::new(&store, Some(vec![seed.pubkey_hex()]), None, None);

        let seed_score = engine.compute_trust(&seed.pubkey_hex()).unwrap();
        assert!(
            seed_score > 0.5,
            "seed should have high trust: {seed_score}"
        );
    }

    #[test]
    fn test_no_netflow_redistribution() {
        let mut store = MemoryBlockStore::new();
        let agent = Identity::from_bytes(&[1u8; 32]);
        let peer = Identity::from_bytes(&[2u8; 32]);

        create_interaction(
            &mut store,
            &agent,
            &peer,
            1,
            1,
            GENESIS_HASH,
            GENESIS_HASH,
            1000,
        );

        // No seed nodes -> integrity only.
        let engine = TrustEngine::new(&store, None, None, None);
        let score = engine.compute_trust(&agent.pubkey_hex()).unwrap();
        assert!(score > 0.0 && score <= 1.0);
    }

    #[test]
    fn test_fraud_trust_penalty() {
        let mut store = MemoryBlockStore::new();
        let agent = Identity::from_bytes(&[1u8; 32]);
        let peer = Identity::from_bytes(&[2u8; 32]);

        // Give the agent a good history first.
        create_interaction(
            &mut store,
            &agent,
            &peer,
            1,
            1,
            GENESIS_HASH,
            GENESIS_HASH,
            1000,
        );

        // Without fraud, trust should be positive.
        let engine = TrustEngine::new(&store, None, None, None);
        let score_before = engine.compute_trust(&agent.pubkey_hex()).unwrap();
        assert!(
            score_before > 0.0,
            "should have positive trust before fraud"
        );

        // Record a double-spend fraud.
        let fake_a = create_half_block(
            &agent,
            2,
            &peer.pubkey_hex(),
            0,
            GENESIS_HASH,
            BlockType::Proposal,
            serde_json::json!({"version": "a"}),
            Some(2000),
        );
        let fake_b = create_half_block(
            &agent,
            2,
            &peer.pubkey_hex(),
            0,
            GENESIS_HASH,
            BlockType::Proposal,
            serde_json::json!({"version": "b"}),
            Some(2001),
        );
        store.add_double_spend(&fake_a, &fake_b).unwrap();

        // After fraud, trust should be hard zero.
        let engine = TrustEngine::new(&store, None, None, None);
        let score_after = engine.compute_trust(&agent.pubkey_hex()).unwrap();
        assert_eq!(score_after, 0.0, "trust should be 0.0 after fraud");
    }

    #[test]
    fn test_chain_integrity_perfect() {
        let mut store = MemoryBlockStore::new();
        let agent = Identity::from_bytes(&[1u8; 32]);
        let peer = Identity::from_bytes(&[2u8; 32]);

        create_interaction(
            &mut store,
            &agent,
            &peer,
            1,
            1,
            GENESIS_HASH,
            GENESIS_HASH,
            1000,
        );

        let engine = TrustEngine::new(&store, None, None, None);
        assert_eq!(
            engine.compute_chain_integrity(&agent.pubkey_hex()).unwrap(),
            1.0
        );
    }

    #[test]
    fn test_checkpoint_full_coverage() {
        // Checkpoint covers all blocks -> structural checks only, no verify.
        let mut store = MemoryBlockStore::new();
        let agent = Identity::from_bytes(&[1u8; 32]);
        let peer = Identity::from_bytes(&[2u8; 32]);

        let (p1, _) = create_interaction(
            &mut store,
            &agent,
            &peer,
            1,
            1,
            GENESIS_HASH,
            GENESIS_HASH,
            1000,
        );
        create_interaction(&mut store, &agent, &peer, 2, 2, &p1, GENESIS_HASH, 2000);

        let mut chain_heads = HashMap::new();
        chain_heads.insert(agent.pubkey_hex(), 2); // covers seq 1 and 2
        let checkpoint = crate::consensus::Checkpoint {
            facilitator_pubkey: "facilitator".into(),
            chain_heads,
            checkpoint_block: crate::halfblock::create_half_block(
                &peer,
                99,
                &agent.pubkey_hex(),
                0,
                GENESIS_HASH,
                BlockType::Proposal,
                serde_json::json!({}),
                Some(3000),
            ),
            signatures: HashMap::new(),
            timestamp: 3000,
            finalized: true,
        };

        let engine = TrustEngine::new(&store, None, None, None).with_checkpoint(checkpoint);
        let integrity = engine.compute_chain_integrity(&agent.pubkey_hex()).unwrap();
        assert_eq!(integrity, 1.0, "full checkpoint coverage should pass");
    }

    #[test]
    fn test_checkpoint_partial() {
        // Checkpoint covers first block only, second block also verified normally.
        let mut store = MemoryBlockStore::new();
        let agent = Identity::from_bytes(&[1u8; 32]);
        let peer = Identity::from_bytes(&[2u8; 32]);

        let (p1, _) = create_interaction(
            &mut store,
            &agent,
            &peer,
            1,
            1,
            GENESIS_HASH,
            GENESIS_HASH,
            1000,
        );
        create_interaction(&mut store, &agent, &peer, 2, 2, &p1, GENESIS_HASH, 2000);

        let mut chain_heads = HashMap::new();
        chain_heads.insert(agent.pubkey_hex(), 1); // covers only seq 1
        let checkpoint = crate::consensus::Checkpoint {
            facilitator_pubkey: "facilitator".into(),
            chain_heads,
            checkpoint_block: crate::halfblock::create_half_block(
                &peer,
                99,
                &agent.pubkey_hex(),
                0,
                GENESIS_HASH,
                BlockType::Proposal,
                serde_json::json!({}),
                Some(3000),
            ),
            signatures: HashMap::new(),
            timestamp: 3000,
            finalized: true,
        };

        let engine = TrustEngine::new(&store, None, None, None).with_checkpoint(checkpoint);
        let integrity = engine.compute_chain_integrity(&agent.pubkey_hex()).unwrap();
        assert_eq!(
            integrity, 1.0,
            "partial checkpoint should still validate remaining blocks"
        );
    }

    #[test]
    fn test_checkpoint_none_fallback() {
        // No checkpoint -> full verification (same as before).
        let mut store = MemoryBlockStore::new();
        let agent = Identity::from_bytes(&[1u8; 32]);
        let peer = Identity::from_bytes(&[2u8; 32]);

        create_interaction(
            &mut store,
            &agent,
            &peer,
            1,
            1,
            GENESIS_HASH,
            GENESIS_HASH,
            1000,
        );

        let engine = TrustEngine::new(&store, None, None, None);
        let integrity = engine.compute_chain_integrity(&agent.pubkey_hex()).unwrap();
        assert_eq!(integrity, 1.0);
    }

    #[test]
    fn test_checkpoint_unknown_pubkey() {
        // Checkpoint exists but doesn't cover this pubkey -> full verification.
        let mut store = MemoryBlockStore::new();
        let agent = Identity::from_bytes(&[1u8; 32]);
        let peer = Identity::from_bytes(&[2u8; 32]);

        create_interaction(
            &mut store,
            &agent,
            &peer,
            1,
            1,
            GENESIS_HASH,
            GENESIS_HASH,
            1000,
        );

        let checkpoint = crate::consensus::Checkpoint {
            facilitator_pubkey: "facilitator".into(),
            chain_heads: HashMap::new(), // empty — doesn't cover agent
            checkpoint_block: crate::halfblock::create_half_block(
                &peer,
                99,
                &agent.pubkey_hex(),
                0,
                GENESIS_HASH,
                BlockType::Proposal,
                serde_json::json!({}),
                Some(3000),
            ),
            signatures: HashMap::new(),
            timestamp: 3000,
            finalized: true,
        };

        let engine = TrustEngine::new(&store, None, None, None).with_checkpoint(checkpoint);
        let integrity = engine.compute_chain_integrity(&agent.pubkey_hex()).unwrap();
        assert_eq!(
            integrity, 1.0,
            "unknown pubkey in checkpoint should fall back to full verify"
        );
    }

    #[test]
    fn test_delegated_trust_budget_split() {
        let mut store = MemoryBlockStore::new();
        let root = Identity::from_bytes(&[1u8; 32]);
        let delegate1 = Identity::from_bytes(&[2u8; 32]);
        let peer = Identity::from_bytes(&[3u8; 32]);

        // Give root some trust.
        create_interaction(
            &mut store,
            &root,
            &peer,
            1,
            1,
            GENESIS_HASH,
            GENESIS_HASH,
            1000,
        );

        // Compute root's trust first.
        let engine_root = TrustEngine::new(&store, None, None, None);
        let root_trust = engine_root.compute_trust(&root.pubkey_hex()).unwrap();
        assert!(root_trust > 0.0);

        // Create delegation context: delegate1 is active delegate of root, 2 active delegations.
        let deleg = crate::delegation::DelegationRecord {
            delegation_id: "d1".to_string(),
            delegator_pubkey: root.pubkey_hex(),
            delegate_pubkey: delegate1.pubkey_hex(),
            scope: vec![],
            max_depth: 1,
            issued_at: 1000,
            expires_at: 999999,
            delegation_block_hash: "aa".repeat(32),
            agreement_block_hash: None,
            parent_delegation_id: None,
            revoked: false,
            revocation_block_hash: None,
        };
        let ctx = DelegationContext {
            active_delegation: Some(deleg),
            was_delegate: true,
            delegations_as_delegator: vec![],
            root_pubkey: Some(root.pubkey_hex()),
            root_active_delegation_count: 2,
            depth: 1,
        };

        let engine = TrustEngine::new(&store, None, None, Some(ctx));
        let delegate_trust = engine.compute_trust(&delegate1.pubkey_hex()).unwrap();
        // Cold start: 0 direct interactions → pure delegation trust
        // delegated = root_trust * delegation_factor / active_count
        let expected = root_trust * 0.8 / 2.0;
        assert!(
            (delegate_trust - expected).abs() < 1e-6,
            "delegate trust {delegate_trust} should be ~root*0.8/2 = {expected}"
        );
    }

    #[test]
    fn test_expired_delegate_zero_trust() {
        let store = MemoryBlockStore::new();
        let delegate = Identity::from_bytes(&[2u8; 32]);

        // was_delegate=true but no active delegation → trust should be 0.
        let ctx = DelegationContext {
            active_delegation: None,
            was_delegate: true,
            delegations_as_delegator: vec![],
            root_pubkey: None,
            root_active_delegation_count: 0,
            depth: 0,
        };

        let engine = TrustEngine::new(&store, None, None, Some(ctx));
        let trust = engine.compute_trust(&delegate.pubkey_hex()).unwrap();
        assert_eq!(trust, 0.0, "expired delegate should have zero trust");
    }

    #[test]
    fn test_delegate_fraud_propagates() {
        let mut store = MemoryBlockStore::new();
        let delegator = Identity::from_bytes(&[1u8; 32]);
        let delegate = Identity::from_bytes(&[2u8; 32]);
        let peer = Identity::from_bytes(&[3u8; 32]);

        // Give the delegator some trust.
        create_interaction(
            &mut store,
            &delegator,
            &peer,
            1,
            1,
            GENESIS_HASH,
            GENESIS_HASH,
            1000,
        );

        // Record delegate fraud (double-spend).
        let fake_a = create_half_block(
            &delegate,
            1,
            &peer.pubkey_hex(),
            0,
            GENESIS_HASH,
            BlockType::Proposal,
            serde_json::json!({"v": "a"}),
            Some(2000),
        );
        let fake_b = create_half_block(
            &delegate,
            1,
            &peer.pubkey_hex(),
            0,
            GENESIS_HASH,
            BlockType::Proposal,
            serde_json::json!({"v": "b"}),
            Some(2001),
        );
        store.add_double_spend(&fake_a, &fake_b).unwrap();

        // Delegator has this delegate in their delegations_as_delegator.
        let deleg_record = crate::delegation::DelegationRecord {
            delegation_id: "d1".to_string(),
            delegator_pubkey: delegator.pubkey_hex(),
            delegate_pubkey: delegate.pubkey_hex(),
            scope: vec![],
            max_depth: 1,
            issued_at: 1000,
            expires_at: 999999,
            delegation_block_hash: "aa".repeat(32),
            agreement_block_hash: None,
            parent_delegation_id: None,
            revoked: false,
            revocation_block_hash: None,
        };
        let ctx = DelegationContext {
            active_delegation: None,
            was_delegate: false,
            delegations_as_delegator: vec![deleg_record],
            root_pubkey: None,
            root_active_delegation_count: 0,
            depth: 0,
        };

        let engine = TrustEngine::new(&store, None, None, Some(ctx));
        let trust = engine.compute_trust(&delegator.pubkey_hex()).unwrap();
        assert_eq!(trust, 0.0, "delegate fraud should propagate to delegator");
    }

    #[test]
    fn test_non_finalized_checkpoint_ignored() {
        let mut store = MemoryBlockStore::new();
        let agent = Identity::from_bytes(&[1u8; 32]);
        let peer = Identity::from_bytes(&[2u8; 32]);

        create_interaction(
            &mut store,
            &agent,
            &peer,
            1,
            1,
            GENESIS_HASH,
            GENESIS_HASH,
            1000,
        );

        let mut chain_heads = HashMap::new();
        chain_heads.insert(agent.pubkey_hex(), 1);
        let checkpoint = crate::consensus::Checkpoint {
            facilitator_pubkey: "facilitator".into(),
            chain_heads,
            checkpoint_block: create_half_block(
                &peer,
                99,
                &agent.pubkey_hex(),
                0,
                GENESIS_HASH,
                BlockType::Proposal,
                serde_json::json!({}),
                Some(3000),
            ),
            signatures: HashMap::new(),
            timestamp: 3000,
            finalized: false, // NOT finalized
        };

        let engine = TrustEngine::new(&store, None, None, None).with_checkpoint(checkpoint);
        let integrity = engine.compute_chain_integrity(&agent.pubkey_hex()).unwrap();
        // Non-finalized checkpoint should still yield correct integrity via full verify.
        assert_eq!(
            integrity, 1.0,
            "non-finalized checkpoint should fall back to full verify"
        );
    }

    #[test]
    fn test_empty_seed_vec_uses_integrity_only() {
        let mut store = MemoryBlockStore::new();
        let agent = Identity::from_bytes(&[1u8; 32]);
        let peer = Identity::from_bytes(&[2u8; 32]);

        create_interaction(
            &mut store,
            &agent,
            &peer,
            1,
            1,
            GENESIS_HASH,
            GENESIS_HASH,
            1000,
        );

        // Some(vec![]) should behave same as None — integrity only.
        let engine_empty = TrustEngine::new(&store, Some(vec![]), None, None);
        let engine_none = TrustEngine::new(&store, None, None, None);

        let score_empty = engine_empty.compute_trust(&agent.pubkey_hex()).unwrap();
        let score_none = engine_none.compute_trust(&agent.pubkey_hex()).unwrap();

        assert!(
            (score_empty - score_none).abs() < 1e-10,
            "empty seeds ({score_empty}) should equal no seeds ({score_none})"
        );
    }

    #[test]
    fn test_trust_with_evidence() {
        let mut store = MemoryBlockStore::new();
        let seed = Identity::from_bytes(&[1u8; 32]);
        let agent = Identity::from_bytes(&[2u8; 32]);

        create_interaction(
            &mut store,
            &seed,
            &agent,
            1,
            1,
            GENESIS_HASH,
            GENESIS_HASH,
            1000,
        );

        let engine = TrustEngine::new(&store, Some(vec![seed.pubkey_hex()]), None, None);
        let evidence = engine
            .compute_trust_with_evidence(&agent.pubkey_hex())
            .unwrap();
        assert!(evidence.trust_score > 0.0);
        assert!(evidence.connectivity > 0.0);
        assert!((evidence.integrity - 1.0).abs() < 1e-10);
        assert!(evidence.diversity > 0.0);
        assert!(evidence.recency > 0.0);
        assert!(evidence.unique_peers >= 1);
        assert!(!evidence.fraud);
        assert!(evidence.path_diversity > 0.0);
    }

    #[test]
    fn test_integrity_broken_hash_mid_chain() {
        let mut store = MemoryBlockStore::new();
        let agent = Identity::from_bytes(&[1u8; 32]);
        let peer = Identity::from_bytes(&[2u8; 32]);

        // Build 4 blocks with a broken hash link at the 4th.
        let (p1, _) = create_interaction(
            &mut store,
            &agent,
            &peer,
            1,
            1,
            GENESIS_HASH,
            GENESIS_HASH,
            1000,
        );
        let (p2, _) = create_interaction(&mut store, &agent, &peer, 2, 2, &p1, GENESIS_HASH, 2000);
        let (_p3, _) = create_interaction(&mut store, &agent, &peer, 3, 3, &p2, GENESIS_HASH, 3000);
        // Block 4 with wrong previous hash — break the chain.
        let bad_proposal = create_half_block(
            &agent,
            4,
            &peer.pubkey_hex(),
            0,
            &"ff".repeat(32), // Wrong previous hash
            BlockType::Proposal,
            serde_json::json!({"service": "test"}),
            Some(4000),
        );
        store.add_block(&bad_proposal).unwrap();

        let engine = TrustEngine::new(&store, None, None, None);
        let integrity = engine.compute_chain_integrity(&agent.pubkey_hex()).unwrap();
        // First 3 blocks valid, 4th breaks chain → 3/4 = 0.75.
        assert!(
            (integrity - 0.75).abs() < 1e-10,
            "integrity should be 0.75, got {integrity}"
        );
    }

    #[test]
    fn test_integrity_sequence_gap() {
        let mut store = MemoryBlockStore::new();
        let agent = Identity::from_bytes(&[1u8; 32]);
        let peer = Identity::from_bytes(&[2u8; 32]);

        // Block at seq 1.
        let b1 = create_half_block(
            &agent,
            1,
            &peer.pubkey_hex(),
            0,
            GENESIS_HASH,
            BlockType::Proposal,
            serde_json::json!({}),
            Some(1000),
        );
        store.add_block(&b1).unwrap();

        // Skip seq 2, add block at seq 3.
        let b3 = create_half_block(
            &agent,
            3,
            &peer.pubkey_hex(),
            0,
            &b1.block_hash, // Previous hash from block 1
            BlockType::Proposal,
            serde_json::json!({}),
            Some(2000),
        );
        store.add_block(&b3).unwrap();

        let engine = TrustEngine::new(&store, None, None, None);
        let integrity = engine.compute_chain_integrity(&agent.pubkey_hex()).unwrap();
        // Sequence gaps are tolerated (checkpoint blocks may create gaps).
        // Both blocks are individually valid → integrity = 1.0.
        assert!(
            (integrity - 1.0).abs() < 1e-10,
            "integrity should be 1.0 (gaps tolerated), got {integrity}"
        );
    }

    // -----------------------------------------------------------------------
    // Phase 1: Recency tests
    // -----------------------------------------------------------------------

    /// Helper: create interaction with a specific outcome in the transaction.
    #[allow(clippy::too_many_arguments)]
    fn create_interaction_with_outcome(
        store: &mut MemoryBlockStore,
        alice: &Identity,
        bob: &Identity,
        alice_seq: u64,
        bob_seq: u64,
        alice_prev: &str,
        bob_prev: &str,
        ts: u64,
        outcome: &str,
    ) -> (String, String) {
        let proposal = create_half_block(
            alice,
            alice_seq,
            &bob.pubkey_hex(),
            0,
            alice_prev,
            BlockType::Proposal,
            serde_json::json!({"service": "test", "outcome": outcome}),
            Some(ts),
        );
        store.add_block(&proposal).unwrap();

        let agreement = create_half_block(
            bob,
            bob_seq,
            &alice.pubkey_hex(),
            alice_seq,
            bob_prev,
            BlockType::Agreement,
            serde_json::json!({"service": "test", "outcome": outcome}),
            Some(ts + 1),
        );
        store.add_block(&agreement).unwrap();

        (proposal.block_hash, agreement.block_hash)
    }

    #[test]
    fn test_recency_all_success() {
        let mut store = MemoryBlockStore::new();
        let agent = Identity::from_bytes(&[1u8; 32]);
        let peer = Identity::from_bytes(&[2u8; 32]);

        let (p1, _) = create_interaction_with_outcome(
            &mut store,
            &agent,
            &peer,
            1,
            1,
            GENESIS_HASH,
            GENESIS_HASH,
            1000,
            "completed",
        );
        create_interaction_with_outcome(
            &mut store,
            &agent,
            &peer,
            2,
            2,
            &p1,
            GENESIS_HASH,
            2000,
            "completed",
        );

        let engine = TrustEngine::new(&store, None, None, None);
        let evidence = engine
            .compute_trust_with_evidence(&agent.pubkey_hex())
            .unwrap();
        assert!(
            (evidence.recency - 1.0).abs() < 1e-6,
            "all successes should give recency ≈ 1.0, got {}",
            evidence.recency
        );
    }

    #[test]
    fn test_recency_all_failures() {
        let mut store = MemoryBlockStore::new();
        let agent = Identity::from_bytes(&[1u8; 32]);
        let peer = Identity::from_bytes(&[2u8; 32]);

        let (p1, _) = create_interaction_with_outcome(
            &mut store,
            &agent,
            &peer,
            1,
            1,
            GENESIS_HASH,
            GENESIS_HASH,
            1000,
            "failed",
        );
        create_interaction_with_outcome(
            &mut store,
            &agent,
            &peer,
            2,
            2,
            &p1,
            GENESIS_HASH,
            2000,
            "failed",
        );

        let engine = TrustEngine::new(&store, None, None, None);
        let evidence = engine
            .compute_trust_with_evidence(&agent.pubkey_hex())
            .unwrap();
        assert!(
            evidence.recency < 1e-6,
            "all failures should give recency ≈ 0.0, got {}",
            evidence.recency
        );
    }

    #[test]
    fn test_recency_recent_success_after_old_failures() {
        let mut store = MemoryBlockStore::new();
        let agent = Identity::from_bytes(&[1u8; 32]);
        let peer = Identity::from_bytes(&[2u8; 32]);

        // Build a chain: old failures then recent successes
        let mut prev = GENESIS_HASH.to_string();
        let mut bob_seq = 0u64;
        for seq in 1..=5 {
            bob_seq += 1;
            let (p, _) = create_interaction_with_outcome(
                &mut store,
                &agent,
                &peer,
                seq,
                bob_seq,
                &prev,
                GENESIS_HASH,
                1000 * seq,
                "failed",
            );
            prev = p;
        }
        for seq in 6..=10 {
            bob_seq += 1;
            let (p, _) = create_interaction_with_outcome(
                &mut store,
                &agent,
                &peer,
                seq,
                bob_seq,
                &prev,
                GENESIS_HASH,
                1000 * seq,
                "completed",
            );
            prev = p;
        }

        let engine = TrustEngine::new(&store, None, None, None);
        let evidence = engine
            .compute_trust_with_evidence(&agent.pubkey_hex())
            .unwrap();
        // Recent successes should dominate → recency > 0.5
        assert!(
            evidence.recency > 0.5,
            "recent successes should give recency > 0.5, got {}",
            evidence.recency
        );
    }

    #[test]
    fn test_recency_no_outcome_backward_compat() {
        let mut store = MemoryBlockStore::new();
        let agent = Identity::from_bytes(&[1u8; 32]);
        let peer = Identity::from_bytes(&[2u8; 32]);

        // Standard create_interaction has no "outcome" field → default 1.0
        create_interaction(
            &mut store,
            &agent,
            &peer,
            1,
            1,
            GENESIS_HASH,
            GENESIS_HASH,
            1000,
        );

        let engine = TrustEngine::new(&store, None, None, None);
        let evidence = engine
            .compute_trust_with_evidence(&agent.pubkey_hex())
            .unwrap();
        assert!(
            (evidence.recency - 1.0).abs() < 1e-6,
            "no outcome field should give recency = 1.0, got {}",
            evidence.recency
        );
    }

    #[test]
    fn test_recency_empty_chain() {
        let store = MemoryBlockStore::new();
        let engine = TrustEngine::new(&store, None, None, None);
        let evidence = engine.compute_trust_with_evidence("unknown").unwrap();
        // Uninformative prior: empty chain → 0.5 (Josang & Ismail 2002)
        assert!(
            (evidence.recency - 0.5).abs() < 1e-6,
            "empty chain should give recency = 0.5, got {}",
            evidence.recency
        );
    }

    // -----------------------------------------------------------------------
    // Phase 1B: MeritRank default
    // -----------------------------------------------------------------------

    #[test]
    fn test_default_algorithm_is_meritrank() {
        let algo = TrustAlgorithm::default();
        #[cfg(feature = "meritrank")]
        assert!(
            matches!(algo, TrustAlgorithm::MeritRank { .. }),
            "default should be MeritRank when feature enabled"
        );
        #[cfg(not(feature = "meritrank"))]
        assert!(
            matches!(algo, TrustAlgorithm::NetFlow),
            "default should be NetFlow when meritrank disabled"
        );
    }

    // -----------------------------------------------------------------------
    // Phase 2: Context-scoped trust
    // -----------------------------------------------------------------------

    /// Helper: create interaction with a specific interaction_type.
    #[allow(clippy::too_many_arguments)]
    fn create_interaction_with_type(
        store: &mut MemoryBlockStore,
        alice: &Identity,
        bob: &Identity,
        alice_seq: u64,
        bob_seq: u64,
        alice_prev: &str,
        bob_prev: &str,
        ts: u64,
        interaction_type: &str,
        outcome: &str,
    ) -> (String, String) {
        let proposal = create_half_block(
            alice,
            alice_seq,
            &bob.pubkey_hex(),
            0,
            alice_prev,
            BlockType::Proposal,
            serde_json::json!({
                "service": "test",
                "interaction_type": interaction_type,
                "outcome": outcome,
            }),
            Some(ts),
        );
        store.add_block(&proposal).unwrap();

        let agreement = create_half_block(
            bob,
            bob_seq,
            &alice.pubkey_hex(),
            alice_seq,
            bob_prev,
            BlockType::Agreement,
            serde_json::json!({
                "service": "test",
                "interaction_type": interaction_type,
                "outcome": outcome,
            }),
            Some(ts + 1),
        );
        store.add_block(&agreement).unwrap();

        (proposal.block_hash, agreement.block_hash)
    }

    #[test]
    fn test_context_different_scores() {
        let mut store = MemoryBlockStore::new();
        let agent = Identity::from_bytes(&[1u8; 32]);
        let peer = Identity::from_bytes(&[2u8; 32]);

        // 3 successful code_execution interactions
        let mut prev = GENESIS_HASH.to_string();
        let mut bob_seq = 0u64;
        for seq in 1..=3 {
            bob_seq += 1;
            let (p, _) = create_interaction_with_type(
                &mut store,
                &agent,
                &peer,
                seq,
                bob_seq,
                &prev,
                GENESIS_HASH,
                1000 * seq,
                "code_execution",
                "completed",
            );
            prev = p;
        }
        // 3 failed data_retrieval interactions
        for seq in 4..=6 {
            bob_seq += 1;
            let (p, _) = create_interaction_with_type(
                &mut store,
                &agent,
                &peer,
                seq,
                bob_seq,
                &prev,
                GENESIS_HASH,
                1000 * seq,
                "data_retrieval",
                "failed",
            );
            prev = p;
        }

        let engine = TrustEngine::new(&store, None, None, None);

        let ev_code = engine
            .compute_trust_with_evidence_ctx(&agent.pubkey_hex(), Some("code_execution"))
            .unwrap();
        let ev_data = engine
            .compute_trust_with_evidence_ctx(&agent.pubkey_hex(), Some("data_retrieval"))
            .unwrap();

        // Code execution: all successes → high recency
        assert!(
            ev_code.recency > 0.9,
            "code_execution recency should be ~1.0, got {}",
            ev_code.recency
        );
        // Data retrieval: all failures → low recency
        assert!(
            ev_data.recency < 0.1,
            "data_retrieval recency should be ~0.0, got {}",
            ev_data.recency
        );
    }

    #[test]
    fn test_context_prefix_matching() {
        let mut store = MemoryBlockStore::new();
        let agent = Identity::from_bytes(&[1u8; 32]);
        let peer = Identity::from_bytes(&[2u8; 32]);

        let (p1, _) = create_interaction_with_type(
            &mut store,
            &agent,
            &peer,
            1,
            1,
            GENESIS_HASH,
            GENESIS_HASH,
            1000,
            "tool:web_search",
            "completed",
        );
        create_interaction_with_type(
            &mut store,
            &agent,
            &peer,
            2,
            2,
            &p1,
            GENESIS_HASH,
            2000,
            "tool:code_exec",
            "completed",
        );

        let engine = TrustEngine::new(&store, None, None, None);

        // Context "tool" should match both "tool:web_search" and "tool:code_exec"
        let ev_tool = engine
            .compute_trust_with_evidence_ctx(&agent.pubkey_hex(), Some("tool"))
            .unwrap();
        assert_eq!(
            ev_tool.interactions, 2,
            "tool context should match 2 interactions via prefix"
        );
    }

    #[test]
    fn test_no_context_backward_compat() {
        let mut store = MemoryBlockStore::new();
        let agent = Identity::from_bytes(&[1u8; 32]);
        let peer = Identity::from_bytes(&[2u8; 32]);

        create_interaction(
            &mut store,
            &agent,
            &peer,
            1,
            1,
            GENESIS_HASH,
            GENESIS_HASH,
            1000,
        );

        let engine = TrustEngine::new(&store, None, None, None);

        let ev_none = engine
            .compute_trust_with_evidence(&agent.pubkey_hex())
            .unwrap();
        let ev_ctx = engine
            .compute_trust_with_evidence_ctx(&agent.pubkey_hex(), None)
            .unwrap();

        assert!(
            (ev_none.trust_score - ev_ctx.trust_score).abs() < 1e-10,
            "None context should equal no-context: {} vs {}",
            ev_none.trust_score,
            ev_ctx.trust_score
        );
    }

    // -----------------------------------------------------------------------
    // Phase 3: Cold start delegation blending
    // -----------------------------------------------------------------------

    #[test]
    fn test_cold_start_zero_interactions_gets_delegated_trust() {
        let mut store = MemoryBlockStore::new();
        let root = Identity::from_bytes(&[1u8; 32]);
        let delegate = Identity::from_bytes(&[2u8; 32]);
        let peer = Identity::from_bytes(&[3u8; 32]);

        // Give root some trust
        create_interaction(
            &mut store,
            &root,
            &peer,
            1,
            1,
            GENESIS_HASH,
            GENESIS_HASH,
            1000,
        );

        let engine_root = TrustEngine::new(&store, None, None, None);
        let root_trust = engine_root.compute_trust(&root.pubkey_hex()).unwrap();

        let deleg = crate::delegation::DelegationRecord {
            delegation_id: "d1".to_string(),
            delegator_pubkey: root.pubkey_hex(),
            delegate_pubkey: delegate.pubkey_hex(),
            scope: vec![],
            max_depth: 1,
            issued_at: 1000,
            expires_at: 999999,
            delegation_block_hash: "aa".repeat(32),
            agreement_block_hash: None,
            parent_delegation_id: None,
            revoked: false,
            revocation_block_hash: None,
        };
        let ctx = DelegationContext {
            active_delegation: Some(deleg),
            was_delegate: true,
            delegations_as_delegator: vec![],
            root_pubkey: Some(root.pubkey_hex()),
            root_active_delegation_count: 1,
            depth: 1,
        };

        let engine = TrustEngine::new(&store, None, None, Some(ctx));
        let trust = engine.compute_trust(&delegate.pubkey_hex()).unwrap();
        // 0 interactions → pure delegation: root_trust * 0.8 / 1
        let expected = root_trust * 0.8;
        assert!(
            (trust - expected).abs() < 1e-6,
            "zero interactions should give delegated trust: {trust} vs {expected}"
        );
        assert!(trust > 0.0);
    }

    #[test]
    fn test_cold_start_blending_partial() {
        let mut store = MemoryBlockStore::new();
        let root = Identity::from_bytes(&[1u8; 32]);
        let delegate = Identity::from_bytes(&[2u8; 32]);
        let peer = Identity::from_bytes(&[3u8; 32]);

        // Give root some trust
        create_interaction(
            &mut store,
            &root,
            &peer,
            1,
            1,
            GENESIS_HASH,
            GENESIS_HASH,
            1000,
        );

        // Give delegate 3 direct interactions (below threshold of 5)
        let mut prev = GENESIS_HASH.to_string();
        let mut bob_seq = 1u64; // peer already used seq 1 with root
        for seq in 1..=3u64 {
            bob_seq += 1;
            let (p, _) = create_interaction(
                &mut store,
                &delegate,
                &peer,
                seq,
                bob_seq,
                &prev,
                GENESIS_HASH,
                2000 + seq,
            );
            prev = p;
        }

        let deleg = crate::delegation::DelegationRecord {
            delegation_id: "d1".to_string(),
            delegator_pubkey: root.pubkey_hex(),
            delegate_pubkey: delegate.pubkey_hex(),
            scope: vec![],
            max_depth: 1,
            issued_at: 1000,
            expires_at: 999999,
            delegation_block_hash: "aa".repeat(32),
            agreement_block_hash: None,
            parent_delegation_id: None,
            revoked: false,
            revocation_block_hash: None,
        };
        let ctx = DelegationContext {
            active_delegation: Some(deleg),
            was_delegate: true,
            delegations_as_delegator: vec![],
            root_pubkey: Some(root.pubkey_hex()),
            root_active_delegation_count: 1,
            depth: 1,
        };

        let engine = TrustEngine::new(&store, None, None, Some(ctx));
        let trust = engine.compute_trust(&delegate.pubkey_hex()).unwrap();
        // With 3 interactions (threshold=5), blend = 0.6 direct + 0.4 delegated
        // Score should be between pure delegation and pure direct
        assert!(trust > 0.0, "blended trust should be positive: {trust}");
    }

    #[test]
    fn test_cold_start_above_threshold_uses_direct() {
        let mut store = MemoryBlockStore::new();
        let root = Identity::from_bytes(&[1u8; 32]);
        let delegate = Identity::from_bytes(&[2u8; 32]);
        let peer = Identity::from_bytes(&[3u8; 32]);

        // Give root some trust
        create_interaction(
            &mut store,
            &root,
            &peer,
            1,
            1,
            GENESIS_HASH,
            GENESIS_HASH,
            1000,
        );

        // Give delegate 6 interactions (above threshold of 5)
        let mut prev = GENESIS_HASH.to_string();
        let mut bob_seq = 1u64;
        for seq in 1..=6u64 {
            bob_seq += 1;
            let (p, _) = create_interaction(
                &mut store,
                &delegate,
                &peer,
                seq,
                bob_seq,
                &prev,
                GENESIS_HASH,
                2000 + seq,
            );
            prev = p;
        }

        let deleg = crate::delegation::DelegationRecord {
            delegation_id: "d1".to_string(),
            delegator_pubkey: root.pubkey_hex(),
            delegate_pubkey: delegate.pubkey_hex(),
            scope: vec![],
            max_depth: 1,
            issued_at: 1000,
            expires_at: 999999,
            delegation_block_hash: "aa".repeat(32),
            agreement_block_hash: None,
            parent_delegation_id: None,
            revoked: false,
            revocation_block_hash: None,
        };
        let ctx = DelegationContext {
            active_delegation: Some(deleg),
            was_delegate: true,
            delegations_as_delegator: vec![],
            root_pubkey: Some(root.pubkey_hex()),
            root_active_delegation_count: 1,
            depth: 1,
        };

        let engine_delegated = TrustEngine::new(&store, None, None, Some(ctx));
        let delegated_trust = engine_delegated
            .compute_trust(&delegate.pubkey_hex())
            .unwrap();

        // Direct trust (no delegation)
        let engine_direct = TrustEngine::new(&store, None, None, None);
        let direct_trust = engine_direct.compute_trust(&delegate.pubkey_hex()).unwrap();

        assert!(
            (delegated_trust - direct_trust).abs() < 1e-6,
            "above threshold should use direct trust: {delegated_trust} vs {direct_trust}"
        );
    }

    #[test]
    fn test_delegation_depth_reduces_trust() {
        let mut store = MemoryBlockStore::new();
        let root = Identity::from_bytes(&[1u8; 32]);
        let delegate = Identity::from_bytes(&[2u8; 32]);
        let peer = Identity::from_bytes(&[3u8; 32]);

        create_interaction(
            &mut store,
            &root,
            &peer,
            1,
            1,
            GENESIS_HASH,
            GENESIS_HASH,
            1000,
        );

        let engine_root = TrustEngine::new(&store, None, None, None);
        let root_trust = engine_root.compute_trust(&root.pubkey_hex()).unwrap();

        // depth=1
        let make_ctx = |depth: usize| {
            let deleg = crate::delegation::DelegationRecord {
                delegation_id: "d1".to_string(),
                delegator_pubkey: root.pubkey_hex(),
                delegate_pubkey: delegate.pubkey_hex(),
                scope: vec![],
                max_depth: 2,
                issued_at: 1000,
                expires_at: 999999,
                delegation_block_hash: "aa".repeat(32),
                agreement_block_hash: None,
                parent_delegation_id: None,
                revoked: false,
                revocation_block_hash: None,
            };
            DelegationContext {
                active_delegation: Some(deleg),
                was_delegate: true,
                delegations_as_delegator: vec![],
                root_pubkey: Some(root.pubkey_hex()),
                root_active_delegation_count: 1,
                depth,
            }
        };

        let engine_d1 = TrustEngine::new(&store, None, None, Some(make_ctx(1)));
        let trust_d1 = engine_d1.compute_trust(&delegate.pubkey_hex()).unwrap();

        let engine_d2 = TrustEngine::new(&store, None, None, Some(make_ctx(2)));
        let trust_d2 = engine_d2.compute_trust(&delegate.pubkey_hex()).unwrap();

        // depth=1: root_trust * 0.8, depth=2: root_trust * 0.8 * 0.8
        let expected_d1 = root_trust * 0.8;
        let expected_d2 = root_trust * 0.8 * 0.8;
        assert!(
            (trust_d1 - expected_d1).abs() < 1e-6,
            "depth=1 trust {trust_d1} should be ~{expected_d1}"
        );
        assert!(
            (trust_d2 - expected_d2).abs() < 1e-6,
            "depth=2 trust {trust_d2} should be ~{expected_d2}"
        );
        assert!(
            trust_d1 > trust_d2,
            "depth=1 ({trust_d1}) should be higher than depth=2 ({trust_d2})"
        );
    }

    // --- AuditReport tests ---

    #[test]
    fn test_audit_report_empty_chain() {
        let store = MemoryBlockStore::new();
        let engine = TrustEngine::new(&store, None, None, None);
        let alice = Identity::from_bytes(&[1u8; 32]);
        let report = engine.compute_audit_report(&alice.pubkey_hex()).unwrap();
        assert_eq!(report.total_blocks, 0);
        assert_eq!(report.audit_blocks, 0);
        assert_eq!(report.bilateral_blocks, 0);
        assert!(report.integrity_valid);
        assert_eq!(report.integrity_score, 1.0);
        assert!(report.event_type_breakdown.is_empty());
        assert!(report.first_timestamp.is_none());
        assert!(report.last_timestamp.is_none());
    }

    #[test]
    fn test_audit_report_with_audit_blocks() {
        let alice = Identity::from_bytes(&[1u8; 32]);
        let mut store = MemoryBlockStore::new();
        let mut proto =
            crate::protocol::TrustChainProtocol::new(alice.clone(), MemoryBlockStore::new());

        let b1 = proto
            .create_audit(
                serde_json::json!({"event_type": "tool_call", "action": "read"}),
                Some(1000),
            )
            .unwrap();
        let b2 = proto
            .create_audit(
                serde_json::json!({"event_type": "llm_decision", "action": "think"}),
                Some(2000),
            )
            .unwrap();
        let b3 = proto
            .create_audit(
                serde_json::json!({"event_type": "tool_call", "action": "write"}),
                Some(3000),
            )
            .unwrap();

        // Copy blocks into the store for the engine.
        store.add_block(&b1).unwrap();
        store.add_block(&b2).unwrap();
        store.add_block(&b3).unwrap();

        let engine = TrustEngine::new(&store, None, None, None);
        let report = engine.compute_audit_report(&alice.pubkey_hex()).unwrap();

        assert_eq!(report.total_blocks, 3);
        assert_eq!(report.audit_blocks, 3);
        assert_eq!(report.bilateral_blocks, 0);
        assert!(report.integrity_valid);
        assert_eq!(report.integrity_score, 1.0);
        assert_eq!(report.event_type_breakdown.get("tool_call"), Some(&2));
        assert_eq!(report.event_type_breakdown.get("llm_decision"), Some(&1));
        assert_eq!(report.first_timestamp, Some(1000));
        assert_eq!(report.last_timestamp, Some(3000));
        assert_eq!(report.chain_length, 3);
    }

    #[test]
    fn test_audit_report_untyped_events() {
        let alice = Identity::from_bytes(&[1u8; 32]);
        let mut store = MemoryBlockStore::new();
        let mut proto =
            crate::protocol::TrustChainProtocol::new(alice.clone(), MemoryBlockStore::new());

        let b1 = proto
            .create_audit(serde_json::json!({"action": "freeform"}), Some(1000))
            .unwrap();
        store.add_block(&b1).unwrap();

        let engine = TrustEngine::new(&store, None, None, None);
        let report = engine.compute_audit_report(&alice.pubkey_hex()).unwrap();

        assert_eq!(report.audit_blocks, 1);
        assert_eq!(report.event_type_breakdown.get("untyped"), Some(&1));
    }

    #[test]
    fn test_audit_report_mixed_blocks() {
        let alice = Identity::from_bytes(&[1u8; 32]);
        let bob = Identity::from_bytes(&[2u8; 32]);
        let mut store = MemoryBlockStore::new();

        // Create an audit block.
        let audit = create_half_block(
            &alice,
            1,
            &alice.pubkey_hex(),
            0,
            GENESIS_HASH,
            BlockType::Audit,
            serde_json::json!({"event_type": "tool_call"}),
            Some(1000),
        );
        store.add_block(&audit).unwrap();

        // Create a proposal block.
        let proposal = create_half_block(
            &alice,
            2,
            &bob.pubkey_hex(),
            0,
            &audit.block_hash,
            BlockType::Proposal,
            serde_json::json!({"interaction_type": "test"}),
            Some(2000),
        );
        store.add_block(&proposal).unwrap();

        let engine = TrustEngine::new(&store, None, None, None);
        let report = engine.compute_audit_report(&alice.pubkey_hex()).unwrap();

        assert_eq!(report.total_blocks, 2);
        assert_eq!(report.audit_blocks, 1);
        assert_eq!(report.bilateral_blocks, 1);
        assert!(report.integrity_valid);
    }

    // ===== Layer 1: Quality-Aware Recency Tests =====
    // Research: trust-differentiation-fixes P0, Josang & Ismail 2002

    /// Helper: create a bilateral interaction with custom transaction JSON.
    #[allow(clippy::too_many_arguments)]
    fn create_interaction_with_tx(
        store: &mut MemoryBlockStore,
        alice: &Identity,
        bob: &Identity,
        alice_seq: u64,
        bob_seq: u64,
        alice_prev: &str,
        bob_prev: &str,
        ts: u64,
        tx: serde_json::Value,
    ) -> (String, String) {
        let proposal = create_half_block(
            alice,
            alice_seq,
            &bob.pubkey_hex(),
            0,
            alice_prev,
            BlockType::Proposal,
            tx.clone(),
            Some(ts),
        );
        store.add_block(&proposal).unwrap();

        let agreement = create_half_block(
            bob,
            bob_seq,
            &alice.pubkey_hex(),
            alice_seq,
            bob_prev,
            BlockType::Agreement,
            tx,
            Some(ts + 1),
        );
        store.add_block(&agreement).unwrap();

        (proposal.block_hash, agreement.block_hash)
    }

    #[test]
    fn test_extract_quality_field() {
        let tx = serde_json::json!({"outcome": "completed", "quality": 0.75});
        assert!((TrustEngine::<MemoryBlockStore>::extract_quality(&tx) - 0.75).abs() < 1e-10);
    }

    #[test]
    fn test_extract_quality_requester_rating_fallback() {
        let tx = serde_json::json!({"outcome": "completed", "requester_rating": 0.6});
        assert!((TrustEngine::<MemoryBlockStore>::extract_quality(&tx) - 0.6).abs() < 1e-10);
    }

    #[test]
    fn test_extract_quality_provider_rating_fallback() {
        let tx = serde_json::json!({"outcome": "completed", "provider_rating": 0.4});
        assert!((TrustEngine::<MemoryBlockStore>::extract_quality(&tx) - 0.4).abs() < 1e-10);
    }

    #[test]
    fn test_extract_quality_binary_fallback() {
        let tx = serde_json::json!({"outcome": "completed"});
        assert!((TrustEngine::<MemoryBlockStore>::extract_quality(&tx) - 1.0).abs() < 1e-10);

        let tx_fail = serde_json::json!({"outcome": "failed"});
        assert!((TrustEngine::<MemoryBlockStore>::extract_quality(&tx_fail)).abs() < 1e-10);
    }

    #[test]
    fn test_extract_quality_clamps() {
        let tx_high = serde_json::json!({"quality": 1.5});
        assert!((TrustEngine::<MemoryBlockStore>::extract_quality(&tx_high) - 1.0).abs() < 1e-10);

        let tx_low = serde_json::json!({"quality": -0.5});
        assert!((TrustEngine::<MemoryBlockStore>::extract_quality(&tx_low)).abs() < 1e-10);
    }

    #[test]
    fn test_extract_quality_priority_order() {
        // quality takes priority over requester_rating
        let tx = serde_json::json!({
            "outcome": "completed",
            "quality": 0.8,
            "requester_rating": 0.3,
            "provider_rating": 0.1
        });
        assert!((TrustEngine::<MemoryBlockStore>::extract_quality(&tx) - 0.8).abs() < 1e-10);
    }

    #[test]
    fn test_empty_chain_recency_returns_half() {
        // Research: Josang & Ismail 2002 — uninformative prior = 0.5
        let store = MemoryBlockStore::new();
        let engine = TrustEngine::new(&store, None, None, None);
        let chain: Vec<crate::halfblock::HalfBlock> = vec![];
        let recency = engine.compute_recency_inner(&chain, 0);
        assert!(
            (recency - 0.5).abs() < 1e-10,
            "Empty chain should return 0.5, got {recency}"
        );
    }

    #[test]
    fn test_quality_aware_recency_honest_vs_sybil() {
        // Research: trust-differentiation-fixes P0
        // Honest agent (quality ~0.85) vs sybil (quality ~0.3)
        // Gap should be significant (> 0.4)
        let mut store = MemoryBlockStore::new();
        let seed = Identity::from_bytes(&[1u8; 32]);

        let honest = Identity::from_bytes(&[10u8; 32]);
        let sybil = Identity::from_bytes(&[20u8; 32]);

        // Create 10 interactions for honest agent (quality 0.85)
        let mut prev_h = crate::types::GENESIS_HASH.to_string();
        let mut prev_s = crate::types::GENESIS_HASH.to_string();
        for i in 0..10u64 {
            let (ph, _) = create_interaction_with_tx(
                &mut store,
                &honest,
                &seed,
                i + 1,
                i + 1,
                &prev_h,
                &prev_s,
                1000 + i * 100,
                serde_json::json!({"outcome": "completed", "quality": 0.85}),
            );
            prev_h = ph;
            prev_s = store
                .get_chain(&seed.pubkey_hex())
                .unwrap()
                .last()
                .map(|b| b.block_hash.clone())
                .unwrap_or_else(|| crate::types::GENESIS_HASH.to_string());
        }

        // Create 10 interactions for sybil agent (quality 0.3)
        let sybil_peer = Identity::from_bytes(&[21u8; 32]);
        let mut prev_sy = crate::types::GENESIS_HASH.to_string();
        let mut prev_sp = crate::types::GENESIS_HASH.to_string();
        for i in 0..10u64 {
            let (psy, _) = create_interaction_with_tx(
                &mut store,
                &sybil,
                &sybil_peer,
                i + 1,
                i + 1,
                &prev_sy,
                &prev_sp,
                2000 + i * 100,
                serde_json::json!({"outcome": "completed", "quality": 0.3}),
            );
            prev_sy = psy;
            prev_sp = store
                .get_chain(&sybil_peer.pubkey_hex())
                .unwrap()
                .last()
                .map(|b| b.block_hash.clone())
                .unwrap_or_else(|| crate::types::GENESIS_HASH.to_string());
        }

        let engine = TrustEngine::new(&store, None, None, None);

        // No seeds → trust = (0.3 × integrity + 0.7 × recency) × confidence_scale
        // Both have integrity=1.0, so gap = 0.7 × (0.85 - 0.3) = 0.385.
        // With seeds, sybils have lower connectivity → gap widens further.
        let honest_trust = engine.compute_trust(&honest.pubkey_hex()).unwrap();
        let sybil_trust = engine.compute_trust(&sybil.pubkey_hex()).unwrap();

        let gap = honest_trust - sybil_trust;
        assert!(
            gap > 0.35,
            "Quality differentiation gap should exceed 0.35 (no-seeds worst case), got {gap} (honest={honest_trust}, sybil={sybil_trust})"
        );
    }

    #[test]
    fn test_avg_quality_in_evidence() {
        let mut store = MemoryBlockStore::new();
        let alice = Identity::from_bytes(&[30u8; 32]);
        let bob = Identity::from_bytes(&[31u8; 32]);

        let mut prev_a = crate::types::GENESIS_HASH.to_string();
        let mut prev_b = crate::types::GENESIS_HASH.to_string();
        for i in 0..5u64 {
            let (pa, _) = create_interaction_with_tx(
                &mut store,
                &alice,
                &bob,
                i + 1,
                i + 1,
                &prev_a,
                &prev_b,
                3000 + i * 100,
                serde_json::json!({"outcome": "completed", "quality": 0.7}),
            );
            prev_a = pa;
            prev_b = store
                .get_chain(&bob.pubkey_hex())
                .unwrap()
                .last()
                .map(|b| b.block_hash.clone())
                .unwrap_or_else(|| crate::types::GENESIS_HASH.to_string());
        }

        let engine = TrustEngine::new(&store, None, None, None);
        let evidence = engine
            .compute_trust_with_evidence(&alice.pubkey_hex())
            .unwrap();

        assert!(
            (evidence.avg_quality - 0.7).abs() < 0.01,
            "avg_quality should be ~0.7, got {}",
            evidence.avg_quality
        );
    }

    #[test]
    fn test_backward_compat_no_quality_field() {
        // Blocks without quality field should still work (binary outcome)
        let mut store = MemoryBlockStore::new();
        let alice = Identity::from_bytes(&[40u8; 32]);
        let bob = Identity::from_bytes(&[41u8; 32]);

        let (_, _) = create_interaction_with_tx(
            &mut store,
            &alice,
            &bob,
            1,
            1,
            crate::types::GENESIS_HASH,
            crate::types::GENESIS_HASH,
            4000,
            serde_json::json!({"outcome": "completed"}),
        );

        let engine = TrustEngine::new(&store, None, None, None);
        let evidence = engine
            .compute_trust_with_evidence(&alice.pubkey_hex())
            .unwrap();

        // Binary "completed" → quality 1.0
        assert!(
            (evidence.avg_quality - 1.0).abs() < 0.01,
            "Binary completed should give avg_quality 1.0, got {}",
            evidence.avg_quality
        );
        // Trust should still be > 0
        assert!(evidence.trust_score > 0.0);
    }

    // -----------------------------------------------------------------------
    // Layer 1.4: Value-Weighted Recency
    // Research: Olariu et al. 2024, Hoffman et al. 2009 (value imbalance)
    // -----------------------------------------------------------------------

    #[test]
    fn test_value_weighted_cheap_wash_trades_negligible() {
        // A $1 self-deal in an avg $100 context should contribute ~1/100th
        // as much trust as a normal transaction.
        let mut store = MemoryBlockStore::new();
        let agent = Identity::from_bytes(&[50u8; 32]);
        let peer = Identity::from_bytes(&[51u8; 32]);

        // 9 interactions at $100 with quality 0.3 (sybil)
        let mut prev = GENESIS_HASH.to_string();
        for i in 1..=9u64 {
            let (p, _) = create_interaction_with_tx(
                &mut store,
                &agent,
                &peer,
                i,
                i,
                &prev,
                GENESIS_HASH,
                1000 + i * 100,
                serde_json::json!({"outcome": "completed", "quality": 0.3, "price": 100.0}),
            );
            prev = p;
        }

        // 1 cheap wash-trade at $1 with quality 1.0 (self-deal)
        create_interaction_with_tx(
            &mut store,
            &agent,
            &peer,
            10,
            10,
            &prev,
            GENESIS_HASH,
            2000,
            serde_json::json!({"outcome": "completed", "quality": 1.0, "price": 1.0}),
        );

        let engine = TrustEngine::new(&store, None, None, None);
        let evidence = engine
            .compute_trust_with_evidence(&agent.pubkey_hex())
            .unwrap();

        // Value-weighted recency should be close to 0.3 (dominated by $100 txns),
        // NOT pulled up significantly by the cheap $1 perfect interaction.
        assert!(
            evidence.value_weighted_recency < 0.4,
            "Value-weighted recency should be < 0.4 (dominated by $100 quality-0.3 txns), got {}",
            evidence.value_weighted_recency
        );
    }

    #[test]
    fn test_value_weighted_expensive_txn_dominates() {
        // An expensive successful transaction should dominate over many cheap failures.
        let mut store = MemoryBlockStore::new();
        let agent = Identity::from_bytes(&[52u8; 32]);
        let peer = Identity::from_bytes(&[53u8; 32]);

        // 5 cheap failures at $1
        let mut prev = GENESIS_HASH.to_string();
        for i in 1..=5u64 {
            let (p, _) = create_interaction_with_tx(
                &mut store,
                &agent,
                &peer,
                i,
                i,
                &prev,
                GENESIS_HASH,
                1000 + i * 100,
                serde_json::json!({"outcome": "failed", "quality": 0.0, "price": 1.0}),
            );
            prev = p;
        }

        // 1 expensive success at $500
        create_interaction_with_tx(
            &mut store,
            &agent,
            &peer,
            6,
            6,
            &prev,
            GENESIS_HASH,
            2000,
            serde_json::json!({"outcome": "completed", "quality": 0.9, "price": 500.0}),
        );

        let engine = TrustEngine::new(&store, None, None, None);
        let evidence = engine
            .compute_trust_with_evidence(&agent.pubkey_hex())
            .unwrap();

        // The $500 success should dominate over 5 × $1 failures
        assert!(
            evidence.value_weighted_recency > 0.5,
            "Expensive success should dominate over cheap failures, got {}",
            evidence.value_weighted_recency
        );
    }

    #[test]
    fn test_value_weighted_backward_compat_no_price() {
        // Blocks without price field should have value_weight = 1.0 (same as before).
        let mut store = MemoryBlockStore::new();
        let agent = Identity::from_bytes(&[54u8; 32]);
        let peer = Identity::from_bytes(&[55u8; 32]);

        let mut prev = GENESIS_HASH.to_string();
        for i in 1..=5u64 {
            let (p, _) = create_interaction_with_tx(
                &mut store,
                &agent,
                &peer,
                i,
                i,
                &prev,
                GENESIS_HASH,
                1000 + i * 100,
                serde_json::json!({"outcome": "completed"}),
            );
            prev = p;
        }

        let engine = TrustEngine::new(&store, None, None, None);
        let evidence = engine
            .compute_trust_with_evidence(&agent.pubkey_hex())
            .unwrap();

        // Without price fields, all weights are equal → recency = quality = 1.0
        assert!(
            (evidence.recency - 1.0).abs() < 1e-6,
            "No price field should give same recency as before: got {}",
            evidence.recency
        );
        assert!(
            (evidence.value_weighted_recency - 1.0).abs() < 1e-6,
            "Value-weighted recency without price should equal basic: got {}",
            evidence.value_weighted_recency
        );
    }

    // -----------------------------------------------------------------------
    // Layer 1.5: Timeout Enforcement
    // Research: trust-model-gaps §4
    // -----------------------------------------------------------------------

    #[test]
    fn test_timeout_no_deadline_no_timeout() {
        // Proposals without deadline_ms should not count as timeouts.
        let mut store = MemoryBlockStore::new();
        let agent = Identity::from_bytes(&[60u8; 32]);
        let peer = Identity::from_bytes(&[61u8; 32]);

        // Peer proposes to agent (orphan — no agreement from agent).
        let proposal = create_half_block(
            &peer,
            1,
            &agent.pubkey_hex(),
            0,
            GENESIS_HASH,
            BlockType::Proposal,
            serde_json::json!({"service": "test"}), // no deadline_ms
            Some(1000),
        );
        store.add_block(&proposal).unwrap();

        // Give agent some history so counterparties are known.
        create_interaction_with_tx(
            &mut store,
            &agent,
            &peer,
            1,
            2,
            GENESIS_HASH,
            &proposal.block_hash,
            2000,
            serde_json::json!({"outcome": "completed"}),
        );

        let engine = TrustEngine::new(&store, None, None, None);
        let evidence = engine
            .compute_trust_with_evidence(&agent.pubkey_hex())
            .unwrap();

        assert_eq!(evidence.timeout_count, 0, "No deadline_ms → no timeout");
    }

    #[test]
    fn test_timeout_expired_proposal_counts() {
        // Peer proposes to agent with deadline_ms that has expired and agent never responded.
        let mut store = MemoryBlockStore::new();
        let agent = Identity::from_bytes(&[62u8; 32]);
        let peer = Identity::from_bytes(&[63u8; 32]);

        // Agent first interacts with peer (so peer is known as counterparty).
        let (pa, _) = create_interaction_with_tx(
            &mut store,
            &agent,
            &peer,
            1,
            1,
            GENESIS_HASH,
            GENESIS_HASH,
            1000,
            serde_json::json!({"outcome": "completed"}),
        );

        // Peer proposes to agent with deadline that is in the past relative to agent's chain.
        let proposal = create_half_block(
            &peer,
            2,
            &agent.pubkey_hex(),
            0,
            &store
                .get_chain(&peer.pubkey_hex())
                .unwrap()
                .last()
                .unwrap()
                .block_hash,
            BlockType::Proposal,
            serde_json::json!({"service": "test", "deadline_ms": 500}), // deadline is 500ms, chain is at 1000+
            Some(400),
        );
        store.add_block(&proposal).unwrap();

        // Agent does more interactions (later timestamps, proving deadline passed).
        create_interaction_with_tx(
            &mut store,
            &agent,
            &peer,
            2,
            3,
            &pa,
            &proposal.block_hash,
            5000,
            serde_json::json!({"outcome": "completed"}),
        );

        let engine = TrustEngine::new(&store, None, None, None);
        let evidence = engine
            .compute_trust_with_evidence(&agent.pubkey_hex())
            .unwrap();

        assert_eq!(
            evidence.timeout_count, 1,
            "Expired orphan proposal should count as timeout"
        );
    }

    #[test]
    fn test_timeout_reduces_recency() {
        // Timeouts should reduce recency compared to the same chain without timeouts.
        let mut store = MemoryBlockStore::new();
        let agent = Identity::from_bytes(&[64u8; 32]);
        let peer = Identity::from_bytes(&[65u8; 32]);

        // 5 good interactions
        let mut prev_a = GENESIS_HASH.to_string();
        let mut prev_b = GENESIS_HASH.to_string();
        for i in 1..=5u64 {
            let (pa, pb) = create_interaction_with_tx(
                &mut store,
                &agent,
                &peer,
                i,
                i,
                &prev_a,
                &prev_b,
                1000 + i * 100,
                serde_json::json!({"outcome": "completed", "quality": 0.8}),
            );
            prev_a = pa;
            prev_b = pb;
        }

        // Peer proposes with expired deadline, agent never responds.
        let proposal = create_half_block(
            &peer,
            6,
            &agent.pubkey_hex(),
            0,
            &prev_b,
            BlockType::Proposal,
            serde_json::json!({"service": "test", "deadline_ms": 100}),
            Some(50),
        );
        store.add_block(&proposal).unwrap();

        let engine = TrustEngine::new(&store, None, None, None);
        let evidence = engine
            .compute_trust_with_evidence(&agent.pubkey_hex())
            .unwrap();

        // value_weighted_recency has no timeout penalty, recency does
        assert!(
            evidence.recency < evidence.value_weighted_recency,
            "Timeout should reduce recency ({}) below value_weighted_recency ({})",
            evidence.recency,
            evidence.value_weighted_recency
        );
    }

    // -----------------------------------------------------------------------
    // Layer 2.1: Wilson Score Confidence
    // Research: Evan Miller 2009, TRAVOS (Teacy et al. 2006)
    // -----------------------------------------------------------------------

    #[test]
    fn test_wilson_empty() {
        let score = TrustEngine::<MemoryBlockStore>::wilson_lower_bound(0.0, 0.0, 1.96);
        assert!(
            score.abs() < 1e-10,
            "Wilson with 0 total should be 0.0, got {score}"
        );
    }

    #[test]
    fn test_wilson_perfect_small_sample() {
        // 5/5 positive with small sample → lower bound should be < 1.0 (uncertainty)
        let score = TrustEngine::<MemoryBlockStore>::wilson_lower_bound(5.0, 5.0, 1.96);
        assert!(
            score > 0.5 && score < 1.0,
            "Wilson(5/5, z=1.96) should be between 0.5 and 1.0, got {score}"
        );
    }

    #[test]
    fn test_wilson_perfect_large_sample() {
        // 100/100 positive → lower bound should be > 0.95 (high confidence)
        let score = TrustEngine::<MemoryBlockStore>::wilson_lower_bound(100.0, 100.0, 1.96);
        assert!(
            score > 0.95,
            "Wilson(100/100, z=1.96) should be > 0.95, got {score}"
        );
    }

    #[test]
    fn test_wilson_half_half() {
        // 50/100 positive → lower bound should be < 0.5
        let score = TrustEngine::<MemoryBlockStore>::wilson_lower_bound(50.0, 100.0, 1.96);
        assert!(
            score > 0.3 && score < 0.5,
            "Wilson(50/100, z=1.96) should be between 0.3 and 0.5, got {score}"
        );
    }

    #[test]
    fn test_wilson_all_negative() {
        // 0/10 positive → lower bound should be close to 0
        let score = TrustEngine::<MemoryBlockStore>::wilson_lower_bound(0.0, 10.0, 1.96);
        assert!(
            score < 0.05,
            "Wilson(0/10, z=1.96) should be < 0.05, got {score}"
        );
    }

    #[test]
    fn test_wilson_monotonicity_with_sample_size() {
        // Confidence should increase with more samples (same ratio)
        let w5 = TrustEngine::<MemoryBlockStore>::wilson_lower_bound(5.0, 5.0, 1.96);
        let w20 = TrustEngine::<MemoryBlockStore>::wilson_lower_bound(20.0, 20.0, 1.96);
        let w100 = TrustEngine::<MemoryBlockStore>::wilson_lower_bound(100.0, 100.0, 1.96);
        assert!(
            w5 < w20 && w20 < w100,
            "Wilson should increase with sample size: w5={w5} w20={w20} w100={w100}"
        );
    }

    #[test]
    fn test_confidence_in_evidence() {
        let mut store = MemoryBlockStore::new();
        let agent = Identity::from_bytes(&[70u8; 32]);
        let peer = Identity::from_bytes(&[71u8; 32]);

        // 10 interactions, all quality = 0.8 (positive)
        let mut prev = GENESIS_HASH.to_string();
        for i in 1..=10u64 {
            let (p, _) = create_interaction_with_tx(
                &mut store,
                &agent,
                &peer,
                i,
                i,
                &prev,
                GENESIS_HASH,
                1000 + i * 100,
                serde_json::json!({"outcome": "completed", "quality": 0.8}),
            );
            prev = p;
        }

        let engine = TrustEngine::new(&store, None, None, None);
        let evidence = engine
            .compute_trust_with_evidence(&agent.pubkey_hex())
            .unwrap();

        assert_eq!(evidence.sample_size, 10);
        assert_eq!(evidence.positive_count, 10); // all quality 0.8 >= 0.5
        assert!(
            evidence.confidence > 0.5,
            "10 positive interactions should give confidence > 0.5, got {}",
            evidence.confidence
        );
    }

    #[test]
    fn test_confidence_empty_chain() {
        let store = MemoryBlockStore::new();
        let engine = TrustEngine::new(&store, None, None, None);
        let evidence = engine.compute_trust_with_evidence("nobody").unwrap();

        assert_eq!(evidence.sample_size, 0);
        assert_eq!(evidence.positive_count, 0);
        assert!(
            evidence.confidence.abs() < 1e-10,
            "Empty chain should have confidence 0.0, got {}",
            evidence.confidence
        );
    }

    #[test]
    fn test_confidence_mixed_outcomes() {
        let mut store = MemoryBlockStore::new();
        let agent = Identity::from_bytes(&[72u8; 32]);
        let peer = Identity::from_bytes(&[73u8; 32]);

        // 5 good (quality 0.8) + 5 bad (quality 0.2)
        let mut prev = GENESIS_HASH.to_string();
        for i in 1..=5u64 {
            let (p, _) = create_interaction_with_tx(
                &mut store,
                &agent,
                &peer,
                i,
                i,
                &prev,
                GENESIS_HASH,
                1000 + i * 100,
                serde_json::json!({"outcome": "completed", "quality": 0.8}),
            );
            prev = p;
        }
        for i in 6..=10u64 {
            let (p, _) = create_interaction_with_tx(
                &mut store,
                &agent,
                &peer,
                i,
                i,
                &prev,
                GENESIS_HASH,
                1000 + i * 100,
                serde_json::json!({"outcome": "failed", "quality": 0.2}),
            );
            prev = p;
        }

        let engine = TrustEngine::new(&store, None, None, None);
        let evidence = engine
            .compute_trust_with_evidence(&agent.pubkey_hex())
            .unwrap();

        assert_eq!(evidence.sample_size, 10);
        assert_eq!(evidence.positive_count, 5); // 5 with quality >= 0.5
        assert!(
            evidence.confidence > 0.0 && evidence.confidence < 0.5,
            "Mixed outcomes should give confidence in (0, 0.5), got {}",
            evidence.confidence
        );
    }

    #[test]
    fn test_new_evidence_fields_in_seed_path() {
        // Ensure new fields are populated when using seed nodes.
        let mut store = MemoryBlockStore::new();
        let seed = Identity::from_bytes(&[80u8; 32]);
        let agent = Identity::from_bytes(&[81u8; 32]);

        let mut prev_a = GENESIS_HASH.to_string();
        let mut prev_s = GENESIS_HASH.to_string();
        for i in 1..=5u64 {
            let (pa, ps) = create_interaction_with_tx(
                &mut store,
                &agent,
                &seed,
                i,
                i,
                &prev_a,
                &prev_s,
                1000 + i * 100,
                serde_json::json!({"outcome": "completed", "quality": 0.9, "price": 50.0}),
            );
            prev_a = pa;
            prev_s = ps;
        }

        let engine = TrustEngine::new(&store, Some(vec![seed.pubkey_hex()]), None, None);
        let evidence = engine
            .compute_trust_with_evidence(&agent.pubkey_hex())
            .unwrap();

        assert!(
            evidence.trust_score > 0.0,
            "should have positive trust with seed"
        );
        assert_eq!(evidence.sample_size, 5);
        assert_eq!(evidence.positive_count, 5);
        assert!(
            evidence.confidence > 0.3,
            "confidence should be > 0.3 with 5 interactions"
        );
        assert!(
            (evidence.value_weighted_recency - evidence.recency).abs() < 0.01,
            "Equal prices → vw_recency ≈ recency"
        );
    }

    // -----------------------------------------------------------------------
    // Layer 6.1: Requester reputation tests
    // -----------------------------------------------------------------------

    /// Helper: create bilateral interaction with SEPARATE proposer/responder tx.
    #[allow(clippy::too_many_arguments)]
    fn create_bilateral_with_separate_tx(
        store: &mut MemoryBlockStore,
        proposer: &Identity,
        responder: &Identity,
        proposer_seq: u64,
        responder_seq: u64,
        proposer_prev: &str,
        responder_prev: &str,
        proposer_tx: serde_json::Value,
        responder_tx: serde_json::Value,
        ts: u64,
    ) -> (String, String) {
        let proposal = create_half_block(
            proposer,
            proposer_seq,
            &responder.pubkey_hex(),
            0,
            proposer_prev,
            BlockType::Proposal,
            proposer_tx,
            Some(ts),
        );
        store.add_block(&proposal).unwrap();

        let agreement = create_half_block(
            responder,
            responder_seq,
            &proposer.pubkey_hex(),
            proposer_seq,
            responder_prev,
            BlockType::Agreement,
            responder_tx,
            Some(ts + 1),
        );
        store.add_block(&agreement).unwrap();

        (proposal.block_hash, agreement.block_hash)
    }

    #[test]
    fn test_requester_trust_no_interactions() {
        let store = MemoryBlockStore::new();
        let engine = TrustEngine::new(&store, None, None, None);
        let evidence = engine.compute_requester_trust("unknown").unwrap();

        assert!(evidence.requester_trust.is_some());
        assert_eq!(evidence.payment_reliability, Some(1.0)); // empty → benefit of doubt
        assert!(evidence.rating_fairness.is_none()); // insufficient data
        assert_eq!(evidence.dispute_rate, Some(0.0)); // empty → 0
    }

    #[test]
    fn test_requester_trust_good_requester() {
        let mut store = MemoryBlockStore::new();
        let requester = Identity::from_bytes(&[1u8; 32]);
        let provider = Identity::from_bytes(&[2u8; 32]);
        let genesis = crate::types::GENESIS_HASH;

        // Create 5 bilateral interactions. Requester proposes, provider responds.
        // Provider's agreement blocks record quality=0.9 (good requester).
        let mut req_prev = genesis.to_string();
        let mut prov_prev = genesis.to_string();
        for i in 0..5u64 {
            let (rh, ph) = create_bilateral_with_separate_tx(
                &mut store,
                &requester,
                &provider,
                i + 1,
                i + 1,
                &req_prev,
                &prov_prev,
                serde_json::json!({"outcome": "completed", "quality": 0.9}),
                serde_json::json!({"outcome": "completed", "quality": 0.9}),
                1000 + i * 100,
            );
            req_prev = rh;
            prov_prev = ph;
        }

        let engine = TrustEngine::new(&store, None, None, None);
        let evidence = engine
            .compute_requester_trust(&requester.pubkey_hex())
            .unwrap();

        assert!(evidence.requester_trust.is_some());
        let rt = evidence.requester_trust.unwrap();
        assert!(rt > 0.3, "Good requester should have moderate trust: {rt}");
        assert!(
            evidence.payment_reliability.unwrap() > 0.8,
            "Good requester has high payment reliability"
        );
        assert_eq!(evidence.dispute_rate.unwrap(), 0.0, "No disputes");
    }

    #[test]
    fn test_requester_trust_bad_payer() {
        let mut store = MemoryBlockStore::new();
        let requester = Identity::from_bytes(&[1u8; 32]);
        let provider = Identity::from_bytes(&[2u8; 32]);
        let genesis = crate::types::GENESIS_HASH;

        // Provider records low quality (requester is a bad payer).
        let mut req_prev = genesis.to_string();
        let mut prov_prev = genesis.to_string();
        for i in 0..5u64 {
            let (rh, ph) = create_bilateral_with_separate_tx(
                &mut store,
                &requester,
                &provider,
                i + 1,
                i + 1,
                &req_prev,
                &prov_prev,
                serde_json::json!({"outcome": "completed", "quality": 0.9}),
                serde_json::json!({"outcome": "failed", "quality": 0.1}),
                1000 + i * 100,
            );
            req_prev = rh;
            prov_prev = ph;
        }

        let engine = TrustEngine::new(&store, None, None, None);
        let evidence = engine
            .compute_requester_trust(&requester.pubkey_hex())
            .unwrap();

        assert!(
            evidence.payment_reliability.unwrap() < 0.3,
            "Bad payer has low reliability: {}",
            evidence.payment_reliability.unwrap()
        );
    }

    #[test]
    fn test_requester_trust_high_dispute_rate() {
        let mut store = MemoryBlockStore::new();
        let requester = Identity::from_bytes(&[1u8; 32]);
        let provider = Identity::from_bytes(&[2u8; 32]);
        let genesis = crate::types::GENESIS_HASH;

        // Provider records disputed interactions.
        let mut req_prev = genesis.to_string();
        let mut prov_prev = genesis.to_string();
        for i in 0..5u64 {
            let (rh, ph) = create_bilateral_with_separate_tx(
                &mut store,
                &requester,
                &provider,
                i + 1,
                i + 1,
                &req_prev,
                &prov_prev,
                serde_json::json!({"outcome": "completed"}),
                serde_json::json!({"outcome": "disputed"}),
                1000 + i * 100,
            );
            req_prev = rh;
            prov_prev = ph;
        }

        let engine = TrustEngine::new(&store, None, None, None);
        let evidence = engine
            .compute_requester_trust(&requester.pubkey_hex())
            .unwrap();

        assert!(
            evidence.dispute_rate.unwrap() > 0.8,
            "All disputed → high dispute rate: {}",
            evidence.dispute_rate.unwrap()
        );
    }

    #[test]
    fn test_requester_fields_none_in_standard() {
        let mut store = MemoryBlockStore::new();
        let alice = Identity::from_bytes(&[1u8; 32]);
        let bob = Identity::from_bytes(&[2u8; 32]);
        let genesis = crate::types::GENESIS_HASH;

        create_interaction(&mut store, &alice, &bob, 1, 1, genesis, genesis, 1000);

        let engine = TrustEngine::new(&store, None, None, None);
        let evidence = engine
            .compute_trust_with_evidence(&alice.pubkey_hex())
            .unwrap();

        assert!(evidence.requester_trust.is_none());
        assert!(evidence.payment_reliability.is_none());
        assert!(evidence.rating_fairness.is_none());
        assert!(evidence.dispute_rate.is_none());
    }

    #[test]
    fn test_rating_fairness_insufficient_data() {
        let mut store = MemoryBlockStore::new();
        let requester = Identity::from_bytes(&[1u8; 32]);
        let provider = Identity::from_bytes(&[2u8; 32]);
        let genesis = crate::types::GENESIS_HASH;

        // Only 1 provider — insufficient for rating fairness (needs 3+).
        let mut req_prev = genesis.to_string();
        let mut prov_prev = genesis.to_string();
        for i in 0..3u64 {
            let (rh, ph) = create_bilateral_with_separate_tx(
                &mut store,
                &requester,
                &provider,
                i + 1,
                i + 1,
                &req_prev,
                &prov_prev,
                serde_json::json!({"outcome": "completed", "quality": 0.9, "requester_rating": 0.9}),
                serde_json::json!({"outcome": "completed", "quality": 0.9}),
                1000 + i * 100,
            );
            req_prev = rh;
            prov_prev = ph;
        }

        let engine = TrustEngine::new(&store, None, None, None);
        let evidence = engine
            .compute_requester_trust(&requester.pubkey_hex())
            .unwrap();

        // Only 1 unique provider rated — below the 3-provider threshold.
        assert!(
            evidence.rating_fairness.is_none(),
            "Should be None with < 3 providers"
        );
    }
}
