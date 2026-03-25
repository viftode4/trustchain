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

/// Configuration for the multiplicative trust model.
///
/// Trust = connectivity × integrity × diversity × recency
/// - **connectivity** = min(path_diversity / K, 1.0)
/// - **integrity** = chain_integrity (fraction of valid blocks)
/// - **diversity** = min(unique_peers / M, 1.0)
/// - **recency** = exponential-decay-weighted outcome quality
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
    /// Trust = connectivity × integrity × diversity × recency (4-factor multiplicative).
    /// If netflow is unavailable (no seed nodes), only integrity × recency is used.
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

        // Compute delegated trust: root_trust * delegation_factor / active_count
        let root_trust = self.compute_standard_trust(root_pubkey, context)?;
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
    /// Trust = connectivity × integrity × diversity × recency (4-factor multiplicative).
    /// When seed nodes are configured, path_diversity is used for connectivity.
    /// When no seeds are configured, connectivity=1.0, diversity=1.0.
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
        // Hard zero for proven fraud.
        let frauds = self.store.get_double_spends(pubkey)?;
        if !frauds.is_empty() {
            let chain = self.store.get_chain(pubkey)?;
            let audit_count = chain.iter().filter(|b| b.is_audit()).count();
            return Ok(TrustEvidence {
                trust_score: 0.0,
                connectivity: 0.0,
                integrity: 0.0,
                diversity: 0.0,
                recency: 0.0,
                unique_peers: self.count_unique_peers(&chain),
                interactions: chain.len(),
                fraud: true,
                path_diversity: 0.0,
                audit_count,
            });
        }

        // Use context-filtered chain for recency and diversity.
        let filtered_chain = self.get_chain_for_context(pubkey, context)?;
        let integrity = self.compute_chain_integrity(pubkey)?;
        let unique_peers = self.count_unique_peers(&filtered_chain);
        let interactions = filtered_chain.len();
        let audit_count = filtered_chain.iter().filter(|b| b.is_audit()).count();
        let diversity = (unique_peers as f64 / self.config.diversity_threshold).min(1.0);
        let recency = self.compute_recency(&filtered_chain);

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
                    });
                }

                let connectivity = (path_div / self.config.connectivity_threshold).min(1.0);
                let trust_score = (connectivity * integrity * diversity * recency).clamp(0.0, 1.0);

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
                });
            }
        }

        // No seeds configured — no Sybil resistance, use integrity × recency only.
        // Connectivity and diversity default to 1.0 since there's no topology to measure.
        Ok(TrustEvidence {
            trust_score: (integrity * recency).clamp(0.0, 1.0),
            connectivity: 1.0,
            integrity,
            diversity: 1.0,
            recency,
            unique_peers,
            interactions,
            fraud: false,
            path_diversity: 0.0,
            audit_count,
        })
    }

    /// Compute recency: exponential-decay-weighted outcome quality.
    ///
    /// recency = Σ(λ^(n-1-k) × outcome_k) / Σ(λ^(n-1-k))
    /// Empty chain → 1.0 (no penalty for no data).
    fn compute_recency(&self, chain: &[crate::halfblock::HalfBlock]) -> f64 {
        if chain.is_empty() {
            return 1.0;
        }
        let lambda = self.config.recency_lambda;
        let n = chain.len();
        let mut weighted_sum = 0.0;
        let mut weight_total = 0.0;
        for (k, block) in chain.iter().enumerate() {
            let weight = lambda.powi((n - 1 - k) as i32);
            let outcome = Self::extract_outcome(&block.transaction);
            weighted_sum += weight * outcome;
            weight_total += weight;
        }
        if weight_total < 1e-10 {
            return 1.0;
        }
        (weighted_sum / weight_total).clamp(0.0, 1.0)
    }

    /// Extract outcome from a block's transaction data.
    ///
    /// "completed" / "success" → 1.0, "failed" / "error" → 0.0.
    /// Missing or unknown → 1.0 (backward compat: assume success).
    fn extract_outcome(transaction: &serde_json::Value) -> f64 {
        match transaction.get("outcome").and_then(|v| v.as_str()) {
            Some("completed") | Some("success") => 1.0,
            Some("failed") | Some("error") => 0.0,
            _ => 1.0, // backward compat: unknown = success
        }
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
                    let root_evidence =
                        self.compute_standard_trust_evidence(root_pubkey, context)?;
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
        // Block 1 valid, block 3 has seq gap → 1/2 = 0.5.
        assert!(
            (integrity - 0.5).abs() < 1e-10,
            "integrity should be 0.5 with sequence gap, got {integrity}"
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
        assert!(
            (evidence.recency - 1.0).abs() < 1e-6,
            "empty chain should give recency = 1.0, got {}",
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
}
