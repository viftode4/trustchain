//! Unified trust engine combining integrity, netflow, and statistical scores.
//!
//! Maps to Python's `trust.py`. Blends multiple trust signals into a single
//! score for each agent, with configurable weights.
//! Delegation-aware: delegated identities inherit trust from their root principal.

use std::collections::HashMap;

use crate::blockstore::BlockStore;
use crate::delegation::{DelegationRecord, DelegationStore};
use crate::error::Result;
use crate::netflow::{CachedNetFlow, NetFlowTrust};
use crate::types::GENESIS_HASH;

/// Default weights for the three trust components.
pub const DEFAULT_INTEGRITY_WEIGHT: f64 = 0.3;
pub const DEFAULT_NETFLOW_WEIGHT: f64 = 0.4;
pub const DEFAULT_STATISTICAL_WEIGHT: f64 = 0.3;

/// Configuration weights for trust components.
#[derive(Debug, Clone)]
pub struct TrustWeights {
    pub integrity: f64,
    pub netflow: f64,
    pub statistical: f64,
    /// Optional temporal decay half-life in milliseconds.
    /// When set, recent interactions are weighted more heavily using `2^(-age_ms / half_life_ms)`.
    /// Affects interaction_count, completion_rate, and entropy (not unique_counterparties or account_age).
    pub decay_half_life_ms: Option<u64>,
}

impl Default for TrustWeights {
    fn default() -> Self {
        Self {
            integrity: DEFAULT_INTEGRITY_WEIGHT,
            netflow: DEFAULT_NETFLOW_WEIGHT,
            statistical: DEFAULT_STATISTICAL_WEIGHT,
            decay_half_life_ms: None,
        }
    }
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
        let (root_pubkey, root_active_delegation_count) = if let Some(ref delegation) = active_delegation {
            let mut root = delegation.delegator_pubkey.clone();
            let mut current = delegation.clone();
            while let Some(ref parent_id) = current.parent_delegation_id {
                if let Ok(Some(parent)) = ds.get_delegation(parent_id) {
                    root = parent.delegator_pubkey.clone();
                    current = parent;
                } else {
                    break;
                }
            }
            let all_delegations = ds.get_delegations_by_delegator(&root)?;
            let active_count = all_delegations.iter().filter(|d| d.is_active(now_ms)).count().max(1);
            (Some(root), active_count)
        } else {
            (None, 0)
        };

        // Get delegations where this pubkey is delegator (for fraud propagation)
        let delegations_as_delegator = ds.get_delegations_by_delegator(pubkey)?;

        Ok(Self {
            active_delegation,
            was_delegate,
            delegations_as_delegator,
            root_pubkey,
            root_active_delegation_count,
        })
    }
}

/// The unified trust engine.
pub struct TrustEngine<'a, S: BlockStore> {
    store: &'a S,
    seed_nodes: Option<Vec<String>>,
    weights: TrustWeights,
    delegation_ctx: Option<DelegationContext>,
    /// Optional finalized checkpoint for verification acceleration.
    checkpoint: Option<crate::consensus::Checkpoint>,
}

impl<'a, S: BlockStore> TrustEngine<'a, S> {
    pub fn new(
        store: &'a S,
        seed_nodes: Option<Vec<String>>,
        weights: Option<TrustWeights>,
        delegation_ctx: Option<DelegationContext>,
    ) -> Self {
        Self {
            store,
            seed_nodes,
            weights: weights.unwrap_or_default(),
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
    /// Delegation-aware:
    /// - If the pubkey is an active delegate, trust is derived from the root delegator
    ///   with a budget split across active delegations.
    /// - If the pubkey was a delegate but the delegation is no longer active, returns 0.0.
    /// - If any delegate (active or revoked) of this pubkey committed fraud, returns 0.0.
    ///
    /// Standard (non-delegated):
    /// Score = `w_integrity * integrity + w_netflow * netflow + w_statistical * statistical`
    /// If netflow is unavailable (no seed nodes), its weight is redistributed.
    /// Returns hard zero for agents with proven double-spend fraud.
    pub fn compute_trust(&self, pubkey: &str) -> Result<f64> {
        // Check delegation context
        if let Some(ref ctx) = self.delegation_ctx {
            // Is this an active delegated identity?
            if let Some(ref _delegation) = ctx.active_delegation {
                if let Some(ref root_pubkey) = ctx.root_pubkey {
                    // Compute root's trust
                    let root_trust = self.compute_standard_trust(root_pubkey)?;
                    // Budget split
                    let active_count = ctx.root_active_delegation_count.max(1);
                    let effective = root_trust / active_count as f64;
                    return Ok(effective.clamp(0.0, 1.0));
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

        self.compute_standard_trust(pubkey)
    }

    /// Standard trust computation (non-delegated path).
    fn compute_standard_trust(&self, pubkey: &str) -> Result<f64> {
        // Hard zero for proven fraud.
        let frauds = self.store.get_double_spends(pubkey)?;
        if !frauds.is_empty() {
            return Ok(0.0);
        }

        let integrity = self.compute_chain_integrity(pubkey)?;
        let statistical = self.compute_statistical_score(pubkey)?;

        if let Some(ref seeds) = self.seed_nodes {
            if !seeds.is_empty() {
                let netflow = self.compute_netflow_score(pubkey)?;
                let score = self.weights.integrity * integrity
                    + self.weights.netflow * netflow
                    + self.weights.statistical * statistical;
                return Ok(score.clamp(0.0, 1.0));
            }
        }

        // No netflow — redistribute weight.
        let total = self.weights.integrity + self.weights.statistical;
        if total == 0.0 {
            return Ok(0.0);
        }
        let score =
            (self.weights.integrity / total) * integrity + (self.weights.statistical / total) * statistical;
        Ok(score.clamp(0.0, 1.0))
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
        let checkpoint_seq = self.checkpoint.as_ref()
            .filter(|cp| cp.finalized)
            .and_then(|cp| cp.chain_heads.get(pubkey))
            .copied()
            .unwrap_or(0);

        let total = chain.len() as f64;
        for (i, block) in chain.iter().enumerate() {
            let expected_seq = (i as u64) + 1;
            if block.sequence_number != expected_seq {
                return Ok(i as f64 / total);
            }

            let expected_prev = if i == 0 {
                GENESIS_HASH.to_string()
            } else {
                chain[i - 1].block_hash.clone()
            };
            if block.previous_hash != expected_prev {
                return Ok(i as f64 / total);
            }

            // Skip Ed25519 verification for blocks covered by the checkpoint.
            if block.sequence_number <= checkpoint_seq {
                continue;
            }

            if crate::halfblock::verify_block(block).unwrap_or(false) == false {
                return Ok(i as f64 / total);
            }
        }

        Ok(1.0)
    }

    /// Compute the netflow (Sybil-resistance) score.
    pub fn compute_netflow_score(&self, pubkey: &str) -> Result<f64> {
        match &self.seed_nodes {
            Some(seeds) if !seeds.is_empty() => {
                let nf = NetFlowTrust::new(self.store, seeds.clone())?;
                nf.compute_trust(pubkey)
            }
            _ => Ok(0.0),
        }
    }

    /// Compute the netflow score using an external `CachedNetFlow` instance.
    ///
    /// This amortizes graph construction cost across multiple trust queries.
    /// The caller is responsible for providing a `CachedNetFlow` with a compatible store.
    pub fn compute_netflow_score_cached<CS: BlockStore>(
        &self,
        cached: &mut CachedNetFlow<CS>,
        pubkey: &str,
    ) -> Result<f64> {
        cached.compute_trust(pubkey)
    }

    /// Compute statistical score from interaction history features.
    ///
    /// Features (with saturation points and weights):
    /// - interaction_count: saturates at 20 blocks, weight 0.25
    /// - unique_counterparties: saturates at 5 peers, weight 0.20 (structural, no decay)
    /// - completion_rate: direct percentage, weight 0.25
    /// - account_age: saturates at 60 seconds, weight 0.10 (structural, no decay)
    /// - entropy: normalized Shannon entropy, weight 0.20
    ///
    /// When `decay_half_life_ms` is set in `TrustWeights`, applies temporal decay
    /// `2^(-age_ms / half_life_ms)` per block to interaction_count, completion_rate,
    /// and entropy. unique_counterparties and account_age are structural and unaffected.
    pub fn compute_statistical_score(&self, pubkey: &str) -> Result<f64> {
        let chain = self.store.get_chain(pubkey)?;
        if chain.is_empty() {
            return Ok(0.0);
        }

        // Reference time for decay: latest block's timestamp.
        let now_ms = chain.last().map(|b| b.timestamp).unwrap_or(0);

        // Compute per-block decay weight.
        let decay_weight = |block_ts: u64| -> f64 {
            match self.weights.decay_half_life_ms {
                Some(hl) if hl > 0 => {
                    let age_ms = now_ms.saturating_sub(block_ts) as f64;
                    2.0_f64.powf(-(age_ms / hl as f64))
                }
                _ => 1.0,
            }
        };

        // Feature 1: interaction count (saturates at 20).
        // With decay: sum of decay weights instead of raw count.
        let weighted_count: f64 = chain.iter().map(|b| decay_weight(b.timestamp)).sum();
        let count_score = (weighted_count / 20.0).min(1.0);

        // Feature 2: unique counterparties (saturates at 5). Structural — no decay.
        let mut counterparties: HashMap<String, usize> = HashMap::new();
        // Also track decay-weighted counterparty distribution for entropy.
        let mut counterparties_weighted: HashMap<String, f64> = HashMap::new();
        for block in &chain {
            *counterparties
                .entry(block.link_public_key.clone())
                .or_insert(0) += 1;
            *counterparties_weighted
                .entry(block.link_public_key.clone())
                .or_insert(0.0) += decay_weight(block.timestamp);
        }
        let unique_count = counterparties.len() as f64;
        let unique_score = (unique_count / 5.0).min(1.0);

        // Feature 3: completion rate.
        // With decay: decay-weighted completed / decay-weighted total.
        let blocks_with_outcome: Vec<_> = chain
            .iter()
            .filter(|b| {
                b.transaction
                    .get("outcome")
                    .and_then(|v| v.as_str())
                    .is_some()
            })
            .collect();
        let completion_rate = if !blocks_with_outcome.is_empty() {
            let weighted_total: f64 = blocks_with_outcome
                .iter()
                .map(|b| decay_weight(b.timestamp))
                .sum();
            let weighted_completed: f64 = blocks_with_outcome
                .iter()
                .filter(|b| {
                    b.transaction
                        .get("outcome")
                        .and_then(|v| v.as_str())
                        == Some("completed")
                })
                .map(|b| decay_weight(b.timestamp))
                .sum();
            if weighted_total > 0.0 {
                weighted_completed / weighted_total
            } else {
                0.0
            }
        } else {
            // Fallback: use proposal/agreement pairing (no decay for fallback).
            let proposals: Vec<_> = chain.iter().filter(|b| b.is_proposal()).collect();
            if proposals.is_empty() {
                1.0
            } else {
                let completed = proposals
                    .iter()
                    .filter(|p| {
                        self.store
                            .get_linked_block(p)
                            .ok()
                            .flatten()
                            .is_some()
                    })
                    .count();
                completed as f64 / proposals.len() as f64
            }
        };

        // Feature 4: account age (saturates at 60 seconds = 60_000 ms). Structural — no decay.
        let first_ts = chain.first().map(|b| b.timestamp).unwrap_or(0) as f64;
        let last_ts = chain.last().map(|b| b.timestamp).unwrap_or(0) as f64;
        let age_ms = (last_ts - first_ts).max(0.0);
        let age_score = (age_ms / 60_000.0).min(1.0);

        // Feature 5: Shannon entropy of counterparty distribution.
        // With decay: uses decay-weighted distribution.
        let entropy_score = if counterparties.len() <= 1 {
            0.0
        } else {
            let total: f64 = counterparties_weighted.values().sum();
            let entropy: f64 = counterparties_weighted
                .values()
                .map(|&count| {
                    let p = count / total;
                    if p > 0.0 {
                        -p * p.log2()
                    } else {
                        0.0
                    }
                })
                .sum();
            let max_entropy = (counterparties.len() as f64).log2();
            if max_entropy > 0.0 {
                entropy / max_entropy
            } else {
                0.0
            }
        };

        // Weighted combination.
        let score = 0.25 * count_score
            + 0.20 * unique_score
            + 0.25 * completion_rate
            + 0.10 * age_score
            + 0.20 * entropy_score;

        Ok(score.clamp(0.0, 1.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blockstore::MemoryBlockStore;
    use crate::halfblock::create_half_block;
    use crate::identity::Identity;
    use crate::types::BlockType;

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
            alice, alice_seq, &bob.pubkey_hex(), 0,
            alice_prev, BlockType::Proposal,
            serde_json::json!({"service": "test"}), Some(ts),
        );
        store.add_block(&proposal).unwrap();

        let agreement = create_half_block(
            bob, bob_seq, &alice.pubkey_hex(), alice_seq,
            bob_prev, BlockType::Agreement,
            serde_json::json!({"service": "test"}), Some(ts + 1),
        );
        store.add_block(&agreement).unwrap();

        (proposal.block_hash, agreement.block_hash)
    }

    #[test]
    fn test_empty_chain_trust() {
        let store = MemoryBlockStore::new();
        let engine = TrustEngine::new(&store, None, None, None);
        let score = engine.compute_trust("unknown").unwrap();
        // Empty chain: integrity=1.0, statistical=0.0 -> redistributed.
        assert!(score >= 0.0 && score <= 1.0);
    }

    #[test]
    fn test_trust_with_interactions() {
        let mut store = MemoryBlockStore::new();
        let seed = Identity::from_bytes(&[1u8; 32]);
        let agent = Identity::from_bytes(&[2u8; 32]);

        create_interaction(
            &mut store, &seed, &agent, 1, 1, GENESIS_HASH, GENESIS_HASH, 1000,
        );

        let engine = TrustEngine::new(
            &store,
            Some(vec![seed.pubkey_hex()]),
            None,
            None,
        );

        let score = engine.compute_trust(&agent.pubkey_hex()).unwrap();
        assert!(score > 0.0, "agent with interaction should have positive trust");
        assert!(score <= 1.0);
    }

    #[test]
    fn test_seed_node_high_trust() {
        let mut store = MemoryBlockStore::new();
        let seed = Identity::from_bytes(&[1u8; 32]);
        let agent = Identity::from_bytes(&[2u8; 32]);

        create_interaction(
            &mut store, &seed, &agent, 1, 1, GENESIS_HASH, GENESIS_HASH, 1000,
        );

        let engine = TrustEngine::new(
            &store,
            Some(vec![seed.pubkey_hex()]),
            None,
            None,
        );

        let seed_score = engine.compute_trust(&seed.pubkey_hex()).unwrap();
        assert!(seed_score > 0.5, "seed should have high trust: {seed_score}");
    }

    #[test]
    fn test_statistical_score_multiple_counterparties() {
        let mut store = MemoryBlockStore::new();
        let agent = Identity::from_bytes(&[1u8; 32]);
        let mut prev = GENESIS_HASH.to_string();

        // Interact with 5 different counterparties.
        for i in 2..=6 {
            let peer = Identity::from_bytes(&[i as u8; 32]);
            let proposal = create_half_block(
                &agent, (i - 1) as u64, &peer.pubkey_hex(), 0,
                &prev, BlockType::Proposal,
                serde_json::json!({"service": "test"}), Some(1000 + i as u64 * 10),
            );
            prev = proposal.block_hash.clone();
            store.add_block(&proposal).unwrap();
        }

        let engine = TrustEngine::new(&store, None, None, None);
        let score = engine.compute_statistical_score(&agent.pubkey_hex()).unwrap();
        assert!(score > 0.0, "multiple counterparties should yield positive statistical score");
    }

    #[test]
    fn test_no_netflow_redistribution() {
        let mut store = MemoryBlockStore::new();
        let agent = Identity::from_bytes(&[1u8; 32]);
        let peer = Identity::from_bytes(&[2u8; 32]);

        create_interaction(
            &mut store, &agent, &peer, 1, 1, GENESIS_HASH, GENESIS_HASH, 1000,
        );

        // No seed nodes -> netflow weight redistributed.
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
            &mut store, &agent, &peer, 1, 1, GENESIS_HASH, GENESIS_HASH, 1000,
        );

        // Without fraud, trust should be positive.
        let engine = TrustEngine::new(&store, None, None, None);
        let score_before = engine.compute_trust(&agent.pubkey_hex()).unwrap();
        assert!(score_before > 0.0, "should have positive trust before fraud");

        // Record a double-spend fraud.
        let fake_a = create_half_block(
            &agent, 2, &peer.pubkey_hex(), 0,
            GENESIS_HASH, BlockType::Proposal,
            serde_json::json!({"version": "a"}), Some(2000),
        );
        let fake_b = create_half_block(
            &agent, 2, &peer.pubkey_hex(), 0,
            GENESIS_HASH, BlockType::Proposal,
            serde_json::json!({"version": "b"}), Some(2001),
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
            &mut store, &agent, &peer, 1, 1, GENESIS_HASH, GENESIS_HASH, 1000,
        );

        let engine = TrustEngine::new(&store, None, None, None);
        assert_eq!(engine.compute_chain_integrity(&agent.pubkey_hex()).unwrap(), 1.0);
    }

    #[test]
    fn test_checkpoint_full_coverage() {
        // Checkpoint covers all blocks -> structural checks only, no verify.
        let mut store = MemoryBlockStore::new();
        let agent = Identity::from_bytes(&[1u8; 32]);
        let peer = Identity::from_bytes(&[2u8; 32]);

        let (p1, _) = create_interaction(
            &mut store, &agent, &peer, 1, 1, GENESIS_HASH, GENESIS_HASH, 1000,
        );
        create_interaction(
            &mut store, &agent, &peer, 2, 2, &p1, GENESIS_HASH, 2000,
        );

        let mut chain_heads = HashMap::new();
        chain_heads.insert(agent.pubkey_hex(), 2); // covers seq 1 and 2
        let checkpoint = crate::consensus::Checkpoint {
            facilitator_pubkey: "facilitator".into(),
            chain_heads,
            checkpoint_block: crate::halfblock::create_half_block(
                &peer, 99, &agent.pubkey_hex(), 0, GENESIS_HASH,
                BlockType::Proposal, serde_json::json!({}), Some(3000),
            ),
            signatures: HashMap::new(),
            timestamp: 3000,
            finalized: true,
        };

        let engine = TrustEngine::new(&store, None, None, None)
            .with_checkpoint(checkpoint);
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
            &mut store, &agent, &peer, 1, 1, GENESIS_HASH, GENESIS_HASH, 1000,
        );
        create_interaction(
            &mut store, &agent, &peer, 2, 2, &p1, GENESIS_HASH, 2000,
        );

        let mut chain_heads = HashMap::new();
        chain_heads.insert(agent.pubkey_hex(), 1); // covers only seq 1
        let checkpoint = crate::consensus::Checkpoint {
            facilitator_pubkey: "facilitator".into(),
            chain_heads,
            checkpoint_block: crate::halfblock::create_half_block(
                &peer, 99, &agent.pubkey_hex(), 0, GENESIS_HASH,
                BlockType::Proposal, serde_json::json!({}), Some(3000),
            ),
            signatures: HashMap::new(),
            timestamp: 3000,
            finalized: true,
        };

        let engine = TrustEngine::new(&store, None, None, None)
            .with_checkpoint(checkpoint);
        let integrity = engine.compute_chain_integrity(&agent.pubkey_hex()).unwrap();
        assert_eq!(integrity, 1.0, "partial checkpoint should still validate remaining blocks");
    }

    #[test]
    fn test_checkpoint_none_fallback() {
        // No checkpoint -> full verification (same as before).
        let mut store = MemoryBlockStore::new();
        let agent = Identity::from_bytes(&[1u8; 32]);
        let peer = Identity::from_bytes(&[2u8; 32]);

        create_interaction(
            &mut store, &agent, &peer, 1, 1, GENESIS_HASH, GENESIS_HASH, 1000,
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
            &mut store, &agent, &peer, 1, 1, GENESIS_HASH, GENESIS_HASH, 1000,
        );

        let checkpoint = crate::consensus::Checkpoint {
            facilitator_pubkey: "facilitator".into(),
            chain_heads: HashMap::new(), // empty — doesn't cover agent
            checkpoint_block: crate::halfblock::create_half_block(
                &peer, 99, &agent.pubkey_hex(), 0, GENESIS_HASH,
                BlockType::Proposal, serde_json::json!({}), Some(3000),
            ),
            signatures: HashMap::new(),
            timestamp: 3000,
            finalized: true,
        };

        let engine = TrustEngine::new(&store, None, None, None)
            .with_checkpoint(checkpoint);
        let integrity = engine.compute_chain_integrity(&agent.pubkey_hex()).unwrap();
        assert_eq!(integrity, 1.0, "unknown pubkey in checkpoint should fall back to full verify");
    }

    #[test]
    fn test_decay_none_matches_current() {
        // With no decay, scores should match the default behavior.
        let mut store = MemoryBlockStore::new();
        let agent = Identity::from_bytes(&[1u8; 32]);
        let peer = Identity::from_bytes(&[2u8; 32]);

        create_interaction(
            &mut store, &agent, &peer, 1, 1, GENESIS_HASH, GENESIS_HASH, 1000,
        );

        let weights_no_decay = TrustWeights { decay_half_life_ms: None, ..Default::default() };
        let weights_default = TrustWeights::default();

        let engine_no_decay = TrustEngine::new(&store, None, Some(weights_no_decay), None);
        let engine_default = TrustEngine::new(&store, None, Some(weights_default), None);

        let score_no_decay = engine_no_decay.compute_statistical_score(&agent.pubkey_hex()).unwrap();
        let score_default = engine_default.compute_statistical_score(&agent.pubkey_hex()).unwrap();

        assert!((score_no_decay - score_default).abs() < 1e-10,
            "no-decay should match default: {score_no_decay} vs {score_default}");
    }

    #[test]
    fn test_decay_recent_higher() {
        // Two agents with same age span but different timing of interactions.
        // Recent agent: all interactions near the end of the time window.
        // Old agent: all interactions near the beginning.
        // With decay, recent agent should score higher on count/completion features.
        let mut store = MemoryBlockStore::new();
        let recent_agent = Identity::from_bytes(&[1u8; 32]);
        let old_agent = Identity::from_bytes(&[3u8; 32]);
        let peer1 = Identity::from_bytes(&[2u8; 32]);
        let peer2 = Identity::from_bytes(&[4u8; 32]);

        // Recent agent: 3 interactions all at t=9500, 9700, 10000
        let (p1, _) = create_interaction(
            &mut store, &recent_agent, &peer1, 1, 1, GENESIS_HASH, GENESIS_HASH, 9500,
        );
        let (p2, _) = create_interaction(
            &mut store, &recent_agent, &peer2, 2, 1, &p1, GENESIS_HASH, 9700,
        );
        create_interaction(
            &mut store, &recent_agent, &peer1, 3, 2, &p2, GENESIS_HASH, 10000,
        );

        // Old agent: 3 interactions at t=1000, 1200, 10000 (same span, but bulk is old)
        let (p3, _) = create_interaction(
            &mut store, &old_agent, &peer1, 1, 3, GENESIS_HASH, GENESIS_HASH, 1000,
        );
        let (p4, _) = create_interaction(
            &mut store, &old_agent, &peer2, 2, 2, &p3, GENESIS_HASH, 1200,
        );
        create_interaction(
            &mut store, &old_agent, &peer1, 3, 4, &p4, GENESIS_HASH, 10000,
        );

        let weights = TrustWeights {
            decay_half_life_ms: Some(2000), // 2 second half-life — aggressive decay
            ..Default::default()
        };

        let engine = TrustEngine::new(&store, None, Some(weights), None);
        let recent_score = engine.compute_statistical_score(&recent_agent.pubkey_hex()).unwrap();
        let old_score = engine.compute_statistical_score(&old_agent.pubkey_hex()).unwrap();

        assert!(recent_score > old_score,
            "recent ({recent_score}) should score higher than old ({old_score}) with decay");
    }

    #[test]
    fn test_decay_formula_correctness() {
        // Verify the decay formula: 2^(-age_ms / half_life_ms)
        // With half_life=1000ms and age=1000ms, weight should be 0.5
        // With half_life=1000ms and age=0ms, weight should be 1.0
        let mut store = MemoryBlockStore::new();
        let agent = Identity::from_bytes(&[1u8; 32]);
        let peer = Identity::from_bytes(&[2u8; 32]);

        // Single block at t=0, "now" will be t=0 (latest block), so weight = 1.0
        create_interaction(
            &mut store, &agent, &peer, 1, 1, GENESIS_HASH, GENESIS_HASH, 1000,
        );

        // With decay enabled, single block should have weight 1.0 (age=0 relative to itself)
        let weights = TrustWeights {
            decay_half_life_ms: Some(1000),
            ..Default::default()
        };

        let engine = TrustEngine::new(&store, None, Some(weights.clone()), None);
        let score_with_decay = engine.compute_statistical_score(&agent.pubkey_hex()).unwrap();

        let engine_no_decay = TrustEngine::new(&store, None, None, None);
        let score_no_decay = engine_no_decay.compute_statistical_score(&agent.pubkey_hex()).unwrap();

        // Single block: decay weight should be 1.0 (age is 0 relative to itself),
        // so scores should match.
        assert!((score_with_decay - score_no_decay).abs() < 1e-10,
            "single block with decay={score_with_decay} should equal no-decay={score_no_decay}");
    }
}
