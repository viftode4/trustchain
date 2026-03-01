//! Unified trust engine combining integrity and netflow scores.
//!
//! Maps to Python's `trust.py`. Blends chain integrity and NetFlow Sybil resistance
//! into a single score, with configurable weights.
//! Delegation-aware: delegated identities inherit trust from their root principal.

use crate::blockstore::BlockStore;
use crate::delegation::{DelegationRecord, DelegationStore};
use crate::error::Result;
use crate::netflow::{CachedNetFlow, NetFlowTrust};
use crate::types::GENESIS_HASH;

/// Default weights for the two trust components.
pub const DEFAULT_INTEGRITY_WEIGHT: f64 = 0.5;
pub const DEFAULT_NETFLOW_WEIGHT: f64 = 0.5;

/// Configuration weights for trust components.
///
/// Only two components remain, both paper-defined:
/// - **integrity**: chain validity (hash linkage, signatures, sequence numbers)
/// - **netflow**: Sybil-resistant max-flow from seed nodes
#[derive(Debug, Clone)]
pub struct TrustWeights {
    pub integrity: f64,
    pub netflow: f64,
}

impl Default for TrustWeights {
    fn default() -> Self {
        Self {
            integrity: DEFAULT_INTEGRITY_WEIGHT,
            netflow: DEFAULT_NETFLOW_WEIGHT,
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
        let (root_pubkey, root_active_delegation_count) =
            if let Some(ref delegation) = active_delegation {
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
                let active_count = all_delegations
                    .iter()
                    .filter(|d| d.is_active(now_ms))
                    .count()
                    .max(1);
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
    /// Score = `w_integrity * integrity + w_netflow * netflow`.
    /// If netflow is unavailable (no seed nodes), only integrity is used.
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
    ///
    /// Score = `w_integrity * integrity + w_netflow * netflow`.
    /// When seed nodes are configured, NetFlow acts as a Sybil-resistance gate:
    /// if there is no path from any seed to the target, the score is zero.
    /// When no seeds are configured, only integrity is used.
    fn compute_standard_trust(&self, pubkey: &str) -> Result<f64> {
        // Hard zero for proven fraud.
        let frauds = self.store.get_double_spends(pubkey)?;
        if !frauds.is_empty() {
            return Ok(0.0);
        }

        let integrity = self.compute_chain_integrity(pubkey)?;

        if let Some(ref seeds) = self.seed_nodes {
            if !seeds.is_empty() {
                let netflow = self.compute_netflow_score(pubkey)?;

                // Sybil gate: no path from seeds → zero trust.
                if netflow < 1e-10 {
                    return Ok(0.0);
                }

                let score = self.weights.integrity * integrity + self.weights.netflow * netflow;
                return Ok(score.clamp(0.0, 1.0));
            }
        }

        // No seeds configured — integrity only.
        Ok(integrity)
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

            if !crate::halfblock::verify_block(block).unwrap_or(false) {
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blockstore::MemoryBlockStore;
    use crate::halfblock::create_half_block;
    use crate::identity::Identity;
    use crate::types::BlockType;
    use std::collections::HashMap;

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
        assert!(score >= 0.0 && score <= 1.0);
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
        };

        let engine = TrustEngine::new(&store, None, None, Some(ctx));
        let delegate_trust = engine.compute_trust(&delegate1.pubkey_hex()).unwrap();
        let expected = root_trust / 2.0;
        assert!(
            (delegate_trust - expected).abs() < 1e-10,
            "delegate trust {delegate_trust} should be ~root/2 = {expected}"
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
    fn test_all_weights_zero() {
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

        let weights = TrustWeights {
            integrity: 0.0,
            netflow: 0.0,
        };

        let engine = TrustEngine::new(&store, None, Some(weights), None);
        let trust = engine.compute_trust(&agent.pubkey_hex()).unwrap();
        // No seeds configured → integrity only, but weights don't matter
        // since integrity is returned directly when no seeds are set.
        assert!(trust >= 0.0 && trust <= 1.0);
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
}
