//! Unified trust engine combining integrity, netflow, and statistical scores.
//!
//! Maps to Python's `trust.py`. Blends multiple trust signals into a single
//! score for each agent, with configurable weights.

use std::collections::HashMap;

use crate::blockstore::BlockStore;
use crate::error::Result;
use crate::netflow::NetFlowTrust;
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
}

impl Default for TrustWeights {
    fn default() -> Self {
        Self {
            integrity: DEFAULT_INTEGRITY_WEIGHT,
            netflow: DEFAULT_NETFLOW_WEIGHT,
            statistical: DEFAULT_STATISTICAL_WEIGHT,
        }
    }
}

/// The unified trust engine.
pub struct TrustEngine<'a, S: BlockStore> {
    store: &'a S,
    seed_nodes: Option<Vec<String>>,
    weights: TrustWeights,
}

impl<'a, S: BlockStore> TrustEngine<'a, S> {
    pub fn new(
        store: &'a S,
        seed_nodes: Option<Vec<String>>,
        weights: Option<TrustWeights>,
    ) -> Self {
        Self {
            store,
            seed_nodes,
            weights: weights.unwrap_or_default(),
        }
    }

    /// Compute the blended trust score for an agent.
    ///
    /// Score = `w_integrity * integrity + w_netflow * netflow + w_statistical * statistical`
    ///
    /// If netflow is unavailable (no seed nodes), its weight is redistributed.
    /// Returns hard zero for agents with proven double-spend fraud.
    pub fn compute_trust(&self, pubkey: &str) -> Result<f64> {
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
    pub fn compute_chain_integrity(&self, pubkey: &str) -> Result<f64> {
        let chain = self.store.get_chain(pubkey)?;
        if chain.is_empty() {
            return Ok(1.0);
        }

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

    /// Compute statistical score from interaction history features.
    ///
    /// Features (with saturation points and weights):
    /// - interaction_count: saturates at 20 blocks, weight 0.25
    /// - unique_counterparties: saturates at 5 peers, weight 0.20
    /// - completion_rate: direct percentage, weight 0.25
    /// - account_age: saturates at 60 seconds, weight 0.10
    /// - entropy: normalized Shannon entropy, weight 0.20
    pub fn compute_statistical_score(&self, pubkey: &str) -> Result<f64> {
        let chain = self.store.get_chain(pubkey)?;
        if chain.is_empty() {
            return Ok(0.0);
        }

        // Feature 1: interaction count (saturates at 20).
        let interaction_count = chain.len() as f64;
        let count_score = (interaction_count / 20.0).min(1.0);

        // Feature 2: unique counterparties (saturates at 5).
        let mut counterparties: HashMap<String, usize> = HashMap::new();
        for block in &chain {
            *counterparties
                .entry(block.link_public_key.clone())
                .or_insert(0) += 1;
        }
        let unique_count = counterparties.len() as f64;
        let unique_score = (unique_count / 5.0).min(1.0);

        // Feature 3: completion rate.
        // Count blocks with "outcome" == "completed" in transaction (matches Python).
        // Falls back to proposal/agreement pairing if no outcome field.
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
            // Python approach: count "completed" outcomes.
            let completed = blocks_with_outcome
                .iter()
                .filter(|b| {
                    b.transaction
                        .get("outcome")
                        .and_then(|v| v.as_str())
                        == Some("completed")
                })
                .count();
            completed as f64 / blocks_with_outcome.len() as f64
        } else {
            // Fallback: use proposal/agreement pairing.
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

        // Feature 4: account age (saturates at 60 seconds = 60_000 ms).
        let first_ts = chain.first().map(|b| b.timestamp).unwrap_or(0) as f64;
        let last_ts = chain.last().map(|b| b.timestamp).unwrap_or(0) as f64;
        let age_ms = (last_ts - first_ts).max(0.0);
        let age_score = (age_ms / 60_000.0).min(1.0);

        // Feature 5: Shannon entropy of counterparty distribution.
        let entropy_score = if counterparties.len() <= 1 {
            0.0
        } else {
            let total: f64 = counterparties.values().sum::<usize>() as f64;
            let entropy: f64 = counterparties
                .values()
                .map(|&count| {
                    let p = count as f64 / total;
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
        let engine = TrustEngine::new(&store, None, None);
        let score = engine.compute_trust("unknown").unwrap();
        // Empty chain: integrity=1.0, statistical=0.0 → redistributed.
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

        let engine = TrustEngine::new(&store, None, None);
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

        // No seed nodes → netflow weight redistributed.
        let engine = TrustEngine::new(&store, None, None);
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
        let engine = TrustEngine::new(&store, None, None);
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
        let engine = TrustEngine::new(&store, None, None);
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

        let engine = TrustEngine::new(&store, None, None);
        assert_eq!(engine.compute_chain_integrity(&agent.pubkey_hex()).unwrap(), 1.0);
    }
}
