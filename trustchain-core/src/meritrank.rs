//! MeritRank-based trust computation — personalized random walks.
//!
//! Alternative backend to NetFlow. Uses Monte Carlo random walks from an ego node
//! to compute subjective trust scores. Supports negative edges for fraud propagation.

use std::collections::HashMap;

use meritrank::{MeritRank as MeritRankEngine, MyGraph, Node, NodeId};

use crate::blockstore::BlockStore;
use crate::error::{Result, TrustChainError};

/// Default number of random walks per ego node.
pub const DEFAULT_NUM_WALKS: usize = 10000;

/// Default alpha (teleport/continue probability — set on the engine internally).
pub const DEFAULT_ALPHA: f64 = 0.85;

/// MeritRank-based trust computation engine.
pub struct MeritRankTrust<'a, S: BlockStore> {
    store: &'a S,
    seed_nodes: Vec<String>,
    num_walks: usize,
}

impl<'a, S: BlockStore> MeritRankTrust<'a, S> {
    /// Create a new MeritRankTrust engine.
    ///
    /// `seed_nodes` are trusted bootstrap identities (at least one required).
    pub fn new(store: &'a S, seed_nodes: Vec<String>, num_walks: Option<usize>) -> Result<Self> {
        if seed_nodes.is_empty() {
            return Err(TrustChainError::netflow(
                "at least one seed node required for MeritRank",
            ));
        }
        Ok(Self {
            store,
            seed_nodes,
            num_walks: num_walks.unwrap_or(DEFAULT_NUM_WALKS),
        })
    }

    /// Build a MeritRank graph from the BlockStore interactions.
    ///
    /// Returns (graph, pubkey_to_id, id_to_pubkey) mappings.
    fn build_graph(&self) -> Result<(MyGraph, HashMap<String, usize>, Vec<String>)> {
        let pubkeys = self.store.get_all_pubkeys()?;

        // Assign contiguous usize IDs to pubkeys.
        let mut pubkey_to_id: HashMap<String, usize> = HashMap::new();
        let mut id_to_pubkey: Vec<String> = Vec::new();

        for pk in &pubkeys {
            if !pubkey_to_id.contains_key(pk) {
                let id = id_to_pubkey.len();
                pubkey_to_id.insert(pk.clone(), id);
                id_to_pubkey.push(pk.clone());
            }
        }

        // Also ensure seed nodes are in the mapping even if they have no blocks.
        for seed in &self.seed_nodes {
            if !pubkey_to_id.contains_key(seed) {
                let id = id_to_pubkey.len();
                pubkey_to_id.insert(seed.clone(), id);
                id_to_pubkey.push(seed.clone());
            }
        }

        let mut graph = MyGraph::new();

        // Add all nodes first.
        for i in 0..id_to_pubkey.len() {
            graph.add_node(Node::new(NodeId::UInt(i)));
        }

        // Build edge weights from interactions.
        // Same logic as NetFlow: each half-block contributes 0.5 to source→target, capped at 1.0.
        let mut edge_weights: HashMap<(usize, usize), f64> = HashMap::new();
        let mut fraud_nodes: std::collections::HashSet<usize> = std::collections::HashSet::new();

        for pk in &pubkeys {
            let chain = self.store.get_chain(pk)?;
            for block in &chain {
                if block.public_key == block.link_public_key {
                    continue; // skip self-loops
                }
                let src_id = pubkey_to_id[&block.public_key];
                // Ensure link pubkey is in the mapping.
                let dst_id = if let Some(&id) = pubkey_to_id.get(&block.link_public_key) {
                    id
                } else {
                    let id = id_to_pubkey.len();
                    pubkey_to_id.insert(block.link_public_key.clone(), id);
                    id_to_pubkey.push(block.link_public_key.clone());
                    graph.add_node(Node::new(NodeId::UInt(id)));
                    id
                };

                let entry = edge_weights.entry((src_id, dst_id)).or_insert(0.0);
                *entry = (*entry + 0.5).min(1.0);
            }

            // Check for fraud (double-spend).
            let frauds = self.store.get_double_spends(pk)?;
            if !frauds.is_empty() {
                if let Some(&id) = pubkey_to_id.get(pk) {
                    fraud_nodes.insert(id);
                }
            }
        }

        // Add edges to the meritrank graph.
        for (&(src, dst), &weight) in &edge_weights {
            graph.add_edge(NodeId::UInt(src), NodeId::UInt(dst), weight);
        }

        // Add negative edges for fraud nodes: all edges pointing TO a fraud node get a
        // negative counterpart, so random walks penalize trust through fraudsters.
        for &fraud_id in &fraud_nodes {
            for (&(src, dst), &weight) in &edge_weights {
                if dst == fraud_id {
                    // Add a negative edge from src to fraud node.
                    // The meritrank engine handles negative weights for penalty propagation.
                    // We replace the positive edge with a negative one.
                    graph.add_edge(NodeId::UInt(src), NodeId::UInt(dst), -weight);
                }
            }
        }

        Ok((graph, pubkey_to_id, id_to_pubkey))
    }

    /// Compute trust from a specific ego node's perspective toward a target.
    ///
    /// Returns a score in `[0.0, 1.0]` (clamped).
    pub fn compute_trust(&self, ego_pubkey: &str, target_pubkey: &str) -> Result<f64> {
        if ego_pubkey == target_pubkey {
            return Ok(1.0);
        }

        let (graph, pubkey_to_id, _) = self.build_graph()?;

        let ego_id = match pubkey_to_id.get(ego_pubkey) {
            Some(&id) => id,
            None => return Ok(0.0),
        };
        let target_id = match pubkey_to_id.get(target_pubkey) {
            Some(&id) => id,
            None => return Ok(0.0),
        };

        let mut engine = MeritRankEngine::new(graph)
            .map_err(|e| TrustChainError::netflow(format!("MeritRank init error: {e:?}")))?;

        engine
            .calculate(NodeId::UInt(ego_id), self.num_walks)
            .map_err(|e| TrustChainError::netflow(format!("MeritRank calculate error: {e:?}")))?;

        let score = engine
            .get_node_score(NodeId::UInt(ego_id), NodeId::UInt(target_id))
            .unwrap_or(0.0);

        Ok(score.clamp(0.0, 1.0))
    }

    /// Compute seed-centric trust for a target (average trust from all seed perspectives).
    ///
    /// This provides a comparable metric to NetFlow's path_diversity:
    /// how much the seed nodes collectively trust the target.
    /// Returns a value in `[0.0, 1.0]`.
    pub fn compute_seed_trust(&self, target_pubkey: &str) -> Result<f64> {
        // Seeds always trust themselves.
        if self.seed_nodes.contains(&target_pubkey.to_string()) {
            return Ok(1.0);
        }

        let (graph, pubkey_to_id, _) = self.build_graph()?;

        let target_id = match pubkey_to_id.get(target_pubkey) {
            Some(&id) => id,
            None => return Ok(0.0),
        };

        let mut engine = MeritRankEngine::new(graph)
            .map_err(|e| TrustChainError::netflow(format!("MeritRank init error: {e:?}")))?;

        let mut total = 0.0;
        let mut count = 0;

        for seed in &self.seed_nodes {
            let seed_id = match pubkey_to_id.get(seed) {
                Some(&id) => id,
                None => continue,
            };

            engine
                .calculate(NodeId::UInt(seed_id), self.num_walks)
                .map_err(|e| {
                    TrustChainError::netflow(format!("MeritRank calculate error: {e:?}"))
                })?;

            let score = engine
                .get_node_score(NodeId::UInt(seed_id), NodeId::UInt(target_id))
                .unwrap_or(0.0);

            total += score.max(0.0);
            count += 1;
        }

        if count == 0 {
            return Ok(0.0);
        }

        // Normalize: average across seeds, then scale to [0, 1].
        // MeritRank scores are proportional (sum to ~1 across all nodes),
        // so we scale by multiplying by the number of reachable nodes to get
        // a meaningful connectivity signal. Cap at 1.0.
        let avg = total / count as f64;

        // Scale factor: in a graph with N nodes, a uniform score would be ~1/N.
        // We want "well-connected" nodes to approach 1.0, so scale by N * connectivity_threshold.
        let n_nodes = pubkey_to_id.len().max(1) as f64;
        let scaled = avg * n_nodes;

        Ok(scaled.clamp(0.0, 1.0))
    }

    /// Compute path diversity using MeritRank as a drop-in for NetFlow.
    ///
    /// Returns the seed trust score (used as the connectivity factor).
    /// Seeds return `f64::INFINITY`.
    pub fn compute_path_diversity(&self, target_pubkey: &str) -> Result<f64> {
        if self.seed_nodes.contains(&target_pubkey.to_string()) {
            return Ok(f64::INFINITY);
        }

        let seed_trust = self.compute_seed_trust(target_pubkey)?;

        // Map to a path_diversity-like scale: multiply by connectivity_threshold
        // so the TrustEngine's `min(path_div / K, 1.0)` formula works naturally.
        // seed_trust is already in [0, 1], and connectivity_threshold K defaults to 3.0,
        // so path_div = seed_trust * K gives connectivity = seed_trust directly.
        Ok(seed_trust * crate::trust::DEFAULT_CONNECTIVITY_THRESHOLD)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blockstore::MemoryBlockStore;
    use crate::halfblock::create_half_block;
    use crate::identity::Identity;
    use crate::types::{BlockType, GENESIS_HASH};

    fn create_interaction(
        store: &mut MemoryBlockStore,
        alice: &Identity,
        bob: &Identity,
        alice_seq: u64,
        bob_seq: u64,
        alice_prev: &str,
        bob_prev: &str,
    ) -> (String, String) {
        let proposal = create_half_block(
            alice,
            alice_seq,
            &bob.pubkey_hex(),
            0,
            alice_prev,
            BlockType::Proposal,
            serde_json::json!({"service": "test"}),
            Some(1000),
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
            Some(1001),
        );
        store.add_block(&agreement).unwrap();

        (proposal.block_hash, agreement.block_hash)
    }

    #[test]
    fn test_basic_trust_from_interactions() {
        let mut store = MemoryBlockStore::new();
        let seed = Identity::from_bytes(&[1u8; 32]);
        let agent = Identity::from_bytes(&[2u8; 32]);

        create_interaction(&mut store, &seed, &agent, 1, 1, GENESIS_HASH, GENESIS_HASH);

        let mr = MeritRankTrust::new(&store, vec![seed.pubkey_hex()], Some(1000)).unwrap();
        let score = mr
            .compute_trust(&seed.pubkey_hex(), &agent.pubkey_hex())
            .unwrap();
        assert!(
            score > 0.0,
            "direct interaction should give positive trust, got {score}"
        );
        assert!(score <= 1.0);
    }

    #[test]
    fn test_sybil_cluster_near_zero() {
        let mut store = MemoryBlockStore::new();
        let seed = Identity::from_bytes(&[1u8; 32]);
        let honest = Identity::from_bytes(&[2u8; 32]);
        let sybil1 = Identity::from_bytes(&[3u8; 32]);
        let sybil2 = Identity::from_bytes(&[4u8; 32]);

        // seed <-> honest
        create_interaction(&mut store, &seed, &honest, 1, 1, GENESIS_HASH, GENESIS_HASH);

        // sybil1 <-> sybil2 (disconnected from seed)
        let mut s1_prev = GENESIS_HASH.to_string();
        let mut s2_prev = GENESIS_HASH.to_string();
        for i in 1..=5 {
            let (p, a) = create_interaction(&mut store, &sybil1, &sybil2, i, i, &s1_prev, &s2_prev);
            s1_prev = p;
            s2_prev = a;
        }

        let mr = MeritRankTrust::new(&store, vec![seed.pubkey_hex()], Some(1000)).unwrap();
        let sybil_score = mr.compute_seed_trust(&sybil1.pubkey_hex()).unwrap();
        let honest_score = mr.compute_seed_trust(&honest.pubkey_hex()).unwrap();

        assert!(
            sybil_score < honest_score,
            "sybil ({sybil_score}) should have lower trust than honest ({honest_score})"
        );
        // Disconnected sybils should get near-zero trust from seeds.
        assert!(
            sybil_score < 0.01,
            "disconnected sybil should have near-zero seed trust, got {sybil_score}"
        );
    }

    #[test]
    fn test_transitive_trust() {
        let mut store = MemoryBlockStore::new();
        let seed = Identity::from_bytes(&[1u8; 32]);
        let middle = Identity::from_bytes(&[2u8; 32]);
        let target = Identity::from_bytes(&[3u8; 32]);

        // seed <-> middle
        let (p1, _) =
            create_interaction(&mut store, &seed, &middle, 1, 1, GENESIS_HASH, GENESIS_HASH);

        // middle <-> target
        create_interaction(&mut store, &middle, &target, 2, 1, &p1, GENESIS_HASH);

        let mr = MeritRankTrust::new(&store, vec![seed.pubkey_hex()], Some(1000)).unwrap();
        let score = mr.compute_seed_trust(&target.pubkey_hex()).unwrap();
        assert!(
            score > 0.0,
            "transitive trust should be positive, got {score}"
        );
    }

    #[test]
    fn test_negative_edges_fraud_penalty() {
        let mut store = MemoryBlockStore::new();
        let seed = Identity::from_bytes(&[1u8; 32]);
        let honest = Identity::from_bytes(&[2u8; 32]);
        let fraud = Identity::from_bytes(&[3u8; 32]);

        // seed <-> honest, seed <-> fraud
        create_interaction(&mut store, &seed, &honest, 1, 1, GENESIS_HASH, GENESIS_HASH);
        create_interaction(&mut store, &seed, &fraud, 2, 1, GENESIS_HASH, GENESIS_HASH);

        // Record fraud's double-spend.
        let fake_a = create_half_block(
            &fraud,
            2,
            &seed.pubkey_hex(),
            0,
            GENESIS_HASH,
            BlockType::Proposal,
            serde_json::json!({"v": "a"}),
            Some(2000),
        );
        let fake_b = create_half_block(
            &fraud,
            2,
            &seed.pubkey_hex(),
            0,
            GENESIS_HASH,
            BlockType::Proposal,
            serde_json::json!({"v": "b"}),
            Some(2001),
        );
        store.add_double_spend(&fake_a, &fake_b).unwrap();

        let mr = MeritRankTrust::new(&store, vec![seed.pubkey_hex()], Some(2000)).unwrap();
        let fraud_score = mr.compute_seed_trust(&fraud.pubkey_hex()).unwrap();
        let honest_score = mr.compute_seed_trust(&honest.pubkey_hex()).unwrap();

        // Fraud node should be penalized relative to honest.
        assert!(
            fraud_score <= honest_score,
            "fraud ({fraud_score}) should not exceed honest ({honest_score})"
        );
    }

    #[test]
    fn test_comparison_both_resist_sybils() {
        use crate::netflow::NetFlowTrust;

        let mut store = MemoryBlockStore::new();
        let seed = Identity::from_bytes(&[1u8; 32]);
        let honest = Identity::from_bytes(&[2u8; 32]);
        let sybil1 = Identity::from_bytes(&[3u8; 32]);
        let sybil2 = Identity::from_bytes(&[4u8; 32]);

        // seed <-> honest
        create_interaction(&mut store, &seed, &honest, 1, 1, GENESIS_HASH, GENESIS_HASH);

        // Disconnected sybil cluster
        create_interaction(
            &mut store,
            &sybil1,
            &sybil2,
            1,
            1,
            GENESIS_HASH,
            GENESIS_HASH,
        );

        // NetFlow
        let nf = NetFlowTrust::new(&store, vec![seed.pubkey_hex()]).unwrap();
        let nf_sybil = nf.compute_path_diversity(&sybil1.pubkey_hex()).unwrap();
        let nf_honest = nf.compute_path_diversity(&honest.pubkey_hex()).unwrap();

        // MeritRank
        let mr = MeritRankTrust::new(&store, vec![seed.pubkey_hex()], Some(1000)).unwrap();
        let mr_sybil = mr.compute_seed_trust(&sybil1.pubkey_hex()).unwrap();
        let mr_honest = mr.compute_seed_trust(&honest.pubkey_hex()).unwrap();

        // Both should resist sybils.
        assert_eq!(nf_sybil, 0.0, "NetFlow: sybil should have 0 path diversity");
        assert!(
            mr_sybil < 0.01,
            "MeritRank: sybil should have near-zero trust, got {mr_sybil}"
        );
        assert!(
            nf_honest > 0.0,
            "NetFlow: honest should have positive trust"
        );
        assert!(
            mr_honest > 0.0,
            "MeritRank: honest should have positive trust, got {mr_honest}"
        );
    }

    #[test]
    fn test_seed_trust_returns_one() {
        let store = MemoryBlockStore::new();
        let seed = Identity::from_bytes(&[1u8; 32]);

        let mr = MeritRankTrust::new(&store, vec![seed.pubkey_hex()], Some(100)).unwrap();
        let score = mr.compute_seed_trust(&seed.pubkey_hex()).unwrap();
        assert_eq!(score, 1.0, "seed should have trust 1.0");
    }

    #[test]
    fn test_path_diversity_returns_infinity_for_seed() {
        let store = MemoryBlockStore::new();
        let seed = Identity::from_bytes(&[1u8; 32]);

        let mr = MeritRankTrust::new(&store, vec![seed.pubkey_hex()], Some(100)).unwrap();
        let pd = mr.compute_path_diversity(&seed.pubkey_hex()).unwrap();
        assert!(pd.is_infinite(), "seed path_diversity should be infinity");
    }

    #[test]
    fn test_unknown_node_zero() {
        let store = MemoryBlockStore::new();
        let seed = Identity::from_bytes(&[1u8; 32]);

        let mr = MeritRankTrust::new(&store, vec![seed.pubkey_hex()], Some(100)).unwrap();
        let score = mr.compute_seed_trust("unknown_pubkey").unwrap();
        assert_eq!(score, 0.0, "unknown node should have zero trust");
    }

    #[test]
    fn test_empty_seeds_error() {
        let store = MemoryBlockStore::new();
        let result = MeritRankTrust::new(&store, vec![], None);
        assert!(result.is_err(), "empty seeds should error");
    }
}
