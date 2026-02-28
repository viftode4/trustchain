//! NetFlow-based Sybil-resistant trust computation.
//!
//! Uses max-flow (Edmonds-Karp / BFS-based Ford-Fulkerson) on the contribution
//! graph to compute trust scores. Agents that are well-connected to seed nodes
//! through real bilateral interactions get high scores; Sybil clusters get ~0.

use std::collections::{HashMap, HashSet, VecDeque};

use crate::blockstore::BlockStore;
use crate::error::{Result, TrustChainError};

/// NetFlow-based trust computation engine.
pub struct NetFlowTrust<'a, S: BlockStore> {
    store: &'a S,
    seed_nodes: Vec<String>,
}

impl<'a, S: BlockStore> NetFlowTrust<'a, S> {
    /// Create a new NetFlowTrust engine.
    ///
    /// `seed_nodes` are trusted bootstrap identities (at least one required).
    pub fn new(store: &'a S, seed_nodes: Vec<String>) -> Result<Self> {
        if seed_nodes.is_empty() {
            return Err(TrustChainError::netflow("at least one seed node required"));
        }
        Ok(Self { store, seed_nodes })
    }

    /// Build the contribution graph from blockchain state.
    ///
    /// Returns `{source: {target: weight}}` where weight is the total contribution
    /// volume. Each half-block (proposal or agreement) contributes 0.5 units.
    pub fn build_contribution_graph(&self) -> Result<HashMap<String, HashMap<String, f64>>> {
        let mut graph: HashMap<String, HashMap<String, f64>> = HashMap::new();
        let pubkeys = self.store.get_all_pubkeys()?;

        for pubkey in &pubkeys {
            let chain = self.store.get_chain(pubkey)?;
            for block in &chain {
                // Skip self-loops.
                if block.public_key == block.link_public_key {
                    continue;
                }
                // Each half-block contributes 0.5 to the source→target edge.
                let entry = graph
                    .entry(block.public_key.clone())
                    .or_default()
                    .entry(block.link_public_key.clone())
                    .or_insert(0.0);
                *entry += 0.5;
            }
        }

        Ok(graph)
    }

    /// Compute the trust score for a target agent.
    ///
    /// Returns a value in `[0.0, 1.0]`:
    /// - Seed nodes always return 1.0
    /// - Others get `max_flow(super_source → target) / max_possible_outflow`
    pub fn compute_trust(&self, target_pubkey: &str) -> Result<f64> {
        // Seed nodes are always trusted.
        if self.seed_nodes.contains(&target_pubkey.to_string()) {
            return Ok(1.0);
        }

        let graph = self.build_contribution_graph()?;

        // Collect all nodes.
        let mut all_nodes: HashSet<&str> = HashSet::new();
        for (src, targets) in &graph {
            all_nodes.insert(src);
            for tgt in targets.keys() {
                all_nodes.insert(tgt);
            }
        }

        if !all_nodes.contains(target_pubkey) {
            return Ok(0.0);
        }

        // Build adjacency with capacities. Add super-source connected to all seeds.
        let super_source = "__super_source__";
        let mut capacity: HashMap<&str, HashMap<&str, f64>> = HashMap::new();

        // Super-source → seed edges.
        let mut total_seed_outflow = 0.0f64;
        for seed in &self.seed_nodes {
            if let Some(edges) = graph.get(seed.as_str()) {
                let seed_outflow: f64 = edges.values().sum();
                total_seed_outflow += seed_outflow;
                capacity
                    .entry(super_source)
                    .or_default()
                    .insert(seed.as_str(), seed_outflow);
            }
        }

        if total_seed_outflow == 0.0 {
            return Ok(0.0);
        }

        // Real graph edges.
        for (src, targets) in &graph {
            for (tgt, &weight) in targets {
                capacity
                    .entry(src.as_str())
                    .or_default()
                    .insert(tgt.as_str(), weight);
            }
        }

        // Edmonds-Karp max-flow from super_source to target.
        let max_flow = edmonds_karp(&mut capacity, super_source, target_pubkey);

        Ok((max_flow / total_seed_outflow).min(1.0))
    }

    /// Compute trust scores for all known agents.
    pub fn compute_all_scores(&self) -> Result<HashMap<String, f64>> {
        let pubkeys = self.store.get_all_pubkeys()?;
        let mut scores = HashMap::new();

        for pubkey in &pubkeys {
            scores.insert(pubkey.clone(), self.compute_trust(pubkey)?);
        }

        // Include seed nodes even if they have no blocks.
        for seed in &self.seed_nodes {
            scores.entry(seed.clone()).or_insert(1.0);
        }

        Ok(scores)
    }
}

/// Edmonds-Karp (BFS-based Ford-Fulkerson) max-flow algorithm.
fn edmonds_karp<'a>(
    capacity: &mut HashMap<&'a str, HashMap<&'a str, f64>>,
    source: &'a str,
    sink: &'a str,
) -> f64 {
    let mut total_flow = 0.0;

    loop {
        // BFS to find augmenting path.
        let mut parent: HashMap<&str, &str> = HashMap::new();
        let mut visited: HashSet<&str> = HashSet::new();
        let mut queue: VecDeque<&str> = VecDeque::new();

        visited.insert(source);
        queue.push_back(source);

        while let Some(node) = queue.pop_front() {
            if node == sink {
                break;
            }
            if let Some(neighbors) = capacity.get(node) {
                // Collect neighbors to avoid borrow issues.
                let neighbors_vec: Vec<(&str, f64)> = neighbors
                    .iter()
                    .map(|(&k, &v)| (k, v))
                    .collect();
                for (next, cap) in neighbors_vec {
                    if !visited.contains(next) && cap > 1e-10 {
                        visited.insert(next);
                        parent.insert(next, node);
                        queue.push_back(next);
                    }
                }
            }
        }

        // No path found — done.
        if !parent.contains_key(sink) {
            break;
        }

        // Find bottleneck.
        let mut path_flow = f64::INFINITY;
        let mut node = sink;
        while let Some(&prev) = parent.get(node) {
            let cap = capacity
                .get(prev)
                .and_then(|m| m.get(node))
                .copied()
                .unwrap_or(0.0);
            path_flow = path_flow.min(cap);
            node = prev;
        }

        // Update residual capacities.
        node = sink;
        while let Some(&prev) = parent.get(node) {
            // Forward edge: decrease capacity.
            if let Some(m) = capacity.get_mut(prev) {
                if let Some(c) = m.get_mut(node) {
                    *c -= path_flow;
                }
            }
            // Reverse edge: increase capacity (for residual graph).
            capacity
                .entry(node)
                .or_default()
                .entry(prev)
                .and_modify(|c| *c += path_flow)
                .or_insert(path_flow);
            node = prev;
        }

        total_flow += path_flow;
    }

    total_flow
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blockstore::MemoryBlockStore;
    use crate::halfblock::{create_half_block, HalfBlock};
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
    ) -> (HalfBlock, HalfBlock) {
        let proposal = create_half_block(
            alice,
            alice_seq,
            &bob.pubkey_hex(),
            0,
            alice_prev,
            BlockType::Proposal,
            serde_json::json!({"service": "compute"}),
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
            serde_json::json!({"service": "compute"}),
            Some(1001),
        );
        store.add_block(&agreement).unwrap();

        (proposal, agreement)
    }

    #[test]
    fn test_seed_node_trust() {
        let store = MemoryBlockStore::new();
        let seed = Identity::from_bytes(&[1u8; 32]);
        let engine = NetFlowTrust::new(&store, vec![seed.pubkey_hex()]).unwrap();

        assert_eq!(engine.compute_trust(&seed.pubkey_hex()).unwrap(), 1.0);
    }

    #[test]
    fn test_unknown_node_zero_trust() {
        let store = MemoryBlockStore::new();
        let seed = Identity::from_bytes(&[1u8; 32]);
        let engine = NetFlowTrust::new(&store, vec![seed.pubkey_hex()]).unwrap();

        assert_eq!(engine.compute_trust("unknown").unwrap(), 0.0);
    }

    #[test]
    fn test_direct_interaction_positive_trust() {
        let mut store = MemoryBlockStore::new();
        let seed = Identity::from_bytes(&[1u8; 32]);
        let agent = Identity::from_bytes(&[2u8; 32]);

        create_interaction(&mut store, &seed, &agent, 1, 1, GENESIS_HASH, GENESIS_HASH);

        let engine = NetFlowTrust::new(&store, vec![seed.pubkey_hex()]).unwrap();
        let score = engine.compute_trust(&agent.pubkey_hex()).unwrap();
        assert!(score > 0.0, "direct interaction should yield positive trust");
        assert!(score <= 1.0);
    }

    #[test]
    fn test_transitive_trust() {
        let mut store = MemoryBlockStore::new();
        let seed = Identity::from_bytes(&[1u8; 32]);
        let middle = Identity::from_bytes(&[2u8; 32]);
        let target = Identity::from_bytes(&[3u8; 32]);

        // seed ↔ middle
        let (p1, _a1) = create_interaction(
            &mut store, &seed, &middle, 1, 1, GENESIS_HASH, GENESIS_HASH,
        );

        // middle ↔ target
        let (_p2, _a2) = create_interaction(
            &mut store, &middle, &target, 2, 1, &p1.block_hash, GENESIS_HASH,
        );

        let engine = NetFlowTrust::new(&store, vec![seed.pubkey_hex()]).unwrap();
        let score = engine.compute_trust(&target.pubkey_hex()).unwrap();
        assert!(
            score > 0.0,
            "transitive interaction should yield positive trust"
        );
    }

    #[test]
    fn test_sybil_cluster_low_trust() {
        let mut store = MemoryBlockStore::new();
        let seed = Identity::from_bytes(&[1u8; 32]);
        let honest = Identity::from_bytes(&[2u8; 32]);
        let sybil1 = Identity::from_bytes(&[3u8; 32]);
        let sybil2 = Identity::from_bytes(&[4u8; 32]);

        // seed ↔ honest (1 interaction).
        create_interaction(&mut store, &seed, &honest, 1, 1, GENESIS_HASH, GENESIS_HASH);

        // sybil1 ↔ sybil2 (many interactions, but no connection to seed).
        let mut s1_prev = GENESIS_HASH.to_string();
        let mut s2_prev = GENESIS_HASH.to_string();
        for i in 1..=10 {
            let (p, a) = create_interaction(
                &mut store, &sybil1, &sybil2, i, i, &s1_prev, &s2_prev,
            );
            s1_prev = p.block_hash.clone();
            s2_prev = a.block_hash.clone();
        }

        let engine = NetFlowTrust::new(&store, vec![seed.pubkey_hex()]).unwrap();
        let sybil_score = engine.compute_trust(&sybil1.pubkey_hex()).unwrap();
        let honest_score = engine.compute_trust(&honest.pubkey_hex()).unwrap();

        assert!(
            sybil_score < honest_score,
            "sybil ({sybil_score}) should have lower trust than honest ({honest_score})"
        );
        assert_eq!(sybil_score, 0.0, "disconnected sybil should have 0 trust");
    }

    #[test]
    fn test_compute_all_scores() {
        let mut store = MemoryBlockStore::new();
        let seed = Identity::from_bytes(&[1u8; 32]);
        let agent = Identity::from_bytes(&[2u8; 32]);

        create_interaction(&mut store, &seed, &agent, 1, 1, GENESIS_HASH, GENESIS_HASH);

        let engine = NetFlowTrust::new(&store, vec![seed.pubkey_hex()]).unwrap();
        let scores = engine.compute_all_scores().unwrap();

        assert_eq!(scores[&seed.pubkey_hex()], 1.0);
        assert!(scores[&agent.pubkey_hex()] > 0.0);
    }

    #[test]
    fn test_empty_seed_nodes_error() {
        let store = MemoryBlockStore::new();
        let result = NetFlowTrust::new(&store, vec![]);
        assert!(result.is_err());
    }

    #[test]
    fn test_contribution_graph_construction() {
        let mut store = MemoryBlockStore::new();
        let alice = Identity::from_bytes(&[1u8; 32]);
        let bob = Identity::from_bytes(&[2u8; 32]);

        create_interaction(&mut store, &alice, &bob, 1, 1, GENESIS_HASH, GENESIS_HASH);

        let engine = NetFlowTrust::new(&store, vec![alice.pubkey_hex()]).unwrap();
        let graph = engine.build_contribution_graph().unwrap();

        // Alice→Bob: 0.5 (proposal), Bob→Alice: 0.5 (agreement).
        assert_eq!(graph[&alice.pubkey_hex()][&bob.pubkey_hex()], 0.5);
        assert_eq!(graph[&bob.pubkey_hex()][&alice.pubkey_hex()], 0.5);
    }
}
