//! P2P capability discovery — find agents by what they've actually done.
//!
//! Capabilities are proven by bilateral interaction history, not self-reported.
//! "I can do compute" means "I have N successful compute interactions, bilaterally
//! signed, cryptographically verifiable."
//!
//! Discovery flow:
//!   1. Scan local blockstore for agents with matching transactions
//!   2. Fan out query to trusted peers via QUIC (they do the same scan)
//!   3. Merge results, compute trust scores, rank, return

use serde::{Deserialize, Serialize};

use trustchain_core::{BlockStore, HalfBlock};

/// A capability discovery query.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityQuery {
    /// The capability to search for (matched against `transaction.service`).
    pub capability: String,
    /// Maximum results to return.
    #[serde(default = "default_max_results")]
    pub max_results: usize,
}

fn default_max_results() -> usize {
    20
}

/// A discovered agent with proven capability.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredAgent {
    /// The agent's public key (hex).
    pub pubkey: String,
    /// Last known network address (if available from peer discovery).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    /// The capability that was matched.
    pub capability: String,
    /// Number of interactions matching this capability in the agent's chain.
    pub interaction_count: u64,
    /// Trust score (computed locally by the querying node, if available).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trust_score: Option<f64>,
}

/// Scan the local blockstore for agents that have interacted with the given capability.
///
/// Returns agents sorted by interaction count descending. Each result is backed
/// by real bilateral signed records — not self-reported claims.
pub fn find_capable_agents<S: BlockStore>(
    store: &S,
    capability: &str,
    max_results: usize,
) -> Vec<DiscoveredAgent> {
    let pubkeys = match store.get_all_pubkeys() {
        Ok(pks) => pks,
        Err(_) => return vec![],
    };

    let mut results = Vec::new();

    for pk in pubkeys {
        let chain = match store.get_chain(&pk) {
            Ok(c) => c,
            Err(_) => continue,
        };

        let count = chain
            .iter()
            .filter(|b| block_matches_capability(b, capability))
            .count();

        if count > 0 {
            results.push(DiscoveredAgent {
                pubkey: pk,
                address: None,
                capability: capability.to_string(),
                interaction_count: count as u64,
                trust_score: None,
            });
        }
    }

    // Sort by interaction count descending.
    results.sort_by(|a, b| b.interaction_count.cmp(&a.interaction_count));
    results.truncate(max_results);
    results
}

/// Check if a block's transaction matches a capability string.
///
/// Matches against:
/// - `transaction.service` — the standard field for service-type interactions
/// - `transaction.capability` — alternative explicit field
fn block_matches_capability(block: &HalfBlock, capability: &str) -> bool {
    if let Some(service) = block.transaction.get("service").and_then(|v| v.as_str()) {
        if service == capability {
            return true;
        }
    }
    if let Some(cap) = block.transaction.get("capability").and_then(|v| v.as_str()) {
        if cap == capability {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use trustchain_core::{
        BlockType, Identity, MemoryBlockStore, GENESIS_HASH, halfblock::create_half_block,
    };

    fn add_interaction(
        store: &mut MemoryBlockStore,
        alice: &Identity,
        bob: &Identity,
        alice_seq: u64,
        bob_seq: u64,
        alice_prev: &str,
        bob_prev: &str,
        service: &str,
    ) -> (String, String) {
        let proposal = create_half_block(
            alice,
            alice_seq,
            &bob.pubkey_hex(),
            0,
            alice_prev,
            BlockType::Proposal,
            serde_json::json!({"service": service}),
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
            serde_json::json!({"service": service}),
            Some(1001),
        );
        store.add_block(&agreement).unwrap();

        (proposal.block_hash, agreement.block_hash)
    }

    #[test]
    fn test_find_capable_agents_empty_store() {
        let store = MemoryBlockStore::new();
        let results = find_capable_agents(&store, "compute", 10);
        assert!(results.is_empty());
    }

    #[test]
    fn test_find_capable_agents_single_match() {
        let mut store = MemoryBlockStore::new();
        let alice = Identity::from_bytes(&[1u8; 32]);
        let bob = Identity::from_bytes(&[2u8; 32]);

        add_interaction(
            &mut store, &alice, &bob, 1, 1, GENESIS_HASH, GENESIS_HASH, "compute",
        );

        let results = find_capable_agents(&store, "compute", 10);
        assert_eq!(results.len(), 2); // both alice and bob have compute blocks
        assert!(results.iter().all(|r| r.capability == "compute"));
        assert!(results.iter().all(|r| r.interaction_count == 1));
    }

    #[test]
    fn test_find_capable_agents_no_match() {
        let mut store = MemoryBlockStore::new();
        let alice = Identity::from_bytes(&[1u8; 32]);
        let bob = Identity::from_bytes(&[2u8; 32]);

        add_interaction(
            &mut store, &alice, &bob, 1, 1, GENESIS_HASH, GENESIS_HASH, "storage",
        );

        let results = find_capable_agents(&store, "compute", 10);
        assert!(results.is_empty());
    }

    #[test]
    fn test_find_capable_agents_sorted_by_count() {
        let mut store = MemoryBlockStore::new();
        let alice = Identity::from_bytes(&[1u8; 32]);
        let bob = Identity::from_bytes(&[2u8; 32]);
        let carol = Identity::from_bytes(&[3u8; 32]);

        // Alice does 2 compute interactions (with bob, then carol).
        let (_, _) = add_interaction(
            &mut store, &alice, &bob, 1, 1, GENESIS_HASH, GENESIS_HASH, "compute",
        );
        let alice_prev = store.get_head_hash(&alice.pubkey_hex()).unwrap();
        let carol_prev = GENESIS_HASH;
        add_interaction(
            &mut store, &alice, &carol, 2, 1, &alice_prev, carol_prev, "compute",
        );

        let results = find_capable_agents(&store, "compute", 10);
        // Alice has 2 compute blocks, bob and carol have 1 each.
        assert!(results[0].interaction_count >= results.last().unwrap().interaction_count);
        assert_eq!(results[0].interaction_count, 2);
    }

    #[test]
    fn test_find_capable_agents_max_results() {
        let mut store = MemoryBlockStore::new();
        let base = Identity::from_bytes(&[1u8; 32]);

        // Create interactions with 5 different peers.
        let mut prev = GENESIS_HASH.to_string();
        for i in 2..=6 {
            let peer = Identity::from_bytes(&[i as u8; 32]);
            let (_, _) = add_interaction(
                &mut store, &base, &peer, (i - 1) as u64, 1, &prev, GENESIS_HASH, "compute",
            );
            prev = store.get_head_hash(&base.pubkey_hex()).unwrap();
        }

        // Limit to 3 results.
        let results = find_capable_agents(&store, "compute", 3);
        assert_eq!(results.len(), 3);
    }

    #[test]
    fn test_block_matches_capability_field() {
        let alice = Identity::from_bytes(&[1u8; 32]);
        let bob = Identity::from_bytes(&[2u8; 32]);

        // "capability" field should also match.
        let block = create_half_block(
            &alice, 1, &bob.pubkey_hex(), 0, GENESIS_HASH, BlockType::Proposal,
            serde_json::json!({"capability": "inference"}),
            Some(1000),
        );

        assert!(block_matches_capability(&block, "inference"));
        assert!(!block_matches_capability(&block, "compute"));
    }
}
