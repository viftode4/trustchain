#![allow(dead_code)]
/// Shared data generators for benchmarks.
use std::collections::HashMap;

use trustchain_core::{
    halfblock::create_half_block,
    types::{BlockType, GENESIS_HASH},
    BlockStore, HalfBlock, Identity, MemoryBlockStore,
};

/// Create deterministic identities: Identity::from_bytes(&[i as u8; 32])
pub fn make_identities(n: usize) -> Vec<Identity> {
    (1..=n)
        .map(|i| Identity::from_bytes(&[i as u8; 32]))
        .collect()
}

/// State tracker for building chains incrementally.
pub struct ChainState {
    pub latest_seq: HashMap<String, u64>,
    pub head_hash: HashMap<String, String>,
}

impl Default for ChainState {
    fn default() -> Self {
        Self::new()
    }
}

impl ChainState {
    pub fn new() -> Self {
        Self {
            latest_seq: HashMap::new(),
            head_hash: HashMap::new(),
        }
    }

    pub fn next_seq(&self, pubkey: &str) -> u64 {
        self.latest_seq.get(pubkey).copied().unwrap_or(0) + 1
    }

    pub fn prev_hash(&self, pubkey: &str) -> String {
        self.head_hash
            .get(pubkey)
            .cloned()
            .unwrap_or_else(|| GENESIS_HASH.to_string())
    }

    pub fn update(&mut self, block: &HalfBlock) {
        self.latest_seq
            .insert(block.public_key.clone(), block.sequence_number);
        self.head_hash
            .insert(block.public_key.clone(), block.block_hash.clone());
    }
}

/// Build a linear chain of n proposal+agreement pairs between alice and bob,
/// storing all blocks in the provided store.
/// Returns 2*n blocks total (n proposals + n agreements).
pub fn build_chain(store: &mut impl BlockStore, n: usize) -> Vec<HalfBlock> {
    let alice = Identity::from_bytes(&[1u8; 32]);
    let bob = Identity::from_bytes(&[2u8; 32]);
    let mut state = ChainState::new();
    let mut blocks = Vec::with_capacity(n * 2);

    for _ in 0..n {
        let a_seq = state.next_seq(&alice.pubkey_hex());
        let a_prev = state.prev_hash(&alice.pubkey_hex());
        let proposal = create_half_block(
            &alice,
            a_seq,
            &bob.pubkey_hex(),
            0,
            &a_prev,
            BlockType::Proposal,
            serde_json::json!({"interaction_type": "service", "outcome": "completed"}),
            Some(1000 + a_seq),
        );
        store.add_block(&proposal).unwrap();
        state.update(&proposal);

        let b_seq = state.next_seq(&bob.pubkey_hex());
        let b_prev = state.prev_hash(&bob.pubkey_hex());
        let agreement = create_half_block(
            &bob,
            b_seq,
            &alice.pubkey_hex(),
            a_seq,
            &b_prev,
            BlockType::Agreement,
            serde_json::json!({"interaction_type": "service", "outcome": "completed"}),
            Some(1001 + b_seq),
        );
        store.add_block(&agreement).unwrap();
        state.update(&agreement);

        blocks.push(proposal);
        blocks.push(agreement);
    }
    blocks
}

/// Build a star network: one seed identity with n_agents spokes.
/// Each spoke has `interactions_per_agent` interactions with the seed.
/// Returns the store, seed pubkey, and all spoke pubkeys.
pub fn build_star_network(
    n_agents: usize,
    interactions_per_agent: usize,
) -> (MemoryBlockStore, String, Vec<String>) {
    let seed = Identity::from_bytes(&[1u8; 32]);
    let seed_pk = seed.pubkey_hex();
    let mut store = MemoryBlockStore::new();
    let mut state = ChainState::new();
    let mut spoke_pks = Vec::with_capacity(n_agents);

    for i in 0..n_agents {
        let agent = Identity::from_bytes(&[(i + 2) as u8; 32]);
        let agent_pk = agent.pubkey_hex();
        spoke_pks.push(agent_pk.clone());

        for _ in 0..interactions_per_agent {
            let s_seq = state.next_seq(&seed_pk);
            let s_prev = state.prev_hash(&seed_pk);
            let proposal = create_half_block(
                &seed,
                s_seq,
                &agent_pk,
                0,
                &s_prev,
                BlockType::Proposal,
                serde_json::json!({"interaction_type": "service", "outcome": "completed"}),
                Some(1000 + s_seq),
            );
            store.add_block(&proposal).unwrap();
            state.update(&proposal);

            let a_seq = state.next_seq(&agent_pk);
            let a_prev = state.prev_hash(&agent_pk);
            let agreement = create_half_block(
                &agent,
                a_seq,
                &seed_pk,
                s_seq,
                &a_prev,
                BlockType::Agreement,
                serde_json::json!({"interaction_type": "service", "outcome": "completed"}),
                Some(1001 + a_seq),
            );
            store.add_block(&agreement).unwrap();
            state.update(&agreement);
        }
    }

    (store, seed_pk, spoke_pks)
}

/// Build a mesh network with n_agents, where each agent interacts with
/// `avg_degree` random neighbors, each edge having `interactions_per_edge` interactions.
/// Uses deterministic "random" wiring: agent i connects to agents (i+1..i+avg_degree) mod n.
pub fn build_mesh_network(
    n_agents: usize,
    avg_degree: usize,
    interactions_per_edge: usize,
) -> (MemoryBlockStore, Vec<String>) {
    let identities: Vec<Identity> = (0..n_agents)
        .map(|i| Identity::from_bytes(&[(i + 1) as u8; 32]))
        .collect();
    let pubkeys: Vec<String> = identities.iter().map(|id| id.pubkey_hex()).collect();
    let mut store = MemoryBlockStore::new();
    let mut state = ChainState::new();

    for i in 0..n_agents {
        for d in 1..=avg_degree {
            let j = (i + d) % n_agents;
            if j == i {
                continue;
            }
            for _ in 0..interactions_per_edge {
                let i_seq = state.next_seq(&pubkeys[i]);
                let i_prev = state.prev_hash(&pubkeys[i]);
                let proposal = create_half_block(
                    &identities[i],
                    i_seq,
                    &pubkeys[j],
                    0,
                    &i_prev,
                    BlockType::Proposal,
                    serde_json::json!({"interaction_type": "service", "outcome": "completed"}),
                    Some(1000 + i_seq),
                );
                store.add_block(&proposal).unwrap();
                state.update(&proposal);

                let j_seq = state.next_seq(&pubkeys[j]);
                let j_prev = state.prev_hash(&pubkeys[j]);
                let agreement = create_half_block(
                    &identities[j],
                    j_seq,
                    &pubkeys[i],
                    i_seq,
                    &j_prev,
                    BlockType::Agreement,
                    serde_json::json!({"interaction_type": "service", "outcome": "completed"}),
                    Some(1001 + j_seq),
                );
                store.add_block(&agreement).unwrap();
                state.update(&agreement);
            }
        }
    }

    (store, pubkeys)
}
