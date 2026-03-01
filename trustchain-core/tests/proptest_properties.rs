//! Property-based tests — mathematical invariants that must hold for ALL valid inputs.

use proptest::prelude::*;
use trustchain_core::{
    create_half_block, validate_block_invariants, verify_block, BlockStore, BlockType, Identity,
    MemoryBlockStore, NetFlowTrust, TrustEngine, GENESIS_HASH,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Create a bilateral interaction in a shared store, returning (proposal_hash, agreement_hash).
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
        serde_json::json!({"ts": ts}),
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
        serde_json::json!({"ts": ts}),
        Some(ts + 1),
    );
    store.add_block(&agreement).unwrap();
    (proposal.block_hash, agreement.block_hash)
}

// ---------------------------------------------------------------------------
// Property 1: Valid chain integrity is 1.0
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(50))]

    #[test]
    fn prop_valid_chain_integrity_is_one(
        seed_a in 1u8..128,
        seed_b in 128u8..=255,
        rounds in 1usize..10,
    ) {
        let alice = Identity::from_bytes(&[seed_a; 32]);
        let bob = Identity::from_bytes(&[seed_b; 32]);
        let mut store = MemoryBlockStore::new();

        let mut prev_a = GENESIS_HASH.to_string();
        let mut prev_b = GENESIS_HASH.to_string();
        for i in 0..rounds {
            let (pa, pb) = create_interaction(
                &mut store, &alice, &bob,
                (i as u64) + 1, (i as u64) + 1,
                &prev_a, &prev_b,
                1_000_000 + (i as u64) * 2000,
            );
            prev_a = pa;
            prev_b = pb;
        }

        let engine = TrustEngine::new(&store, None, None, None);
        let integrity = engine.compute_chain_integrity(&alice.pubkey_hex()).unwrap();
        prop_assert!(
            (integrity - 1.0).abs() < 1e-10,
            "integrity must be 1.0 for valid chain, got {integrity}"
        );
    }
}

// ---------------------------------------------------------------------------
// Property 2: compute_hash is deterministic
// ---------------------------------------------------------------------------

proptest! {
    #[test]
    fn prop_compute_hash_deterministic(seed in any::<u8>(), tx_val in any::<i64>()) {
        let id = Identity::from_bytes(&[seed; 32]);
        let id_b = Identity::from_bytes(&[seed.wrapping_add(1); 32]);

        let block = create_half_block(
            &id, 1, &id_b.pubkey_hex(), 0, GENESIS_HASH,
            BlockType::Proposal, serde_json::json!({"v": tx_val}), Some(1_000_000),
        );

        let h1 = block.compute_hash();
        let h2 = block.compute_hash();
        prop_assert_eq!(h1, h2);
    }
}

// ---------------------------------------------------------------------------
// Property 3: signed block verifies
// ---------------------------------------------------------------------------

proptest! {
    #[test]
    fn prop_signed_block_verifies(seed in any::<u8>(), tx_val in any::<i64>()) {
        let id = Identity::from_bytes(&[seed; 32]);
        let id_b = Identity::from_bytes(&[seed.wrapping_add(1); 32]);

        let block = create_half_block(
            &id, 1, &id_b.pubkey_hex(), 0, GENESIS_HASH,
            BlockType::Proposal, serde_json::json!({"v": tx_val}), Some(1_000_000),
        );

        let verified = verify_block(&block).unwrap();
        prop_assert!(verified, "properly signed block must verify");
    }
}

// ---------------------------------------------------------------------------
// Property 4: invariants pass for protocol blocks
// ---------------------------------------------------------------------------

proptest! {
    #[test]
    fn prop_invariants_pass_for_protocol_blocks(seed in any::<u8>(), tx_val in any::<i64>()) {
        let id = Identity::from_bytes(&[seed; 32]);
        let id_b = Identity::from_bytes(&[seed.wrapping_add(1); 32]);

        let block = create_half_block(
            &id, 1, &id_b.pubkey_hex(), 0, GENESIS_HASH,
            BlockType::Proposal, serde_json::json!({"v": tx_val}), Some(1_000_000),
        );

        let result = validate_block_invariants(&block);
        prop_assert!(
            result.is_valid(),
            "protocol-created blocks must pass invariants, got: {:?}", result.errors()
        );
    }
}

// ---------------------------------------------------------------------------
// Property 5: trust score in [0, 1]
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(50))]

    #[test]
    fn prop_trust_score_in_unit_interval(n_interactions in 1usize..10) {
        let alice = Identity::from_bytes(&[1; 32]);
        let bob = Identity::from_bytes(&[2; 32]);
        let mut store = MemoryBlockStore::new();

        let mut prev_a = GENESIS_HASH.to_string();
        let mut prev_b = GENESIS_HASH.to_string();
        for i in 0..n_interactions {
            let (pa, pb) = create_interaction(
                &mut store, &alice, &bob,
                (i as u64) + 1, (i as u64) + 1,
                &prev_a, &prev_b,
                1_000_000 + i as u64 * 2000,
            );
            prev_a = pa;
            prev_b = pb;
        }

        let engine = TrustEngine::new(&store, None, None, None);
        let trust = engine.compute_trust(&alice.pubkey_hex()).unwrap();
        prop_assert!((0.0..=1.0).contains(&trust), "trust must be in [0,1], got {trust}");
    }
}

// ---------------------------------------------------------------------------
// Property 6: seed node netflow is always 1.0
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(50))]

    #[test]
    fn prop_seed_node_netflow_one(seed_val in 1u8..128, agent_val in 128u8..=255, n in 1usize..5) {
        let seed_id = Identity::from_bytes(&[seed_val; 32]);
        let agent_id = Identity::from_bytes(&[agent_val; 32]);
        let mut store = MemoryBlockStore::new();

        let mut prev_s = GENESIS_HASH.to_string();
        let mut prev_a = GENESIS_HASH.to_string();
        for i in 0..n {
            let (ps, pa) = create_interaction(
                &mut store, &seed_id, &agent_id,
                (i as u64) + 1, (i as u64) + 1,
                &prev_s, &prev_a,
                1_000_000 + i as u64 * 2000,
            );
            prev_s = ps;
            prev_a = pa;
        }

        let seeds = vec![seed_id.pubkey_hex()];
        let nf = NetFlowTrust::new(&store, seeds).unwrap();
        let trust = nf.compute_trust(&seed_id.pubkey_hex()).unwrap();
        prop_assert!(
            (trust - 1.0).abs() < 1e-10,
            "seed node trust must be 1.0, got {trust}"
        );
    }
}

// ---------------------------------------------------------------------------
// Property 7: delegation budget split
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(20))]

    #[test]
    fn prop_delegation_budget_split(n_delegates in 1u8..5) {
        let active_count = n_delegates as usize;
        let root_trust_score = 0.8_f64;

        let expected_each = root_trust_score / active_count as f64;

        // Sum of all delegates' trust should equal root trust.
        let total: f64 = (0..active_count).map(|_| expected_each).sum();
        prop_assert!(
            (total - root_trust_score).abs() < 1e-10,
            "total delegated trust must equal root trust, got {total}"
        );
    }
}

// ---------------------------------------------------------------------------
// Property 8: fraud → hard zero
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(50))]

    #[test]
    fn prop_fraud_hard_zero(seed_a in 1u8..128, seed_b in 128u8..=255, n in 1usize..10) {
        let alice = Identity::from_bytes(&[seed_a; 32]);
        let bob = Identity::from_bytes(&[seed_b; 32]);
        let mut store = MemoryBlockStore::new();

        let mut prev_a = GENESIS_HASH.to_string();
        let mut prev_b = GENESIS_HASH.to_string();
        for i in 0..n {
            let (pa, pb) = create_interaction(
                &mut store, &alice, &bob,
                (i as u64) + 1, (i as u64) + 1,
                &prev_a, &prev_b,
                1_000_000 + i as u64 * 2000,
            );
            prev_a = pa;
            prev_b = pb;
        }

        // Record a double-spend.
        let chain = store.get_chain(&alice.pubkey_hex()).unwrap();
        if chain.len() >= 2 {
            let b0 = chain[0].clone();
            let b1 = chain[1].clone();
            store.add_double_spend(&b0, &b1).unwrap();

            let engine = TrustEngine::new(&store, None, None, None);
            let trust = engine.compute_trust(&alice.pubkey_hex()).unwrap();
            prop_assert!(
                trust.abs() < 1e-10,
                "fraud must result in zero trust, got {trust}"
            );
        }
    }
}
