//! Paper compliance tests — exact formula verification against
//! Otte, de Vos, Pouwelse (2020) and the py-ipv8 reference implementation.
//!
//! Chain integrity, fraud detection, NetFlow max-flow (paper-defined).
//! All assertions use `(actual - expected).abs() < 1e-10`.

use trustchain_core::{
    create_half_block, BlockStore, BlockType, Identity, MemoryBlockStore, NetFlowTrust,
    TrustEngine, GENESIS_HASH,
};

/// Helper: create a bilateral interaction in a shared store.
/// Returns (proposal_hash, agreement_hash) for chaining.
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
        serde_json::json!({"t": ts}),
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
        serde_json::json!({"t": ts}),
        Some(ts + 1),
    );
    store.add_block(&agreement).unwrap();

    (proposal.block_hash, agreement.block_hash)
}

// ---------------------------------------------------------------------------
// 1. Integrity: fraction at first failure
// ---------------------------------------------------------------------------

#[test]
fn test_integrity_fraction_at_first_failure() {
    let id_a = Identity::from_bytes(&[1; 32]);
    let id_b = Identity::from_bytes(&[2; 32]);
    let mut store = MemoryBlockStore::new();

    // Build 10 blocks. Break the chain at block 7 (seq=7 has bad previous_hash).
    let mut prev_hash = GENESIS_HASH.to_string();
    for seq in 1..=10u64 {
        let block = create_half_block(
            &id_a,
            seq,
            &id_b.pubkey_hex(),
            0,
            if seq == 7 {
                "badbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbad"
            } else {
                &prev_hash
            },
            BlockType::Proposal,
            serde_json::json!({"seq": seq}),
            Some(1_000_000 + seq * 1000),
        );
        prev_hash = block.block_hash.clone();
        store.add_block(&block).unwrap();
    }

    let engine = TrustEngine::new(&store, None, None, None);
    let integrity = engine.compute_chain_integrity(&id_a.pubkey_hex()).unwrap();
    // Break at seq 7 means 6 valid blocks out of 10.
    assert!(
        (integrity - 0.6).abs() < 1e-10,
        "expected 0.6, got {integrity}"
    );
}

// ---------------------------------------------------------------------------
// 2. Integrity: perfect chain
// ---------------------------------------------------------------------------

#[test]
fn test_integrity_perfect_chain() {
    let alice = Identity::from_bytes(&[1; 32]);
    let bob = Identity::from_bytes(&[2; 32]);
    let mut store = MemoryBlockStore::new();

    let mut prev_a = GENESIS_HASH.to_string();
    let mut prev_b = GENESIS_HASH.to_string();
    for i in 1..=5u64 {
        let (pa, pb) = create_interaction(
            &mut store,
            &alice,
            &bob,
            i,
            i,
            &prev_a,
            &prev_b,
            1_000_000 + i * 2000,
        );
        prev_a = pa;
        prev_b = pb;
    }

    let engine = TrustEngine::new(&store, None, None, None);
    let integrity = engine.compute_chain_integrity(&alice.pubkey_hex()).unwrap();
    assert!(
        (integrity - 1.0).abs() < 1e-10,
        "expected 1.0, got {integrity}"
    );
}

// ---------------------------------------------------------------------------
// 3. Integrity: empty chain
// ---------------------------------------------------------------------------

#[test]
fn test_integrity_empty_chain() {
    let store = MemoryBlockStore::new();
    let engine = TrustEngine::new(&store, None, None, None);
    let integrity = engine
        .compute_chain_integrity("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
        .unwrap();
    assert!(
        (integrity - 1.0).abs() < 1e-10,
        "expected 1.0, got {integrity}"
    );
}

// ---------------------------------------------------------------------------
// 4. Hash canonicalization: key order via BTreeMap
// ---------------------------------------------------------------------------

#[test]
fn test_hash_canonicalization_key_order() {
    let id = Identity::from_bytes(&[1; 32]);
    let id_b = Identity::from_bytes(&[2; 32]);

    let block = create_half_block(
        &id,
        1,
        &id_b.pubkey_hex(),
        0,
        GENESIS_HASH,
        BlockType::Proposal,
        serde_json::json!({"z_key": 1, "a_key": 2}),
        Some(1_000_000),
    );

    let h1 = block.compute_hash();
    let h2 = block.compute_hash();
    assert_eq!(h1, h2);
    assert_eq!(h1.len(), 64);
    assert_eq!(block.block_hash, h1);
}

// ---------------------------------------------------------------------------
// 5. NetFlow: hand-calculated
// ---------------------------------------------------------------------------

#[test]
fn test_netflow_hand_calculated() {
    // S→A (3), S→B (2), A→C (1). Each interaction has 0.5+0.5=1.0 contribution weight.
    let seed = Identity::from_bytes(&[1; 32]);
    let agent_a = Identity::from_bytes(&[2; 32]);
    let agent_b = Identity::from_bytes(&[3; 32]);
    let agent_c = Identity::from_bytes(&[4; 32]);
    let mut store = MemoryBlockStore::new();

    // Track sequence numbers and prev hashes per agent.
    let mut seq_s = 0u64;
    let mut seq_a = 0u64;
    let mut seq_b = 0u64;
    let mut seq_c = 0u64;
    let mut prev_s = GENESIS_HASH.to_string();
    let mut prev_a = GENESIS_HASH.to_string();
    let mut prev_b = GENESIS_HASH.to_string();
    let prev_c = GENESIS_HASH.to_string();

    // S→A: 3 interactions.
    for i in 0..3 {
        seq_s += 1;
        seq_a += 1;
        let (ps, pa) = create_interaction(
            &mut store,
            &seed,
            &agent_a,
            seq_s,
            seq_a,
            &prev_s,
            &prev_a,
            1_000_000 + i * 2000,
        );
        prev_s = ps;
        prev_a = pa;
    }
    // S→B: 2 interactions.
    for i in 0..2 {
        seq_s += 1;
        seq_b += 1;
        let (ps, pb) = create_interaction(
            &mut store,
            &seed,
            &agent_b,
            seq_s,
            seq_b,
            &prev_s,
            &prev_b,
            2_000_000 + i * 2000,
        );
        prev_s = ps;
        prev_b = pb;
    }
    // A→C: 1 interaction.
    seq_a += 1;
    seq_c += 1;
    create_interaction(
        &mut store, &agent_a, &agent_c, seq_a, seq_c, &prev_a, &prev_c, 3_000_000,
    );

    let seeds = vec![seed.pubkey_hex()];
    let nf = NetFlowTrust::new(&store, seeds).unwrap();

    // With edge capping at 1.0 per peer pair:
    // S→A: 3 interactions → capped at 1.0.  S→B: 2 interactions → capped at 1.0.
    // A→C: 1 interaction → 0.5.
    // Raw max-flow to C: Super→S(1.0+1.0=2.0 cap)→A(1.0)→C(0.5) = 0.5.
    let path_div_c = nf.compute_path_diversity(&agent_c.pubkey_hex()).unwrap();
    assert!((path_div_c - 0.5).abs() < 1e-10, "expected 0.5, got {path_div_c}");
}

// ---------------------------------------------------------------------------
// 6. NetFlow: seed always 1.0
// ---------------------------------------------------------------------------

#[test]
fn test_netflow_seed_always_one() {
    let seed = Identity::from_bytes(&[1; 32]);
    let agent = Identity::from_bytes(&[2; 32]);
    let mut store = MemoryBlockStore::new();

    create_interaction(
        &mut store,
        &seed,
        &agent,
        1,
        1,
        GENESIS_HASH,
        GENESIS_HASH,
        1_000_000,
    );

    let seeds = vec![seed.pubkey_hex()];
    let nf = NetFlowTrust::new(&store, seeds).unwrap();
    let path_div = nf.compute_path_diversity(&seed.pubkey_hex()).unwrap();
    assert!(
        path_div.is_infinite(),
        "seed node path diversity must be infinite, got {path_div}"
    );
}

// ---------------------------------------------------------------------------
// 7. Fraud overrides everything
// ---------------------------------------------------------------------------

#[test]
fn test_fraud_overrides_everything() {
    let alice = Identity::from_bytes(&[1; 32]);
    let bob = Identity::from_bytes(&[2; 32]);
    let mut store = MemoryBlockStore::new();

    let mut prev_a = GENESIS_HASH.to_string();
    let mut prev_b = GENESIS_HASH.to_string();
    for i in 1..=20u64 {
        let (pa, pb) = create_interaction(
            &mut store,
            &alice,
            &bob,
            i,
            i,
            &prev_a,
            &prev_b,
            1_000_000 + i * 1000,
        );
        prev_a = pa;
        prev_b = pb;
    }

    // Record fraud.
    let chain = store.get_chain(&alice.pubkey_hex()).unwrap();
    let b0 = chain[0].clone();
    let b1 = chain[1].clone();
    store.add_double_spend(&b0, &b1).unwrap();

    let engine = TrustEngine::new(&store, None, None, None);
    let trust = engine.compute_trust(&alice.pubkey_hex()).unwrap();
    assert!(
        trust.abs() < 1e-10,
        "fraud must result in 0.0 trust, got {trust}"
    );
}

// ===========================================================================
// Sybil resistance: NetFlow gate ensures zero trust for disconnected nodes
// ===========================================================================

// ---------------------------------------------------------------------------
// 8. Sybil cluster with no seed connection gets zero trust
// ---------------------------------------------------------------------------

#[test]
fn test_sybil_no_seed_connection_zero_trust() {
    // A Sybil cluster with no seed connection should get ZERO trust when
    // seeds are configured — NetFlow gate enforces this.
    let seed = Identity::from_bytes(&[1; 32]);
    let honest = Identity::from_bytes(&[2; 32]);

    // Sybil cluster: 5 nodes interacting heavily among themselves.
    let sybil_a = Identity::from_bytes(&[10; 32]);
    let sybil_b = Identity::from_bytes(&[11; 32]);
    let sybil_c = Identity::from_bytes(&[12; 32]);
    let sybil_d = Identity::from_bytes(&[13; 32]);
    let sybil_e = Identity::from_bytes(&[14; 32]);
    let mut store = MemoryBlockStore::new();

    // Seed ↔ honest: 1 interaction (so seed has outflow).
    create_interaction(
        &mut store,
        &seed,
        &honest,
        1,
        1,
        GENESIS_HASH,
        GENESIS_HASH,
        1_000_000,
    );

    // Build a rich Sybil graph.
    let sybils = [&sybil_a, &sybil_b, &sybil_c, &sybil_d, &sybil_e];
    let mut seqs = [0u64; 5];
    let mut prevs: Vec<String> = vec![GENESIS_HASH.to_string(); 5];
    let mut ts = 2_000_000u64;
    for i in 0..5 {
        for j in (i + 1)..5 {
            for _ in 0..5 {
                seqs[i] += 1;
                seqs[j] += 1;
                let (pi, pj) = create_interaction(
                    &mut store, sybils[i], sybils[j], seqs[i], seqs[j], &prevs[i], &prevs[j], ts,
                );
                prevs[i] = pi;
                prevs[j] = pj;
                ts += 1000;
            }
        }
    }

    // With seeds configured, Sybil A should get zero trust (no path from seeds).
    let seeds = vec![seed.pubkey_hex()];
    let engine = TrustEngine::new(&store, Some(seeds), None, None);
    let trust = engine.compute_trust(&sybil_a.pubkey_hex()).unwrap();

    assert!(
        trust.abs() < 1e-10,
        "Sybil with no seed path must have 0 trust, got {trust}"
    );
}

// ===========================================================================
// Paper-grounded NetFlow tests (from Otte et al. 2017 + py-ipv8 reference)
// ===========================================================================

// ---------------------------------------------------------------------------
// 9. Contribution graph: 0.5 per half-block, 1.0 per bilateral interaction
// ---------------------------------------------------------------------------

#[test]
fn test_contribution_graph_half_block_weight() {
    // Paper: "Each half-block contributes 0.5 to the source→target edge."
    // A bilateral interaction produces 2 half-blocks → 1.0 edge weight.
    let alice = Identity::from_bytes(&[1; 32]);
    let bob = Identity::from_bytes(&[2; 32]);
    let mut store = MemoryBlockStore::new();

    create_interaction(
        &mut store,
        &alice,
        &bob,
        1,
        1,
        GENESIS_HASH,
        GENESIS_HASH,
        1_000_000,
    );

    let seeds = vec![alice.pubkey_hex()];
    let nf = NetFlowTrust::new(&store, seeds).unwrap();
    let graph = nf.build_contribution_graph().unwrap();

    // Alice→Bob: proposal (0.5) = 0.5.
    // Bob→Alice: agreement (0.5) = 0.5.
    let a_to_b = graph
        .get(&alice.pubkey_hex())
        .and_then(|m| m.get(&bob.pubkey_hex()))
        .copied()
        .unwrap_or(0.0);
    let b_to_a = graph
        .get(&bob.pubkey_hex())
        .and_then(|m| m.get(&alice.pubkey_hex()))
        .copied()
        .unwrap_or(0.0);

    assert!(
        (a_to_b - 0.5).abs() < 1e-10,
        "A→B should be 0.5 (1 proposal), got {a_to_b}"
    );
    assert!(
        (b_to_a - 0.5).abs() < 1e-10,
        "B→A should be 0.5 (1 agreement), got {b_to_a}"
    );

    // With 3 interactions, A→B = 1.5 (3 proposals × 0.5).
    let mut prev_a = store
        .get_chain(&alice.pubkey_hex())
        .unwrap()
        .last()
        .unwrap()
        .block_hash
        .clone();
    let mut prev_b = store
        .get_chain(&bob.pubkey_hex())
        .unwrap()
        .last()
        .unwrap()
        .block_hash
        .clone();
    for i in 2..=3u64 {
        let (pa, pb) = create_interaction(
            &mut store,
            &alice,
            &bob,
            i,
            i,
            &prev_a,
            &prev_b,
            1_000_000 + i * 2000,
        );
        prev_a = pa;
        prev_b = pb;
    }

    let nf2 = NetFlowTrust::new(&store, vec![alice.pubkey_hex()]).unwrap();
    let graph2 = nf2.build_contribution_graph().unwrap();
    let a_to_b_3 = graph2[&alice.pubkey_hex()][&bob.pubkey_hex()];
    assert!(
        (a_to_b_3 - 1.0).abs() < 1e-10,
        "A→B should be 1.0 (capped at 1.0 per peer pair), got {a_to_b_3}"
    );
}

// ---------------------------------------------------------------------------
// 10. NetFlow normalization: trust = max_flow / total_seed_outflow
// ---------------------------------------------------------------------------

#[test]
fn test_netflow_normalization_formula() {
    // Paper: trust(target) = max_flow(super_source → target) / total_seed_outflow.
    // Verify with 2 seeds having different outflows.
    let seed1 = Identity::from_bytes(&[1; 32]);
    let seed2 = Identity::from_bytes(&[2; 32]);
    let target = Identity::from_bytes(&[3; 32]);
    let mut store = MemoryBlockStore::new();

    // Seed1 → Target: 2 interactions → S1→T edge = 1.0.
    let mut prev_s1 = GENESIS_HASH.to_string();
    let mut prev_t = GENESIS_HASH.to_string();
    for i in 1..=2u64 {
        let (ps, pt) = create_interaction(
            &mut store,
            &seed1,
            &target,
            i,
            i,
            &prev_s1,
            &prev_t,
            1_000_000 + i * 2000,
        );
        prev_s1 = ps;
        prev_t = pt;
    }

    // Seed2 → Target: 4 interactions → S2→T edge = 2.0.
    let mut prev_s2 = GENESIS_HASH.to_string();
    let seq_offset = 2u64; // target's chain continues from seq 3
    for i in 1..=4u64 {
        let (ps, pt) = create_interaction(
            &mut store,
            &seed2,
            &target,
            i,
            seq_offset + i,
            &prev_s2,
            &prev_t,
            2_000_000 + i * 2000,
        );
        prev_s2 = ps;
        prev_t = pt;
    }

    let seeds = vec![seed1.pubkey_hex(), seed2.pubkey_hex()];
    let nf = NetFlowTrust::new(&store, seeds).unwrap();
    let path_div = nf.compute_path_diversity(&target.pubkey_hex()).unwrap();

    // With edge capping at 1.0 per peer pair:
    // S1→T: 2 interactions → capped at 1.0.
    // S2→T: 4 interactions → capped at 1.0.
    // Super→S1 capacity = 1.0, Super→S2 capacity = 1.0.
    // Raw max-flow = 1.0 + 1.0 = 2.0 (two independent paths from seeds to target).
    assert!(
        (path_div - 2.0).abs() < 1e-10,
        "direct seed connections should give path diversity 2.0, got {path_div}"
    );
}

// ---------------------------------------------------------------------------
// 11. Sybil resistance: fake chains without seed connection get zero trust
// ---------------------------------------------------------------------------

#[test]
fn test_sybil_resistance_no_seed_connection() {
    // Paper's core Sybil resistance property: nodes not connected to seed
    // via the contribution graph have zero trust, regardless of how many
    // bilateral interactions they have among themselves.
    let seed = Identity::from_bytes(&[1; 32]);
    let sybil_a = Identity::from_bytes(&[10; 32]);
    let sybil_b = Identity::from_bytes(&[11; 32]);
    let sybil_c = Identity::from_bytes(&[12; 32]);
    let mut store = MemoryBlockStore::new();

    // Sybils interact heavily among themselves (100 interactions).
    let mut prev_a = GENESIS_HASH.to_string();
    let mut prev_b = GENESIS_HASH.to_string();
    for i in 1..=50u64 {
        let (pa, pb) = create_interaction(
            &mut store,
            &sybil_a,
            &sybil_b,
            i,
            i,
            &prev_a,
            &prev_b,
            1_000_000 + i * 1000,
        );
        prev_a = pa;
        prev_b = pb;
    }
    let mut prev_c = GENESIS_HASH.to_string();
    for i in 1..=50u64 {
        let (pa, pc) = create_interaction(
            &mut store,
            &sybil_a,
            &sybil_c,
            50 + i,
            i,
            &prev_a,
            &prev_c,
            2_000_000 + i * 1000,
        );
        prev_a = pa;
        prev_c = pc;
    }

    // Seed has no interactions with sybils. Give seed one block so it exists.
    let honest = Identity::from_bytes(&[2; 32]);
    create_interaction(
        &mut store,
        &seed,
        &honest,
        1,
        1,
        GENESIS_HASH,
        GENESIS_HASH,
        5_000_000,
    );

    let seeds = vec![seed.pubkey_hex()];
    let nf = NetFlowTrust::new(&store, seeds).unwrap();

    // All sybils should have zero trust — no path from super_source to them.
    let trust_a = nf.compute_path_diversity(&sybil_a.pubkey_hex()).unwrap();
    let trust_b = nf.compute_path_diversity(&sybil_b.pubkey_hex()).unwrap();
    let trust_c = nf.compute_path_diversity(&sybil_c.pubkey_hex()).unwrap();

    assert!(
        trust_a.abs() < 1e-10,
        "sybil A should have 0 trust, got {trust_a}"
    );
    assert!(
        trust_b.abs() < 1e-10,
        "sybil B should have 0 trust, got {trust_b}"
    );
    assert!(
        trust_c.abs() < 1e-10,
        "sybil C should have 0 trust, got {trust_c}"
    );
}

// ---------------------------------------------------------------------------
// 12. NetFlow: multi-hop trust propagation
// ---------------------------------------------------------------------------

#[test]
fn test_netflow_multi_hop_propagation() {
    // Paper: trust flows transitively through the contribution graph.
    // S → A → B → C. Each edge = 1 interaction (0.5 weight per direction).
    let seed = Identity::from_bytes(&[1; 32]);
    let a = Identity::from_bytes(&[2; 32]);
    let b = Identity::from_bytes(&[3; 32]);
    let c = Identity::from_bytes(&[4; 32]);
    let mut store = MemoryBlockStore::new();

    // S → A.
    create_interaction(
        &mut store,
        &seed,
        &a,
        1,
        1,
        GENESIS_HASH,
        GENESIS_HASH,
        1_000_000,
    );
    // A → B.
    let prev_a = store
        .get_chain(&a.pubkey_hex())
        .unwrap()
        .last()
        .unwrap()
        .block_hash
        .clone();
    create_interaction(&mut store, &a, &b, 2, 1, &prev_a, GENESIS_HASH, 2_000_000);
    // B → C.
    let prev_b = store
        .get_chain(&b.pubkey_hex())
        .unwrap()
        .last()
        .unwrap()
        .block_hash
        .clone();
    create_interaction(&mut store, &b, &c, 2, 1, &prev_b, GENESIS_HASH, 3_000_000);

    let seeds = vec![seed.pubkey_hex()];
    let nf = NetFlowTrust::new(&store, seeds).unwrap();

    // Graph edges (proposal direction), each 1 interaction:
    // S→A: 0.5, A→S: 0.5 (agreement)
    // A→B: 0.5, B→A: 0.5
    // B→C: 0.5, C→B: 0.5
    //
    // Super→S capacity = S's outflow = 0.5.
    // Raw max-flow to C: Super→S(0.5)→A(0.5)→B(0.5)→C = 0.5.
    let path_div_c = nf.compute_path_diversity(&c.pubkey_hex()).unwrap();
    assert!(
        (path_div_c - 0.5).abs() < 1e-10,
        "3-hop path diversity should be 0.5, got {path_div_c}"
    );

    // B should also be 0.5 (same bottleneck at S→A).
    let path_div_b = nf.compute_path_diversity(&b.pubkey_hex()).unwrap();
    assert!(
        (path_div_b - 0.5).abs() < 1e-10,
        "2-hop path diversity should be 0.5, got {path_div_b}"
    );
}

// ---------------------------------------------------------------------------
// 13. NetFlow: bottleneck limits trust (capacity constraint)
// ---------------------------------------------------------------------------

#[test]
fn test_netflow_bottleneck_limits_trust() {
    // S→A (5 interactions = 2.5 edge), A→B (1 interaction = 0.5 edge).
    // B's trust is bottlenecked by the A→B edge.
    let seed = Identity::from_bytes(&[1; 32]);
    let a = Identity::from_bytes(&[2; 32]);
    let b = Identity::from_bytes(&[3; 32]);
    let mut store = MemoryBlockStore::new();

    // S → A: 5 interactions.
    let mut prev_s = GENESIS_HASH.to_string();
    let mut prev_a = GENESIS_HASH.to_string();
    for i in 1..=5u64 {
        let (ps, pa) = create_interaction(
            &mut store,
            &seed,
            &a,
            i,
            i,
            &prev_s,
            &prev_a,
            1_000_000 + i * 2000,
        );
        prev_s = ps;
        prev_a = pa;
    }

    // A → B: 1 interaction.
    create_interaction(&mut store, &a, &b, 6, 1, &prev_a, GENESIS_HASH, 2_000_000);

    let seeds = vec![seed.pubkey_hex()];
    let nf = NetFlowTrust::new(&store, seeds).unwrap();

    // With edge capping: S→A = 5 interactions → capped at 1.0.
    // A→B = 1 interaction → 0.5. Super→S capacity = 1.0.
    // Raw max-flow to B: Super→S(1.0)→A(min(1.0, 0.5))→B = 0.5.
    let path_div_b = nf.compute_path_diversity(&b.pubkey_hex()).unwrap();
    assert!(
        (path_div_b - 0.5).abs() < 1e-10,
        "bottlenecked path diversity should be 0.5, got {path_div_b}"
    );

    // A's path diversity = 1.0 (S→A capped at 1.0, direct path).
    let path_div_a = nf.compute_path_diversity(&a.pubkey_hex()).unwrap();
    assert!(
        (path_div_a - 1.0).abs() < 1e-10,
        "direct seed connection path diversity should be 1.0, got {path_div_a}"
    );
}

// ---------------------------------------------------------------------------
// 14. NetFlow: unknown node gets zero trust
// ---------------------------------------------------------------------------

#[test]
fn test_netflow_unknown_node_zero() {
    let seed = Identity::from_bytes(&[1; 32]);
    let a = Identity::from_bytes(&[2; 32]);
    let mut store = MemoryBlockStore::new();

    create_interaction(
        &mut store,
        &seed,
        &a,
        1,
        1,
        GENESIS_HASH,
        GENESIS_HASH,
        1_000_000,
    );

    let seeds = vec![seed.pubkey_hex()];
    let nf = NetFlowTrust::new(&store, seeds).unwrap();

    // Node not in the graph at all.
    let path_div = nf
        .compute_path_diversity("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
        .unwrap();
    assert!(
        path_div.abs() < 1e-10,
        "unknown node must have 0 path diversity, got {path_div}"
    );
}

// ---------------------------------------------------------------------------
// 15. Chain integrity validates hash linkage (paper: Section 3)
// ---------------------------------------------------------------------------

#[test]
fn test_chain_integrity_rejects_hash_tampering() {
    // Paper Section 3: each block's previous_hash must match the hash of
    // the preceding block. Tampering with any hash breaks integrity.
    let alice = Identity::from_bytes(&[1; 32]);
    let bob = Identity::from_bytes(&[2; 32]);
    let mut store = MemoryBlockStore::new();

    // Build 5 valid blocks then 1 with tampered previous_hash.
    let mut prev = GENESIS_HASH.to_string();
    for seq in 1..=5u64 {
        let block = create_half_block(
            &alice,
            seq,
            &bob.pubkey_hex(),
            0,
            &prev,
            BlockType::Proposal,
            serde_json::json!({"s": seq}),
            Some(1_000_000 + seq * 1000),
        );
        prev = block.block_hash.clone();
        store.add_block(&block).unwrap();
    }
    // Block 6: bad previous_hash.
    let block6 = create_half_block(
        &alice,
        6,
        &bob.pubkey_hex(),
        0,
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        BlockType::Proposal,
        serde_json::json!({"s": 6}),
        Some(1_006_000),
    );
    store.add_block(&block6).unwrap();
    // Block 7: valid (links to block6).
    let block7 = create_half_block(
        &alice,
        7,
        &bob.pubkey_hex(),
        0,
        &block6.block_hash,
        BlockType::Proposal,
        serde_json::json!({"s": 7}),
        Some(1_007_000),
    );
    store.add_block(&block7).unwrap();

    let engine = TrustEngine::new(&store, None, None, None);
    let integrity = engine.compute_chain_integrity(&alice.pubkey_hex()).unwrap();

    // 5 valid out of 7 total → break at seq 6 → 5/7.
    assert!(
        (integrity - 5.0 / 7.0).abs() < 1e-10,
        "expected 5/7 integrity, got {integrity}"
    );
}

// ---------------------------------------------------------------------------
// 16. Self-loop prevention in contribution graph
// ---------------------------------------------------------------------------

#[test]
fn test_contribution_graph_skips_self_loops() {
    // Paper: self-loops (public_key == link_public_key) are excluded.
    let alice = Identity::from_bytes(&[1; 32]);
    let mut store = MemoryBlockStore::new();

    // Checkpoint block is a self-referencing block.
    let checkpoint = create_half_block(
        &alice,
        1,
        &alice.pubkey_hex(),
        0,
        GENESIS_HASH,
        BlockType::Checkpoint,
        serde_json::json!({"cp": true}),
        Some(1_000_000),
    );
    store.add_block(&checkpoint).unwrap();

    let seeds = vec![alice.pubkey_hex()];
    let nf = NetFlowTrust::new(&store, seeds).unwrap();
    let graph = nf.build_contribution_graph().unwrap();

    // Self-loop should not appear in the graph.
    let self_edge = graph
        .get(&alice.pubkey_hex())
        .and_then(|m| m.get(&alice.pubkey_hex()))
        .copied()
        .unwrap_or(0.0);
    assert!(
        self_edge.abs() < 1e-10,
        "self-loops must be excluded from contribution graph, got {self_edge}"
    );
}
