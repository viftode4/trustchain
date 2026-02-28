//! Comprehensive protocol stress tests — Part 2.
//!
//! Covers paper claims not exercised in stress.rs:
//! - CHECO multi-node consensus round (§4 — facilitator election, propose, co-sign, finalize)
//! - Double-countersign fraud detection (§3.3 — second responder to same proposal)
//! - Trust score exact math verification (§5 — formula weights, weight redistribution)
//! - Chain integrity with broken hash links (§3.2 — partial integrity score)
//! - Trust monotonicity (more interactions must raise trust, never lower it)
//! - Multi-seed NetFlow (§4.1 — multiple seed nodes, alien isolation)
//! - Stale checkpoint rejection regression (CHECO availability bug fix)
//!
//! Run with: cargo test --test stress2 -- --nocapture

use std::collections::HashMap;
use trustchain_core::{
    BlockStore, CHECOConsensus, Identity, MemoryBlockStore, TrustEngine,
    halfblock::{create_half_block, validate_and_record, validate_block},
    netflow::NetFlowTrust,
    types::{BlockType, GENESIS_HASH, ValidationResult},
};

// ─── Test 9: Full CHECO 5-node consensus round ────────────────────────────────
//
// Verifies the complete CHECO protocol:
//   1. Deterministic facilitator election across 5 peers
//   2. Facilitator proposes a checkpoint covering all agents' chain heads
//   3. 3-of-4 co-signers validate and sign
//   4. Facilitator finalizes with ≥ min_signers signatures
//   5. is_finalized() returns true for all covered blocks

#[test]
fn stress_checo_5node_consensus_round() {
    // 5 agents in a ring: 0→1→2→3→4→0
    let ids: Vec<Identity> = (1u8..=5).map(|s| Identity::from_bytes(&[s; 32])).collect();
    let pks: Vec<String> = ids.iter().map(|id| id.pubkey_hex()).collect();

    // Each agent sends one proposal to the next agent in the ring.
    let all_blocks: Vec<_> = (0..5usize)
        .map(|i| {
            let j = (i + 1) % 5;
            create_half_block(
                &ids[i],
                1,
                &pks[j],
                0,
                GENESIS_HASH,
                BlockType::Proposal,
                serde_json::json!({"ring_step": i}),
                Some(1000 + i as u64),
            )
        })
        .collect();

    // Build one CHECOConsensus per agent — each engine gets all blocks in its store.
    // Threshold = 3 (majority of 5).
    let mut engines: Vec<CHECOConsensus<MemoryBlockStore>> = (0..5usize)
        .map(|i| {
            let mut store = MemoryBlockStore::new();
            for block in &all_blocks {
                store.add_block(block).unwrap();
            }
            let peers: Vec<String> = (0..5).filter(|j| *j != i).map(|j| pks[j].clone()).collect();
            CHECOConsensus::new(ids[i].clone(), store, Some(peers), 3)
        })
        .collect();

    // Deterministically elect the facilitator (all engines agree since state is identical).
    let facilitator_pk = engines[0].select_facilitator().unwrap();
    let fac_idx = pks
        .iter()
        .position(|pk| *pk == facilitator_pk)
        .expect("facilitator must be one of the 5 agents");
    println!("CHECO: facilitator is agent {fac_idx} ({}...)", &facilitator_pk[..8]);

    // Facilitator proposes a checkpoint.
    let checkpoint = engines[fac_idx].propose_checkpoint().unwrap();
    assert!(checkpoint.is_checkpoint(), "proposed block must have checkpoint type");

    // Collect 3 co-signatures from non-facilitator agents.
    let mut sigs: HashMap<String, String> = HashMap::new();
    for (i, engine) in engines.iter().enumerate() {
        if i == fac_idx {
            continue;
        }
        let valid = engine.validate_checkpoint(&checkpoint).unwrap();
        assert!(valid, "agent {i} should accept the checkpoint as valid");
        let sig = engine.sign_checkpoint(&checkpoint).unwrap();
        sigs.insert(pks[i].clone(), sig);
        if sigs.len() >= 3 {
            break;
        }
    }
    assert_eq!(sigs.len(), 3, "should collect exactly 3 co-signatures (threshold)");

    // Facilitator finalizes the checkpoint with the collected co-signatures.
    let finalized = engines[fac_idx]
        .finalize_checkpoint(checkpoint, sigs)
        .unwrap();

    assert!(finalized.finalized, "checkpoint must be marked finalized");
    assert_eq!(
        finalized.chain_heads.len(),
        5,
        "checkpoint must cover all 5 agents"
    );

    // Every agent's seq=1 block is now covered by the finalized checkpoint.
    for pk in &pks {
        assert!(
            engines[fac_idx].is_finalized(pk, 1),
            "seq=1 for agent {}... should be finalized",
            &pk[..8]
        );
    }

    println!(
        "CHECO: checkpoint finalized, covers {} agents ✓",
        finalized.chain_heads.len()
    );
}

// ─── Test 10: Double-countersign fraud detection (§3.3) ───────────────────────
//
// Scenario:
//   Alice proposes → Bob agrees (legitimate, seq 1) → Bob tries to agree AGAIN
//   to the same proposal with different content (seq 2, same link back to Alice seq 1).
//
// Paper requirement: the second countersign must be detected and recorded as fraud.
// This test also serves as a regression for the `&& link.link_sequence_number != UNKNOWN_SEQ`
// dead-code bug: before the fix, this fraud was silently ignored.

#[test]
fn stress_double_countersign_detected() {
    let alice = Identity::from_bytes(&[1; 32]);
    let bob = Identity::from_bytes(&[2; 32]);
    let mut store = MemoryBlockStore::new();

    // Alice proposes to Bob (seq=1).
    let proposal = create_half_block(
        &alice,
        1,
        &bob.pubkey_hex(),
        0,
        GENESIS_HASH,
        BlockType::Proposal,
        serde_json::json!({"service": "compute"}),
        Some(1000),
    );
    store.add_block(&proposal).unwrap();

    // Bob agrees — legitimate first response (seq=1, links to Alice seq=1).
    let agreement_1 = create_half_block(
        &bob,
        1,
        &alice.pubkey_hex(),
        1,
        GENESIS_HASH,
        BlockType::Agreement,
        serde_json::json!({"result": "ok"}),
        Some(1001),
    );
    store.add_block(&agreement_1).unwrap();

    // First agreement must validate cleanly.
    let r1 = validate_block(&agreement_1, &store);
    assert!(
        !matches!(r1, ValidationResult::Invalid(_)),
        "legitimate first agreement should not be Invalid, got: {r1:?}"
    );

    // Bob attempts to agree to the SAME Alice proposal again (seq=2, same link_seq=1).
    // Different transaction content → different block_hash → double-countersign.
    let agreement_2 = create_half_block(
        &bob,
        2,
        &alice.pubkey_hex(),
        1, // same link: Alice seq=1
        &agreement_1.block_hash,
        BlockType::Agreement,
        serde_json::json!({"result": "tampered — fraudulent second response"}),
        Some(1002),
    );

    // validate_and_record must detect and record the double-countersign fraud.
    let r2 = validate_and_record(&agreement_2, &mut store);
    assert!(
        matches!(r2, ValidationResult::Invalid(_)),
        "second agreement to same proposal must be detected as double-countersign fraud"
    );
    if let ValidationResult::Invalid(ref errors) = r2 {
        assert!(
            errors.iter().any(|e| e.contains("Double countersign")),
            "expected 'Double countersign' error, got: {errors:?}"
        );
    }

    // The fraud evidence must be persisted so the trust engine can hard-zero Bob.
    let frauds = store.get_double_spends(&bob.pubkey_hex()).unwrap();
    assert_eq!(
        frauds.len(),
        1,
        "exactly one double-countersign fraud should be recorded"
    );
    println!("double-countersign: detected and recorded ✓");
}

// ─── Test 11: Trust score exact math — weight formula and redistribution ───────
//
// Verifies two concrete formula applications (§5):
//
//   A) Empty agent:
//      integrity=1.0, statistical=0.0, no netflow
//      → no-netflow redistribution: (0.3/0.6)*1.0 + (0.3/0.6)*0.0 = 0.5
//
//   B) 20 proposals, 1 counterparty, same timestamp, no agreements:
//      count_score   = 20/20 = 1.0
//      unique_score  =  1/5  = 0.2
//      completion_rate = 0.0   (no linked agreements in store)
//      age_score     = 0.0   (all same timestamp → age_ms=0)
//      entropy_score = 0.0   (1 counterparty → no diversity)
//      statistical   = 0.25×1.0 + 0.20×0.2 + 0.25×0.0 + 0.10×0.0 + 0.20×0.0 = 0.29
//      trust (no nf) = 0.5×integrity + 0.5×statistical = 0.5×1.0 + 0.5×0.29 = 0.645

#[test]
fn stress_trust_exact_math_no_netflow() {
    // Case A: empty chain → exactly 0.5
    {
        let store = MemoryBlockStore::new();
        let engine = TrustEngine::new(&store, None, None);
        let score = engine
            .compute_trust(&Identity::from_bytes(&[1; 32]).pubkey_hex())
            .unwrap();
        assert!(
            (score - 0.5).abs() < 1e-9,
            "empty agent must score exactly 0.5 (half-trust baseline), got {score}"
        );
    }

    // Case B: 20 proposals to 1 counterparty, same timestamp, no agreements.
    {
        let alice = Identity::from_bytes(&[1; 32]);
        let peer = Identity::from_bytes(&[2; 32]);
        let mut store = MemoryBlockStore::new();
        let mut prev = GENESIS_HASH.to_string();
        for i in 1u64..=20 {
            let b = create_half_block(
                &alice,
                i,
                &peer.pubkey_hex(),
                0,
                &prev,
                BlockType::Proposal,
                serde_json::json!({"i": i}),
                Some(5000), // all same timestamp → age_ms = 0
            );
            prev = b.block_hash.clone();
            store.add_block(&b).unwrap();
        }

        let engine = TrustEngine::new(&store, None, None);
        let integrity = engine
            .compute_chain_integrity(&alice.pubkey_hex())
            .unwrap();
        let statistical = engine
            .compute_statistical_score(&alice.pubkey_hex())
            .unwrap();
        let trust = engine.compute_trust(&alice.pubkey_hex()).unwrap();

        assert!(
            (integrity - 1.0).abs() < 1e-9,
            "perfect chain must have integrity=1.0, got {integrity}"
        );

        // statistical = 0.25×1.0 + 0.20×0.2 + 0.25×0.0 + 0.10×0.0 + 0.20×0.0
        let expected_stat: f64 = 0.25 * 1.0 + 0.20 * 0.2 + 0.25 * 0.0 + 0.10 * 0.0 + 0.20 * 0.0;
        assert!(
            (statistical - expected_stat).abs() < 1e-6,
            "statistical should be ≈{expected_stat:.4}, got {statistical:.6}"
        );

        // No netflow → redistribute: (0.3/0.6)×integrity + (0.3/0.6)×statistical
        let expected_trust = 0.5 * integrity + 0.5 * statistical;
        assert!(
            (trust - expected_trust).abs() < 1e-6,
            "trust formula mismatch: expected {expected_trust:.6}, got {trust:.6}"
        );

        println!(
            "exact math: integrity={integrity:.4} stat={statistical:.4} trust={trust:.4} ✓"
        );
    }
}

// ─── Test 12: Chain integrity degrades with a broken hash link (§3.2) ─────────
//
// Constructs a 5-block chain where block 4 uses GENESIS_HASH as prev_hash instead
// of block 3's hash.  The integrity scanner stops at the first broken link and
// returns (valid_blocks / total_blocks) = 3/5 = 0.6.

#[test]
fn stress_chain_integrity_broken_link() {
    let alice = Identity::from_bytes(&[1; 32]);
    let peer = Identity::from_bytes(&[2; 32]);
    let mut store = MemoryBlockStore::new();

    // Blocks 1–3 form a correct chain.
    let b1 = create_half_block(
        &alice, 1, &peer.pubkey_hex(), 0, GENESIS_HASH,
        BlockType::Proposal, serde_json::json!({}), Some(1000),
    );
    let b2 = create_half_block(
        &alice, 2, &peer.pubkey_hex(), 0, &b1.block_hash,
        BlockType::Proposal, serde_json::json!({}), Some(2000),
    );
    let b3 = create_half_block(
        &alice, 3, &peer.pubkey_hex(), 0, &b2.block_hash,
        BlockType::Proposal, serde_json::json!({}), Some(3000),
    );

    // Block 4 deliberately anchors to GENESIS_HASH instead of b3 — valid signature,
    // broken chain link.  This simulates a tampered or gap-filled block.
    let b4_broken = create_half_block(
        &alice, 4, &peer.pubkey_hex(), 0, GENESIS_HASH, // WRONG prev — should be b3.block_hash
        BlockType::Proposal, serde_json::json!({}), Some(4000),
    );

    // Block 5 continues from the broken block (valid local chain from b4 onwards).
    let b5 = create_half_block(
        &alice, 5, &peer.pubkey_hex(), 0, &b4_broken.block_hash,
        BlockType::Proposal, serde_json::json!({}), Some(5000),
    );

    for b in [&b1, &b2, &b3, &b4_broken, &b5] {
        store.add_block(b).unwrap();
    }

    let engine = TrustEngine::new(&store, None, None);
    let integrity = engine
        .compute_chain_integrity(&alice.pubkey_hex())
        .unwrap();

    // Scanner stops at i=3 (seq=4) where expected_prev=b3.hash ≠ actual=GENESIS_HASH.
    // Returns 3.0 / 5.0 = 0.6.
    assert!(
        (integrity - 0.6).abs() < 1e-9,
        "chain with broken link at seq=4 should score 0.6, got {integrity}"
    );
    println!("chain integrity: broken link at seq=4 → score={integrity:.2} ✓");
}

// ─── Test 13: Trust score is monotonically non-decreasing with more interactions ─
//
// Adding more legitimate interactions must never decrease an agent's trust score.
// Verifies the key property that the system rewards honest participation.

#[test]
fn stress_trust_monotonicity() {
    let peer_pk = Identity::from_bytes(&[99; 32]).pubkey_hex();

    // Build trust score for an agent with `n` proposals (no agreements, same counterparty).
    let trust_for_n = |n: u64| -> f64 {
        let agent = Identity::from_bytes(&[1; 32]);
        let mut store = MemoryBlockStore::new();
        let mut prev = GENESIS_HASH.to_string();
        for i in 1u64..=n {
            let b = create_half_block(
                &agent,
                i,
                &peer_pk,
                0,
                &prev,
                BlockType::Proposal,
                serde_json::json!({"i": i}),
                Some(i * 1000),
            );
            prev = b.block_hash.clone();
            store.add_block(&b).unwrap();
        }
        TrustEngine::new(&store, None, None)
            .compute_trust(&agent.pubkey_hex())
            .unwrap()
    };

    let t0 = trust_for_n(0); // empty — baseline
    let t5 = trust_for_n(5); // modest history
    let t20 = trust_for_n(20); // saturated count_score

    println!("trust monotonicity: t0={t0:.4}  t5={t5:.4}  t20={t20:.4}");

    assert!(
        (t0 - 0.5).abs() < 1e-9,
        "empty agent must score exactly 0.5, got {t0}"
    );
    assert!(
        t5 > t0,
        "5 interactions should raise trust above baseline ({t5:.4} > {t0:.4})"
    );
    assert!(
        t20 > t5,
        "20 interactions should raise trust above 5 ({t20:.4} > {t5:.4})"
    );
    assert!(t20 <= 1.0, "trust must be capped at 1.0");
    println!("trust monotonicity: t0 < t5 < t20 ≤ 1.0 ✓");
}

// ─── Test 14: NetFlow with multiple seed nodes (§4.1) ─────────────────────────
//
// An honest agent connected to 2 seed nodes should have nonzero trust.
// An agent with no seed connections must score 0.0 regardless of local activity.
// More seed paths must not decrease trust (max-flow can only increase).

#[test]
fn stress_netflow_multi_seed() {
    let seed1 = Identity::from_bytes(&[1; 32]);
    let seed2 = Identity::from_bytes(&[2; 32]);
    let honest = Identity::from_bytes(&[3; 32]);
    let alien = Identity::from_bytes(&[4; 32]); // no seed connections

    let mut store = MemoryBlockStore::new();

    // Honest ↔ seed1 interaction.
    let p1 = create_half_block(
        &seed1, 1, &honest.pubkey_hex(), 0, GENESIS_HASH,
        BlockType::Proposal, serde_json::json!({}), Some(1000),
    );
    let a1 = create_half_block(
        &honest, 1, &seed1.pubkey_hex(), 1, GENESIS_HASH,
        BlockType::Agreement, serde_json::json!({}), Some(1001),
    );
    store.add_block(&p1).unwrap();
    store.add_block(&a1).unwrap();

    // Honest ↔ seed2 interaction.
    let p2 = create_half_block(
        &seed2, 1, &honest.pubkey_hex(), 0, GENESIS_HASH,
        BlockType::Proposal, serde_json::json!({}), Some(2000),
    );
    let a2 = create_half_block(
        &honest, 2, &seed2.pubkey_hex(), 1, &a1.block_hash,
        BlockType::Agreement, serde_json::json!({}), Some(2001),
    );
    store.add_block(&p2).unwrap();
    store.add_block(&a2).unwrap();

    // Alien activity: proposal only, no seed connections.
    let alien_p = create_half_block(
        &alien, 1, &honest.pubkey_hex(), 0, GENESIS_HASH,
        BlockType::Proposal, serde_json::json!({}), Some(3000),
    );
    store.add_block(&alien_p).unwrap();

    // Single-seed engine (only seed1).
    let engine1 = NetFlowTrust::new(&store, vec![seed1.pubkey_hex()]).unwrap();
    let score_1seed = engine1.compute_trust(&honest.pubkey_hex()).unwrap();

    // Multi-seed engine (seed1 + seed2).
    let engine2 =
        NetFlowTrust::new(&store, vec![seed1.pubkey_hex(), seed2.pubkey_hex()]).unwrap();
    let score_2seed = engine2.compute_trust(&honest.pubkey_hex()).unwrap();
    let alien_score = engine2.compute_trust(&alien.pubkey_hex()).unwrap();

    println!(
        "netflow multi-seed: 1-seed={score_1seed:.4}  2-seed={score_2seed:.4}  alien={alien_score:.4}"
    );

    assert!(
        score_1seed > 0.0,
        "honest with 1 seed interaction must have nonzero trust"
    );
    assert!(
        score_2seed > 0.0,
        "honest with 2 seed interactions must have nonzero trust"
    );
    assert_eq!(
        alien_score, 0.0,
        "agent with no seed connections must score exactly 0.0"
    );
    assert!(
        score_2seed >= score_1seed,
        "two seed paths must not decrease trust ({score_2seed:.4} >= {score_1seed:.4})"
    );
    println!("netflow multi-seed: isolation and path monotonicity verified ✓");
}

// ─── Test 15: Stale checkpoint rejected; future seq accepted (CHECO bug fix) ───
//
// Regression test for the CHECO availability fix:
//   - OLD behaviour: claimed_seq > our_seq → reject  (broke active networks)
//   - NEW behaviour: our_seq > claimed_seq → reject  (only truly stale)
//                    claimed_seq > our_seq → accept  (normal gossip skew)
//
// The paper requires validators to accept checkpoints from faster peers.

#[test]
fn stress_stale_checkpoint_rejected() {
    let alice = Identity::from_bytes(&[1; 32]);
    let bob = Identity::from_bytes(&[2; 32]); // validator
    let carol = Identity::from_bytes(&[3; 32]); // facilitator (checkpoint author)

    // Validator knows alice is at seq=5.
    let mut validator_store = MemoryBlockStore::new();
    let mut prev = GENESIS_HASH.to_string();
    for i in 1u64..=5 {
        let b = create_half_block(
            &alice,
            i,
            &bob.pubkey_hex(),
            0,
            &prev,
            BlockType::Proposal,
            serde_json::json!({"i": i}),
            Some(i * 1000),
        );
        prev = b.block_hash.clone();
        validator_store.add_block(&b).unwrap();
    }
    let validator = CHECOConsensus::new(
        bob.clone(),
        validator_store,
        Some(vec![carol.pubkey_hex()]),
        1,
    );

    // Helper: construct a signed checkpoint block claiming alice is at `claimed_seq`.
    let make_checkpoint = |claimed_seq: u64| -> trustchain_core::HalfBlock {
        let heads = serde_json::json!({ alice.pubkey_hex(): claimed_seq });
        create_half_block(
            &carol,
            1,
            &carol.pubkey_hex(),
            0,
            GENESIS_HASH,
            BlockType::Checkpoint,
            serde_json::json!({
                "interaction_type": "checkpoint",
                "outcome": "proposed",
                "timestamp": 99_999u64,
                "chain_heads": heads,
                "checkpoint_round": 1u64,
            }),
            Some(99_999),
        )
    };

    // STALE: facilitator claims alice=3, but validator knows alice=5 → must reject.
    let stale = make_checkpoint(3);
    let result = validator.validate_checkpoint(&stale);
    assert!(
        result.is_err(),
        "stale checkpoint (claimed=3, known=5) must be rejected"
    );
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("stale"),
        "error message should contain 'stale', got: {err_msg}"
    );

    // FUTURE (gossip skew): facilitator claims alice=7, validator knows alice=5 → must accept.
    // This is the scenario that was incorrectly broken before the fix.
    let future = make_checkpoint(7);
    let result = validator.validate_checkpoint(&future);
    assert!(
        result.is_ok(),
        "future checkpoint (claimed=7, known=5) should be accepted as normal gossip skew, got: {result:?}"
    );

    // EXACT MATCH: facilitator claims alice=5, validator knows alice=5 → accept.
    let exact = make_checkpoint(5);
    assert!(
        validator.validate_checkpoint(&exact).is_ok(),
        "exact-match checkpoint (claimed=5, known=5) should be accepted"
    );

    println!("stale checkpoint regression: stale=rejected, future=accepted, exact=accepted ✓");
}
