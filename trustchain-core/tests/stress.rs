//! Stress tests for the TrustChain protocol.
//!
//! These tests exercise concurrent access patterns, high-volume interactions,
//! fraud detection under load, and chain integrity at scale.
//!
//! Run with: cargo test --test stress -- --nocapture

use std::sync::Arc;
use tokio::sync::Mutex;
use trustchain_core::{
    BlockStore, Identity, MemoryBlockStore, TrustChainProtocol,
    halfblock::{create_half_block, validate_and_record},
    types::{BlockType, GENESIS_HASH, ValidationResult},
    netflow::NetFlowTrust,
};

// ─── helpers ─────────────────────────────────────────────────────────────────

fn make_protocol(seed: u8) -> TrustChainProtocol<MemoryBlockStore> {
    TrustChainProtocol::new(
        Identity::from_bytes(&[seed; 32]),
        MemoryBlockStore::new(),
    )
}

// ─── Test 1: sequential high-volume bilateral interactions ───────────────────

#[tokio::test]
async fn stress_sequential_100_interactions() {
    let mut alice = make_protocol(1);
    let mut bob   = make_protocol(2);
    let bob_pk = bob.pubkey();
    let alice_pk = alice.pubkey();

    for i in 1..=100u64 {
        let tx = serde_json::json!({"round": i, "service": "compute"});
        let proposal  = alice.create_proposal(&bob_pk, tx, None).unwrap();
        bob.receive_proposal(&proposal).unwrap();
        let agreement = bob.create_agreement(&proposal, None).unwrap();
        alice.receive_agreement(&agreement).unwrap();
    }

    // Every interaction should produce 2 blocks in each chain.
    assert_eq!(alice.store().get_latest_seq(&alice_pk).unwrap(), 100);
    assert_eq!(bob.store().get_latest_seq(&bob_pk).unwrap(),     100);

    // Verify chain hash links are all intact.
    let alice_chain = alice.store().get_chain(&alice_pk).unwrap();
    for window in alice_chain.windows(2) {
        assert_eq!(
            window[1].previous_hash, window[0].block_hash,
            "broken hash link at seq {} → {}",
            window[0].sequence_number, window[1].sequence_number
        );
    }

    let bob_chain = alice.store().get_chain(&bob_pk).unwrap();
    for window in bob_chain.windows(2) {
        assert_eq!(
            window[1].previous_hash, window[0].block_hash,
            "broken hash link at seq {} → {}",
            window[0].sequence_number, window[1].sequence_number
        );
    }
}

// ─── Test 2: concurrent proposals through a shared protocol mutex ─────────────

#[tokio::test]
async fn stress_concurrent_proposals_shared_lock() {
    let alice: Arc<Mutex<TrustChainProtocol<MemoryBlockStore>>> =
        Arc::new(Mutex::new(make_protocol(10)));
    let bob_pk = Identity::from_bytes(&[20; 32]).pubkey_hex();

    // Spawn 50 concurrent tasks all trying to create proposals through the same lock.
    let mut handles = vec![];
    for i in 0..50u64 {
        let alice = alice.clone();
        let bob_pk = bob_pk.clone();
        handles.push(tokio::spawn(async move {
            let mut proto = alice.lock().await;
            proto.create_proposal(&bob_pk, serde_json::json!({"task": i}), None)
        }));
    }

    let mut successes = 0;
    let mut failures  = 0;
    for handle in handles {
        match handle.await.unwrap() {
            Ok(_)  => successes += 1,
            Err(e) => { eprintln!("proposal failed: {e}"); failures += 1; }
        }
    }

    // All 50 should succeed — the mutex serializes them, no duplicate seqs.
    assert_eq!(successes, 50, "expected 50 successful proposals");
    assert_eq!(failures,   0, "expected 0 failures");

    let alice_pk = Identity::from_bytes(&[10; 32]).pubkey_hex();
    let seq = alice.lock().await.store().get_latest_seq(&alice_pk).unwrap();
    assert_eq!(seq, 50, "chain should have exactly 50 blocks");
}

// ─── Test 3: duplicate proposal idempotency ──────────────────────────────────

#[tokio::test]
async fn stress_duplicate_proposal_idempotent() {
    let mut alice = make_protocol(1);
    let mut bob   = make_protocol(2);
    let bob_pk = bob.pubkey();

    let proposal = alice.create_proposal(&bob_pk, serde_json::json!({"x": 1}), None).unwrap();

    // Deliver the same proposal 10 times — should be idempotent.
    for _ in 0..10 {
        bob.receive_proposal(&proposal).unwrap();
    }

    assert_eq!(bob.store().get_latest_seq(&proposal.public_key).unwrap(), 1,
        "proposal stored once despite 10 deliveries");
}

// ─── Test 4: fraud detection under concurrent load ───────────────────────────

#[tokio::test]
async fn stress_double_sign_detected_under_load() {
    let alice_id = Identity::from_bytes(&[1; 32]);
    let bob_pk   = Identity::from_bytes(&[2; 32]).pubkey_hex();

    let mut store = MemoryBlockStore::new();

    // Create 50 legitimate blocks.
    let mut prev = GENESIS_HASH.to_string();
    for i in 1u64..=50 {
        let b = create_half_block(
            &alice_id, i, &bob_pk, 0, &prev,
            BlockType::Proposal, serde_json::json!({"i": i}), Some(i * 1000),
        );
        let result = validate_and_record(&b, &mut store);
        assert!(!matches!(result, ValidationResult::Invalid(_)),
            "legitimate block {i} failed validation");
        prev = b.block_hash.clone();
        store.add_block(&b).unwrap();
    }

    // Now inject a double-sign at seq 25 (different transaction).
    let prev_of_25 = store.get_block(&alice_id.pubkey_hex(), 24).unwrap().unwrap().block_hash;
    let fraud_block = create_half_block(
        &alice_id, 25, &bob_pk, 0, &prev_of_25,
        BlockType::Proposal, serde_json::json!({"fraud": true}), Some(25_000),
    );
    let result = validate_and_record(&fraud_block, &mut store);

    assert!(matches!(result, ValidationResult::Invalid(_)),
        "fraud block should be detected as invalid");
    if let ValidationResult::Invalid(ref errors) = result {
        assert!(errors.iter().any(|e| e.contains("Double sign")),
            "expected double sign error, got: {:?}", errors);
    }

    let frauds = store.get_double_spends(&alice_id.pubkey_hex()).unwrap();
    assert_eq!(frauds.len(), 1, "fraud should be recorded exactly once");
}

// ─── Test 5: chain integrity with many participants ──────────────────────────

#[tokio::test]
async fn stress_multi_party_chain_integrity() {
    // 10 agents, each does 5 interactions with the next agent (ring topology).
    let mut protos: Vec<TrustChainProtocol<MemoryBlockStore>> =
        (0u8..10).map(make_protocol).collect();

    for round in 0..5 {
        for i in 0..10 {
            let j = (i + 1) % 10;
            let bob_pk = protos[j].pubkey();
            let tx = serde_json::json!({"round": round, "from": i, "to": j});

            // Move blocks between protocols via serialization (simulates network).
            let proposal = {
                let alice = &mut protos[i];
                alice.create_proposal(&bob_pk, tx, None).unwrap()
            };
            {
                let bob = &mut protos[j];
                bob.receive_proposal(&proposal).unwrap();
                let agreement = bob.create_agreement(&proposal, None).unwrap();
                // Give alice the agreement too.
                protos[i].receive_agreement(&agreement).unwrap();
            }
        }
    }

    // In a 10-node ring each agent is both initiator (to next) and responder (to prev),
    // so each agent accumulates 2 blocks per round = 10 blocks after 5 rounds.
    for (idx, proto) in protos.iter().enumerate() {
        let pk = Identity::from_bytes(&[idx as u8; 32]).pubkey_hex();
        let seq = proto.store().get_latest_seq(&pk).unwrap();
        assert_eq!(seq, 10, "agent {idx} should have seq=10 (5 rounds × 2 blocks), got {seq}");

        let chain = proto.store().get_chain(&pk).unwrap();
        for window in chain.windows(2) {
            assert_eq!(
                window[1].previous_hash, window[0].block_hash,
                "agent {idx}: broken chain link at seq {}→{}",
                window[0].sequence_number, window[1].sequence_number
            );
        }
    }
}

// ─── Test 6: NetFlow trust under Sybil pressure at scale ─────────────────────

#[test]
fn stress_netflow_sybil_resistance_at_scale() {
    let mut store = MemoryBlockStore::new();
    let seed   = Identity::from_bytes(&[1; 32]);
    let honest = Identity::from_bytes(&[2; 32]);

    // Seed and honest agent do 10 real interactions.
    let mut s_prev  = GENESIS_HASH.to_string();
    let mut h_prev  = GENESIS_HASH.to_string();
    for i in 1u64..=10 {
        let p = create_half_block(
            &seed, i, &honest.pubkey_hex(), 0, &s_prev,
            BlockType::Proposal, serde_json::json!({}), Some(i * 1000),
        );
        let a = create_half_block(
            &honest, i, &seed.pubkey_hex(), i, &h_prev,
            BlockType::Agreement, serde_json::json!({}), Some(i * 1001),
        );
        s_prev = p.block_hash.clone();
        h_prev = a.block_hash.clone();
        store.add_block(&p).unwrap();
        store.add_block(&a).unwrap();
    }

    // Create a Sybil cluster of 20 agents with many mutual interactions but
    // zero connection to the seed.
    let sybils: Vec<Identity> = (100u8..120).map(|s| Identity::from_bytes(&[s; 32])).collect();
    let mut sybil_prevs: Vec<String> = vec![GENESIS_HASH.to_string(); 20];
    // Track per-agent sequence numbers (each agent accumulates blocks as both proposer and responder).
    let mut sybil_seqs: Vec<u64> = vec![0u64; 20];

    for round in 0..10u64 {
        for i in 0..20 {
            let j = (i + 1) % 20;
            sybil_seqs[i] += 1;
            let p_seq = sybil_seqs[i];
            let p = create_half_block(
                &sybils[i], p_seq, &sybils[j].pubkey_hex(), 0, &sybil_prevs[i],
                BlockType::Proposal, serde_json::json!({"round": round}), Some(round * 1000 + i as u64),
            );
            let p_hash = p.block_hash.clone();

            sybil_seqs[j] += 1;
            let a_seq = sybil_seqs[j];
            let a = create_half_block(
                &sybils[j], a_seq, &sybils[i].pubkey_hex(), p_seq, &sybil_prevs[j],
                BlockType::Agreement, serde_json::json!({"round": round}), Some(round * 1000 + i as u64 + 1),
            );
            sybil_prevs[i] = p_hash;
            sybil_prevs[j] = a.block_hash.clone();
            store.add_block(&p).unwrap();
            store.add_block(&a).unwrap();
        }
    }

    let engine = NetFlowTrust::new(&store, vec![seed.pubkey_hex()]).unwrap();
    let honest_score = engine.compute_trust(&honest.pubkey_hex()).unwrap();
    let sybil_score  = engine.compute_trust(&sybils[0].pubkey_hex()).unwrap();

    println!("honest score: {honest_score:.4}  sybil score: {sybil_score:.4}");

    assert!(
        honest_score > 0.0,
        "honest agent with real seed interactions should have positive trust"
    );
    assert_eq!(
        sybil_score, 0.0,
        "sybil disconnected from seed should have 0 trust despite 500 mutual interactions"
    );
    assert!(
        honest_score > sybil_score,
        "honest agent must outrank sybil cluster"
    );
}

// ─── Test 7: block hash stability under repeated serialisation ───────────────

#[test]
fn stress_hash_stability_1000_roundtrips() {
    let id = Identity::from_bytes(&[42; 32]);
    let block = create_half_block(
        &id, 1, &"b".repeat(64), 0, GENESIS_HASH,
        BlockType::Proposal,
        serde_json::json!({"nested": {"key": "val", "num": 3.14, "arr": [1,2,3]}}),
        None,
    );

    let original_hash = block.block_hash.clone();
    let mut current = block;

    for i in 0..1000 {
        let json = serde_json::to_string(&current).unwrap();
        let parsed: trustchain_core::HalfBlock = serde_json::from_str(&json).unwrap();
        assert_eq!(
            original_hash, parsed.compute_hash(),
            "hash drifted on round-trip {i}"
        );
        current = parsed;
    }
}

// ─── Test 8: cross-link pubkey mismatch is now caught (bug fix regression) ───

#[test]
fn stress_cross_link_pubkey_mismatch_rejected() {
    use trustchain_core::halfblock::validate_block;

    let alice_id   = Identity::from_bytes(&[1; 32]);
    let bob_id     = Identity::from_bytes(&[2; 32]);
    let mallory_id = Identity::from_bytes(&[3; 32]);

    let mut store = MemoryBlockStore::new();

    // Alice creates a proposal directed at Bob.
    let alice_proposal = create_half_block(
        &alice_id, 1, &bob_id.pubkey_hex(), 0, GENESIS_HASH,
        BlockType::Proposal, serde_json::json!({"service": "x"}), Some(1000),
    );
    store.add_block(&alice_proposal).unwrap();

    // Mallory creates a FAKE agreement claiming to be linked to Alice's proposal.
    // Mallory signs it (valid signature) but wrongly claims Alice's proposal links to Mallory.
    let mallory_agreement = create_half_block(
        &mallory_id, 1, &alice_id.pubkey_hex(), alice_proposal.sequence_number, GENESIS_HASH,
        BlockType::Agreement, serde_json::json!({"service": "x"}), Some(1001),
    );

    // This must be caught: Alice's proposal points to Bob, not Mallory.
    let result = validate_block(&mallory_agreement, &store);
    assert!(
        matches!(result, ValidationResult::Invalid(_)),
        "fake agreement from Mallory should be rejected"
    );
    if let ValidationResult::Invalid(ref errors) = result {
        assert!(
            errors.iter().any(|e| e.contains("Public key mismatch")),
            "expected pubkey mismatch error, got: {:?}", errors
        );
    }
}
