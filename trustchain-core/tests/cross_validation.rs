//! Cross-validation test vectors — generates deterministic vectors for Rust ↔ Python verification.
//!
//! Writes `test_vectors.json` to the workspace root, consumed by the Python SDK tests.

use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use trustchain_core::{
    create_half_block, BlockStore, BlockType, Identity, MemoryBlockStore, TrustEngine, GENESIS_HASH,
};

/// Helper: create a bilateral interaction in a shared store.
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
        json!({"ts": ts}),
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
        json!({"ts": ts}),
        Some(ts + 1),
    );
    store.add_block(&agreement).unwrap();
    (proposal.block_hash, agreement.block_hash)
}

#[test]
fn test_generate_and_verify_vectors() {
    let mut vectors = json!({});

    // -----------------------------------------------------------------------
    // 1. Identity vectors: deterministic seeds → expected pubkeys.
    // -----------------------------------------------------------------------
    let mut identity_vectors = vec![];
    for i in 1u8..=5 {
        let seed = [i; 32];
        let id = Identity::from_bytes(&seed);
        let pubkey = id.pubkey_hex();
        assert_eq!(pubkey.len(), 64);
        identity_vectors.push(json!({
            "seed": hex::encode(seed),
            "pubkey": pubkey,
        }));
    }
    vectors["identity_vectors"] = json!(identity_vectors);

    // -----------------------------------------------------------------------
    // 2. Hash vectors: canonical JSON → SHA-256.
    // -----------------------------------------------------------------------
    let mut hash_vectors = vec![];
    let test_jsons = vec![
        json!({"a": 1, "b": 2}),
        json!({"z": "last", "a": "first"}),
        json!({"nested": {"x": 1}, "flat": true}),
    ];

    for test_json in &test_jsons {
        let map: BTreeMap<String, serde_json::Value> =
            serde_json::from_value(test_json.clone()).unwrap();
        let canonical = serde_json::to_string(&map).unwrap();
        let hash = hex::encode(Sha256::digest(canonical.as_bytes()));

        hash_vectors.push(json!({
            "input": test_json,
            "canonical": canonical,
            "sha256": hash,
        }));
    }
    vectors["hash_vectors"] = json!(hash_vectors);

    // -----------------------------------------------------------------------
    // 3. Block vectors: fixed-timestamp proposals → expected hashes.
    // -----------------------------------------------------------------------
    let id_a = Identity::from_bytes(&[1; 32]);
    let id_b = Identity::from_bytes(&[2; 32]);

    let block = create_half_block(
        &id_a,
        1,
        &id_b.pubkey_hex(),
        0,
        GENESIS_HASH,
        BlockType::Proposal,
        json!({"interaction_type": "test", "amount": 42}),
        Some(1_700_000_000_000u64),
    );

    vectors["block_vectors"] = json!([{
        "creator_seed": hex::encode([1u8; 32]),
        "counterparty_seed": hex::encode([2u8; 32]),
        "sequence_number": 1,
        "link_sequence_number": 0,
        "previous_hash": GENESIS_HASH,
        "block_type": "proposal",
        "transaction": {"interaction_type": "test", "amount": 42},
        "timestamp": 1_700_000_000_000u64,
        "expected_block_hash": block.block_hash,
        "expected_signature": block.signature,
        "expected_public_key": block.public_key,
    }]);

    assert_eq!(block.block_hash, block.compute_hash());
    assert!(trustchain_core::verify_block(&block).unwrap());

    // -----------------------------------------------------------------------
    // 4. Trust vectors: small interaction graph → expected scores.
    // -----------------------------------------------------------------------
    let mut store = MemoryBlockStore::new();

    let mut prev_a = GENESIS_HASH.to_string();
    let mut prev_b = GENESIS_HASH.to_string();
    for i in 0..3u64 {
        let (pa, pb) = create_interaction(
            &mut store,
            &id_a,
            &id_b,
            i + 1,
            i + 1,
            &prev_a,
            &prev_b,
            1_700_000_000_000 + i * 10_000,
        );
        prev_a = pa;
        prev_b = pb;
    }

    let engine = TrustEngine::new(&store, None, None, None);
    let integrity_a = engine.compute_chain_integrity(&id_a.pubkey_hex()).unwrap();
    let integrity_b = engine.compute_chain_integrity(&id_b.pubkey_hex()).unwrap();

    vectors["trust_vectors"] = json!([{
        "description": "3 bilateral interactions between A(seed=1) and B(seed=2)",
        "seed_a": hex::encode([1u8; 32]),
        "seed_b": hex::encode([2u8; 32]),
        "n_interactions": 3,
        "base_timestamp": 1_700_000_000_000u64,
        "timestamp_step": 10_000,
        "scores_a": {
            "integrity": integrity_a,
        },
        "scores_b": {
            "integrity": integrity_b,
        },
    }]);

    assert!((integrity_a - 1.0).abs() < 1e-10);
    assert!((integrity_b - 1.0).abs() < 1e-10);

    // -----------------------------------------------------------------------
    // Write test_vectors.json to workspace root.
    // -----------------------------------------------------------------------
    let output_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../test_vectors.json");
    let json_str = serde_json::to_string_pretty(&vectors).unwrap();
    std::fs::write(&output_path, json_str).unwrap();

    eprintln!(
        "Wrote test vectors to {}",
        output_path.canonicalize().unwrap().display()
    );
}
