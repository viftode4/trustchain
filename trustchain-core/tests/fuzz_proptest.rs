//! Fuzz testing via proptest — random input generation to catch panics.
//!
//! Proptest strategies generate random `HalfBlock` structs (well-formed and malformed)
//! and throw them at core functions. Goal: **no panics ever**.

use proptest::prelude::*;
use trustchain_core::{
    create_half_block, validate_block_invariants, BlockType, HalfBlock, Identity, MemoryBlockStore,
    MemoryDelegationStore, TrustChainProtocol,
};

// ---------------------------------------------------------------------------
// Strategy helpers
// ---------------------------------------------------------------------------

/// Generate a well-formed HalfBlock with valid structure.
fn arb_halfblock() -> impl Strategy<Value = HalfBlock> {
    (
        any::<u8>(),     // identity seed byte
        1u64..1000,      // sequence_number
        any::<u8>(),     // link identity seed byte
        0u64..100,       // link_sequence_number
        prop::bool::ANY, // is_genesis (seq==1)
        prop::sample::select(vec![
            "proposal",
            "agreement",
            "checkpoint",
            "delegation",
            "revocation",
            "succession",
        ]),
    )
        .prop_map(
            |(seed_byte, seq, link_seed, link_seq, is_genesis, block_type)| {
                let seed = [seed_byte; 32];
                let id = Identity::from_bytes(&seed);
                let link_id = Identity::from_bytes(&[link_seed; 32]);

                let actual_seq = if is_genesis { 1 } else { seq.max(2) };
                let prev_hash = if actual_seq == 1 {
                    "0000000000000000000000000000000000000000000000000000000000000000".to_string()
                } else {
                    // Use a deterministic fake previous hash.
                    hex::encode([seed_byte; 32])
                };

                let bt = BlockType::from_str_loose(block_type).unwrap_or(BlockType::Proposal);
                let link_pk = if bt == BlockType::Checkpoint {
                    id.pubkey_hex()
                } else {
                    link_id.pubkey_hex()
                };

                create_half_block(
                    &id,
                    actual_seq,
                    &link_pk,
                    link_seq,
                    &prev_hash,
                    bt,
                    serde_json::json!({"test": true}),
                    Some(1_000_000),
                )
            },
        )
}

/// Generate a malformed HalfBlock with arbitrary-length strings (stress error paths).
fn arb_malformed_halfblock() -> impl Strategy<Value = HalfBlock> {
    (
        ".*",           // public_key (arbitrary)
        0u64..10000,    // sequence_number
        ".*",           // link_public_key (arbitrary)
        0u64..10000,    // link_sequence_number
        ".*",           // previous_hash (arbitrary)
        ".*",           // signature (arbitrary)
        ".*",           // block_type (arbitrary)
        ".*",           // block_hash (arbitrary)
        0u64..u64::MAX, // timestamp
    )
        .prop_map(|(pk, seq, lpk, lseq, prev, sig, bt, bh, ts)| HalfBlock {
            public_key: pk,
            sequence_number: seq,
            link_public_key: lpk,
            link_sequence_number: lseq,
            previous_hash: prev,
            signature: sig,
            block_type: bt,
            transaction: serde_json::json!(null),
            block_hash: bh,
            timestamp: ts,
        })
}

// ---------------------------------------------------------------------------
// Fuzz targets
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]

    /// Random HalfBlock → `validate_block_invariants()` — never panics, returns Valid or Invalid.
    #[test]
    fn fuzz_validate_block_invariants(block in arb_malformed_halfblock()) {
        let result = validate_block_invariants(&block);
        // Must return *something* — Valid or Invalid, never panic.
        let _ = result.is_valid();
    }

    /// Random HalfBlock → `compute_hash()` twice → same result, always 64 hex chars.
    #[test]
    fn fuzz_compute_hash_idempotent(block in arb_halfblock()) {
        let hash1 = block.compute_hash();
        let hash2 = block.compute_hash();
        prop_assert_eq!(&hash1, &hash2, "compute_hash must be deterministic");
        prop_assert_eq!(hash1.len(), 64, "hash must be 64 hex chars");
        prop_assert!(hash1.chars().all(|c| c.is_ascii_hexdigit()), "hash must be valid hex");
    }

    /// Random HalfBlock → serialize JSON → deserialize → assert equality.
    #[test]
    fn fuzz_serde_roundtrip(block in arb_halfblock()) {
        let json = serde_json::to_string(&block).expect("serialize should not fail");
        let deserialized: HalfBlock = serde_json::from_str(&json).expect("deserialize should not fail");
        prop_assert_eq!(block, deserialized);
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// Random delegation proposal blocks → `accept_delegation()` — Ok or Err, never panic.
    #[test]
    fn fuzz_accept_delegation_no_panic(
        delegator_seed in any::<u8>(),
        delegate_seed in any::<u8>().prop_filter("different seeds", |s| *s != 0),
        scope_str in ".*",
        max_depth in 0u32..3,
        ttl_ms in 1u64..100_000,
    ) {
        // Make sure delegator and delegate are different.
        let dseed = if delegator_seed == delegate_seed {
            delegator_seed.wrapping_add(1)
        } else {
            delegate_seed
        };

        let id_a = Identity::from_bytes(&[delegator_seed; 32]);
        let id_b = Identity::from_bytes(&[dseed; 32]);

        let store_a = MemoryBlockStore::new();
        let mut proto_a = TrustChainProtocol::new(id_a.clone(), store_a);

        let mut deleg_store = MemoryDelegationStore::new();
        let proposal = proto_a.create_delegation_proposal(
            &id_b.pubkey_hex(),
            vec![scope_str],
            max_depth,
            ttl_ms,
            None::<&MemoryDelegationStore>,
        );

        if let Ok(prop_block) = proposal {
            let store_b = MemoryBlockStore::new();
            let mut proto_b = TrustChainProtocol::new(id_b, store_b);
            // Should return Ok or Err, never panic.
            let _ = proto_b.accept_delegation(&prop_block, &mut deleg_store);
        }
    }
}
