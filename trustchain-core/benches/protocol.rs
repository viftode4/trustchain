mod helpers;

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use trustchain_core::{Identity, MemoryBlockStore, SqliteBlockStore, TrustChainProtocol};

fn bench_propose_agree_memory(c: &mut Criterion) {
    let alice_id = Identity::from_bytes(&[1u8; 32]);
    let bob_id = Identity::from_bytes(&[2u8; 32]);

    c.bench_function("propose_agree_memory", |b| {
        b.iter(|| {
            let mut alice =
                TrustChainProtocol::new(alice_id.clone(), MemoryBlockStore::new());
            let mut bob =
                TrustChainProtocol::new(bob_id.clone(), MemoryBlockStore::new());

            let proposal = alice
                .create_proposal(
                    &bob_id.pubkey_hex(),
                    serde_json::json!({"interaction_type": "service", "outcome": "completed"}),
                    Some(1000),
                )
                .unwrap();
            bob.receive_proposal(black_box(&proposal)).unwrap();
            let agreement = bob.create_agreement(black_box(&proposal), Some(1001)).unwrap();
            alice.receive_agreement(black_box(&agreement)).unwrap();
        })
    });
}

fn bench_propose_agree_sqlite(c: &mut Criterion) {
    let alice_id = Identity::from_bytes(&[1u8; 32]);
    let bob_id = Identity::from_bytes(&[2u8; 32]);

    c.bench_function("propose_agree_sqlite", |b| {
        b.iter(|| {
            let alice_store = SqliteBlockStore::in_memory().unwrap();
            let bob_store = SqliteBlockStore::in_memory().unwrap();
            let mut alice = TrustChainProtocol::new(alice_id.clone(), alice_store);
            let mut bob = TrustChainProtocol::new(bob_id.clone(), bob_store);

            let proposal = alice
                .create_proposal(
                    &bob_id.pubkey_hex(),
                    serde_json::json!({"interaction_type": "service", "outcome": "completed"}),
                    Some(1000),
                )
                .unwrap();
            bob.receive_proposal(black_box(&proposal)).unwrap();
            let agreement = bob.create_agreement(black_box(&proposal), Some(1001)).unwrap();
            alice.receive_agreement(black_box(&agreement)).unwrap();
        })
    });
}

fn bench_propose_agree_sequential_100(c: &mut Criterion) {
    c.bench_function("propose_agree_100_sequential", |b| {
        b.iter(|| {
            let alice_id = Identity::from_bytes(&[1u8; 32]);
            let bob_id = Identity::from_bytes(&[2u8; 32]);
            let mut alice =
                TrustChainProtocol::new(alice_id.clone(), MemoryBlockStore::new());
            let mut bob =
                TrustChainProtocol::new(bob_id.clone(), MemoryBlockStore::new());

            for i in 0..100u64 {
                let proposal = alice
                    .create_proposal(
                        &bob_id.pubkey_hex(),
                        serde_json::json!({"interaction_type": "service", "outcome": "completed"}),
                        Some(1000 + i * 2),
                    )
                    .unwrap();
                bob.receive_proposal(&proposal).unwrap();
                let agreement = bob.create_agreement(&proposal, Some(1001 + i * 2)).unwrap();
                alice.receive_agreement(&agreement).unwrap();
            }
        })
    });
}

criterion_group!(benches, bench_propose_agree_memory, bench_propose_agree_sqlite, bench_propose_agree_sequential_100);
criterion_main!(benches);
