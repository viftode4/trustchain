mod helpers;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use trustchain_core::{
    halfblock::create_half_block,
    types::{BlockType, GENESIS_HASH},
    BlockStore, Identity, MemoryBlockStore, SqliteBlockStore,
};

fn bench_sqlite_sequential_insert(c: &mut Criterion) {
    let mut group = c.benchmark_group("sqlite_sequential_insert");
    let alice = Identity::from_bytes(&[1u8; 32]);
    let bob = Identity::from_bytes(&[2u8; 32]);

    for &n in &[100, 1_000, 10_000] {
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &n| {
            b.iter(|| {
                let mut store = SqliteBlockStore::in_memory().unwrap();
                let mut prev_hash = GENESIS_HASH.to_string();

                for seq in 1..=n as u64 {
                    let block = create_half_block(
                        &alice,
                        seq,
                        &bob.pubkey_hex(),
                        0,
                        &prev_hash,
                        BlockType::Proposal,
                        serde_json::json!({"interaction_type": "service"}),
                        Some(1000 + seq),
                    );
                    prev_hash = block.block_hash.clone();
                    store.add_block(&block).unwrap();
                }
            });
        });
    }
    group.finish();
}

fn bench_sqlite_get_chain(c: &mut Criterion) {
    let mut group = c.benchmark_group("sqlite_get_chain");
    let alice = Identity::from_bytes(&[1u8; 32]);
    let bob = Identity::from_bytes(&[2u8; 32]);

    for &n in &[100, 1_000, 10_000] {
        // Pre-populate the store
        let mut store = SqliteBlockStore::in_memory().unwrap();
        let mut prev_hash = GENESIS_HASH.to_string();
        for seq in 1..=n as u64 {
            let block = create_half_block(
                &alice,
                seq,
                &bob.pubkey_hex(),
                0,
                &prev_hash,
                BlockType::Proposal,
                serde_json::json!({"interaction_type": "service"}),
                Some(1000 + seq),
            );
            prev_hash = block.block_hash.clone();
            store.add_block(&block).unwrap();
        }

        let pk = alice.pubkey_hex();
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, _| {
            b.iter(|| store.get_chain(&pk).unwrap());
        });
    }
    group.finish();
}

fn bench_memory_vs_sqlite_insert(c: &mut Criterion) {
    let mut group = c.benchmark_group("store_insert_1000");
    let alice = Identity::from_bytes(&[1u8; 32]);
    let bob = Identity::from_bytes(&[2u8; 32]);

    // Pre-create blocks
    let mut blocks = Vec::with_capacity(1000);
    let mut prev_hash = GENESIS_HASH.to_string();
    for seq in 1..=1000u64 {
        let block = create_half_block(
            &alice,
            seq,
            &bob.pubkey_hex(),
            0,
            &prev_hash,
            BlockType::Proposal,
            serde_json::json!({"interaction_type": "service"}),
            Some(1000 + seq),
        );
        prev_hash = block.block_hash.clone();
        blocks.push(block);
    }

    group.bench_function("memory", |b| {
        b.iter(|| {
            let mut store = MemoryBlockStore::new();
            for block in &blocks {
                store.add_block(block).unwrap();
            }
        });
    });

    group.bench_function("sqlite", |b| {
        b.iter(|| {
            let mut store = SqliteBlockStore::in_memory().unwrap();
            for block in &blocks {
                store.add_block(block).unwrap();
            }
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_sqlite_sequential_insert,
    bench_sqlite_get_chain,
    bench_memory_vs_sqlite_insert,
);
criterion_main!(benches);
