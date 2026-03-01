mod helpers;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use std::collections::HashMap;
use std::time::Duration;
use trustchain_core::{Identity, MemoryBlockStore, TrustEngine};

// ---------------------------------------------------------------------------
// TrustEngine.compute_trust() — no seeds (integrity only)
// ---------------------------------------------------------------------------
fn bench_trust_engine_no_seeds(c: &mut Criterion) {
    let mut group = c.benchmark_group("trust_engine_no_seeds");

    for &n in &[500, 5_000, 50_000] {
        let mut store = MemoryBlockStore::new();
        helpers::build_chain(&mut store, n);
        let alice_pk = Identity::from_bytes(&[1u8; 32]).pubkey_hex();

        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, _| {
            b.iter(|| {
                let engine = TrustEngine::new(&store, None, None, None);
                engine.compute_trust(&alice_pk).unwrap()
            });
        });
    }
    group.finish();
}

// ---------------------------------------------------------------------------
// TrustEngine.compute_trust() — with seeds (full pipeline incl. NetFlow)
// ---------------------------------------------------------------------------
fn bench_trust_engine_with_seeds(c: &mut Criterion) {
    let mut group = c.benchmark_group("trust_engine_with_seeds");
    group.measurement_time(Duration::from_secs(15));

    for &n_agents in &[50, 500, 2_000] {
        let (store, seed_pk, spoke_pks) = helpers::build_star_network(n_agents, 3);
        let target = &spoke_pks[spoke_pks.len() / 2];

        group.bench_with_input(BenchmarkId::from_parameter(n_agents), &n_agents, |b, _| {
            b.iter(|| {
                let engine = TrustEngine::new(&store, Some(vec![seed_pk.clone()]), None, None);
                engine.compute_trust(target).unwrap()
            });
        });
    }
    group.finish();
}

// ---------------------------------------------------------------------------
// TrustEngine.compute_trust() — very large chain (100K blocks)
// ---------------------------------------------------------------------------
fn bench_trust_engine_large(c: &mut Criterion) {
    let mut group = c.benchmark_group("trust_engine_large");
    group.measurement_time(Duration::from_secs(20));
    group.sample_size(10);

    let mut store = MemoryBlockStore::new();
    helpers::build_chain(&mut store, 100_000);
    let alice_pk = Identity::from_bytes(&[1u8; 32]).pubkey_hex();

    group.bench_function("100k_blocks_no_seeds", |b| {
        b.iter(|| {
            let engine = TrustEngine::new(&store, None, None, None);
            engine.compute_trust(&alice_pk).unwrap()
        });
    });
    group.finish();
}

// ---------------------------------------------------------------------------
// Chain integrity: no checkpoint vs checkpoint covering 90%
// ---------------------------------------------------------------------------
fn bench_chain_integrity_with_checkpoint(c: &mut Criterion) {
    let mut group = c.benchmark_group("chain_integrity_checkpoint");
    group.measurement_time(Duration::from_secs(15));

    for &n in &[500, 5_000, 50_000] {
        let mut store = MemoryBlockStore::new();
        helpers::build_chain(&mut store, n);
        let alice_pk = Identity::from_bytes(&[1u8; 32]).pubkey_hex();

        // Build checkpoint covering 90% of blocks.
        let checkpoint_seq = (n as u64) * 9 / 10;
        let mut chain_heads = HashMap::new();
        chain_heads.insert(alice_pk.clone(), checkpoint_seq);
        let checkpoint = trustchain_core::Checkpoint {
            facilitator_pubkey: "facilitator".into(),
            chain_heads,
            checkpoint_block: trustchain_core::halfblock::create_half_block(
                &Identity::from_bytes(&[99u8; 32]),
                1,
                &alice_pk,
                0,
                trustchain_core::types::GENESIS_HASH,
                trustchain_core::types::BlockType::Proposal,
                serde_json::json!({}),
                Some(99999),
            ),
            signatures: HashMap::new(),
            timestamp: 99999,
            finalized: true,
        };

        group.bench_with_input(BenchmarkId::new("no_checkpoint", n), &n, |b, _| {
            b.iter(|| {
                let engine = TrustEngine::new(&store, None, None, None);
                engine.compute_chain_integrity(&alice_pk).unwrap()
            });
        });

        let cp = checkpoint.clone();
        group.bench_with_input(BenchmarkId::new("checkpoint_90pct", n), &n, |b, _| {
            b.iter(|| {
                let engine = TrustEngine::new(&store, None, None, None).with_checkpoint(cp.clone());
                engine.compute_chain_integrity(&alice_pk).unwrap()
            });
        });

        // Also benchmark 99% coverage to see near-total skip.
        let mut chain_heads_99 = HashMap::new();
        chain_heads_99.insert(alice_pk.clone(), (n as u64) * 99 / 100);
        let checkpoint_99 = trustchain_core::Checkpoint {
            facilitator_pubkey: "facilitator".into(),
            chain_heads: chain_heads_99,
            checkpoint_block: checkpoint.checkpoint_block.clone(),
            signatures: HashMap::new(),
            timestamp: 99999,
            finalized: true,
        };

        group.bench_with_input(BenchmarkId::new("checkpoint_99pct", n), &n, |b, _| {
            b.iter(|| {
                let engine = TrustEngine::new(&store, None, None, None)
                    .with_checkpoint(checkpoint_99.clone());
                engine.compute_chain_integrity(&alice_pk).unwrap()
            });
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_trust_engine_no_seeds,
    bench_trust_engine_with_seeds,
    bench_trust_engine_large,
    bench_chain_integrity_with_checkpoint,
);
criterion_main!(benches);
