mod helpers;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use trustchain_core::{Identity, MemoryBlockStore, TrustChainProtocol, TrustEngine};

fn bench_chain_integrity(c: &mut Criterion) {
    let mut group = c.benchmark_group("chain_integrity");

    for &n in &[100, 1_000, 10_000] {
        // Build a chain of n interaction pairs
        let mut store = MemoryBlockStore::new();
        helpers::build_chain(&mut store, n);
        let alice_pk = Identity::from_bytes(&[1u8; 32]).pubkey_hex();

        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, _| {
            b.iter(|| {
                let engine = TrustEngine::new(&store, None, None, None);
                engine.compute_chain_integrity(&alice_pk).unwrap()
            });
        });
    }
    group.finish();
}

fn bench_validate_chain(c: &mut Criterion) {
    let mut group = c.benchmark_group("validate_chain");

    for &n in &[100, 1_000, 10_000] {
        let mut store = MemoryBlockStore::new();
        helpers::build_chain(&mut store, n);
        let alice_id = Identity::from_bytes(&[1u8; 32]);
        let alice_pk = alice_id.pubkey_hex();
        let protocol = TrustChainProtocol::new(alice_id, store);

        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, _| {
            b.iter(|| protocol.validate_chain(&alice_pk).unwrap());
        });
    }
    group.finish();
}

criterion_group!(benches, bench_chain_integrity, bench_validate_chain);
criterion_main!(benches);
