mod helpers;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use std::time::Duration;
use trustchain_core::meritrank::MeritRankTrust;

// ---------------------------------------------------------------------------
// MeritRank: single seed trust query — star topology
// ---------------------------------------------------------------------------
fn bench_meritrank_single(c: &mut Criterion) {
    let mut group = c.benchmark_group("meritrank_single");
    group.measurement_time(Duration::from_secs(10));

    for &n_agents in &[50, 200, 500] {
        let (store, seed_pk, spoke_pks) = helpers::build_star_network(n_agents, 3);
        let target = &spoke_pks[spoke_pks.len() / 2];

        group.bench_with_input(BenchmarkId::new("star", n_agents), &n_agents, |b, _| {
            b.iter(|| {
                let mr = MeritRankTrust::new(&store, vec![seed_pk.clone()], Some(1000)).unwrap();
                mr.compute_seed_trust(target).unwrap()
            });
        });
    }
    group.finish();
}

// ---------------------------------------------------------------------------
// MeritRank: varying walk counts
// ---------------------------------------------------------------------------
fn bench_meritrank_walk_counts(c: &mut Criterion) {
    let mut group = c.benchmark_group("meritrank_walk_counts");
    group.measurement_time(Duration::from_secs(10));

    let (store, seed_pk, spoke_pks) = helpers::build_star_network(100, 3);
    let target = &spoke_pks[spoke_pks.len() / 2];

    for &num_walks in &[100, 1_000, 5_000, 10_000] {
        group.bench_with_input(BenchmarkId::new("walks", num_walks), &num_walks, |b, _| {
            b.iter(|| {
                let mr =
                    MeritRankTrust::new(&store, vec![seed_pk.clone()], Some(num_walks)).unwrap();
                mr.compute_seed_trust(target).unwrap()
            });
        });
    }
    group.finish();
}

// ---------------------------------------------------------------------------
// MeritRank: mesh topology
// ---------------------------------------------------------------------------
fn bench_meritrank_mesh(c: &mut Criterion) {
    let mut group = c.benchmark_group("meritrank_mesh");
    group.measurement_time(Duration::from_secs(10));

    for &(n_agents, degree) in &[(50, 5), (200, 4)] {
        let (store, pubkeys) = helpers::build_mesh_network(n_agents, degree, 3);
        let seed_pk = pubkeys[0].clone();
        let target = &pubkeys[pubkeys.len() / 2];

        group.bench_with_input(
            BenchmarkId::new(format!("mesh_d{degree}"), n_agents),
            &n_agents,
            |b, _| {
                b.iter(|| {
                    let mr =
                        MeritRankTrust::new(&store, vec![seed_pk.clone()], Some(1000)).unwrap();
                    mr.compute_seed_trust(target).unwrap()
                });
            },
        );
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_meritrank_single,
    bench_meritrank_walk_counts,
    bench_meritrank_mesh,
);
criterion_main!(benches);
