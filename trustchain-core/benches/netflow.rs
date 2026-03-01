mod helpers;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use std::time::Duration;
use trustchain_core::{CachedNetFlow, NetFlowTrust};

// ---------------------------------------------------------------------------
// Uncached: single trust query — star topology
// ---------------------------------------------------------------------------
fn bench_netflow_single(c: &mut Criterion) {
    let mut group = c.benchmark_group("netflow_single");
    group.measurement_time(Duration::from_secs(10));

    for &n_agents in &[50, 500, 2_000, 5_000] {
        let (store, seed_pk, spoke_pks) = helpers::build_star_network(n_agents, 3);
        let netflow = NetFlowTrust::new(&store, vec![seed_pk]).unwrap();
        let target = &spoke_pks[spoke_pks.len() / 2];

        group.bench_with_input(BenchmarkId::new("star", n_agents), &n_agents, |b, _| {
            b.iter(|| netflow.compute_trust(target).unwrap());
        });
    }
    group.finish();
}

// ---------------------------------------------------------------------------
// Uncached: single trust query — large star (10K+)
// ---------------------------------------------------------------------------
fn bench_netflow_single_large(c: &mut Criterion) {
    let mut group = c.benchmark_group("netflow_single_large");
    group.measurement_time(Duration::from_secs(20));
    group.sample_size(10);

    for &n_agents in &[10_000, 20_000] {
        let (store, seed_pk, spoke_pks) = helpers::build_star_network(n_agents, 2);
        let netflow = NetFlowTrust::new(&store, vec![seed_pk]).unwrap();
        let target = &spoke_pks[spoke_pks.len() / 2];

        group.bench_with_input(BenchmarkId::new("star", n_agents), &n_agents, |b, _| {
            b.iter(|| netflow.compute_trust(target).unwrap());
        });
    }
    group.finish();
}

// ---------------------------------------------------------------------------
// Uncached: compute_all_scores — star
// ---------------------------------------------------------------------------
fn bench_netflow_all_scores(c: &mut Criterion) {
    let mut group = c.benchmark_group("netflow_all_scores");
    group.measurement_time(Duration::from_secs(15));

    for &n_agents in &[50, 200, 1_000] {
        let (store, seed_pk, _) = helpers::build_star_network(n_agents, 3);
        let netflow = NetFlowTrust::new(&store, vec![seed_pk]).unwrap();

        group.bench_with_input(BenchmarkId::new("star", n_agents), &n_agents, |b, _| {
            b.iter(|| netflow.compute_all_scores().unwrap());
        });
    }
    group.finish();
}

// ---------------------------------------------------------------------------
// Uncached: mesh topology (denser graph, harder for max-flow)
// ---------------------------------------------------------------------------
fn bench_netflow_mesh(c: &mut Criterion) {
    let mut group = c.benchmark_group("netflow_mesh");
    group.measurement_time(Duration::from_secs(10));

    for &(n_agents, degree) in &[(50, 5), (200, 4), (500, 3)] {
        let (store, pubkeys) = helpers::build_mesh_network(n_agents, degree, 3);
        let seed_pk = pubkeys[0].clone();
        let netflow = NetFlowTrust::new(&store, vec![seed_pk]).unwrap();
        let target = &pubkeys[pubkeys.len() / 2];

        group.bench_with_input(
            BenchmarkId::new(format!("mesh_d{degree}"), n_agents),
            &n_agents,
            |b, _| {
                b.iter(|| netflow.compute_trust(target).unwrap());
            },
        );
    }
    group.finish();
}

// ---------------------------------------------------------------------------
// Cached: single trust query — star (warm cache, no graph rebuild)
// ---------------------------------------------------------------------------
fn bench_cached_netflow_single(c: &mut Criterion) {
    let mut group = c.benchmark_group("cached_netflow_single");
    group.measurement_time(Duration::from_secs(10));

    for &n_agents in &[50, 500, 2_000, 5_000] {
        let (store, seed_pk, spoke_pks) = helpers::build_star_network(n_agents, 3);
        let mut cached = CachedNetFlow::new(store, vec![seed_pk]).unwrap();
        let target = spoke_pks[spoke_pks.len() / 2].clone();

        // Warm up: build graph once.
        let _ = cached.compute_trust(&target).unwrap();

        group.bench_with_input(BenchmarkId::new("star", n_agents), &n_agents, |b, _| {
            b.iter(|| cached.compute_trust(&target).unwrap());
        });
    }
    group.finish();
}

// ---------------------------------------------------------------------------
// Cached: single trust query — large star (10K+)
// ---------------------------------------------------------------------------
fn bench_cached_netflow_single_large(c: &mut Criterion) {
    let mut group = c.benchmark_group("cached_netflow_single_large");
    group.measurement_time(Duration::from_secs(20));
    group.sample_size(10);

    for &n_agents in &[10_000, 20_000] {
        let (store, seed_pk, spoke_pks) = helpers::build_star_network(n_agents, 2);
        let mut cached = CachedNetFlow::new(store, vec![seed_pk]).unwrap();
        let target = spoke_pks[spoke_pks.len() / 2].clone();
        let _ = cached.compute_trust(&target).unwrap();

        group.bench_with_input(BenchmarkId::new("star", n_agents), &n_agents, |b, _| {
            b.iter(|| cached.compute_trust(&target).unwrap());
        });
    }
    group.finish();
}

// ---------------------------------------------------------------------------
// Cached: compute_all_scores — star (graph reuse across N queries)
// ---------------------------------------------------------------------------
fn bench_cached_netflow_all_scores(c: &mut Criterion) {
    let mut group = c.benchmark_group("cached_netflow_all_scores");
    group.measurement_time(Duration::from_secs(15));

    for &n_agents in &[50, 200, 1_000] {
        let (store, seed_pk, _) = helpers::build_star_network(n_agents, 3);
        let mut cached = CachedNetFlow::new(store, vec![seed_pk]).unwrap();
        let _ = cached.compute_all_scores().unwrap();

        group.bench_with_input(BenchmarkId::new("star", n_agents), &n_agents, |b, _| {
            b.iter(|| cached.compute_all_scores().unwrap());
        });
    }
    group.finish();
}

// ---------------------------------------------------------------------------
// Cached: mesh topology
// ---------------------------------------------------------------------------
fn bench_cached_netflow_mesh(c: &mut Criterion) {
    let mut group = c.benchmark_group("cached_netflow_mesh");
    group.measurement_time(Duration::from_secs(10));

    for &(n_agents, degree) in &[(50, 5), (200, 4), (500, 3)] {
        let (store, pubkeys) = helpers::build_mesh_network(n_agents, degree, 3);
        let seed_pk = pubkeys[0].clone();
        let mut cached = CachedNetFlow::new(store, vec![seed_pk]).unwrap();
        let target = pubkeys[pubkeys.len() / 2].clone();
        let _ = cached.compute_trust(&target).unwrap();

        group.bench_with_input(
            BenchmarkId::new(format!("mesh_d{degree}"), n_agents),
            &n_agents,
            |b, _| {
                b.iter(|| cached.compute_trust(&target).unwrap());
            },
        );
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_netflow_single,
    bench_netflow_single_large,
    bench_netflow_all_scores,
    bench_netflow_mesh,
    bench_cached_netflow_single,
    bench_cached_netflow_single_large,
    bench_cached_netflow_all_scores,
    bench_cached_netflow_mesh,
);
criterion_main!(benches);
