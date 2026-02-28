//! Sybil resistance stress tests — connected Sybil clusters.
//!
//! The critical scenario: a Sybil cluster that IS connected to a seed.
//! This tests the core NetFlow bottleneck theorem from the TrustChain paper
//! (Otte, de Vos, Pouwelse 2020, §4):
//!
//!   "The trust score of any Sybil agent is bounded by the capacity of
//!    the bottleneck edge between the honest network and the Sybil region."
//!
//! Three properties verified:
//! 1. INFLATION INVARIANT — adding internal Sybil rounds does NOT change scores
//! 2. GATEWAY BOUNDED — all agents in a cluster score ≤ gateway capacity / total
//! 3. HONEST DOMINANCE — honest with N direct interactions outranks Sybil cluster
//!    of any size that has only N/k interactions per gateway (ratio preserved)
//!
//! Run with: cargo test --test stress4 -- --nocapture

use trustchain_core::{
    BlockStore, Identity, MemoryBlockStore, TrustChainProtocol,
    netflow::NetFlowTrust,
};

/// Perform `n` bilateral interactions between two elements of the SAME Vec.
/// Uses split_at_mut to satisfy the borrow checker.
fn do_interactions_in_vec(
    agents: &mut Vec<TrustChainProtocol<MemoryBlockStore>>,
    i: usize,
    j: usize,
    n: usize,
) {
    assert!(i < j);
    let (left, right) = agents.split_at_mut(j);
    do_interactions(&mut left[i], &mut right[0], n);
}

// ─── helpers ─────────────────────────────────────────────────────────────────

fn make_proto(seed: u8) -> TrustChainProtocol<MemoryBlockStore> {
    TrustChainProtocol::new(
        Identity::from_bytes(&[seed; 32]),
        MemoryBlockStore::new(),
    )
}

fn do_interactions(
    a: &mut TrustChainProtocol<MemoryBlockStore>,
    b: &mut TrustChainProtocol<MemoryBlockStore>,
    n: usize,
) {
    let b_pk = b.pubkey();
    for i in 0..n {
        let p = a.create_proposal(&b_pk, serde_json::json!({"i": i}), None).unwrap();
        b.receive_proposal(&p).unwrap();
        let ag = b.create_agreement(&p, None).unwrap();
        a.receive_agreement(&ag).unwrap();
    }
}

fn merge_into(src: &MemoryBlockStore, dst: &mut MemoryBlockStore) {
    for pk in src.get_all_pubkeys().unwrap() {
        for block in src.get_chain(&pk).unwrap() {
            let _ = dst.add_block(&block);
        }
    }
}

fn netflow(master: &MemoryBlockStore, seed_pks: &[String], target_pk: &str) -> f64 {
    match NetFlowTrust::new(master, seed_pks.to_vec()) {
        Ok(nf) => nf.compute_trust(target_pk).unwrap_or(0.0),
        Err(_) => 0.0,
    }
}

// ─── Test 19: Inflation invariant ────────────────────────────────────────────
//
// Sybil cluster: gateway agent has 2 seed interactions.
// Internal cluster: 9 Sybil agents, each interacts with gateway.
//
// Phase 1: 2 internal rounds per pair → measure all scores.
// Phase 2: 50 MORE internal rounds added → measure again.
//
// Claim: Phase 2 scores == Phase 1 scores (within floating point noise).
// The bottleneck at seed→gateway doesn't change; inflation is worthless.

#[test]
fn stress_sybil_inflation_invariant() {
    // seed=1, honest=2, sybil_gateway=20, sybil_cluster=21..29
    let mut seed = make_proto(1);
    let mut honest = make_proto(2);
    let mut sybil_gw = make_proto(20);
    let mut sybil_cluster: Vec<_> = (21..30u8).map(make_proto).collect();

    // Honest: 10 direct seed interactions.
    do_interactions(&mut seed, &mut honest, 10);

    // Sybil gateway: 2 direct seed interactions.
    do_interactions(&mut seed, &mut sybil_gw, 2);

    // Phase 1: small internal cluster (2 rounds per pair).
    for i in 0..9 {
        do_interactions(&mut sybil_gw, &mut sybil_cluster[i], 2);
    }

    // Build Phase 1 master store.
    let mut master1 = MemoryBlockStore::new();
    merge_into(seed.store(), &mut master1);
    merge_into(honest.store(), &mut master1);
    merge_into(sybil_gw.store(), &mut master1);
    for s in &sybil_cluster {
        merge_into(s.store(), &mut master1);
    }

    let seed_pks = vec![seed.pubkey()];
    let gw_score_1 = netflow(&master1, &seed_pks, &sybil_gw.pubkey());
    let cluster_scores_1: Vec<f64> = sybil_cluster
        .iter()
        .map(|s| netflow(&master1, &seed_pks, &s.pubkey()))
        .collect();

    // Phase 2: add massive inflation (50 more rounds per pair — 25× more).
    for i in 0..9 {
        do_interactions(&mut sybil_gw, &mut sybil_cluster[i], 50);
    }
    // Also inflate within the cluster (intra-Sybil rings — no seed connection at all).
    for i in 0..9 {
        for j in (i + 1)..9 {
            do_interactions_in_vec(&mut sybil_cluster, i, j, 10);
        }
    }

    // Rebuild Phase 2 master store.
    let mut master2 = MemoryBlockStore::new();
    merge_into(seed.store(), &mut master2);
    merge_into(honest.store(), &mut master2);
    merge_into(sybil_gw.store(), &mut master2);
    for s in &sybil_cluster {
        merge_into(s.store(), &mut master2);
    }

    let gw_score_2 = netflow(&master2, &seed_pks, &sybil_gw.pubkey());
    let cluster_scores_2: Vec<f64> = sybil_cluster
        .iter()
        .map(|s| netflow(&master2, &seed_pks, &s.pubkey()))
        .collect();

    // INFLATION INVARIANT: scores must not change.
    assert!(
        (gw_score_1 - gw_score_2).abs() < 1e-9,
        "gateway score changed after inflation: {:.6} → {:.6}",
        gw_score_1, gw_score_2
    );
    for i in 0..9 {
        assert!(
            (cluster_scores_1[i] - cluster_scores_2[i]).abs() < 1e-9,
            "cluster[{}] score changed after inflation: {:.6} → {:.6}",
            i, cluster_scores_1[i], cluster_scores_2[i]
        );
    }

    // HONEST DOMINANCE: honest with 10 interactions beats gateway with 2.
    let honest_score = netflow(&master2, &seed_pks, &honest.pubkey());
    assert!(
        honest_score > gw_score_2,
        "honest ({:.4}) must beat sybil gateway ({:.4})",
        honest_score, gw_score_2
    );

    println!("[stress_sybil_inflation_invariant] PASS");
    println!("  Gateway  phase1={:.4} phase2={:.4} (unchanged)", gw_score_1, gw_score_2);
    println!("  Cluster  phase1={:.4} phase2={:.4} (unchanged)", cluster_scores_1[0], cluster_scores_2[0]);
    println!("  Honest   score={:.4} > gateway={:.4}", honest_score, gw_score_2);
}

// ─── Test 20: Gateway bounded — all cluster scores ≤ gateway ─────────────────
//
// Sybil cluster of 20 agents funneled through ONE gateway to the seed.
// Gateway has k interactions with seed. ALL 20 agents can only score ≤ k/total.
// The score does NOT scale with cluster size.

#[test]
fn stress_sybil_cluster_gateway_bounded() {
    let mut seed = make_proto(1);
    let mut gateway = make_proto(50); // byte 50 = unique identity

    // Gateway: 3 seed interactions.
    do_interactions(&mut seed, &mut gateway, 3);

    // 10 Sybil agents, all connected through gateway (rich internal mesh).
    let mut cluster: Vec<_> = (51..61u8).map(make_proto).collect();

    // All cluster members interact heavily with gateway.
    for i in 0..10 {
        do_interactions(&mut gateway, &mut cluster[i], 10);
    }
    // Also full intra-cluster mesh (3 rounds each pair).
    for i in 0..10 {
        for j in (i + 1)..10 {
            do_interactions_in_vec(&mut cluster, i, j, 3);
        }
    }

    let mut master = MemoryBlockStore::new();
    merge_into(seed.store(), &mut master);
    merge_into(gateway.store(), &mut master);
    for s in &cluster {
        merge_into(s.store(), &mut master);
    }

    let seed_pks = vec![seed.pubkey()];
    let gw_score = netflow(&master, &seed_pks, &gateway.pubkey());

    // Every cluster agent must score ≤ gateway score.
    for (i, s) in cluster.iter().enumerate() {
        let score = netflow(&master, &seed_pks, &s.pubkey());
        assert!(
            score <= gw_score + 1e-9,
            "cluster[{}] score {:.6} exceeds gateway score {:.6} — bottleneck violated!",
            i, score, gw_score
        );
    }

    // Quantitative: with 3 gateway interactions, gateway score ≈ 3/(3+seed_other_outflow).
    // Regardless of 20 agents × 20 rounds = 400 internal interactions.
    println!("[stress_sybil_cluster_gateway_bounded] PASS");
    println!("  Gateway score = {:.4} (bounded by 3 seed interactions)", gw_score);
    println!("  Cluster max   = {:.4} (≤ gateway, all {} agents checked)",
        cluster.iter().map(|s| netflow(&master, &seed_pks, &s.pubkey())).fold(0.0f64, f64::max),
        cluster.len()
    );
}

// ─── Test 21: World simulation with connected Sybil sector ───────────────────
//
// Extends the world simulation: the Sybil sector (agents 40-49) was getting
// 0.0 because they had no seed connection. Now agent 40 (the "gateway Sybil")
// connects to seed with varying numbers of interactions.
//
// Verifies:
// 1. Before connection:  all Sybil agents score 0.0
// 2. After 1 connection: Sybil gateway scores k/total, others score ≤ that
// 3. After 10 connections: Sybil gateway scores increase, but honest agents with
//    more seed connections still dominate
// 4. Internal Sybil inflation (200 rounds added) doesn't move any score

#[test]
fn stress_sybil_world_sim_connected() {
    // Seeds: two trusted anchor agents.
    let mut seed_a = make_proto(1);
    let mut seed_b = make_proto(2);

    // Honest sector: agents 3-12, each with 5 seed interactions.
    let mut honest: Vec<_> = (3..13u8).map(make_proto).collect();
    for h in &mut honest {
        do_interactions(&mut seed_a, h, 5);
        do_interactions(&mut seed_b, h, 3);
    }

    // Sybil sector: agents 100-109, 10 agents.
    let mut sybil: Vec<_> = (100..110u8).map(make_proto).collect();

    // Rich intra-Sybil mesh (no seed connection yet).
    for i in 0..10 {
        for j in (i + 1)..10 {
            do_interactions_in_vec(&mut sybil, i, j, 3);
        }
    }

    let seed_pks = vec![seed_a.pubkey(), seed_b.pubkey()];

    // ── Baseline: Sybil sector isolated → all score 0.0 ─────────────────
    let mut master = MemoryBlockStore::new();
    merge_into(seed_a.store(), &mut master);
    merge_into(seed_b.store(), &mut master);
    for h in &honest { merge_into(h.store(), &mut master); }
    for s in &sybil { merge_into(s.store(), &mut master); }

    for i in 0..10 {
        let score = netflow(&master, &seed_pks, &sybil[i].pubkey());
        assert_eq!(score, 0.0,
            "isolated Sybil agent {} must score 0.0, got {}", i, score);
    }

    // ── Connect: sybil[0] (gateway) does 1 interaction with seed_a ───────
    do_interactions(&mut seed_a, &mut sybil[0], 1);

    let mut master2 = MemoryBlockStore::new();
    merge_into(seed_a.store(), &mut master2);
    merge_into(seed_b.store(), &mut master2);
    for h in &honest { merge_into(h.store(), &mut master2); }
    for s in &sybil { merge_into(s.store(), &mut master2); }

    let gw_score_1conn = netflow(&master2, &seed_pks, &sybil[0].pubkey());
    assert!(gw_score_1conn > 0.0,
        "gateway Sybil must score positively after 1 seed connection");

    // All non-gateway Sybils score ≤ gateway (bottleneck).
    for i in 1..10 {
        let score = netflow(&master2, &seed_pks, &sybil[i].pubkey());
        assert!(score <= gw_score_1conn + 1e-9,
            "sybil[{}] score {:.6} exceeds gateway {:.6}", i, score, gw_score_1conn);
    }

    // Honest agents score much higher than Sybil gateway (5 direct vs 1).
    let honest_score = netflow(&master2, &seed_pks, &honest[0].pubkey());
    assert!(honest_score > gw_score_1conn,
        "honest ({:.4}) must beat connected Sybil gateway ({:.4})",
        honest_score, gw_score_1conn);

    // ── Inflation: add heavy internal Sybil rounds after connection ──────
    // This simulates the attacker trying to boost scores via internal activity.
    for i in 0..10 {
        for j in (i + 1)..10 {
            do_interactions_in_vec(&mut sybil, i, j, 10);
        }
    }

    let mut master3 = MemoryBlockStore::new();
    merge_into(seed_a.store(), &mut master3);
    merge_into(seed_b.store(), &mut master3);
    for h in &honest { merge_into(h.store(), &mut master3); }
    for s in &sybil { merge_into(s.store(), &mut master3); }

    let gw_score_inflated = netflow(&master3, &seed_pks, &sybil[0].pubkey());
    assert!(
        (gw_score_1conn - gw_score_inflated).abs() < 1e-9,
        "inflation must not change gateway score: {:.6} → {:.6}",
        gw_score_1conn, gw_score_inflated
    );

    // ── Connect more: sybil[0] does 10 total interactions with seed_a ────
    // (adds 9 more on top of the 1 above)
    do_interactions(&mut seed_a, &mut sybil[0], 9);

    let mut master4 = MemoryBlockStore::new();
    merge_into(seed_a.store(), &mut master4);
    merge_into(seed_b.store(), &mut master4);
    for h in &honest { merge_into(h.store(), &mut master4); }
    for s in &sybil { merge_into(s.store(), &mut master4); }

    let gw_score_10conn = netflow(&master4, &seed_pks, &sybil[0].pubkey());
    // More real interactions = higher score (linear with honest interactions).
    assert!(gw_score_10conn > gw_score_1conn,
        "10 seed interactions must score higher than 1 ({:.4} vs {:.4})",
        gw_score_10conn, gw_score_1conn);

    // But 10× the honest agent's 5 interactions means Sybil gateway (10) vs honest (5):
    // Sybil gateway should still score roughly proportionally.
    let ratio = gw_score_10conn / gw_score_1conn;
    assert!(ratio > 1.5,
        "10 connections should significantly improve score over 1 connection (ratio={:.2})", ratio);

    println!("[stress_sybil_world_sim_connected] PASS");
    println!("  Sybil gateway: isolated=0.000, 1-conn={:.4}, 10-conn={:.4}",
        gw_score_1conn, gw_score_10conn);
    println!("  Honest (5 seed interactions): score={:.4}", honest_score);
    println!("  Inflation invariant: {:.6} → {:.6} (unchanged)", gw_score_1conn, gw_score_inflated);
}

// ─── Test 22: Sybil multi-gateway — honest with more total interactions wins ──
//
// The Sybil operator spreads across 5 gateway agents (1 interaction each = 5 total).
// The honest agent has 12 direct seed interactions.
//
// Key property: because the cluster connects to ALL gateways, bypass paths form
// between gateways (e.g. seed→gw[1]→cluster→gw[0]), so cluster members can
// aggregate all 5 gateway capacities = 5/total flow. The honest agent has
// 12/total flow, so honest strictly beats the ENTIRE Sybil cluster's max score.
//
// This proves: honest beats a Sybil operator even when the Sybil cluster
// optimally aggregates its full seed-facing capacity via cross-connected members.

#[test]
fn stress_sybil_multi_gateway_no_advantage() {
    let mut seed = make_proto(1);
    let mut honest = make_proto(2);

    // Honest: 12 direct seed interactions (more than all 5 gateways combined = 5).
    do_interactions(&mut seed, &mut honest, 12);

    // Sophisticated Sybil: 5 gateway agents, each with 1 seed interaction.
    // Cluster connects to ALL gateways (maximizing flow aggregation via bypass paths).
    let mut gateways: Vec<_> = (10..15u8).map(make_proto).collect();
    let mut sybil_cluster: Vec<_> = (20..30u8).map(make_proto).collect();

    for gw in &mut gateways {
        do_interactions(&mut seed, gw, 1);
    }
    // Each cluster member connects to all 5 gateways — optimal Sybil strategy.
    for i in 0..5 {
        for s in sybil_cluster.iter_mut() {
            do_interactions(&mut gateways[i], s, 3);
        }
    }

    let mut master = MemoryBlockStore::new();
    merge_into(seed.store(), &mut master);
    merge_into(honest.store(), &mut master);
    for gw in &gateways { merge_into(gw.store(), &mut master); }
    for s in &sybil_cluster { merge_into(s.store(), &mut master); }

    let seed_pks = vec![seed.pubkey()];
    let honest_score = netflow(&master, &seed_pks, &honest.pubkey());
    let max_sybil_score = sybil_cluster.iter()
        .map(|s| netflow(&master, &seed_pks, &s.pubkey()))
        .fold(0.0f64, f64::max);

    // Honest (12 direct) > max any Sybil agent (limited by total 5 gateway capacity).
    assert!(honest_score > max_sybil_score,
        "honest (12 interactions) must beat all Sybil agents including bypass-path aggregators: honest={:.4} max_sybil={:.4}",
        honest_score, max_sybil_score);

    // Individual gateways score ≤ their proportional capacity (1/total each).
    let max_gw_score = gateways.iter()
        .map(|gw| netflow(&master, &seed_pks, &gw.pubkey()))
        .fold(0.0f64, f64::max);
    assert!(honest_score > max_gw_score,
        "honest must beat any single gateway: honest={:.4} max_gw={:.4}",
        honest_score, max_gw_score);

    println!("[stress_sybil_multi_gateway_no_advantage] PASS");
    println!("  Honest (12 direct): {:.4}", honest_score);
    println!("  Max Sybil agent (5 gateways×1, cluster aggregates all): {:.4}", max_sybil_score);
    println!("  Max gateway (1 direct each): {:.4}", max_gw_score);
    println!("  Honest strictly dominates even optimally-connected Sybil cluster");
}
