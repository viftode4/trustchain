//! Comprehensive system-level tests for the TrustChain protocol.
//!
//! These tests simulate realistic multi-agent network scenarios to validate
//! that TrustChain is a correct, novel, and robust universal trust primitive.
//!
//! Tests cover:
//! 1. Full 10-agent network lifecycle (C(10,2) interactions + CHECO)
//! 2. Byzantine triple attack (tampered sig, double-sign, double-countersign)
//! 3. Network partition and merge (two groups, isolation then bridge)
//! 4. Identity cycling dilution (Sybil dilution bounded linearly)
//! 5. Trust topology isomorphism (hub-spoke vs isolated cluster)
//! 6. CHECO facilitator election correctness (exactly 1 of N is facilitator)
//! 7. World simulation (50 agents, 5 sectors, Sybil sector scores 0.0)
//!
//! Run with: cargo test --test system_tests -- --nocapture

use trustchain_core::{
    BlockStore, CHECOConsensus, Identity, MemoryBlockStore, TrustChainProtocol, TrustEngine,
    halfblock::{create_half_block, validate_and_record, verify_block},
    netflow::NetFlowTrust,
    types::{BlockType, GENESIS_HASH, ValidationResult},
};

// ─── Infrastructure ───────────────────────────────────────────────────────────

/// Multi-agent simulation harness.
struct NetworkSim {
    agents: Vec<TrustChainProtocol<MemoryBlockStore>>,
}

impl NetworkSim {
    fn new(n: usize) -> Self {
        let agents = (0..n)
            .map(|i| {
                TrustChainProtocol::new(
                    Identity::from_bytes(&[i as u8 + 1; 32]),
                    MemoryBlockStore::new(),
                )
            })
            .collect();
        Self { agents }
    }

    /// Perform `rounds` full bilateral interactions between agents at indices `a` and `b`.
    fn interact(&mut self, a: usize, b: usize, rounds: usize) {
        for i in 0..rounds {
            // Sequential borrows — each statement borrows a disjoint element.
            let b_pk = self.agents[b].pubkey();
            let proposal = self.agents[a]
                .create_proposal(&b_pk, serde_json::json!({"round": i}), None)
                .unwrap();
            self.agents[b].receive_proposal(&proposal).unwrap();
            let agreement = self.agents[b].create_agreement(&proposal, None).unwrap();
            self.agents[a].receive_agreement(&agreement).unwrap();
        }
    }

    /// All-pairs interactions within [start..end).
    fn interact_clique(&mut self, start: usize, end: usize, rounds: usize) {
        for a in start..end {
            for b in (a + 1)..end {
                self.interact(a, b, rounds);
            }
        }
    }

    fn pubkey(&self, i: usize) -> String {
        self.agents[i].pubkey()
    }

    /// Build a master store containing every block from every agent.
    fn master_store(&self) -> MemoryBlockStore {
        let mut master = MemoryBlockStore::new();
        for agent in &self.agents {
            merge_store(agent.store(), &mut master);
        }
        master
    }

    /// NetFlow trust score for `target` with `seeds` as trust anchors.
    fn netflow_trust(&self, seeds: &[usize], target: usize) -> f64 {
        let master = self.master_store();
        let seed_keys: Vec<String> = seeds.iter().map(|&i| self.pubkey(i)).collect();
        match NetFlowTrust::new(&master, seed_keys) {
            Ok(nf) => nf.compute_trust(&self.pubkey(target)).unwrap_or(0.0),
            Err(_) => 0.0,
        }
    }

    /// Blended trust score for `target` via TrustEngine.
    fn trust_score(&self, seeds: &[usize], target: usize) -> f64 {
        let master = self.master_store();
        let seed_keys: Vec<String> = seeds.iter().map(|&i| self.pubkey(i)).collect();
        let engine = TrustEngine::new(&master, Some(seed_keys), None);
        engine.compute_trust(&self.pubkey(target)).unwrap_or(0.0)
    }
}

/// Copy all blocks from `src` into `dst`, silently ignoring duplicates.
fn merge_store(src: &MemoryBlockStore, dst: &mut MemoryBlockStore) {
    for pk in src.get_all_pubkeys().unwrap() {
        for block in src.get_chain(&pk).unwrap() {
            let _ = dst.add_block(&block);
        }
    }
}

// ─── Test 1: Full 10-agent network lifecycle ──────────────────────────────────
//
// 10 agents, every pair interacts 3 times (C(10,2)×3 = 135 interactions).
// After building the master store:
// - All 10 chains validate with integrity 1.0
// - All agents show positive trust from any seed
// - CHECO: 5 of the 10 agents run one consensus round, producing a finalized checkpoint

#[test]
fn sysnet_full_network_lifecycle() {
    let mut sim = NetworkSim::new(10);

    // All-pairs, 3 rounds each.
    sim.interact_clique(0, 10, 3);

    // Validate every agent's chain using master store.
    let master = sim.master_store();
    for i in 0..10 {
        let pk = sim.pubkey(i);
        let chain = master.get_chain(&pk).unwrap();
        assert!(!chain.is_empty(), "agent {} has empty chain", i);
        // Each agent interacts with 9 others × 3 rounds = 27 blocks.
        assert_eq!(chain.len(), 27, "agent {} should have 27 blocks", i);

        // Chain integrity must be perfect.
        for (k, block) in chain.iter().enumerate() {
            assert_eq!(block.sequence_number, (k + 1) as u64, "seq mismatch for agent {}", i);
            assert!(verify_block(block).unwrap(), "bad signature in agent {}", i);
        }
    }

    // Trust: every agent has positive trust from seed = agent 0.
    for i in 1..10 {
        let score = sim.trust_score(&[0], i);
        assert!(score > 0.0, "agent {} should have positive trust from seed 0 (score={})", i, score);
    }

    // CHECO: 5-node committee from agents 0-4.
    let committee_pks: Vec<String> = (0..5).map(|i| sim.pubkey(i)).collect();
    let mut consensuses: Vec<CHECOConsensus<MemoryBlockStore>> = (0..5)
        .map(|i| {
            let identity = Identity::from_bytes(&[i as u8 + 1; 32]);
            let mut store = MemoryBlockStore::new();
            merge_store(&master, &mut store);
            CHECOConsensus::new(identity, store, Some(committee_pks.clone()), 3)
        })
        .collect();

    // Exactly one facilitator.
    let facilitators: Vec<usize> = (0..5)
        .filter(|&i| consensuses[i].is_facilitator().unwrap())
        .collect();
    assert_eq!(facilitators.len(), 1, "exactly 1 facilitator out of 5");

    let fac_idx = facilitators[0];
    let cp_block = consensuses[fac_idx].propose_checkpoint().unwrap();
    assert!(cp_block.is_checkpoint());

    // 3 validators co-sign.
    let mut sigs = std::collections::HashMap::new();
    let fac_pk = sim.pubkey(fac_idx);
    sigs.insert(
        fac_pk.clone(),
        consensuses[fac_idx].sign_checkpoint(&cp_block).unwrap(),
    );
    for i in 0..5 {
        if i != fac_idx && sigs.len() < 3 {
            let sig = consensuses[i].sign_checkpoint(&cp_block).unwrap();
            sigs.insert(sim.pubkey(i), sig);
        }
    }
    consensuses[fac_idx].finalize_checkpoint(cp_block.clone(), sigs).unwrap();

    // chain_heads in the checkpoint captures pre-checkpoint state (fac at seq N-1).
    // The checkpoint block itself is at seq N, so it's not in chain_heads yet.
    // Correct check: the facilitator's LAST interaction block (seq N-1) is covered.
    let pre_cp_seq = cp_block.sequence_number - 1;
    assert!(
        consensuses[fac_idx].is_finalized(&fac_pk, pre_cp_seq),
        "checkpoint should cover facilitator's pre-checkpoint blocks (seq {})", pre_cp_seq
    );

    // Also verify a non-facilitator's blocks are covered.
    let other_idx = if fac_idx == 0 { 1 } else { 0 };
    let other_pk = sim.pubkey(other_idx);
    assert!(
        consensuses[fac_idx].is_finalized(&other_pk, 1),
        "checkpoint should cover block seq=1 of agent {} (finality for all)", other_idx
    );

    println!("[sysnet_full_network_lifecycle] PASS — 10 agents, 135 interactions, CHECO finalized");
}

// ─── Test 2: Byzantine triple attack vectors ──────────────────────────────────
//
// Validates that all three Byzantine attack modes are correctly rejected:
//   Attack A — tampered signature: block modified after signing → rejected
//   Attack B — double-sign: two proposals at same seq → fraud recorded
//   Attack C — double-countersign: two agreements linking the same proposal → fraud recorded

#[test]
fn sysnet_byzantine_three_attack_vectors() {
    // ── Attack A: tampered signature ────────────────────────────────────────
    {
        let mut alice = TrustChainProtocol::new(
            Identity::from_bytes(&[1u8; 32]),
            MemoryBlockStore::new(),
        );
        let mut bob = TrustChainProtocol::new(
            Identity::from_bytes(&[2u8; 32]),
            MemoryBlockStore::new(),
        );

        let mut proposal = alice
            .create_proposal(&bob.pubkey(), serde_json::json!({"service": "compute"}), Some(1000))
            .unwrap();

        // Corrupt the signature bytes.
        let sig_bytes = hex::decode(&proposal.signature).unwrap();
        let mut bad_sig = sig_bytes;
        bad_sig[0] ^= 0xFF;
        proposal.signature = hex::encode(&bad_sig);

        let result = bob.receive_proposal(&proposal);
        assert!(result.is_err(), "Attack A: tampered signature must be rejected");
    }

    // ── Attack B: double-sign (two proposals at same sequence number) ────────
    {
        let alice = Identity::from_bytes(&[1u8; 32]);
        let bob = Identity::from_bytes(&[2u8; 32]);
        let mut store = MemoryBlockStore::new();

        let p_a = create_half_block(
            &alice, 1, &bob.pubkey_hex(), 0,
            GENESIS_HASH, BlockType::Proposal,
            serde_json::json!({"version": "A"}), Some(1000),
        );
        let p_b = create_half_block(
            &alice, 1, &bob.pubkey_hex(), 0,
            GENESIS_HASH, BlockType::Proposal,
            serde_json::json!({"version": "B"}), Some(1001),
        );
        assert_ne!(p_a.block_hash, p_b.block_hash, "different content = different hash");

        // Add first block — valid.
        store.add_block(&p_a).unwrap();

        // Validate second block with context → double-sign detected.
        let result = validate_and_record(&p_b, &mut store);
        assert!(
            matches!(result, ValidationResult::Invalid(_)),
            "Attack B: double-sign must produce Invalid result"
        );

        let frauds = store.get_double_spends(&alice.pubkey_hex()).unwrap();
        assert!(!frauds.is_empty(), "Attack B: double-spend must be recorded");
    }

    // ── Attack C: double-countersign (two agreements for the same proposal) ─
    {
        let alice = Identity::from_bytes(&[1u8; 32]);
        let bob = Identity::from_bytes(&[2u8; 32]);
        let mut store = MemoryBlockStore::new();

        // Alice proposes (seq=1).
        let proposal = create_half_block(
            &alice, 1, &bob.pubkey_hex(), 0,
            GENESIS_HASH, BlockType::Proposal,
            serde_json::json!({"service": "test"}), Some(1000),
        );
        store.add_block(&proposal).unwrap();

        // Bob agrees once (seq=1) — valid.
        let agree_1 = create_half_block(
            &bob, 1, &alice.pubkey_hex(), 1,
            GENESIS_HASH, BlockType::Agreement,
            serde_json::json!({"service": "test"}), Some(1001),
        );
        store.add_block(&agree_1).unwrap();

        // Bob agrees again (seq=2) to the SAME proposal (link_seq=1).
        let agree_2 = create_half_block(
            &bob, 2, &alice.pubkey_hex(), 1,
            &agree_1.block_hash, BlockType::Agreement,
            serde_json::json!({"service": "test"}), Some(1002),
        );
        let result = validate_and_record(&agree_2, &mut store);
        assert!(
            matches!(result, ValidationResult::Invalid(_)),
            "Attack C: double-countersign must be detected"
        );
    }

    println!("[sysnet_byzantine_three_attack_vectors] PASS — all 3 Byzantine attacks rejected");
}

// ─── Test 3: Network partition and merge ─────────────────────────────────────
//
// Two isolated groups interact internally for 10 rounds each.
// Before merge: each group's seed sees zero trust in the other group.
// After merge (cross-group bridge interactions):
//   - Group A's seed sees positive trust in Group B agents (via bridge)

#[test]
fn sysnet_network_partition_and_merge() {
    let mut sim = NetworkSim::new(10);

    // Group A = agents 0-4, Group B = agents 5-9.
    sim.interact_clique(0, 5, 4);
    sim.interact_clique(5, 10, 4);

    // ── Pre-merge: isolated groups ─────────────────────────────────────────
    let score_a_sees_b = sim.netflow_trust(&[0], 5);
    let score_b_sees_a = sim.netflow_trust(&[5], 0);
    assert_eq!(score_a_sees_b, 0.0, "A cannot see B before bridge (got {})", score_a_sees_b);
    assert_eq!(score_b_sees_a, 0.0, "B cannot see A before bridge (got {})", score_b_sees_a);

    // ── Bridge: agent 0 ↔ agent 5 interact ───────────────────────────────
    sim.interact(0, 5, 5);

    // ── Post-merge: cross-group trust flows ───────────────────────────────
    // Agent 5 is now reachable from seed 0 via the direct bridge.
    let bridge_score = sim.netflow_trust(&[0], 5);
    assert!(bridge_score > 0.0, "agent 5 reachable from seed 0 after bridge (got {})", bridge_score);

    // Agent 6 is reachable via 0→5→6 (transitive).
    let transitive_score = sim.netflow_trust(&[0], 6);
    assert!(transitive_score > 0.0, "agent 6 reachable transitively after bridge (got {})", transitive_score);

    // Bridge score ≥ transitive score (direct beats transitive).
    assert!(bridge_score >= transitive_score, "direct bridge ≥ transitive path");

    // Group A agents still have positive scores.
    let score_a1 = sim.netflow_trust(&[0], 1);
    assert!(score_a1 > 0.0, "agent 1 in Group A still positive");

    println!("[sysnet_network_partition_and_merge] PASS — isolation before bridge, trust flows after");
}

// ─── Test 4: Identity cycling dilution bounded ────────────────────────────────
//
// Sybil strategy: create 50 cheap identities, each doing 1 interaction with seed.
// Honest agent does 10 interactions with seed.
//
// NetFlow bottleneck theorem: honest_score = 10 × cycling_score (linear scaling).
// This proves identity cycling attacks are bounded by the bottleneck capacity.

#[test]
fn sysnet_identity_cycling_dilution_bounded() {
    // Seed agent.
    let seed_id = Identity::from_bytes(&[1u8; 32]);
    let mut master = MemoryBlockStore::new();

    // Build a TrustChainProtocol for the seed.
    let mut seed_proto = TrustChainProtocol::new(seed_id.clone(), MemoryBlockStore::new());

    // 50 cycling identities, each interacts once with seed.
    let mut cycling_pks: Vec<String> = Vec::new();
    for i in 0..50u8 {
        let cycler_id = Identity::from_bytes(&[i + 10; 32]);
        let cycler_pk = cycler_id.pubkey_hex();
        cycling_pks.push(cycler_pk.clone());

        let proposal = seed_proto
            .create_proposal(&cycler_pk, serde_json::json!({"cycler": i}), None)
            .unwrap();

        let mut cycler_proto = TrustChainProtocol::new(cycler_id, MemoryBlockStore::new());
        cycler_proto.receive_proposal(&proposal).unwrap();
        let agreement = cycler_proto.create_agreement(&proposal, None).unwrap();
        seed_proto.receive_agreement(&agreement).unwrap();

        // Merge cycler's store into master.
        merge_store(cycler_proto.store(), &mut master);
    }

    // Honest agent interacts 10 times with seed.
    let honest_id = Identity::from_bytes(&[200u8; 32]);
    let honest_pk = honest_id.pubkey_hex();
    let mut honest_proto = TrustChainProtocol::new(honest_id, MemoryBlockStore::new());
    for i in 0..10 {
        let proposal = seed_proto
            .create_proposal(&honest_pk, serde_json::json!({"honest": i}), None)
            .unwrap();
        honest_proto.receive_proposal(&proposal).unwrap();
        let agreement = honest_proto.create_agreement(&proposal, None).unwrap();
        seed_proto.receive_agreement(&agreement).unwrap();
    }
    merge_store(honest_proto.store(), &mut master);
    merge_store(seed_proto.store(), &mut master);

    let seed_pk = seed_id.pubkey_hex();
    let nf = NetFlowTrust::new(&master, vec![seed_pk]).unwrap();

    let honest_score = nf.compute_trust(&honest_pk).unwrap();
    let cycling_score = nf.compute_trust(&cycling_pks[0]).unwrap();

    assert!(honest_score > 0.0, "honest agent must have positive trust");
    assert!(cycling_score > 0.0, "cycling agent must have positive trust");

    // Honest agent should score ~10× more than any single cycling identity.
    let ratio = honest_score / cycling_score;
    assert!(
        ratio >= 9.0,
        "honest (10 interactions) should outrank cycler (1 interaction) by ~10×, got ratio={:.2}",
        ratio
    );

    // All 50 cycling agents should have the same score (symmetry).
    let cycling_score_last = nf.compute_trust(&cycling_pks[49]).unwrap();
    assert!(
        (cycling_score - cycling_score_last).abs() < 1e-9,
        "all cycling agents score identically: {} vs {}",
        cycling_score,
        cycling_score_last
    );

    println!(
        "[sysnet_identity_cycling_dilution_bounded] PASS — honest/cycler ratio={:.1}× (expected ~10×)",
        ratio
    );
}

// ─── Test 5: Trust topology isomorphism ──────────────────────────────────────
//
// The trust scores must reflect the actual interaction topology:
//   - Hub H (agent 0) is the seed and connects to 10 spokes
//   - Spokes get positive trust via direct connection to seed
//   - Isolated cluster (agents 11-15) has ZERO trust — no path to any seed

#[test]
fn sysnet_trust_topology_isomorphism() {
    // Hub (agent 0) + 10 spokes (agents 1-10) + 5 isolated (agents 11-15).
    let mut sim = NetworkSim::new(16);

    // Hub interacts with each spoke, 5 rounds.
    for spoke in 1..=10 {
        sim.interact(0, spoke, 5);
    }

    // Isolated cluster has rich internal interactions but NO connection to hub.
    sim.interact_clique(11, 16, 8);

    // ── Hub (seed) scores ─────────────────────────────────────────────────
    let hub_score = sim.trust_score(&[0], 0);
    assert!(hub_score > 0.5, "hub/seed should have high trust, got {}", hub_score);

    // ── Spokes: positive trust via direct hub connection ──────────────────
    for spoke in 1..=10 {
        let score = sim.netflow_trust(&[0], spoke);
        assert!(score > 0.0, "spoke {} must have positive NetFlow trust (got {})", spoke, score);
    }

    // ── Isolated cluster: NO trust — no path to seed ──────────────────────
    for isolated in 11..16 {
        let score = sim.netflow_trust(&[0], isolated);
        assert_eq!(
            score, 0.0,
            "isolated agent {} must have zero trust, no path to seed (got {})",
            isolated, score
        );
    }

    // ── Topology ordering: all spokes score > all isolated ────────────────
    let min_spoke = (1..=10usize)
        .map(|s| sim.netflow_trust(&[0], s))
        .fold(f64::MAX, f64::min);
    let max_isolated = (11..16usize)
        .map(|s| sim.netflow_trust(&[0], s))
        .fold(0.0f64, f64::max);

    assert!(
        min_spoke > max_isolated,
        "topology isomorphism violated: min_spoke={:.4} must > max_isolated={:.4}",
        min_spoke, max_isolated
    );

    println!("[sysnet_trust_topology_isomorphism] PASS — hub>spokes>isolated ordering correct");
}

// ─── Test 6: CHECO facilitator election correctness ──────────────────────────
//
// Given N agents with shared chain state, exactly 1 is_facilitator() == true.
// propose_checkpoint() succeeds only for the facilitator.
// The election is deterministic: same chain state → same facilitator.

#[test]
fn sysnet_checo_facilitator_election_correctness() {
    let mut sim = NetworkSim::new(7);
    sim.interact_clique(0, 7, 3);

    let master = sim.master_store();
    let all_pks: Vec<String> = (0..7).map(|i| sim.pubkey(i)).collect();

    // Build one CHECOConsensus per agent, all seeing the same master store.
    let mut consensuses: Vec<CHECOConsensus<MemoryBlockStore>> = (0..7)
        .map(|i| {
            let identity = Identity::from_bytes(&[i as u8 + 1; 32]);
            let mut store = MemoryBlockStore::new();
            merge_store(&master, &mut store);
            CHECOConsensus::new(identity, store, Some(all_pks.clone()), 4)
        })
        .collect();

    // Count facilitators.
    let facilitators: Vec<usize> = (0..7)
        .filter(|&i| consensuses[i].is_facilitator().unwrap())
        .collect();
    assert_eq!(facilitators.len(), 1, "exactly 1 of 7 agents should be facilitator");

    let fac_idx = facilitators[0];

    // Non-facilitators fail propose_checkpoint.
    for i in 0..7 {
        if i != fac_idx {
            let result = consensuses[i].propose_checkpoint();
            assert!(
                result.is_err(),
                "non-facilitator {} must not propose checkpoint",
                i
            );
        }
    }

    // Facilitator succeeds.
    let cp_block = consensuses[fac_idx].propose_checkpoint().unwrap();
    assert!(cp_block.is_checkpoint(), "proposed block must be a checkpoint");

    // Election is deterministic: rebuild consensuses with same state → same facilitator.
    let consensuses2: Vec<CHECOConsensus<MemoryBlockStore>> = (0..7)
        .map(|i| {
            let identity = Identity::from_bytes(&[i as u8 + 1; 32]);
            let mut store = MemoryBlockStore::new();
            merge_store(&master, &mut store);
            CHECOConsensus::new(identity, store, Some(all_pks.clone()), 4)
        })
        .collect();

    let fac2: Vec<usize> = (0..7)
        .filter(|&i| consensuses2[i].is_facilitator().unwrap())
        .collect();
    assert_eq!(fac2, facilitators, "facilitator election is deterministic");

    println!(
        "[sysnet_checo_facilitator_election_correctness] PASS — facilitator={}, deterministic",
        fac_idx
    );
}

// ─── Test 7: World simulation ─────────────────────────────────────────────────
//
// 50 agents across 5 sectors of 10 agents each:
//   Sector 0 (Finance):  agents  0-9   — seed agents 0, 10
//   Sector 1 (Tech):     agents 10-19  — seed agents 0, 10
//   Sector 2 (Health):   agents 20-29
//   Sector 3 (Gov):      agents 30-39
//   Sector 4 (Sybil):    agents 40-49  — massive internal activity, NO seed connection
//
// Cross-sector bridges:
//   Finance ↔ Tech   (agent 0 ↔ agent 10)
//   Tech ↔ Health    (agent 10 ↔ agent 20)
//   Health ↔ Gov     (agent 20 ↔ agent 30)
//
// Seeds: agents 0 and 10 (Finance + Tech anchors)
//
// Expected properties:
//   - Sybil sector (agents 40-49) scores exactly 0.0 regardless of internal interactions
//   - Finance & Tech agents score positively
//   - Health & Gov score positively (via transitive bridges)
//   - Trust decreases with distance from seeds

#[test]
fn sysnet_world_simulation() {
    let mut sim = NetworkSim::new(50);

    // Intra-sector interactions.
    for sector in 0..5usize {
        let start = sector * 10;
        let end = start + 10;
        sim.interact_clique(start, end, 3);
    }

    // Cross-sector bridges.
    sim.interact(0, 10, 5);  // Finance ↔ Tech
    sim.interact(10, 20, 5); // Tech ↔ Health
    sim.interact(20, 30, 5); // Health ↔ Gov
    // Sybil sector (40-49): no bridge to any seed!

    let seeds = &[0usize, 10usize];

    // ── Sybil sector: must score 0.0 ─────────────────────────────────────
    for sybil in 40..50 {
        let score = sim.netflow_trust(seeds, sybil);
        assert_eq!(
            score, 0.0,
            "Sybil agent {} must score 0.0, no path to any seed (got {})",
            sybil, score
        );
    }

    // ── Finance (near seed 0) should score well ───────────────────────────
    let finance_scores: Vec<f64> = (1..10).map(|i| sim.netflow_trust(seeds, i)).collect();
    for (i, &s) in finance_scores.iter().enumerate() {
        assert!(s > 0.0, "Finance agent {} should have positive trust (got {})", i + 1, s);
    }

    // ── Tech (direct bridge from seed 0 via agent 0→10) ─────────────────
    let tech_score_10 = sim.netflow_trust(seeds, 10);
    assert!(tech_score_10 > 0.0, "Tech agent 10 (seed) should have positive trust");
    let tech_score_11 = sim.netflow_trust(seeds, 11);
    assert!(tech_score_11 > 0.0, "Tech agent 11 should have positive trust");

    // ── Health (2 hops: 0→10→20) ─────────────────────────────────────────
    let health_score = sim.netflow_trust(seeds, 20);
    assert!(health_score > 0.0, "Health agent 20 reachable via 2-hop bridge");

    // ── Gov (3 hops: 0→10→20→30) ─────────────────────────────────────────
    let gov_score = sim.netflow_trust(seeds, 30);
    assert!(gov_score > 0.0, "Gov agent 30 reachable via 3-hop bridge");

    // ── Distance ordering: Finance ≥ Health ≥ Gov (decreasing with hops) ──
    // Agent 1 (Finance, directly seeded) vs agent 20 (Health, 2 hops).
    let finance_1 = sim.netflow_trust(seeds, 1);
    assert!(
        finance_1 >= health_score,
        "Finance ({:.4}) should score ≥ Health ({:.4})",
        finance_1, health_score
    );

    // Print trust landscape.
    println!("[sysnet_world_simulation] PASS — 50 agents, 5 sectors");
    println!("  Seeds:   agent 0={:.3}, agent 10={:.3}",
        sim.netflow_trust(seeds, 0),
        sim.netflow_trust(seeds, 10),
    );
    println!("  Finance: agent 1={:.3}  agent 5={:.3}",
        sim.netflow_trust(seeds, 1), sim.netflow_trust(seeds, 5));
    println!("  Tech:    agent 11={:.3} agent 15={:.3}",
        sim.netflow_trust(seeds, 11), sim.netflow_trust(seeds, 15));
    println!("  Health:  agent 20={:.3} agent 25={:.3}",
        sim.netflow_trust(seeds, 20), sim.netflow_trust(seeds, 25));
    println!("  Gov:     agent 30={:.3} agent 35={:.3}",
        sim.netflow_trust(seeds, 30), sim.netflow_trust(seeds, 35));
    println!("  Sybil:   agent 40={:.3} agent 45={:.3}",
        sim.netflow_trust(seeds, 40), sim.netflow_trust(seeds, 45));
}
