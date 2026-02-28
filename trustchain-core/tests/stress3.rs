//! Comprehensive protocol stress tests — Part 3.
//!
//! Closes the remaining gaps against the TrustChain paper:
//! - CHECO multi-round with facilitator rotation (state-dependent election)
//! - NetFlow transitive trust (3-hop path from seed, not just 1-hop)
//! - Sybil resistance with exactly 1 seed interaction (bottleneck analysis)
//! - Out-of-order gossip block delivery (agreement before proposal)
//! - Statistical score ceiling (all 5 features saturated → score = 1.0)
//!
//! Run with: cargo test --test stress3 -- --nocapture

use std::collections::HashMap;
use trustchain_core::{
    BlockStore, CHECOConsensus, Identity, MemoryBlockStore, TrustChainProtocol, TrustEngine,
    halfblock::{create_half_block, validate_block},
    netflow::NetFlowTrust,
    types::{BlockType, GENESIS_HASH, ValidationResult},
};

// ─── helpers ─────────────────────────────────────────────────────────────────

fn make_proto(seed: u8) -> TrustChainProtocol<MemoryBlockStore> {
    TrustChainProtocol::new(
        Identity::from_bytes(&[seed; 32]),
        MemoryBlockStore::new(),
    )
}

/// Perform `n` full bilateral interactions (proposal + agreement) between `a` and `b`.
fn do_interactions(
    a: &mut TrustChainProtocol<MemoryBlockStore>,
    b: &mut TrustChainProtocol<MemoryBlockStore>,
    n: usize,
) {
    let b_pk = b.pubkey();
    for i in 0..n {
        let proposal = a
            .create_proposal(&b_pk, serde_json::json!({"i": i}), None)
            .unwrap();
        b.receive_proposal(&proposal).unwrap();
        let agreement = b.create_agreement(&proposal, None).unwrap();
        a.receive_agreement(&agreement).unwrap();
    }
}

/// Copy all blocks from `src` into `dst`, silently ignoring duplicates.
fn merge_into(src: &MemoryBlockStore, dst: &mut MemoryBlockStore) {
    for pk in src.get_all_pubkeys().unwrap() {
        for block in src.get_chain(&pk).unwrap() {
            let _ = dst.add_block(&block);
        }
    }
}

// ─── Test 16: CHECO two consecutive rounds with facilitator rotation ──────────
//
// Verifies that CHECO is not a one-shot protocol:
//   Round 1: facilitator proposes/finalizes checkpoint → block added to their chain (seq+1)
//   Gossip:  checkpoint block propagated to all stores
//   Round 2: chain head state changes → SHA-256 hash changes → facilitator may rotate
//            Second round must also produce a valid finalized checkpoint covering all agents.
//   Key: round 2 checkpoint reflects the round 1 facilitator's updated chain head (seq=2).

#[test]
fn stress_checo_two_rounds_facilitator_rotation() {
    let ids: Vec<Identity> = (1u8..=5).map(|s| Identity::from_bytes(&[s; 32])).collect();
    let pks: Vec<String> = ids.iter().map(|id| id.pubkey_hex()).collect();

    // Ring proposals: each agent → next agent.
    let ring_blocks: Vec<_> = (0..5usize)
        .map(|i| {
            let j = (i + 1) % 5;
            create_half_block(
                &ids[i], 1, &pks[j], 0, GENESIS_HASH,
                BlockType::Proposal, serde_json::json!({"ring": i}), Some(1000 + i as u64),
            )
        })
        .collect();

    // Build 5 engines, each seeing all ring blocks.
    let mut engines: Vec<CHECOConsensus<MemoryBlockStore>> = (0..5usize)
        .map(|i| {
            let mut store = MemoryBlockStore::new();
            for b in &ring_blocks { store.add_block(b).unwrap(); }
            let peers = (0..5).filter(|j| *j != i).map(|j| pks[j].clone()).collect();
            CHECOConsensus::new(ids[i].clone(), store, Some(peers), 3)
        })
        .collect();

    // ── Round 1 ──────────────────────────────────────────────────────────────
    let fac1_pk = engines[0].select_facilitator().unwrap();
    let fac1 = pks.iter().position(|p| *p == fac1_pk).unwrap();
    println!("Round 1 facilitator: agent {fac1} ({}...)", &fac1_pk[..8]);

    let cp1 = engines[fac1].propose_checkpoint().unwrap();

    let mut sigs1: HashMap<String, String> = HashMap::new();
    for (i, engine) in engines.iter().enumerate() {
        if i != fac1 {
            sigs1.insert(pks[i].clone(), engine.sign_checkpoint(&cp1).unwrap());
            if sigs1.len() >= 3 { break; }
        }
    }
    let fin1 = engines[fac1].finalize_checkpoint(cp1.clone(), sigs1).unwrap();
    assert!(fin1.finalized, "round 1 checkpoint must be finalized");
    println!("Round 1: finalized. chain_heads = {:?}", fin1.chain_heads.values().collect::<Vec<_>>());

    // ── Gossip: propagate round-1 checkpoint block to all peers ──────────────
    // In production, gossip delivers this automatically.  Here we do it manually.
    for (i, engine) in engines.iter_mut().enumerate() {
        if i != fac1 {
            // cp1 is the checkpoint block added to fac1's chain.
            let _ = engine.store_mut().add_block(&cp1);
        }
    }

    // All engines now see fac1 at seq=2 (their ring proposal + the checkpoint block).
    // This changes the input to SHA-256 → facilitator may rotate.

    // ── Round 2 ──────────────────────────────────────────────────────────────
    let fac2_pk = engines[0].select_facilitator().unwrap();
    let fac2 = pks.iter().position(|p| *p == fac2_pk).unwrap();
    println!("Round 2 facilitator: agent {fac2} ({}...)", &fac2_pk[..8]);

    let cp2 = engines[fac2].propose_checkpoint().unwrap();
    assert!(cp2.is_checkpoint());

    let mut sigs2: HashMap<String, String> = HashMap::new();
    for (i, engine) in engines.iter().enumerate() {
        if i != fac2 {
            // validate_checkpoint checks for stale — round 2 checkpt claims fac1=seq2,
            // validators see fac1=seq2 (after gossip) → no stale rejection.
            let ok = engine.validate_checkpoint(&cp2).unwrap();
            assert!(ok, "agent {i} must accept round 2 checkpoint");
            sigs2.insert(pks[i].clone(), engine.sign_checkpoint(&cp2).unwrap());
            if sigs2.len() >= 3 { break; }
        }
    }
    let fin2 = engines[fac2].finalize_checkpoint(cp2, sigs2).unwrap();
    assert!(fin2.finalized, "round 2 checkpoint must be finalized");

    // Round 2 checkpoint must reflect fac1's updated state (seq=2 from round 1).
    let fac1_head_in_r2 = fin2.chain_heads.get(&fac1_pk).copied().unwrap_or(0);
    assert!(
        fac1_head_in_r2 >= 2,
        "round 2 checkpoint must see round 1 facilitator at seq≥2 (proposal + checkpoint block)"
    );

    // All 5 agents' seq=1 blocks are still covered (round 2 chain_heads ≥ 1 for all).
    for pk in &pks {
        let head = fin2.chain_heads.get(pk).copied().unwrap_or(0);
        assert!(head >= 1, "agent {}... must appear in round 2 checkpoint", &pk[..8]);
    }

    println!("CHECO two rounds: both finalized, fac1_head_in_r2={fac1_head_in_r2} ✓");
}

// ─── Test 17: NetFlow transitive trust across 3 hops ─────────────────────────
//
// Graph:  seed ↔ alice (5 interactions)
//               alice ↔ bob  (5 interactions)
//                      bob  ↔ carol (5 interactions)
//
// Carol has NO direct seed interaction — she gets trust through a 3-hop path.
// An isolated agent with no interactions scores exactly 0.0.
//
// NetFlow normalization: score = max_flow(super_source → target) / total_seed_outflow.
// With uniform N=5 interactions on each edge, every reachable agent in the chain
// receives max_flow = seed_outflow → score = 1.0.  Isolation → score = 0.0.

#[test]
fn stress_netflow_transitive_3hop() {
    let mut seed_p  = make_proto(1);
    let mut alice_p = make_proto(2);
    let mut bob_p   = make_proto(3);
    let mut carol_p = make_proto(4);

    do_interactions(&mut seed_p,  &mut alice_p, 5);
    do_interactions(&mut alice_p, &mut bob_p,   5);
    do_interactions(&mut bob_p,   &mut carol_p, 5);
    // isolated agent: no interactions with anyone in the chain

    // Build a master store visible to the NetFlow engine.
    let mut master = MemoryBlockStore::new();
    for p in [&seed_p, &alice_p, &bob_p, &carol_p] {
        merge_into(p.store(), &mut master);
    }

    let engine = NetFlowTrust::new(&master, vec![seed_p.pubkey()]).unwrap();

    let alice_score = engine.compute_trust(&alice_p.pubkey()).unwrap();
    let bob_score   = engine.compute_trust(&bob_p.pubkey()).unwrap();
    let carol_score = engine.compute_trust(&carol_p.pubkey()).unwrap();

    // An agent that never appears in the graph scores exactly 0.
    let isolated = Identity::from_bytes(&[99; 32]).pubkey_hex();
    let isolated_score = engine.compute_trust(&isolated).unwrap();

    println!(
        "3-hop transitive: alice={alice_score:.4}  bob={bob_score:.4}  \
         carol={carol_score:.4}  isolated={isolated_score:.4}"
    );

    assert!(alice_score > 0.0, "alice (1 hop from seed) must have positive trust");
    assert!(bob_score   > 0.0, "bob   (2 hops) must have positive trust");
    assert!(carol_score > 0.0, "carol (3 hops) must have positive trust — transitive NetFlow");
    assert_eq!(isolated_score, 0.0, "agent with no edges must score exactly 0.0");

    // Closer to seed must score at least as high as further away.
    assert!(
        alice_score >= carol_score,
        "1-hop alice ({alice_score:.4}) must be ≥ 3-hop carol ({carol_score:.4})"
    );
    println!("3-hop transitive trust verified ✓");
}

// ─── Test 18: Sybil cluster with exactly 1 seed interaction is bounded ────────
//
// The canonical NetFlow Sybil scenario from the paper:
//   - Honest agent:  5 direct seed interactions  → high trust
//   - Sybil cluster: 1 direct seed interaction (sybil[0]) + 50 mutual interactions
//                    among 20 cluster members
//
// Max-flow to any cluster member is bounded by the seed → sybil[0] edge (bottleneck).
// Internal cluster interactions cannot amplify trust beyond this bottleneck —
// that is the core Sybil resistance claim of NetFlow.
//
// Quantitative derivation:
//   super_source → seed capacity = total seed outflow
//   seed → honest:   5 proposals × 0.5 = 2.5
//   seed → sybil[0]: 1 proposal  × 0.5 = 0.5
//   total_seed_outflow = 3.0
//
//   max_flow(honest)   = 2.5  →  score = 2.5/3.0 ≈ 0.833
//   max_flow(sybil[0]) = 0.5  →  score = 0.5/3.0 ≈ 0.167
//   max_flow(sybil[5]) = 0.5  →  score = 0.5/3.0 ≈ 0.167  (bottleneck unchanged by cluster)

#[test]
fn stress_sybil_one_seed_connection_bounded() {
    let seed    = Identity::from_bytes(&[1; 32]);
    let honest  = Identity::from_bytes(&[2; 32]);
    let sybils: Vec<Identity> = (100u8..120).map(|s| Identity::from_bytes(&[s; 32])).collect();

    let mut store = MemoryBlockStore::new();

    // ── Honest agent: 5 direct seed interactions ─────────────────────────────
    let mut seed_prev   = GENESIS_HASH.to_string();
    let mut honest_prev = GENESIS_HASH.to_string();
    for i in 1u64..=5 {
        let p = create_half_block(
            &seed, i, &honest.pubkey_hex(), 0, &seed_prev,
            BlockType::Proposal, serde_json::json!({"i": i}), Some(i * 100),
        );
        let a = create_half_block(
            &honest, i, &seed.pubkey_hex(), i, &honest_prev,
            BlockType::Agreement, serde_json::json!({"i": i}), Some(i * 100 + 1),
        );
        seed_prev   = p.block_hash.clone();
        honest_prev = a.block_hash.clone();
        store.add_block(&p).unwrap();
        store.add_block(&a).unwrap();
    }

    // ── Sybil[0]: exactly 1 seed interaction ─────────────────────────────────
    let sybil0_prev_seed_seq = 6u64; // seed continues at seq 6
    let sybil0_agreement_seq = 1u64;
    {
        let p = create_half_block(
            &seed, sybil0_prev_seed_seq, &sybils[0].pubkey_hex(), 0, &seed_prev,
            BlockType::Proposal, serde_json::json!({}), Some(700),
        );
        let a = create_half_block(
            &sybils[0], sybil0_agreement_seq, &seed.pubkey_hex(), sybil0_prev_seed_seq,
            GENESIS_HASH,
            BlockType::Agreement, serde_json::json!({}), Some(701),
        );
        seed_prev = p.block_hash.clone();
        store.add_block(&p).unwrap();
        store.add_block(&a).unwrap();
    }

    // ── Sybil cluster: 50 mutual interactions in a ring (no more seed connections) ──
    // sybil[i] ↔ sybil[(i+1)%20], 50 rounds
    let mut sybil_prevs: Vec<String> = {
        // sybil[0] already has seq=1 (the seed agreement). Start from seq=2 for sybil[0].
        let mut v = vec![GENESIS_HASH.to_string(); 20];
        // sybil[0]'s prev is the agreement block we already added.
        // Rebuild sybil[0]'s prev from store.
        let chain = store.get_chain(&sybils[0].pubkey_hex()).unwrap();
        if let Some(last) = chain.last() {
            v[0] = last.block_hash.clone();
        }
        v
    };
    let mut sybil_seqs: Vec<u64> = {
        let mut v = vec![0u64; 20];
        v[0] = 1; // sybil[0] already has seq=1
        v
    };

    for round in 0u64..50 {
        for i in 0usize..20 {
            let j = (i + 1) % 20;
            sybil_seqs[i] += 1;
            let p_seq = sybil_seqs[i];
            let p = create_half_block(
                &sybils[i], p_seq, &sybils[j].pubkey_hex(), 0, &sybil_prevs[i],
                BlockType::Proposal, serde_json::json!({"r": round}),
                Some(1000 + round * 100 + i as u64),
            );
            let p_hash = p.block_hash.clone();

            sybil_seqs[j] += 1;
            let a_seq = sybil_seqs[j];
            let a = create_half_block(
                &sybils[j], a_seq, &sybils[i].pubkey_hex(), p_seq, &sybil_prevs[j],
                BlockType::Agreement, serde_json::json!({"r": round}),
                Some(1000 + round * 100 + i as u64 + 1),
            );
            sybil_prevs[i] = p_hash;
            sybil_prevs[j] = a.block_hash.clone();
            store.add_block(&p).unwrap();
            store.add_block(&a).unwrap();
        }
    }

    // ── NetFlow scores ────────────────────────────────────────────────────────
    let engine = NetFlowTrust::new(&store, vec![seed.pubkey_hex()]).unwrap();

    let honest_score  = engine.compute_trust(&honest.pubkey_hex()).unwrap();
    let sybil0_score  = engine.compute_trust(&sybils[0].pubkey_hex()).unwrap();
    let sybil5_score  = engine.compute_trust(&sybils[5].pubkey_hex()).unwrap();
    let sybil10_score = engine.compute_trust(&sybils[10].pubkey_hex()).unwrap();

    println!(
        "sybil-1-seed: honest={honest_score:.4}  sybil[0]={sybil0_score:.4}  \
         sybil[5]={sybil5_score:.4}  sybil[10]={sybil10_score:.4}"
    );

    // Honest agent with 5 seed interactions must significantly outrank the cluster.
    assert!(
        honest_score > sybil0_score,
        "honest (5 seed interactions) must outrank sybil[0] (1 seed interaction): \
         {honest_score:.4} > {sybil0_score:.4}"
    );

    // The 50 internal cluster interactions must NOT amplify trust beyond the
    // seed → sybil[0] bottleneck.  Sybil[5] (no direct seed link) must score
    // ≤ sybil[0] (the only cluster member with a seed edge).
    assert!(
        sybil0_score >= sybil5_score,
        "direct-seed sybil[0] ({sybil0_score:.4}) must be ≥ indirect sybil[5] ({sybil5_score:.4}): \
         internal interactions must not amplify beyond the bottleneck"
    );
    assert!(
        sybil0_score >= sybil10_score,
        "direct-seed sybil[0] ({sybil0_score:.4}) must be ≥ sybil[10] ({sybil10_score:.4})"
    );

    // Honest must outrank ALL cluster members with no direct seed connection.
    assert!(
        honest_score > sybil5_score,
        "honest ({honest_score:.4}) must outrank cluster member with no direct seed ({sybil5_score:.4})"
    );
    assert!(
        honest_score > sybil10_score,
        "honest ({honest_score:.4}) must outrank sybil[10] ({sybil10_score:.4})"
    );

    println!("Sybil bottleneck property verified ✓  (internal interactions cannot amplify trust)");
}

// ─── Test 19: Out-of-order gossip block delivery ──────────────────────────────
//
// In a real P2P network, gossip may deliver blocks out of order.
// A node that receives Bob's AGREEMENT before Alice's PROPOSAL must:
//   1. Accept the agreement without erroring (return Partial, not Invalid)
//   2. Not be able to follow the link (proposal not yet known)
//   3. After the proposal arrives: validate correctly, link resolvable, integrity = 1.0

#[test]
fn stress_out_of_order_gossip_delivery() {
    let alice = Identity::from_bytes(&[1; 32]);
    let bob   = Identity::from_bytes(&[2; 32]);

    // Full bilateral interaction: Alice proposes, Bob agrees.
    let proposal = create_half_block(
        &alice, 1, &bob.pubkey_hex(), 0, GENESIS_HASH,
        BlockType::Proposal, serde_json::json!({"service": "x"}), Some(1000),
    );
    let agreement = create_half_block(
        &bob, 1, &alice.pubkey_hex(), 1, GENESIS_HASH,
        BlockType::Agreement, serde_json::json!({"result": "ok"}), Some(1001),
    );

    // ── Phase 1: gossip delivers agreement FIRST ──────────────────────────────
    let mut store = MemoryBlockStore::new();
    store.add_block(&agreement).unwrap();

    // Validate agreement with only itself in the store — linked proposal unknown.
    // Must NOT be Invalid (we have insufficient info, not proof of fraud).
    let r1 = validate_block(&agreement, &store);
    assert!(
        !matches!(r1, ValidationResult::Invalid(_)),
        "agreement received before proposal must not be Invalid (insufficient context), got: {r1:?}"
    );

    // The agreement's back-link to Alice's proposal cannot be resolved yet
    // (get_linked_block on an agreement returns the proposal via store lookup).
    let linked_before = store.get_linked_block(&agreement).unwrap();
    assert!(linked_before.is_none(), "proposal not yet in store — agreement's back-link must be unresolvable");

    // ── Phase 2: proposal arrives (delayed by gossip) ─────────────────────────
    store.add_block(&proposal).unwrap();

    // Re-validate — now both halves are present.
    let r2 = validate_block(&agreement, &store);
    assert!(
        !matches!(r2, ValidationResult::Invalid(_)),
        "agreement must still be valid after proposal arrives, got: {r2:?}"
    );

    // Both directions are now resolvable.
    let linked_after = store.get_linked_block(&agreement).unwrap();
    assert!(
        linked_after.is_some(),
        "agreement's back-link must resolve to proposal after proposal arrives"
    );
    assert_eq!(
        linked_after.unwrap().block_hash, proposal.block_hash,
        "resolved back-link must be Alice's proposal"
    );
    // Forward-link: proposal → agreement
    let fwd = store.get_linked_block(&proposal).unwrap();
    assert!(fwd.is_some(), "proposal's forward-link must resolve to agreement");
    assert_eq!(fwd.unwrap().block_hash, agreement.block_hash);

    // Alice's chain integrity must be 1.0 despite out-of-order receipt.
    let engine = TrustEngine::new(&store, None, None);
    let integrity = engine.compute_chain_integrity(&alice.pubkey_hex()).unwrap();
    assert_eq!(
        integrity, 1.0,
        "Alice's chain integrity must be 1.0 regardless of the order blocks were received"
    );

    println!("out-of-order gossip: agreement→proposal → both valid, link resolved, integrity=1.0 ✓");
}

// ─── Test 20: Statistical score ceiling — all 5 features saturated ────────────
//
// Constructs the maximum-score statistical scenario from §5:
//   count_score    = 20/20 = 1.0    (saturated at 20 interactions)
//   unique_score   =  5/5  = 1.0    (5 distinct counterparties)
//   completion_rate = 20/20 = 1.0   (every proposal has a linked agreement)
//   age_score      = 1.0            (history spans > 60 seconds = 60 000 ms)
//   entropy_score  = 1.0            (perfectly uniform: 4 interactions × 5 peers)
//
//   statistical = 0.25×1 + 0.20×1 + 0.25×1 + 0.10×1 + 0.20×1 = 1.0
//   trust (no netflow) = 0.5×integrity + 0.5×statistical = 1.0

#[test]
fn stress_statistical_score_ceiling() {
    let alice = Identity::from_bytes(&[1; 32]);
    let peers: Vec<Identity> = (10u8..15).map(|s| Identity::from_bytes(&[s; 32])).collect();

    let mut store = MemoryBlockStore::new();
    let mut alice_prev = GENESIS_HASH.to_string();
    let mut peer_prevs: Vec<String> = vec![GENESIS_HASH.to_string(); 5];
    let mut peer_seqs:  Vec<u64>   = vec![0u64; 5];

    // 4 rounds × 5 peers = 20 interactions.
    // Timestamps: seq k → (k-1) × 3500 ms, so seq 1 = 0 ms, seq 20 = 19×3500 = 66 500 ms.
    // age_ms = 66 500 > 60 000 → age_score = 1.0
    for round in 0usize..4 {
        for (pi, peer) in peers.iter().enumerate() {
            let alice_seq = (round * 5 + pi) as u64 + 1;
            let ts = (alice_seq - 1) * 3500;

            // Alice proposes to peer.
            let proposal = create_half_block(
                &alice, alice_seq, &peer.pubkey_hex(), 0, &alice_prev,
                BlockType::Proposal,
                serde_json::json!({"peer": pi, "round": round}),
                Some(ts),
            );
            alice_prev = proposal.block_hash.clone();
            store.add_block(&proposal).unwrap();

            // Peer agrees (link back to alice_seq so get_linked_block resolves).
            peer_seqs[pi] += 1;
            let agreement = create_half_block(
                peer, peer_seqs[pi], &alice.pubkey_hex(), alice_seq, &peer_prevs[pi],
                BlockType::Agreement,
                serde_json::json!({"peer": pi, "round": round}),
                Some(ts + 1),
            );
            peer_prevs[pi] = agreement.block_hash.clone();
            store.add_block(&agreement).unwrap();
        }
    }

    let engine = TrustEngine::new(&store, None, None);
    let alice_pk = alice.pubkey_hex();

    let integrity   = engine.compute_chain_integrity(&alice_pk).unwrap();
    let statistical = engine.compute_statistical_score(&alice_pk).unwrap();
    let trust       = engine.compute_trust(&alice_pk).unwrap();

    println!(
        "stat ceiling: integrity={integrity:.6}  statistical={statistical:.6}  trust={trust:.6}"
    );

    assert!(
        (integrity - 1.0).abs() < 1e-9,
        "20-block perfect chain must have integrity=1.0, got {integrity}"
    );

    // statistical must equal exactly 1.0 when all 5 features are saturated.
    assert!(
        (statistical - 1.0).abs() < 1e-6,
        "all features saturated: statistical must be 1.0, got {statistical:.8}\n\
         (count=1.0, unique=1.0, completion=1.0, age=1.0, entropy=1.0)"
    );

    // No netflow: trust = (0.3/0.6)×integrity + (0.3/0.6)×statistical = 0.5×1.0 + 0.5×1.0 = 1.0
    assert!(
        (trust - 1.0).abs() < 1e-6,
        "maximum trust must be 1.0 when all components are saturated, got {trust:.8}"
    );

    println!("statistical score ceiling: all 5 features = 1.0, trust = 1.0 ✓");
}
