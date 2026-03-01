# Trust Computation Optimizations

Design document for performance optimizations to the TrustChain v2 trust computation engine.

## 1. Executive Summary

Four optimizations address scaling bottlenecks identified through benchmarking:

1. **Fix `compute_all_scores()`** — Rust was rebuilding the graph N times; now builds once
2. **Temporal decay** — Recent interactions weighted more via `2^(-age/half_life)`
3. **Graph caching** — `CachedNetFlow` avoids rebuilding the contribution graph when no new blocks arrived
4. **Checkpoint-anchored verification** — Skip Ed25519 verification for blocks covered by finalized CHECO checkpoints

All optimizations are backward-compatible. Default behavior is unchanged when optional parameters are omitted.

## 2. Current Architecture

```
                    ┌─────────────────┐
                    │   TrustEngine   │
                    │                 │
                    │  compute_trust()│
                    └────┬───┬───┬────┘
                         │   │   │
              ┌──────────┘   │   └──────────┐
              ▼              ▼              ▼
    ┌─────────────┐  ┌────────────┐  ┌────────────┐
    │  integrity   │  │  netflow   │  │ statistical│
    │  (0.3 wt)   │  │  (0.4 wt)  │  │  (0.3 wt)  │
    └──────┬──────┘  └─────┬──────┘  └─────┬──────┘
           │               │               │
     verify_block()   NetFlowTrust    chain scan
     per block from   build_graph()   counterparties
     genesis          max-flow        entropy, age
```

**Data flow:**
- `TrustEngine.compute_trust(pubkey)` blends three scores
- `compute_chain_integrity()` walks the chain from genesis, verifying each block's Ed25519 signature
- `compute_netflow_score()` creates a `NetFlowTrust`, builds the contribution graph, and runs Edmonds-Karp max-flow
- `compute_statistical_score()` scans the chain for interaction features

## 3. Bottleneck Analysis

| Bottleneck | Complexity | Measured (10K blocks/agents) |
|---|---|---|
| NetFlow graph rebuild per `compute_trust()` | O(total_blocks) per call | ~50ms per graph build |
| `compute_all_scores()` rebuilds graph N times | O(N × total_blocks) | N × 50ms |
| Ed25519 verify per block in integrity check | O(chain_length × 61µs) | ~611ms for 10K blocks |
| No temporal decay | N/A (quality issue) | Old interactions inflate scores |

## 4. Optimization Details

### 4.1 Fix `compute_all_scores()` (Rust)

**Before:** `compute_all_scores()` called `compute_trust()` N times, each rebuilding the contribution graph from all chains.

**After:** Build graph once, prepare super-source edges once, clone the residual capacity map for each per-target max-flow run.

**Complexity:** O(total_blocks) + O(N × max_flow) instead of O(N × total_blocks) + O(N × max_flow)

**Files:** `trustchain-core/src/netflow.rs`

**Note:** Python already had this optimization. Rust now matches.

### 4.2 Temporal Decay

**Design:** Optional `decay_half_life_ms: Option<u64>` in `TrustWeights` (Rust) / `decay_half_life_ms` param in `TrustEngine.__init__()` (Python).

**Formula:** Per-block weight = `2^(-age_ms / half_life_ms)` where `age_ms = now_ms - block.timestamp` and `now_ms` is the latest block's timestamp.

**Affected features:**
- `interaction_count` → sum of decay weights instead of raw count
- `completion_rate` → decay-weighted completed / decay-weighted total
- `entropy` → decay-weighted counterparty distribution

**Unaffected features (structural):**
- `unique_counterparties` — presence is binary, not volume
- `account_age` — time span is structural

**Default:** `None` — no decay, identical to previous behavior.

**Files:**
- `trustchain-core/src/trust.rs` — `TrustWeights.decay_half_life_ms`, modified `compute_statistical_score()`
- `trustchain-py/src/trustchain/trust.py` — `TrustEngine(decay_half_life_ms=...)`, modified `compute_statistical_score()`

### 4.3 Graph Caching

**Design:**
- **Rust:** New `CachedNetFlow<S: BlockStore>` struct that *owns* the store. Caches `HashMap<String, HashMap<String, f64>>` and invalidates when `store.get_block_count()` changes or `invalidate()` is called.
- **Python:** Added `_cached_graph` + `_last_block_count` fields to existing `NetFlowTrust`. `compute_trust()` and `compute_all_scores()` now call `_get_or_build_graph()` instead of `build_contribution_graph()` directly. New `invalidate_cache()` method for explicit reset.

**API (Rust):**
```rust
pub struct CachedNetFlow<S: BlockStore> { ... }

impl<S: BlockStore> CachedNetFlow<S> {
    pub fn new(store: S, seed_nodes: Vec<String>) -> Result<Self>
    pub fn invalidate(&mut self)
    pub fn compute_trust(&mut self, target_pubkey: &str) -> Result<f64>
    pub fn compute_all_scores(&mut self) -> Result<HashMap<String, f64>>
    pub fn store(&self) -> &S
}
```

**Integration with TrustEngine:**
```rust
// TrustEngine gains a method for cached netflow:
engine.compute_netflow_score_cached(&mut cached_netflow, pubkey)
```

**Files:**
- `trustchain-core/src/netflow.rs` — `CachedNetFlow` struct
- `trustchain-core/src/lib.rs` — re-export
- `trustchain-core/src/trust.rs` — `compute_netflow_score_cached()`
- `trustchain-py/src/trustchain/netflow.py` — caching in `NetFlowTrust`

### 4.4 Checkpoint-Anchored Verification

**Design:** Optional `Checkpoint` attached to `TrustEngine` via builder pattern (Rust) or constructor param (Python). When present and finalized, `compute_chain_integrity()` skips Ed25519 verification for blocks with `sequence_number ≤ checkpoint.chain_heads[pubkey]`.

**Structural checks always performed:** sequence numbering, previous hash linking.

**API:**
```rust
// Rust: builder pattern
let engine = TrustEngine::new(&store, seeds, weights, deleg_ctx)
    .with_checkpoint(checkpoint);

// Python: constructor param
engine = TrustEngine(store, checkpoint=checkpoint)
```

**Speedup:** For a 10K-block chain with checkpoint at sequence 9000, only 1000 blocks need Ed25519 verification → ~90% speedup on integrity computation.

**Files:**
- `trustchain-core/src/trust.rs` — `checkpoint` field, `with_checkpoint()`, modified `compute_chain_integrity()`
- `trustchain-py/src/trustchain/trust.py` — `checkpoint` param, modified `compute_chain_integrity()`

## 5. Rust vs Python Differences

| Aspect | Rust | Python |
|---|---|---|
| Super-source capacity | `seed_outflow` (sum of seed's edges) | `float("inf")` per seed |
| NetFlowTrust ownership | Borrows store (`&'a S`) | Owns store |
| CachedNetFlow | Separate struct (owns store) | Caching added to existing `NetFlowTrust` |
| Delegation in netflow | Not implemented (no delegation_store) | Resolves delegates to root identity |
| Score rounding | No rounding (full f64 precision) | `round(..., 3)` |
| Checkpoint integration | Builder pattern `.with_checkpoint()` | Constructor param `checkpoint=` |

## 6. Backward Compatibility Guarantees

All optimizations are additive and opt-in:
- `TrustWeights::default()` has `decay_half_life_ms: None` → no decay
- `TrustEngine::new()` signature unchanged → no checkpoint
- `NetFlowTrust` API unchanged → caching is transparent (same results)
- `CachedNetFlow` is a new type → no existing code affected
- Existing tests pass without modification

## 7. Future Work

- **Dinic's algorithm:** O(V²E) vs Edmonds-Karp O(VE²) — significant for dense graphs
- **Incremental graph updates:** Update contribution graph when individual blocks arrive, instead of full rebuild
- **Graph partitioning:** For very large networks, partition the graph and compute trust per partition
- **ML scoring:** Replace hand-tuned feature weights with learned weights from interaction outcome data
- **Persistent graph cache:** Store the contribution graph alongside the block database for cold-start acceleration
