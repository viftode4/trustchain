# TrustChain Rust Workspace

Bilateral signed interaction ledger implementing IETF draft-pouwelse-trustchain-01, extended
with NetFlow Sybil-resistant trust computation. No blockchain, offline-capable.

## Build & Test

```sh
cargo build                                    # debug build
cargo build --release --bin trustchain-node    # release binary
cargo test --workspace                         # run all tests (currently 296)
cargo test --workspace --features mcp          # include MCP feature tests
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all
```

CI runs tests on ubuntu, windows, macos. Requires `protoc` on PATH (needed by tonic-build).

## Crate Structure

| Crate | Role |
|---|---|
| `trustchain-core` | Identity, HalfBlock, BlockStore, NetFlow trust, protocol state machine, delegation |
| `trustchain-transport` | QUIC (quinn), gRPC (tonic), HTTP REST (axum), transparent proxy (port 8203), MCP server (rmcp) |
| `trustchain-node` | Binary entry point -- CLI, config, sidecar lifecycle |
| `trustchain-wasm` | WASM bindings for browser/Node.js |

`trustchain-transport` feature `mcp` is optional (rmcp, schemars). Default features off.
`trustchain-core` feature `sqlite` is on by default; WASM builds disable it.

## Key Conventions

### Timestamps
All timestamps are `u64` milliseconds since Unix epoch -- no `f64`, no seconds. Wire-compatible
with Python SDK (`int` ms) and TypeScript SDK.

### Canonical JSON Hashing
Serialize the block as a `BTreeMap<String, Value>` (sorted keys), set `"signature": ""`,
serialize with compact separators (`serde_json::to_string`), SHA-256 the UTF-8 bytes.
Ed25519 signature is over the UTF-8 bytes of the hex-encoded `block_hash`.

### Constants (types.rs) -- never change these values
```rust
GENESIS_HASH = "0000...0000"  // 64 hex zeros -- previous_hash of first block
GENESIS_SEQ  = 1              // first valid sequence number
UNKNOWN_SEQ  = 0              // proposal's link_sequence_number before agreement replies
MAX_DELEGATION_TTL_MS = 30 * 24 * 3600 * 1000  // 30-day cap, enforced in core
```

### Storage
- `BlockStore` is `Send` but NOT `Sync`. Do not add a `Sync` bound.
- `SqliteBlockStore` uses `Mutex<Connection>` internally.
- `DelegationStore` uses a separate `delegations.db` file alongside `trustchain.db`.
- `AppState` in `http.rs` is generic: `AppState<S: BlockStore, D: DelegationStore>`.

### Delegation Rules
- Sub-delegation with empty scope under a restricted parent is scope escalation -> reject.
- `MAX_DELEGATION_TTL_MS` is enforced in `create_delegation_proposal()` at the core layer,
  not just the HTTP API, so callers cannot bypass the cap.

### Ports (sidecar mode)
- 8200/UDP -- QUIC peer-to-peer
- 8201/TCP -- gRPC
- 8202/TCP -- HTTP REST API
- 8203/TCP -- transparent HTTP proxy (sidecar)

QUIC port offset relative to HTTP port is a configurable constant (`QUIC_PORT_OFFSET`).

## Code Style
- Run `cargo fmt --all` and `cargo clippy --workspace --all-targets -- -D warnings` before
  every commit. Zero warnings policy -- CI enforces `-D warnings`.
- Use `thiserror` for library errors, `anyhow` for binary/application errors.
- Log with `log::warn!/error!` (not `eprintln!`) so the subscriber controls output.

## Wire Compatibility
Any change to block field names, hash computation, serialization order, or BlockType string
values MUST be coordinated with the Python SDK (`trustchain-py`) and TypeScript SDK
(`trustchain-js`). The canonical JSON format is the cross-language contract.

## Do Not
- Do not change `GENESIS_HASH`, `GENESIS_SEQ`, or `UNKNOWN_SEQ` values.
- Do not use `f64` or seconds for any timestamp field.
- Do not add `Sync` to `BlockStore` -- `SqliteBlockStore` cannot satisfy it.
- Do not auto-accept delegations or successions on crawl -- require explicit
  `POST /accept_delegation` or `POST /accept_succession`.
- Do not skip `cargo clippy` or `cargo fmt` before committing.
