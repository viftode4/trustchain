<!-- OMX:AGENTS-INIT:MANAGED -->
<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-04-07 | Updated: 2026-05-21 -->

# trustchain

## Purpose
Authoritative Rust workspace implementing IETF draft-pouwelse-trustchain-01: bilateral signed interaction ledger with pluggable Sybil-resistant trust (NetFlow + MeritRank). No blockchain, offline-capable. Ships as a library, a sidecar binary, and WASM bindings. Rust is the cross-SDK ground truth — Python and TypeScript SDKs match this implementation. See `CLAUDE.md` for full conventions.

## Key Files
| File | Description |
|------|-------------|
| `CLAUDE.md` | Authoritative Rust-side guide (read first) |
| `Cargo.toml` | Workspace manifest |
| `Cargo.lock` | Lockfile |
| `README.md` | Repo overview |
| `LICENSE` | License |
| `Dockerfile`, `docker-compose.yml` | Container build / orchestration |
| `install.sh` | Local install script |
| `test_vectors.json` | Cross-SDK wire-format test vectors |
| `.mcp.json` | MCP server configuration |

## Subdirectories
| Directory | Purpose |
|-----------|---------|
| `trustchain-core/` | Identity, HalfBlock, BlockStore, NetFlow + MeritRank trust, protocol state machine, delegation |
| `trustchain-transport/` | QUIC (quinn), gRPC (tonic), HTTP REST (axum), transparent proxy (8203), IPv8 UDP, MCP server (rmcp) |
| `trustchain-node/` | Binary entry point — CLI, config, sidecar lifecycle |
| `trustchain-wasm/` | WASM bindings (browser / Node.js); SQLite disabled in WASM builds |
| `proto/` | Protocol buffer definitions |
| `deploy/` | Deployment artifacts |

## For AI Agents
### Working In This Directory
- Read `CLAUDE.md` before any non-trivial change.
- Keep timestamps as `u64` milliseconds. Never `f64`, never seconds.
- Canonical JSON: `BTreeMap<String, Value>` sorted keys, `signature: ""`, `serde_json::to_string`, SHA-256 UTF-8 bytes, Ed25519 over UTF-8 of hex `block_hash`.
- Never change `GENESIS_HASH = "0"*64`, `GENESIS_SEQ = 1`, `UNKNOWN_SEQ = 0`, or `MAX_DELEGATION_TTL_MS = 30 days`.
- `BlockStore` is `Send` but NOT `Sync` — do not add a `Sync` bound (SqliteBlockStore uses `Mutex<Connection>`).
- Delegation TTL cap is enforced at the core layer in `create_delegation_proposal()`, not just HTTP.
- Sub-delegation with empty scope under a restricted parent = scope escalation → reject.
- Sidecar ports: 8000/UDP (IPv8, feature `ipv8`), 8200/UDP (QUIC), 8201/TCP (gRPC), 8202/TCP (HTTP REST), 8203/TCP (transparent proxy).
- Do not auto-accept delegations or successions on crawl — require explicit `POST /accept_delegation` / `POST /accept_succession`.

### Testing Requirements
- `cargo build` / `cargo build --release --bin trustchain-node`
- `cargo test --workspace` (currently 523 tests)
- `cargo test --workspace --features mcp,meritrank,ipv8` to exercise optional features
- `cargo clippy --workspace --all-targets -- -D warnings` (zero-warnings policy)
- `cargo fmt --all` before every commit
- CI: ubuntu/windows/macos. Requires `protoc` on PATH (tonic-build).

### Common Patterns
- `thiserror` for library errors, `anyhow` for binary/application errors.
- Log via `log::warn!/error!`, not `eprintln!`.
- `AppState<S: BlockStore, D: DelegationStore>` is generic in `http.rs`.
- `trustchain-core` features: `meritrank` (optional), `sqlite` (default, off for WASM).
- `trustchain-transport` features: `mcp`, `ipv8` (both optional).

## Dependencies
### Internal
- Wire-compatibility contract with `../trustchain-py` and `../trustchain-js`.

### External
- `serde`, `serde_json`, `ed25519-dalek`, `sha2`, `tokio`, `quinn`, `tonic`, `axum`, `rusqlite`, `rmcp` (mcp), `meritrank` (optional), `sha1` (ipv8).

<!-- OMX:AGENTS-INIT:MANUAL:START -->
## Local Notes
- Read `CLAUDE.md` here before making non-trivial changes; it is the detailed Rust-side guide.
- Verification: `cargo build`, `cargo test --workspace`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo fmt --all`.
- Keep timestamps as `u64` milliseconds, preserve canonical JSON hashing, and do not change `GENESIS_HASH`, `GENESIS_SEQ`, or `UNKNOWN_SEQ`.
- `BlockStore` must remain `Send` but not `Sync`; do not add a `Sync` bound.
- Any wire-format, block-field, hash, or delegation-constant change requires matching updates in `../trustchain-py` and `../trustchain-js`.
<!-- OMX:AGENTS-INIT:MANUAL:END -->
