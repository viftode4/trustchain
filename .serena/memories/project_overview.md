# TrustChain — Rust Workspace

## Purpose
Universal trust primitive for agents, humans, devices. Bilateral signed interaction records with NetFlow-based Sybil resistance. Ed25519 identity, half-block chains, CHECO checkpoint consensus.

## Structure (4 crates)
- `trustchain-core/` — types, halfblock, protocol, trust engine, netflow, delegation, crawler, consensus, blockstore
- `trustchain-transport/` — HTTP (axum), QUIC (quinn), gRPC (tonic), MCP (rmcp), TLS, proxy, gossip, STUN
- `trustchain-node/` — CLI binary, node runtime, config
- `trustchain-wasm/` — WASM bindings

## Tech Stack
- Rust 2021 edition, workspace resolver v2
- Ed25519 (ed25519-dalek), SHA-256 (sha2), SQLite (rusqlite bundled)
- Axum 0.8 (HTTP), Quinn 0.11 (QUIC), Tonic 0.12 (gRPC), rmcp 0.17 (MCP)
- Tokio async runtime, Clap CLI

## Key Conventions
- All timestamps: `u64` milliseconds since epoch
- Public keys: 64 lowercase hex chars (Ed25519)
- Block hashes: SHA-256 of BTreeMap-sorted JSON (canonical form)
- `BlockStore` trait is `Send` (not `Send+Sync`); SQLite uses `Mutex<Connection>`
- Half-block model: proposal + agreement = one bilateral interaction
- Wire compat with Python SDK (same JSON format)
