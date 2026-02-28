# TrustChain

Decentralized trust infrastructure for agents, humans, and devices.

TrustChain is a universal trust primitive — bilateral signed interaction records with Sybil resistance via NetFlow. Any two parties interact, trust is handled automatically at the infrastructure layer.

## Crates

| Crate | Description |
|-------|-------------|
| [`trustchain-core`](trustchain-core/) | Identity (Ed25519), half-blocks, block storage, trust engine, NetFlow, CHECO consensus |
| [`trustchain-transport`](trustchain-transport/) | QUIC P2P, gRPC, HTTP REST, transparent proxy, peer discovery, MCP server |
| [`trustchain-node`](trustchain-node/) | CLI binary — standalone node, sidecar proxy, MCP stdio |
| [`trustchain-wasm`](trustchain-wasm/) | WASM bindings for browser/edge nodes |

## Quick Start

### Install the binary

```bash
cargo install trustchain-node
```

Or download from [GitHub Releases](https://github.com/levvlad/trustchain/releases).

### Run a node

```bash
# Generate identity
trustchain-node keygen

# Start as sidecar (transparent proxy for your agent)
trustchain-node sidecar --name my-agent --endpoint http://localhost:8080

# Or run a full node
trustchain-node run --config node.toml
```

### Use as a library

```toml
[dependencies]
trustchain-core = "0.1"
trustchain-transport = "0.1"
```

## Building from Source

```bash
git clone https://github.com/levvlad/trustchain.git
cd trustchain
cargo build --release
```

### Run tests

```bash
cargo test --workspace
cargo test --workspace --features mcp
```

## Architecture

```
trustchain-core          (protocol layer — no networking)
       |
trustchain-transport     (QUIC, gRPC, HTTP, proxy, discovery)
       |
trustchain-node          (CLI binary, node runtime)
       |
trustchain-wasm          (browser bindings)
```

## Related Projects

- [trustchain-sdk](https://github.com/levvlad/trustchain-sdk) — Python SDK for trust primitives
- [trustchain-agent-os](https://github.com/levvlad/trustchain-agent-os) — Agent framework with trust-native protocol layer

## License

MIT
