# TrustChain

[![CI](https://github.com/viftode4/trustchain/actions/workflows/ci.yml/badge.svg)](https://github.com/viftode4/trustchain/actions)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**Decentralized trust infrastructure for the AI agent economy.**

TrustChain is a universal trust primitive — a bilateral signed ledger where every agent-to-agent interaction produces cryptographic proof. Trust scores emerge from real interaction history, not ratings or reputation systems. Sybil attacks fail because fake identities have no legitimate transaction graph to exploit.

Built on the [TrustChain protocol](https://doi.org/10.1016/j.future.2017.08.048) (Otte, de Vos, Pouwelse — TU Delft), extended with NetFlow trust computation for AI agent economies.

## Quick Start

### For Python agents (easiest)

```bash
pip install trustchain-py
```

```python
from trustchain import with_trust

@with_trust(name="my-agent")
def main():
    # All HTTP calls are now trust-protected. Binary downloads automatically.
    ...

main()
```

### Install the binary directly

Download from [GitHub Releases](https://github.com/viftode4/trustchain/releases), or:

```bash
cargo install trustchain-node
```

### Run as a sidecar

```bash
# Generates identity, starts all services, prints HTTP_PROXY
trustchain-node sidecar --name my-agent --endpoint http://localhost:8080

# Then in your agent:
export HTTP_PROXY=http://127.0.0.1:8203
python my_agent.py   # all outbound HTTP calls are now trust-protected
```

### Launch wrapper (Dapr-style)

```bash
trustchain-node launch --name my-agent -- python my_agent.py
```

## Key Features

- **Transparent sidecar proxy** — agents set `HTTP_PROXY` once; trust is handled invisibly
- **Ed25519 identity** — self-sovereign keypairs, auto-generated on first run
- **Bilateral half-block chain** — each party signs only their own block; no coordinator
- **NetFlow Sybil resistance** — max-flow from seed nodes; fake identities can't manufacture trust
- **QUIC P2P transport** — TLS 1.3 mutual auth, STUN NAT traversal
- **Live dashboard** — embedded HTML dashboard at `GET /dashboard`
- **Trust headers** — `X-TrustChain-Score`, `X-TrustChain-Pubkey`, `X-TrustChain-Interactions` injected into proxied responses
- **SQLite storage** — WAL mode, survives restarts
- **Delegation protocol** — identity succession and capability delegation with revocation
- **MCP server** — expose trust tools to Claude Desktop, Cursor, VS Code Copilot
- **296 tests** across the workspace

## Architecture

```mermaid
graph TD
    Agent["Agent Process\n(any framework)"]
    Proxy["Transparent Proxy\n:8203"]
    HTTP["HTTP REST API\n:8202"]
    GRPC["gRPC API\n:8201"]
    QUIC["QUIC P2P\n:8200"]
    Dashboard["Dashboard\n/dashboard"]
    MCP["MCP Server\n/mcp or stdio"]
    Core["TrustEngine\nNetFlow + Chain Integrity"]
    Store["SQLite BlockStore"]

    Agent -->|HTTP_PROXY=:8203| Proxy
    Proxy --> Core
    HTTP --> Core
    GRPC --> Core
    Dashboard --> HTTP
    MCP --> Core
    Core --> Store
    QUIC <-->|proposal/agreement| RemoteSidecar["Remote Sidecar"]
```

### Crate Structure

| Crate | Description |
|-------|-------------|
| [`trustchain-core`](trustchain-core/) | Identity, half-blocks, block storage, trust engine, NetFlow, CHECO consensus, delegation |
| [`trustchain-transport`](trustchain-transport/) | QUIC P2P, gRPC, HTTP REST, transparent proxy, dashboard, peer discovery, MCP server |
| [`trustchain-node`](trustchain-node/) | CLI binary — sidecar, launch wrapper, keygen, MCP stdio |
| [`trustchain-wasm`](trustchain-wasm/) | WASM bindings for browser/edge (experimental) |

## Default Ports

| Port | Protocol | Purpose |
|------|----------|---------|
| 8200 | QUIC/UDP | P2P transport |
| 8201 | gRPC/TCP | Protobuf API |
| 8202 | HTTP/TCP | REST API + dashboard + MCP |
| 8203 | HTTP/TCP | Transparent proxy |

All ports shift with `--port-base`.

## HTTP API

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/healthz` | Liveness probe |
| `GET` | `/status` | Node status: pubkey, chain length, peer count |
| `GET` | `/dashboard` | Live trust dashboard (embedded HTML) |
| `GET` | `/metrics` | Prometheus metrics |
| `GET` | `/trust/{pubkey}` | Trust score (0.0–1.0) |
| `POST` | `/propose` | Initiate bilateral interaction |
| `GET` | `/peers` | List known peers |
| `GET` | `/discover` | Discover peers by capability |
| `POST` | `/delegate` | Create delegation |
| `POST` | `/revoke` | Revoke delegation |
| `GET` | `/chain/{pubkey}` | Full chain for a peer |
| `GET` | `/block/{pubkey}/{seq}` | Single block by sequence |
| `GET` | `/crawl/{pubkey}` | Crawl peer's chain |
| `GET` | `/delegations/{pubkey}` | List delegations |
| `GET` | `/identity/{pubkey}` | Resolve identity |
| `POST` | `/accept_delegation` | Accept inbound delegation |
| `POST` | `/accept_succession` | Accept identity succession |

## Trust Scoring

| Component | Weight | What it measures |
|-----------|--------|-----------------|
| **Chain Integrity** | 50% | Hash links, sequence continuity, Ed25519 signatures |
| **NetFlow** | 50% | Max-flow from seed nodes — Sybil resistance |

Proven fraud → permanent hard-zero trust score.

## Protocol

Based on [IETF draft-pouwelse-trustchain](https://datatracker.ietf.org/doc/draft-pouwelse-trustchain/):

```
Alice's chain:              Bob's chain:
┌──────────────┐            ┌──────────────┐
│ PROPOSAL     │──────────► │ AGREEMENT    │
│ seq=2, sig=A │ ◄───────── │ seq=2, sig=B │
└──────────────┘            └──────────────┘
       ▲                           ▲
┌──────────────┐            ┌──────────────┐
│ PROPOSAL     │──────────► │ AGREEMENT    │
│ seq=1, sig=A │ ◄───────── │ seq=1, sig=B │
└──────────────┘            └──────────────┘
```

## Building from Source

```bash
git clone https://github.com/viftode4/trustchain.git
cd trustchain
cargo build --release
cargo test --workspace   # 296 tests
```

## Research

**Core paper**: Otte, de Vos, Pouwelse — [TrustChain: A Sybil-resistant scalable blockchain](https://doi.org/10.1016/j.future.2017.08.048) (Future Generation Computer Systems, 2020)

**IETF drafts**:
- [draft-pouwelse-trustchain-01](https://datatracker.ietf.org/doc/draft-pouwelse-trustchain/) — base bilateral ledger protocol (Pouwelse, TU Delft, 2018)
- draft-viftode-trustchain-trust-00 — trust computation, NetFlow Sybil resistance, delegation, succession (filed March 2026)

## Related Projects

- [trustchain-py](https://github.com/viftode4/trustchain-py) — Python SDK: `pip install trustchain-py`, `@with_trust` decorator
- [trustchain-js](https://github.com/viftode4/trustchain-js) — TypeScript SDK
- [trustchain-agent-os](https://github.com/viftode4/trustchain-agent-os) — Agent framework adapters (12 frameworks)

## License

MIT
