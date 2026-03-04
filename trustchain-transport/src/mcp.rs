//! MCP (Model Context Protocol) server for TrustChain.
//!
//! Exposes trust primitives as MCP tools for LLM hosts like
//! Claude Desktop, Claude Code, Cursor, and VS Code Copilot.
//!
//! Two transports:
//! - **Streamable HTTP**: mounted at `/mcp` on the existing axum server
//! - **stdio**: for local MCP hosts via `trustchain-node mcp-stdio`

use std::sync::Arc;

use schemars::JsonSchema;
use serde::Deserialize;
use tokio::sync::Mutex;

use rmcp::{
    handler::server::{tool::ToolRouter, wrapper::Parameters, ServerHandler},
    model::*,
    service::{RequestContext, RoleServer, ServiceExt},
    tool, tool_router,
    transport::streamable_http_server::{
        session::local::LocalSessionManager,
        tower::{StreamableHttpServerConfig, StreamableHttpService},
    },
    ErrorData as McpError,
};

use trustchain_core::{BlockStore, BlockStoreCrawler, TrustChainProtocol, TrustEngine};

use crate::discovery::PeerDiscovery;

// ---------------------------------------------------------------------------
// Tool parameter types
// ---------------------------------------------------------------------------

/// Parameters for the `trustchain_check_trust` tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct CheckTrustParams {
    /// Hex-encoded Ed25519 public key of the peer to check trust for.
    pub peer: String,
}

/// Parameters for the `trustchain_discover_peers` tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct DiscoverPeersParams {
    /// Capability to search for (reserved for future use).
    #[serde(default)]
    pub capability: Option<String>,
    /// Minimum trust score threshold (0.0 to 1.0). Peers below this are excluded.
    #[serde(default)]
    pub min_trust: Option<f64>,
    /// Maximum number of results to return (default: 20).
    #[serde(default)]
    pub max_results: Option<usize>,
}

/// Parameters for the `trustchain_record_interaction` tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct RecordInteractionParams {
    /// Hex-encoded Ed25519 public key of the counterparty.
    pub peer: String,
    /// Arbitrary transaction data to record in the block.
    #[serde(default)]
    pub transaction: Option<serde_json::Value>,
}

/// Parameters for the `trustchain_verify_chain` tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct VerifyChainParams {
    /// Hex-encoded Ed25519 public key of the peer whose chain to verify.
    pub peer: String,
}

// ---------------------------------------------------------------------------
// MCP Server (generic over BlockStore)
// ---------------------------------------------------------------------------

/// MCP server exposing TrustChain primitives as tools.
///
/// Generic over `S: BlockStore` — works with `SqliteBlockStore` in production
/// and `MemoryBlockStore` in tests.
#[derive(Clone)]
pub struct TrustChainMcpServer<S: BlockStore + 'static> {
    protocol: Arc<Mutex<TrustChainProtocol<S>>>,
    discovery: Arc<PeerDiscovery>,
    agent_endpoint: Option<String>,
    seed_nodes: Vec<String>,
    tool_router: ToolRouter<Self>,
}

#[tool_router]
impl<S: BlockStore + 'static> TrustChainMcpServer<S> {
    /// Create a new MCP server backed by existing protocol and discovery instances.
    pub fn new(
        protocol: Arc<Mutex<TrustChainProtocol<S>>>,
        discovery: Arc<PeerDiscovery>,
        agent_endpoint: Option<String>,
        seed_nodes: Vec<String>,
    ) -> Self {
        Self {
            protocol,
            discovery,
            agent_endpoint,
            seed_nodes,
            tool_router: Self::tool_router(),
        }
    }

    /// Helper to build a TrustEngine with the server's seed_nodes.
    fn make_engine<'a>(&self, store: &'a S) -> TrustEngine<'a, S> {
        let seed_nodes_opt = if self.seed_nodes.is_empty() {
            None
        } else {
            Some(self.seed_nodes.clone())
        };
        TrustEngine::new(store, seed_nodes_opt, None, None)
    }

    /// Check the trust score and component breakdown for a peer.
    #[tool(
        name = "trustchain_check_trust",
        description = "Check the trust score for a peer. Returns trust = connectivity × integrity × diversity, \
                        plus full evidence: path_diversity, unique_peers, fraud status."
    )]
    async fn check_trust(
        &self,
        params: Parameters<CheckTrustParams>,
    ) -> Result<CallToolResult, McpError> {
        let proto = self.protocol.lock().await;
        let store = proto.store();
        let engine = self.make_engine(store);

        let evidence = engine
            .compute_trust_with_evidence(&params.0.peer)
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        let result = serde_json::json!({
            "peer": params.0.peer,
            "trust_score": evidence.trust_score,
            "connectivity": evidence.connectivity,
            "integrity": evidence.integrity,
            "diversity": evidence.diversity,
            "unique_peers": evidence.unique_peers,
            "interactions": evidence.interactions,
            "interaction_count": evidence.interactions,
            "fraud": evidence.fraud,
            "path_diversity": if evidence.path_diversity.is_infinite() { 0.0 } else { evidence.path_diversity },
        });

        Ok(CallToolResult::success(vec![Content::text(
            serde_json::to_string_pretty(&result).unwrap(),
        )]))
    }

    /// Discover known peers, optionally filtered by minimum trust score.
    #[tool(
        name = "trustchain_discover_peers",
        description = "Discover known peers ranked by trust score. Optionally filter by minimum \
                        trust threshold and limit results. Returns peer addresses, public keys, \
                        and trust scores."
    )]
    async fn discover_peers(
        &self,
        params: Parameters<DiscoverPeersParams>,
    ) -> Result<CallToolResult, McpError> {
        let min_trust = params.0.min_trust.unwrap_or(0.0);
        let max_results = params.0.max_results.unwrap_or(20);

        // If a capability filter is provided, use find_capable_agents to get matching peers.
        // Otherwise, return all known peers (backward compatible).
        let capability_filter = params
            .0
            .capability
            .as_deref()
            .filter(|c| !c.is_empty())
            .map(|s| s.to_string());

        let mut scored: Vec<serde_json::Value> = if let Some(ref capability) = capability_filter {
            let proto = self.protocol.lock().await;
            let store = proto.store();
            let engine = self.make_engine(store);
            let capable = crate::discover::find_capable_agents(store, capability, max_results);
            capable
                .iter()
                .filter_map(|agent| {
                    let trust = engine.compute_trust(&agent.pubkey).unwrap_or(0.0);
                    if trust >= min_trust {
                        Some(serde_json::json!({
                            "pubkey": agent.pubkey,
                            "address": agent.address,
                            "trust_score": trust,
                            "capability": agent.capability,
                            "interaction_count": agent.interaction_count,
                        }))
                    } else {
                        None
                    }
                })
                .collect()
        } else {
            let peers = self.discovery.get_peers().await;
            let proto = self.protocol.lock().await;
            let store = proto.store();
            let engine = self.make_engine(store);
            peers
                .iter()
                .filter_map(|p| {
                    let trust = engine.compute_trust(&p.pubkey).unwrap_or(0.0);
                    if trust >= min_trust {
                        Some(serde_json::json!({
                            "pubkey": p.pubkey,
                            "address": p.address,
                            "trust_score": trust,
                            "latest_seq": p.latest_seq,
                        }))
                    } else {
                        None
                    }
                })
                .collect()
        };

        scored.sort_by(|a, b| {
            let ta = a["trust_score"].as_f64().unwrap_or(0.0);
            let tb = b["trust_score"].as_f64().unwrap_or(0.0);
            tb.partial_cmp(&ta).unwrap_or(std::cmp::Ordering::Equal)
        });
        scored.truncate(max_results);

        let result = serde_json::json!({
            "peer_count": scored.len(),
            "peers": scored,
        });

        Ok(CallToolResult::success(vec![Content::text(
            serde_json::to_string_pretty(&result).unwrap(),
        )]))
    }

    /// Record a trust interaction with a peer by creating a proposal block.
    #[tool(
        name = "trustchain_record_interaction",
        description = "Record a trust interaction with a peer by creating a proposal block on \
                        the bilateral ledger. The counterparty must sign the agreement to \
                        complete the record. Returns the proposal block hash and sequence number."
    )]
    async fn record_interaction(
        &self,
        params: Parameters<RecordInteractionParams>,
    ) -> Result<CallToolResult, McpError> {
        let mut proto = self.protocol.lock().await;
        let tx = params
            .0
            .transaction
            .clone()
            .unwrap_or(serde_json::json!({}));

        let proposal = proto
            .create_proposal(&params.0.peer, tx, None)
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        let result = serde_json::json!({
            "status": "proposal_created",
            "block_hash": proposal.block_hash,
            "sequence_number": proposal.sequence_number,
            "peer": params.0.peer,
        });

        Ok(CallToolResult::success(vec![Content::text(
            serde_json::to_string_pretty(&result).unwrap(),
        )]))
    }

    /// Get this node's identity information.
    #[tool(
        name = "trustchain_get_identity",
        description = "Get this node's identity: Ed25519 public key, chain length, block count, \
                        known peer count, and agent endpoint (if running as sidecar)."
    )]
    async fn get_identity(&self) -> Result<CallToolResult, McpError> {
        let proto = self.protocol.lock().await;
        let pubkey = proto.pubkey();
        let store = proto.store();
        let latest_seq = store.get_latest_seq(&pubkey).unwrap_or(0);
        let block_count = store.get_block_count().unwrap_or(0);
        let peer_count = self.discovery.peer_count().await;

        let result = serde_json::json!({
            "public_key": pubkey,
            "latest_sequence": latest_seq,
            "block_count": block_count,
            "peer_count": peer_count,
            "agent_endpoint": self.agent_endpoint,
        });

        Ok(CallToolResult::success(vec![Content::text(
            serde_json::to_string_pretty(&result).unwrap(),
        )]))
    }

    /// Verify the integrity of a peer's trust chain.
    #[tool(
        name = "trustchain_verify_chain",
        description = "Verify the integrity of a peer's trust chain. Checks hash links, \
                        signatures, and sequence continuity. Returns validation status, \
                        integrity score, and a tampering summary."
    )]
    async fn verify_chain(
        &self,
        params: Parameters<VerifyChainParams>,
    ) -> Result<CallToolResult, McpError> {
        let proto = self.protocol.lock().await;
        let store = proto.store();

        let is_valid = proto
            .validate_chain(&params.0.peer)
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        let integrity = proto.integrity_score(&params.0.peer).unwrap_or(0.0);
        let chain = store.get_chain(&params.0.peer).unwrap_or_default();

        let crawler = BlockStoreCrawler::new(store);
        let report = crawler
            .detect_tampering()
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        let result = serde_json::json!({
            "peer": params.0.peer,
            "is_valid": is_valid,
            "integrity_score": integrity,
            "chain_length": chain.len(),
            "tampering_report": {
                "is_clean": report.is_clean(),
                "issue_count": report.issue_count(),
                "chain_gaps": report.chain_gaps.len(),
                "hash_breaks": report.hash_breaks.len(),
                "signature_failures": report.signature_failures.len(),
            }
        });

        Ok(CallToolResult::success(vec![Content::text(
            serde_json::to_string_pretty(&result).unwrap(),
        )]))
    }
}

// ---------------------------------------------------------------------------
// ServerHandler implementation
// ---------------------------------------------------------------------------

impl<S: BlockStore + 'static> ServerHandler for TrustChainMcpServer<S> {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            protocol_version: ProtocolVersion::V_2025_03_26,
            capabilities: ServerCapabilities::builder().enable_tools().build(),
            server_info: Implementation {
                name: "trustchain".into(),
                version: env!("CARGO_PKG_VERSION").into(),
                title: None,
                description: None,
                website_url: None,
                icons: None,
            },
            instructions: Some(
                "TrustChain — decentralized trust for AI agents. \
                 Check trust scores, discover peers, record interactions, \
                 and verify chain integrity."
                    .into(),
            ),
        }
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let tcc = rmcp::handler::server::tool::ToolCallContext::new(self, request, context);
        self.tool_router.call(tcc).await
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        Ok(ListToolsResult::with_all_items(self.tool_router.list_all()))
    }
}

// ---------------------------------------------------------------------------
// Transport helpers
// ---------------------------------------------------------------------------

/// Build a `StreamableHttpService` for mounting on an axum router via `nest_service("/mcp", ..)`.
pub fn build_mcp_http_service<S: BlockStore + 'static>(
    protocol: Arc<Mutex<TrustChainProtocol<S>>>,
    discovery: Arc<PeerDiscovery>,
    agent_endpoint: Option<String>,
    seed_nodes: Vec<String>,
) -> StreamableHttpService<TrustChainMcpServer<S>, LocalSessionManager> {
    StreamableHttpService::new(
        move || {
            Ok(TrustChainMcpServer::new(
                protocol.clone(),
                discovery.clone(),
                agent_endpoint.clone(),
                seed_nodes.clone(),
            ))
        },
        LocalSessionManager::default().into(),
        StreamableHttpServerConfig::default(),
    )
}

/// Run the MCP server over stdio (stdin/stdout). Blocks until the client disconnects.
pub async fn run_mcp_stdio<S: BlockStore + 'static>(
    protocol: Arc<Mutex<TrustChainProtocol<S>>>,
    discovery: Arc<PeerDiscovery>,
    seed_nodes: Vec<String>,
) -> anyhow::Result<()> {
    let server = TrustChainMcpServer::new(protocol, discovery, None, seed_nodes);
    let transport = rmcp::transport::io::stdio();
    let service = server
        .serve(transport)
        .await
        .map_err(|e| anyhow::anyhow!("MCP stdio init failed: {e}"))?;
    service
        .waiting()
        .await
        .map_err(|e| anyhow::anyhow!("MCP stdio error: {e}"))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use trustchain_core::{Identity, MemoryBlockStore};

    fn make_test_server() -> TrustChainMcpServer<MemoryBlockStore> {
        let identity = Identity::from_bytes(&[1u8; 32]);
        let store = MemoryBlockStore::new();
        let protocol = TrustChainProtocol::new(identity.clone(), store);
        let discovery = PeerDiscovery::new(identity.pubkey_hex(), vec![]);

        TrustChainMcpServer::new(
            Arc::new(Mutex::new(protocol)),
            Arc::new(discovery),
            Some("http://localhost:9002".to_string()),
            vec![],
        )
    }

    #[tokio::test]
    async fn test_get_identity() {
        let server = make_test_server();
        let result = server.get_identity().await.unwrap();
        assert!(!result.content.is_empty());
        let json = parse_tool_json(&result);
        assert!(json.get("public_key").is_some());
        assert_eq!(json["peer_count"], 0);
        assert_eq!(json["agent_endpoint"], "http://localhost:9002");
    }

    #[tokio::test]
    async fn test_check_trust_unknown_peer() {
        let server = make_test_server();
        let params = Parameters(CheckTrustParams {
            peer: "deadbeef".to_string(),
        });
        let result = server.check_trust(params).await.unwrap();
        let json = parse_tool_json(&result);
        // Unknown peers get a neutral trust score (not necessarily 0.0).
        assert!(json["trust_score"].as_f64().unwrap() >= 0.0);
        assert_eq!(json["interaction_count"], 0);
    }

    #[tokio::test]
    async fn test_discover_peers_empty() {
        let server = make_test_server();
        let params = Parameters(DiscoverPeersParams {
            capability: None,
            min_trust: None,
            max_results: None,
        });
        let result = server.discover_peers(params).await.unwrap();
        let json = parse_tool_json(&result);
        assert_eq!(json["peer_count"], 0);
    }

    #[tokio::test]
    async fn test_record_interaction() {
        let server = make_test_server();
        let bob = Identity::from_bytes(&[2u8; 32]);
        let params = Parameters(RecordInteractionParams {
            peer: bob.pubkey_hex(),
            transaction: Some(serde_json::json!({"service": "test"})),
        });
        let result = server.record_interaction(params).await.unwrap();
        let json = parse_tool_json(&result);
        assert_eq!(json["status"], "proposal_created");
        assert_eq!(json["sequence_number"], 1);
    }

    #[tokio::test]
    async fn test_verify_chain_empty() {
        let server = make_test_server();
        let params = Parameters(VerifyChainParams {
            peer: "deadbeef".to_string(),
        });
        let result = server.verify_chain(params).await.unwrap();
        let json = parse_tool_json(&result);
        assert!(json.get("is_valid").is_some());
        assert!(json.get("integrity_score").is_some());
        assert!(json.get("tampering_report").is_some());
    }

    #[test]
    fn test_tool_count() {
        let server = make_test_server();
        let tools = server.tool_router.list_all();
        assert_eq!(tools.len(), 5, "expected 5 MCP tools, got {}", tools.len());
    }

    fn make_test_server_with_seeds(seeds: Vec<String>) -> TrustChainMcpServer<MemoryBlockStore> {
        let identity = Identity::from_bytes(&[1u8; 32]);
        let store = MemoryBlockStore::new();
        let protocol = TrustChainProtocol::new(identity.clone(), store);
        let discovery = PeerDiscovery::new(identity.pubkey_hex(), vec![]);

        TrustChainMcpServer::new(
            Arc::new(Mutex::new(protocol)),
            Arc::new(discovery),
            Some("http://localhost:9002".to_string()),
            seeds,
        )
    }

    #[tokio::test]
    async fn test_check_trust_with_seed_nodes() {
        let seed = Identity::from_bytes(&[1u8; 32]); // server itself as seed
        let server = make_test_server_with_seeds(vec![seed.pubkey_hex()]);

        // Record an interaction first to give the peer some trust.
        let bob = Identity::from_bytes(&[2u8; 32]);
        let record_params = Parameters(RecordInteractionParams {
            peer: bob.pubkey_hex(),
            transaction: Some(serde_json::json!({"service": "test"})),
        });
        server.record_interaction(record_params).await.unwrap();

        // Check trust — with seed nodes, netflow component should contribute.
        let params = Parameters(CheckTrustParams {
            peer: bob.pubkey_hex(),
        });
        let result = server.check_trust(params).await.unwrap();
        let json = parse_tool_json(&result);
        let trust = json["trust_score"].as_f64().unwrap();
        assert!(
            trust >= 0.0,
            "trust with seed nodes should be non-negative: {trust}"
        );
    }

    #[tokio::test]
    async fn test_record_then_check_trust() {
        let server = make_test_server();
        let bob = Identity::from_bytes(&[2u8; 32]);

        // Record an interaction.
        let record_params = Parameters(RecordInteractionParams {
            peer: bob.pubkey_hex(),
            transaction: Some(serde_json::json!({"service": "compute"})),
        });
        let record_result = server.record_interaction(record_params).await.unwrap();
        let record_json = parse_tool_json(&record_result);
        assert_eq!(record_json["status"], "proposal_created");
        assert_eq!(record_json["sequence_number"], 1);

        // Check our own identity — our chain should have the proposal we just created.
        let identity_result = server.get_identity().await.unwrap();
        let identity_json = parse_tool_json(&identity_result);
        let our_pubkey = identity_json["public_key"].as_str().unwrap().to_string();

        let check_params = Parameters(CheckTrustParams { peer: our_pubkey });
        let check_result = server.check_trust(check_params).await.unwrap();
        let check_json = parse_tool_json(&check_result);
        let count = check_json["interaction_count"].as_u64().unwrap();
        assert!(
            count >= 1,
            "our chain should have at least 1 block after recording: {count}"
        );
    }

    /// Helper: extract the first text content from a CallToolResult and parse as JSON.
    fn parse_tool_json(result: &CallToolResult) -> serde_json::Value {
        let raw = result
            .content
            .first()
            .and_then(|c| c.as_text())
            .expect("expected text content");
        serde_json::from_str(&raw.text).expect("expected valid JSON")
    }
}
