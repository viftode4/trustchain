//! HTTP REST API for TrustChain nodes, using Axum.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use trustchain_core::{BlockStore, DelegationStore, HalfBlock, TrustChainProtocol, TrustEngine};

use crate::discover::{self, CapabilityQuery, DiscoveredAgent};
use crate::discovery::PeerDiscovery;
use crate::message::{MessageType, TransportMessage, block_to_bytes, bytes_to_block};
use crate::quic::QuicTransport;

/// Shared application state for HTTP handlers, generic over BlockStore and DelegationStore.
pub struct AppState<S: BlockStore + 'static, D: DelegationStore + 'static = trustchain_core::MemoryDelegationStore> {
    pub protocol: Arc<Mutex<TrustChainProtocol<S>>>,
    pub discovery: Arc<PeerDiscovery>,
    /// QUIC transport for P2P communication (optional — None in tests).
    pub quic: Option<Arc<QuicTransport>>,
    /// The agent endpoint this sidecar proxies for (e.g. "http://localhost:9002").
    pub agent_endpoint: Option<String>,
    /// Delegation store for delegation/revocation/succession tracking.
    pub delegation_store: Arc<Mutex<D>>,
}

// Manual Clone impl — Arc handles the cloning, S/D don't need Clone.
impl<S: BlockStore + 'static, D: DelegationStore + 'static> Clone for AppState<S, D> {
    fn clone(&self) -> Self {
        Self {
            protocol: self.protocol.clone(),
            discovery: self.discovery.clone(),
            quic: self.quic.clone(),
            agent_endpoint: self.agent_endpoint.clone(),
            delegation_store: self.delegation_store.clone(),
        }
    }
}

/// Response for status endpoint.
#[derive(Serialize)]
pub struct StatusResponse {
    pub public_key: String,
    pub latest_seq: u64,
    pub block_count: usize,
    pub peer_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_endpoint: Option<String>,
}

/// Request for proposal endpoint.
#[derive(Deserialize)]
pub struct ProposeRequest {
    pub counterparty_pubkey: String,
    pub transaction: serde_json::Value,
}

/// Response for proposal endpoint.
#[derive(Serialize)]
pub struct ProposeResponse {
    pub proposal: HalfBlock,
    /// The agreement block, if P2P handshake completed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agreement: Option<HalfBlock>,
    /// Whether the full P2P handshake completed.
    pub completed: bool,
}

/// Request for receiving a proposal from a remote node.
#[derive(Deserialize)]
pub struct ReceiveProposalRequest {
    pub proposal: HalfBlock,
}

/// Response for receiving a proposal — returns the agreement if accepted.
#[derive(Serialize)]
pub struct ReceiveProposalResponse {
    pub accepted: bool,
    pub agreement: Option<HalfBlock>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Request for receiving an agreement from a remote node.
#[derive(Deserialize)]
pub struct ReceiveAgreementRequest {
    pub agreement: HalfBlock,
}

/// Response for receiving an agreement.
#[derive(Serialize)]
pub struct ReceiveAgreementResponse {
    pub accepted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Query parameters for crawl endpoint.
#[derive(Deserialize)]
pub struct CrawlQuery {
    pub start_seq: Option<u64>,
}

/// Query parameters for capability discovery endpoint.
#[derive(Deserialize)]
pub struct DiscoverParams {
    /// The capability to search for (e.g. "compute", "storage").
    pub capability: String,
    /// Minimum trust score for returned agents (0.0 - 1.0).
    pub min_trust: Option<f64>,
    /// Maximum results to return.
    pub max_results: Option<usize>,
    /// Number of peers to fan out the query to.
    pub fan_out: Option<usize>,
}

/// Response for capability discovery.
#[derive(Serialize)]
pub struct DiscoverResponse {
    pub agents: Vec<DiscoveredAgent>,
    /// How many peers were queried in the fan-out.
    pub queried_peers: usize,
}

/// Response for block retrieval.
#[derive(Serialize)]
pub struct BlockResponse {
    pub block: Option<HalfBlock>,
}

/// Response wrapping a list of blocks.
#[derive(Serialize)]
pub struct BlocksResponse {
    pub blocks: Vec<HalfBlock>,
}

/// Request for registering a peer at runtime.
#[derive(Deserialize)]
pub struct RegisterPeerRequest {
    pub pubkey: String,
    pub address: String,
    #[serde(default)]
    pub agent_endpoint: Option<String>,
}

/// Generic error response.
#[derive(Serialize)]
pub struct ErrorResponse {
    pub error: String,
}

/// Response for trust score endpoint.
#[derive(Serialize)]
pub struct TrustScoreResponse {
    pub pubkey: String,
    pub trust_score: f64,
    pub interaction_count: usize,
    pub block_count: usize,
}

/// Request for delegation endpoint.
#[derive(Deserialize)]
pub struct DelegateRequest {
    pub delegate_pubkey: String,
    #[serde(default)]
    pub scope: Vec<String>,
    #[serde(default)]
    pub max_depth: u32,
    /// TTL in seconds (converted to ms internally).
    #[serde(default = "default_ttl_seconds")]
    pub ttl_seconds: u64,
}

fn default_ttl_seconds() -> u64 {
    3600
}

/// Request for revocation endpoint.
#[derive(Deserialize)]
pub struct RevokeRequest {
    pub delegation_id: String,
}

/// Response for delegation endpoints.
#[derive(Serialize)]
pub struct DelegationResponse {
    pub block: HalfBlock,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delegation_id: Option<String>,
}

/// Response for identity resolution.
#[derive(Serialize)]
pub struct IdentityResponse {
    pub pubkey: String,
    pub resolved_pubkey: String,
    pub is_successor: bool,
}

/// Health check response.
#[derive(Serialize)]
pub struct HealthResponse {
    pub status: String,
    pub public_key: String,
}

/// Prometheus-style metrics response (plain text).
pub struct MetricsResponse(pub String);

#[derive(Serialize)]
pub struct PeerInfoResponse {
    pub pubkey: String,
    pub address: String,
    pub latest_seq: u64,
}

/// Build the Axum router with all REST endpoints.
pub fn build_router<S: BlockStore + Send + 'static, D: DelegationStore + Send + 'static>(
    state: AppState<S, D>,
) -> Router {
    Router::new()
        .route("/status", get(handle_status::<S, D>))
        .route("/healthz", get(handle_healthz::<S, D>))
        .route("/metrics", get(handle_metrics::<S, D>))
        .route("/propose", post(handle_propose::<S, D>))
        .route("/receive_proposal", post(handle_receive_proposal::<S, D>))
        .route("/receive_agreement", post(handle_receive_agreement::<S, D>))
        .route("/chain/{pubkey}", get(handle_get_chain::<S, D>))
        .route("/block/{pubkey}/{seq}", get(handle_get_block::<S, D>))
        .route("/crawl/{pubkey}", get(handle_crawl::<S, D>))
        .route("/peers", get(handle_get_peers::<S, D>).post(handle_register_peer::<S, D>))
        .route("/trust/{pubkey}", get(handle_trust_score::<S, D>))
        .route("/discover", get(handle_discover::<S, D>))
        .route("/delegate", post(handle_delegate::<S, D>))
        .route("/revoke", post(handle_revoke::<S, D>))
        .route("/delegations/{pubkey}", get(handle_get_delegations::<S, D>))
        .route("/delegation/{id}", get(handle_get_delegation::<S, D>))
        .route("/identity/{pubkey}", get(handle_identity::<S, D>))
        .with_state(state)
}

/// Start the HTTP server.
pub async fn start_http_server<S: BlockStore + Send + 'static, D: DelegationStore + Send + 'static>(
    addr: SocketAddr,
    state: AppState<S, D>,
) -> Result<(), Box<dyn std::error::Error>> {
    let router = build_router(state);

    log::info!("HTTP server listening on {addr}");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, router).await?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

async fn handle_status<S: BlockStore + 'static, D: DelegationStore + Send + 'static>(
    State(state): State<AppState<S, D>>,
) -> Result<Json<StatusResponse>, StatusCode> {
    let proto = state.protocol.lock().await;
    let pubkey = proto.pubkey();

    let latest_seq = proto.store().get_latest_seq(&pubkey).unwrap_or(0);
    let block_count = proto.store().get_block_count().unwrap_or(0);
    let peer_count = state.discovery.peer_count().await;

    Ok(Json(StatusResponse {
        public_key: pubkey,
        latest_seq,
        block_count,
        peer_count,
        agent_endpoint: state.agent_endpoint.clone(),
    }))
}

async fn handle_propose<S: BlockStore + 'static, D: DelegationStore + Send + 'static>(
    State(state): State<AppState<S, D>>,
    Json(req): Json<ProposeRequest>,
) -> Result<Json<ProposeResponse>, (StatusCode, Json<ErrorResponse>)> {
    // Step 1: Create proposal locally.
    let proposal = {
        let mut proto = state.protocol.lock().await;
        proto.create_proposal(&req.counterparty_pubkey, req.transaction, None)
            .map_err(|e| (StatusCode::BAD_REQUEST, Json(ErrorResponse { error: e.to_string() })))?
    };

    // Step 2: Look up the counterparty's address and send via QUIC P2P.
    let peer = state.discovery.get_peer(&req.counterparty_pubkey).await;
    let quic = state.quic.as_ref();

    if let (Some(peer), Some(quic)) = (peer, quic) {
        // Parse the peer's QUIC address.
        let quic_addr = peer_quic_addr(&peer.address);
        if let Ok(addr) = quic_addr {
            // Build TransportMessage with the proposal.
            let our_pubkey = {
                let proto = state.protocol.lock().await;
                proto.pubkey()
            };
            let msg = TransportMessage::new(
                MessageType::Proposal,
                our_pubkey,
                block_to_bytes(&proposal),
                uuid_v4(),
            );

            let msg_bytes = serde_json::to_vec(&msg).unwrap_or_default();

            // Send proposal over QUIC and wait for agreement response.
            match tokio::time::timeout(
                std::time::Duration::from_secs(10),
                quic.send_message(addr, &msg_bytes),
            ).await {
                Ok(Ok(response_bytes)) => {
                    // Try to parse the response as a TransportMessage containing an agreement.
                    if let Ok(resp_msg) = serde_json::from_slice::<TransportMessage>(&response_bytes) {
                        if resp_msg.message_type == MessageType::Agreement {
                            if let Ok(agreement) = bytes_to_block(&resp_msg.payload) {
                                // Store the agreement locally.
                                let mut proto = state.protocol.lock().await;
                                match proto.receive_agreement(&agreement) {
                                    Ok(_) => {
                                        return Ok(Json(ProposeResponse {
                                            proposal,
                                            agreement: Some(agreement),
                                            completed: true,
                                        }));
                                    }
                                    Err(e) => {
                                        log::warn!("P2P agreement invalid: {e}");
                                    }
                                }
                            }
                        }
                    }
                    // Response wasn't a valid agreement — check if it's an error.
                    if let Ok(err_resp) = serde_json::from_slice::<serde_json::Value>(&response_bytes) {
                        if let Some(err_msg) = err_resp.get("error").and_then(|v| v.as_str()) {
                            log::warn!("peer rejected proposal: {err_msg}");
                        }
                    }
                }
                Ok(Err(e)) => {
                    log::warn!("QUIC send failed: {e}");
                }
                Err(_) => {
                    log::warn!("QUIC proposal timed out");
                }
            }
        }
    }

    // P2P not available or failed — return proposal only.
    Ok(Json(ProposeResponse {
        proposal,
        agreement: None,
        completed: false,
    }))
}

/// Derive the QUIC address from a peer's HTTP address.
/// Peers store HTTP addresses like "127.0.0.1:8202" — QUIC is on port - 2.
pub(crate) fn peer_quic_addr(http_addr: &str) -> Result<std::net::SocketAddr, String> {
    let addr = http_addr
        .strip_prefix("http://")
        .unwrap_or(http_addr);
    addr.parse::<std::net::SocketAddr>()
        .map(|a| std::net::SocketAddr::new(a.ip(), a.port() - 2))
        .map_err(|e| format!("invalid peer address: {e}"))
}

/// Generate a simple request ID.
pub(crate) fn uuid_v4() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    format!("{:016x}{:016x}", rng.gen::<u64>(), rng.gen::<u64>())
}

/// Receive a proposal from a remote node — validates, stores, and returns agreement.
async fn handle_receive_proposal<S: BlockStore + 'static, D: DelegationStore + Send + 'static>(
    State(state): State<AppState<S, D>>,
    Json(req): Json<ReceiveProposalRequest>,
) -> Json<ReceiveProposalResponse> {
    let mut proto = state.protocol.lock().await;

    // Receive and validate the proposal.
    if let Err(e) = proto.receive_proposal(&req.proposal) {
        return Json(ReceiveProposalResponse {
            accepted: false,
            agreement: None,
            error: Some(e.to_string()),
        });
    }

    // Create agreement.
    match proto.create_agreement(&req.proposal, None) {
        Ok(agreement) => Json(ReceiveProposalResponse {
            accepted: true,
            agreement: Some(agreement),
            error: None,
        }),
        Err(e) => Json(ReceiveProposalResponse {
            accepted: false,
            agreement: None,
            error: Some(e.to_string()),
        }),
    }
}

/// Receive an agreement from a remote node — validates and stores.
async fn handle_receive_agreement<S: BlockStore + 'static, D: DelegationStore + Send + 'static>(
    State(state): State<AppState<S, D>>,
    Json(req): Json<ReceiveAgreementRequest>,
) -> Json<ReceiveAgreementResponse> {
    let mut proto = state.protocol.lock().await;

    match proto.receive_agreement(&req.agreement) {
        Ok(_) => Json(ReceiveAgreementResponse {
            accepted: true,
            error: None,
        }),
        Err(e) => Json(ReceiveAgreementResponse {
            accepted: false,
            error: Some(e.to_string()),
        }),
    }
}

async fn handle_get_chain<S: BlockStore + 'static, D: DelegationStore + Send + 'static>(
    State(state): State<AppState<S, D>>,
    Path(pubkey): Path<String>,
) -> Result<Json<BlocksResponse>, StatusCode> {
    let proto = state.protocol.lock().await;

    match proto.store().get_chain(&pubkey) {
        Ok(blocks) => Ok(Json(BlocksResponse { blocks })),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

async fn handle_get_block<S: BlockStore + 'static, D: DelegationStore + Send + 'static>(
    State(state): State<AppState<S, D>>,
    Path((pubkey, seq)): Path<(String, u64)>,
) -> Result<Json<BlockResponse>, StatusCode> {
    let proto = state.protocol.lock().await;

    match proto.store().get_block(&pubkey, seq) {
        Ok(block) => Ok(Json(BlockResponse { block })),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

async fn handle_crawl<S: BlockStore + 'static, D: DelegationStore + Send + 'static>(
    State(state): State<AppState<S, D>>,
    Path(pubkey): Path<String>,
    Query(params): Query<CrawlQuery>,
) -> Result<Json<BlocksResponse>, StatusCode> {
    let proto = state.protocol.lock().await;
    let start = params.start_seq.unwrap_or(1);

    match proto.store().crawl(&pubkey, start) {
        Ok(blocks) => Ok(Json(BlocksResponse { blocks })),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

async fn handle_get_peers<S: BlockStore + 'static, D: DelegationStore + Send + 'static>(
    State(state): State<AppState<S, D>>,
) -> Json<Vec<PeerInfoResponse>> {
    let peers = state.discovery.get_peers().await;
    let response: Vec<PeerInfoResponse> = peers
        .iter()
        .map(|p| PeerInfoResponse {
            pubkey: p.pubkey.clone(),
            address: p.address.clone(),
            latest_seq: p.latest_seq,
        })
        .collect();
    Json(response)
}

/// Register a peer at runtime (for bidirectional discovery).
async fn handle_register_peer<S: BlockStore + 'static, D: DelegationStore + Send + 'static>(
    State(state): State<AppState<S, D>>,
    Json(req): Json<RegisterPeerRequest>,
) -> Json<serde_json::Value> {
    state
        .discovery
        .add_peer(req.pubkey.clone(), req.address, 0)
        .await;
    if let Some(ep) = req.agent_endpoint {
        state.discovery.add_alias(ep, req.pubkey).await;
    }
    Json(serde_json::json!({"status": "ok"}))
}

/// Query the trust score for a given public key.
async fn handle_trust_score<S: BlockStore + 'static, D: DelegationStore + Send + 'static>(
    State(state): State<AppState<S, D>>,
    Path(pubkey): Path<String>,
) -> Result<Json<TrustScoreResponse>, (StatusCode, Json<ErrorResponse>)> {
    let proto = state.protocol.lock().await;
    let store = proto.store();

    let engine = TrustEngine::new(store, None, None);
    let trust_score = engine.compute_trust(&pubkey).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )
    })?;

    let chain = store.get_chain(&pubkey).unwrap_or_default();
    let interaction_count = chain.len();
    let block_count = store.get_block_count().unwrap_or(0);

    Ok(Json(TrustScoreResponse {
        pubkey,
        trust_score,
        interaction_count,
        block_count,
    }))
}

/// P2P capability discovery — find agents by proven interaction history.
///
/// Fans out to trusted peers via QUIC, merges results, ranks by trust score.
async fn handle_discover<S: BlockStore + 'static, D: DelegationStore + Send + 'static>(
    State(state): State<AppState<S, D>>,
    Query(params): Query<DiscoverParams>,
) -> Json<DiscoverResponse> {
    let max_results = params.max_results.unwrap_or(20);
    let min_trust = params.min_trust.unwrap_or(0.0);
    let fan_out = params.fan_out.unwrap_or(5);

    // 1. Query local blockstore.
    let mut agents_map: std::collections::HashMap<String, DiscoveredAgent> = {
        let proto = state.protocol.lock().await;
        let local = discover::find_capable_agents(proto.store(), &params.capability, max_results);
        local.into_iter().map(|a| (a.pubkey.clone(), a)).collect()
    };

    // 2. Fan out to trusted peers via QUIC.
    let peers = state.discovery.get_gossip_peers(fan_out).await;
    let queried_peers = peers.len();

    if let Some(quic) = &state.quic {
        let query = CapabilityQuery {
            capability: params.capability.clone(),
            max_results,
        };
        let query_bytes = serde_json::to_vec(&query).unwrap_or_default();

        let mut handles = Vec::new();
        for peer in &peers {
            let quic = quic.clone();
            let query_bytes = query_bytes.clone();
            let peer_addr = peer.address.clone();

            handles.push(tokio::spawn(async move {
                let quic_addr = peer_quic_addr(&peer_addr)
                    .map_err(|e| anyhow::anyhow!(e))?;
                let msg = TransportMessage::new(
                    MessageType::CapabilityRequest,
                    String::new(),
                    query_bytes,
                    uuid_v4(),
                );
                let msg_bytes = serde_json::to_vec(&msg)?;

                let resp_bytes = tokio::time::timeout(
                    std::time::Duration::from_secs(5),
                    quic.send_message(quic_addr, &msg_bytes),
                )
                .await
                .map_err(|_| anyhow::anyhow!("timeout"))?
                .map_err(|e| anyhow::anyhow!("QUIC: {e}"))?;

                let resp_msg: TransportMessage = serde_json::from_slice(&resp_bytes)?;
                let agents: Vec<DiscoveredAgent> =
                    serde_json::from_slice(&resp_msg.payload).unwrap_or_default();
                Ok::<_, anyhow::Error>(agents)
            }));
        }

        for handle in handles {
            if let Ok(Ok(agents)) = handle.await {
                for agent in agents {
                    agents_map
                        .entry(agent.pubkey.clone())
                        .and_modify(|existing| {
                            // Keep the higher interaction count.
                            existing.interaction_count =
                                existing.interaction_count.max(agent.interaction_count);
                            // Prefer an address if we don't have one.
                            if existing.address.is_none() {
                                existing.address = agent.address.clone();
                            }
                        })
                        .or_insert(agent);
                }
            }
        }
    }

    // 3. Compute trust scores (requires protocol lock for store access).
    {
        let proto = state.protocol.lock().await;
        let engine = TrustEngine::new(proto.store(), None, None);
        for agent in agents_map.values_mut() {
            agent.trust_score = engine.compute_trust(&agent.pubkey).ok();
        }
    }

    // 4. Enrich with addresses from peer discovery.
    for agent in agents_map.values_mut() {
        if agent.address.is_none() {
            if let Some(peer) = state.discovery.get_peer(&agent.pubkey).await {
                agent.address = Some(peer.address);
            }
        }
    }

    // 5. Filter by min_trust and sort by trust score descending.
    let mut results: Vec<DiscoveredAgent> = agents_map
        .into_values()
        .filter(|a| a.trust_score.unwrap_or(0.0) >= min_trust)
        .collect();

    results.sort_by(|a, b| {
        b.trust_score
            .unwrap_or(0.0)
            .partial_cmp(&a.trust_score.unwrap_or(0.0))
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    results.truncate(max_results);

    Json(DiscoverResponse {
        agents: results,
        queried_peers,
    })
}

// ---------------------------------------------------------------------------
// Observability handlers
// ---------------------------------------------------------------------------

async fn handle_healthz<S: BlockStore + 'static, D: DelegationStore + Send + 'static>(
    State(state): State<AppState<S, D>>,
) -> Result<Json<HealthResponse>, StatusCode> {
    let proto = state.protocol.lock().await;
    let pubkey = proto.pubkey();
    Ok(Json(HealthResponse {
        status: "ok".to_string(),
        public_key: pubkey,
    }))
}

async fn handle_metrics<S: BlockStore + 'static, D: DelegationStore + Send + 'static>(
    State(state): State<AppState<S, D>>,
) -> (StatusCode, [(axum::http::HeaderName, &'static str); 1], String) {
    let proto = state.protocol.lock().await;
    let pubkey = proto.pubkey();
    let block_count = proto.store().get_block_count().unwrap_or(0);
    let chain_length = proto.store().get_latest_seq(&pubkey).unwrap_or(0);
    drop(proto);

    let peer_count = state.discovery.peer_count().await;
    let delegation_count = {
        let ds = state.delegation_store.lock().await;
        ds.delegation_count().unwrap_or(0)
    };

    let metrics = format!(
        "# HELP trustchain_block_count Total blocks stored\n\
         # TYPE trustchain_block_count gauge\n\
         trustchain_block_count {block_count}\n\
         # HELP trustchain_chain_length Length of this node's chain\n\
         # TYPE trustchain_chain_length gauge\n\
         trustchain_chain_length {chain_length}\n\
         # HELP trustchain_peer_count Number of known peers\n\
         # TYPE trustchain_peer_count gauge\n\
         trustchain_peer_count {peer_count}\n\
         # HELP trustchain_delegation_count Number of delegations\n\
         # TYPE trustchain_delegation_count gauge\n\
         trustchain_delegation_count {delegation_count}\n"
    );

    (
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "text/plain; version=0.0.4")],
        metrics,
    )
}

// ---------------------------------------------------------------------------
// Delegation handlers
// ---------------------------------------------------------------------------

async fn handle_delegate<S: BlockStore + 'static, D: DelegationStore + Send + 'static>(
    State(state): State<AppState<S, D>>,
    Json(req): Json<DelegateRequest>,
) -> Result<Json<DelegationResponse>, (StatusCode, Json<ErrorResponse>)> {
    let mut proto = state.protocol.lock().await;
    let ds = state.delegation_store.clone();
    let ds_guard = ds.lock().await;

    let block = proto
        .create_delegation_proposal(
            &req.delegate_pubkey,
            req.scope,
            req.max_depth,
            req.ttl_seconds * 1000, // convert seconds to ms
            Some(&*ds_guard),
        )
        .map_err(|e| (StatusCode::BAD_REQUEST, Json(ErrorResponse { error: e.to_string() })))?;

    let delegation_id = block.transaction["delegation_id"]
        .as_str()
        .map(|s| s.to_string());

    Ok(Json(DelegationResponse {
        block,
        delegation_id,
    }))
}

async fn handle_revoke<S: BlockStore + 'static, D: DelegationStore + Send + 'static>(
    State(state): State<AppState<S, D>>,
    Json(req): Json<RevokeRequest>,
) -> Result<Json<DelegationResponse>, (StatusCode, Json<ErrorResponse>)> {
    let mut proto = state.protocol.lock().await;
    let mut ds = state.delegation_store.lock().await;

    let block = proto
        .create_revocation(&req.delegation_id, &mut *ds)
        .map_err(|e| (StatusCode::BAD_REQUEST, Json(ErrorResponse { error: e.to_string() })))?;

    Ok(Json(DelegationResponse {
        block,
        delegation_id: Some(req.delegation_id),
    }))
}

async fn handle_get_delegations<S: BlockStore + 'static, D: DelegationStore + Send + 'static>(
    State(state): State<AppState<S, D>>,
    Path(pubkey): Path<String>,
) -> Result<Json<Vec<trustchain_core::DelegationRecord>>, StatusCode> {
    let ds = state.delegation_store.lock().await;
    let delegations = ds
        .get_delegations_for_pubkey(&pubkey)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(delegations))
}

async fn handle_get_delegation<S: BlockStore + 'static, D: DelegationStore + Send + 'static>(
    State(state): State<AppState<S, D>>,
    Path(id): Path<String>,
) -> Result<Json<trustchain_core::DelegationRecord>, (StatusCode, Json<ErrorResponse>)> {
    let ds = state.delegation_store.lock().await;
    let delegation = ds
        .get_delegation(&id)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: e.to_string() })))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, Json(ErrorResponse { error: "Delegation not found".to_string() })))?;
    Ok(Json(delegation))
}

async fn handle_identity<S: BlockStore + 'static, D: DelegationStore + Send + 'static>(
    State(state): State<AppState<S, D>>,
    Path(pubkey): Path<String>,
) -> Result<Json<IdentityResponse>, StatusCode> {
    let ds = state.delegation_store.lock().await;
    let resolved = ds
        .resolve_identity(&pubkey)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(IdentityResponse {
        pubkey: pubkey.clone(),
        resolved_pubkey: resolved.clone(),
        is_successor: resolved != pubkey,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;
    use trustchain_core::{Identity, MemoryBlockStore, MemoryDelegationStore};

    fn make_test_state() -> AppState<MemoryBlockStore, MemoryDelegationStore> {
        let identity = Identity::from_bytes(&[1u8; 32]);
        let store = MemoryBlockStore::new();
        let protocol = TrustChainProtocol::new(identity.clone(), store);
        let discovery = PeerDiscovery::new(identity.pubkey_hex(), vec![]);

        AppState {
            protocol: Arc::new(Mutex::new(protocol)),
            discovery: Arc::new(discovery),
            quic: None,
            agent_endpoint: None,
            delegation_store: Arc::new(Mutex::new(MemoryDelegationStore::new())),
        }
    }

    #[tokio::test]
    async fn test_status_endpoint() {
        let state = make_test_state();
        let app = build_router(state);

        let request = Request::builder()
            .uri("/status")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_propose_endpoint() {
        let state = make_test_state();
        let app = build_router(state);

        let bob_pubkey = Identity::from_bytes(&[2u8; 32]).pubkey_hex();
        let body = serde_json::json!({
            "counterparty_pubkey": bob_pubkey,
            "transaction": {"service": "compute"},
        });

        let request = Request::builder()
            .method("POST")
            .uri("/propose")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&body).unwrap()))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_chain_endpoint_empty() {
        let state = make_test_state();
        let app = build_router(state);

        let request = Request::builder()
            .uri("/chain/nonexistent")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_peers_endpoint() {
        let state = make_test_state();
        let app = build_router(state);

        let request = Request::builder()
            .uri("/peers")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_trust_endpoint() {
        let state = make_test_state();
        let app = build_router(state);

        let bob = Identity::from_bytes(&[2u8; 32]);
        let request = Request::builder()
            .uri(&format!("/trust/{}", bob.pubkey_hex()))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let trust_resp: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(trust_resp.get("trust_score").is_some());
        assert!(trust_resp.get("interaction_count").is_some());
    }

    #[tokio::test]
    async fn test_status_includes_agent_endpoint() {
        let identity = Identity::from_bytes(&[1u8; 32]);
        let store = MemoryBlockStore::new();
        let protocol = TrustChainProtocol::new(identity.clone(), store);
        let discovery = PeerDiscovery::new(identity.pubkey_hex(), vec![]);

        let state = AppState {
            protocol: Arc::new(Mutex::new(protocol)),
            discovery: Arc::new(discovery),
            quic: None,
            agent_endpoint: Some("http://localhost:9002".to_string()),
            delegation_store: Arc::new(Mutex::new(MemoryDelegationStore::new())),
        };
        let app = build_router(state);

        let request = Request::builder()
            .uri("/status")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let status: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(status["agent_endpoint"], "http://localhost:9002");
    }

    #[tokio::test]
    async fn test_register_peer_endpoint() {
        let state = make_test_state();
        let app = build_router(state.clone());

        let body = serde_json::json!({
            "pubkey": "deadbeef",
            "address": "http://127.0.0.1:8212",
            "agent_endpoint": "http://localhost:9002",
        });

        let request = Request::builder()
            .method("POST")
            .uri("/peers")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&body).unwrap()))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        // Verify peer was registered.
        let peer = state.discovery.get_peer("deadbeef").await;
        assert!(peer.is_some());

        // Verify alias was registered.
        let by_alias = state.discovery.get_peer_by_address("localhost:9002").await;
        assert!(by_alias.is_some());
        assert_eq!(by_alias.unwrap().pubkey, "deadbeef");
    }

    #[tokio::test]
    async fn test_receive_proposal_endpoint() {
        let state = make_test_state();

        // Create a proposal from Alice to the test node.
        let alice = Identity::from_bytes(&[2u8; 32]);
        let test_pubkey = Identity::from_bytes(&[1u8; 32]).pubkey_hex();
        let proposal = trustchain_core::create_half_block(
            &alice,
            1,
            &test_pubkey,
            0,
            trustchain_core::GENESIS_HASH,
            trustchain_core::BlockType::Proposal,
            serde_json::json!({"service": "test"}),
            Some(1000),
        );

        let app = build_router(state);
        let body = serde_json::json!({ "proposal": proposal });

        let request = Request::builder()
            .method("POST")
            .uri("/receive_proposal")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&body).unwrap()))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
}
