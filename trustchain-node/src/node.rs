//! Node — wires together protocol, storage, and all transports.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{mpsc, Mutex};

use trustchain_core::{
    validate_block_invariants, verify_block, BlockStore, CHECOConsensus, HalfBlock, Identity,
    PersistentPeer, SqliteBlockStore, SqliteDelegationStore, TrustChainProtocol, ValidationResult,
};
use trustchain_transport::{
    build_router, discover,
    message::{
        block_to_bytes, bytes_to_block, BlockPairBroadcastPayload, CheckpointFinalizedPayload,
        CheckpointProposalPayload, CheckpointVotePayload, CheckpointWire, FraudProofPayload,
        MessageType, TransportMessage,
    },
    start_grpc_server, start_proxy_server, AppState, ConnectionPool, PeerDiscovery, ProxyState,
    QuicTransport, QUIC_PORT_OFFSET,
};

use crate::config::NodeConfig;

/// Default broadcast fanout (number of peers to gossip to).
const BROADCAST_FANOUT: usize = 10;
/// Default TTL for broadcast messages.
const BROADCAST_TTL: u8 = 3;
/// Max number of relayed block IDs to track (ring buffer).
const BROADCAST_HISTORY_SIZE: usize = 10_000;

/// Tracks which block IDs we've already relayed, preventing infinite loops.
#[derive(Debug)]
pub struct BroadcastTracker {
    /// Set of block IDs we've seen (block_hash values).
    seen: std::collections::HashSet<String>,
    /// Order of insertion for eviction (ring buffer).
    order: VecDeque<String>,
}

impl BroadcastTracker {
    pub fn new() -> Self {
        Self {
            seen: std::collections::HashSet::new(),
            order: VecDeque::new(),
        }
    }

    /// Returns true if this block ID was NOT seen before (and marks it as seen).
    pub fn mark_if_new(&mut self, block_id: &str) -> bool {
        if self.seen.contains(block_id) {
            return false;
        }
        self.seen.insert(block_id.to_string());
        self.order.push_back(block_id.to_string());
        // Evict old entries.
        while self.seen.len() > BROADCAST_HISTORY_SIZE {
            if let Some(old) = self.order.pop_front() {
                self.seen.remove(&old);
            }
        }
        true
    }
}

/// A running TrustChain node.
pub struct Node {
    pub identity: Identity,
    pub config: NodeConfig,
    pub protocol: Arc<Mutex<TrustChainProtocol<SqliteBlockStore>>>,
    pub discovery: Arc<PeerDiscovery>,
    pub pool: Arc<ConnectionPool>,
    pub broadcast_tracker: Arc<Mutex<BroadcastTracker>>,
    pub consensus: Arc<Mutex<CHECOConsensus<SqliteBlockStore>>>,
    pub delegation_store: Arc<Mutex<SqliteDelegationStore>>,
    /// Latest finalized checkpoint, shared with HTTP handlers for trust queries.
    pub latest_checkpoint: Arc<Mutex<Option<trustchain_core::Checkpoint>>>,
}

impl Node {
    /// Create a new node from configuration.
    pub fn new(identity: Identity, config: NodeConfig) -> Self {
        let db_path = config.db_path.to_str().unwrap_or("trustchain.db");
        let store = SqliteBlockStore::open(db_path).expect("failed to open SQLite database");
        let protocol = TrustChainProtocol::new(identity.clone(), store);

        // Second store handle to the same DB file (WAL mode enables concurrent readers).
        let consensus_store =
            SqliteBlockStore::open(db_path).expect("failed to open SQLite database for consensus");

        // Load persisted checkpoints from previous runs.
        let persisted_checkpoints = consensus_store.load_checkpoints().unwrap_or_default();
        let checkpoint_count = persisted_checkpoints.len();

        let mut consensus =
            CHECOConsensus::new(identity.clone(), consensus_store, None, config.min_signers);
        // Extract latest checkpoint before loading into consensus.
        let latest_cp = persisted_checkpoints.last().cloned();
        if !persisted_checkpoints.is_empty() {
            consensus.load_checkpoints(persisted_checkpoints);
            tracing::info!(count = checkpoint_count, "loaded persisted checkpoints");
        }

        let discovery =
            PeerDiscovery::new(identity.pubkey_hex(), config.effective_bootstrap_nodes());
        let pool = ConnectionPool::default();

        // Open delegation store in the same data directory.
        let deleg_db_path = config.db_path.with_file_name("delegations.db");
        let delegation_store = SqliteDelegationStore::open(&deleg_db_path)
            .expect("failed to open delegation database");

        Self {
            identity,
            config,
            protocol: Arc::new(Mutex::new(protocol)),
            discovery: Arc::new(discovery),
            pool: Arc::new(pool),
            broadcast_tracker: Arc::new(Mutex::new(BroadcastTracker::new())),
            consensus: Arc::new(Mutex::new(consensus)),
            delegation_store: Arc::new(Mutex::new(delegation_store)),
            latest_checkpoint: Arc::new(Mutex::new(latest_cp)),
        }
    }

    /// Start all node services (QUIC, gRPC, HTTP, discovery).
    pub async fn run(&self) -> anyhow::Result<()> {
        let pubkey = self.identity.pubkey_hex();
        tracing::info!(pubkey = &pubkey[..8], "starting TrustChain node");

        // Start QUIC transport.
        let quic_addr: SocketAddr = self.config.quic_addr.parse()?;
        let quic = QuicTransport::bind_with_rate_limit(
            quic_addr,
            &pubkey,
            self.config.max_connections_per_ip_per_sec,
        )
        .await
        .map_err(|e| anyhow::anyhow!("QUIC bind failed: {e}"))?;
        let quic_local = quic
            .local_addr()
            .map_err(|e| anyhow::anyhow!("QUIC local addr: {e}"))?;
        tracing::info!(%quic_local, "QUIC transport ready");

        // Compute the HTTP address we will advertise to other peers.
        // Priority: explicit advertise_addr > STUN-derived > loopback fallback.
        let http_port: u16 = self
            .config
            .http_addr
            .parse::<SocketAddr>()
            .map(|a| a.port())
            .unwrap_or(8202);
        let mut our_http_addr: String = self
            .config
            .advertise_addr
            .clone()
            .unwrap_or_else(|| format!("http://127.0.0.1:{http_port}"));

        // Discover public address via STUN (for NAT traversal).
        if let Some(ref stun_server) = self.config.stun_server {
            match trustchain_transport::stun::discover_public_addr(stun_server).await {
                Ok(public_addr) => {
                    tracing::info!(%public_addr, "discovered public QUIC address via STUN");
                    // If no explicit advertise_addr, derive our public HTTP address from STUN.
                    if self.config.advertise_addr.is_none() {
                        our_http_addr = format!("http://{}:{http_port}", public_addr.ip());
                        tracing::info!(our_http_addr, "using STUN-derived advertise address");
                    }
                }
                Err(e) => {
                    tracing::debug!(err = %e, "STUN discovery failed (set advertise_addr in config for public nodes)");
                }
            }
        }

        // Start QUIC accept loop with message routing.
        let (quic_tx, quic_rx) = mpsc::channel::<(Vec<u8>, mpsc::Sender<Vec<u8>>)>(256);
        let quic_accept_handle = {
            let quic = Arc::new(quic);
            let q = quic.clone();
            let handle = tokio::spawn(async move {
                if let Err(e) = q.accept_loop(quic_tx).await {
                    tracing::error!("QUIC accept loop error: {e}");
                }
            });
            // Spawn the message router for QUIC.
            let protocol = self.protocol.clone();
            let discovery = self.discovery.clone();
            let tracker = self.broadcast_tracker.clone();
            let quic_for_router = quic.clone();
            let consensus_for_router = self.consensus.clone();
            let checkpoint_for_router = self.latest_checkpoint.clone();
            let delegation_for_router = self.delegation_store.clone();
            tokio::spawn(Self::quic_message_router(
                quic_rx,
                protocol,
                discovery,
                tracker,
                quic_for_router,
                consensus_for_router,
                checkpoint_for_router,
                delegation_for_router,
            ));
            (handle, quic)
        };
        tracing::info!("QUIC message router started");

        // Start gRPC service.
        let grpc_addr: SocketAddr = self.config.grpc_addr.parse()?;
        let grpc_protocol = self.protocol.clone();
        let grpc_discovery = self.discovery.clone();
        let grpc_handle = tokio::spawn(async move {
            if let Err(e) = start_grpc_server(grpc_addr, grpc_protocol, grpc_discovery).await {
                tracing::error!("gRPC server error: {e}");
            }
        });
        tracing::info!(%grpc_addr, "gRPC service ready");

        // Start HTTP REST API (+ MCP if feature enabled).
        let http_addr: SocketAddr = self.config.http_addr.parse()?;
        let http_state = AppState {
            protocol: self.protocol.clone(),
            discovery: self.discovery.clone(),
            quic: Some(quic_accept_handle.1.clone()),
            agent_endpoint: self.config.agent_endpoint.clone(),
            delegation_store: self.delegation_store.clone(),
            latest_checkpoint: self.latest_checkpoint.clone(),
            seed_nodes: self.config.effective_bootstrap_nodes(),
            agent_name: self.config.agent_name.clone(),
        };

        #[cfg(feature = "mcp")]
        let mcp_protocol = self.protocol.clone();
        #[cfg(feature = "mcp")]
        let mcp_discovery = self.discovery.clone();
        #[cfg(feature = "mcp")]
        let mcp_endpoint = self.config.agent_endpoint.clone();
        #[cfg(feature = "mcp")]
        let mcp_seed_nodes = self.config.effective_bootstrap_nodes();

        let http_handle = tokio::spawn(async move {
            let router = build_router(http_state);

            #[cfg(feature = "mcp")]
            let router = {
                let mcp_svc = trustchain_transport::mcp::build_mcp_http_service(
                    mcp_protocol,
                    mcp_discovery,
                    mcp_endpoint,
                    mcp_seed_nodes,
                );
                router.nest_service("/mcp", mcp_svc)
            };

            let listener = match tokio::net::TcpListener::bind(http_addr).await {
                Ok(l) => l,
                Err(e) => {
                    tracing::error!("HTTP bind failed: {e}");
                    return;
                }
            };
            if let Err(e) = axum::serve(listener, router).await {
                tracing::error!("HTTP server error: {e}");
            }
        });
        tracing::info!(%http_addr, "HTTP API ready");
        #[cfg(feature = "mcp")]
        tracing::info!("MCP endpoint: http://{http_addr}/mcp");

        // Start transparent HTTP proxy (agent sidecar).
        let proxy_addr: SocketAddr = self.config.proxy_addr.parse()?;
        let proxy_state = ProxyState {
            protocol: self.protocol.clone(),
            discovery: self.discovery.clone(),
            quic: quic_accept_handle.1.clone(),
            client: reqwest::Client::new(),
            peer_locks: std::sync::Arc::new(tokio::sync::Mutex::new(
                std::collections::HashMap::new(),
            )),
            delegation_store: Some(self.delegation_store.clone()),
            seed_nodes: self.config.effective_bootstrap_nodes(),
        };
        let proxy_handle = tokio::spawn(async move {
            if let Err(e) = start_proxy_server(proxy_addr, proxy_state).await {
                tracing::error!("proxy server error: {e}");
            }
        });
        tracing::info!(%proxy_addr, "trust proxy ready — set HTTP_PROXY=http://{proxy_addr}");

        // Start peer discovery bootstrap + gossip.
        let disc = self.discovery.clone();
        let disc_protocol = self.protocol.clone();
        let bootstrap_nodes = self.config.effective_bootstrap_nodes();
        let disc_delegation_store = self.delegation_store.clone();
        let discovery_handle = tokio::spawn(async move {
            Self::discovery_loop(disc, disc_protocol, bootstrap_nodes, disc_delegation_store).await;
        });
        tracing::info!("peer discovery started");

        // Start CHECO consensus checkpoint loop.
        let checkpoint_consensus = self.consensus.clone();
        let checkpoint_discovery = self.discovery.clone();
        let checkpoint_quic = quic_accept_handle.1.clone();
        let checkpoint_interval = self.config.checkpoint_interval_secs;
        let checkpoint_shared = self.latest_checkpoint.clone();
        let checkpoint_handle = tokio::spawn(async move {
            Self::checkpoint_loop(
                checkpoint_consensus,
                checkpoint_discovery,
                checkpoint_quic,
                checkpoint_interval,
                checkpoint_shared,
            )
            .await;
        });
        tracing::info!(
            interval_secs = checkpoint_interval,
            "CHECO checkpoint loop started"
        );

        // Start connection pool cleanup task.
        let pool = self.pool.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(60)).await;
                pool.cleanup().await;
            }
        });

        // Register ourselves in the discovery layer so peers can find us.
        self.discovery
            .add_peer(pubkey.clone(), our_http_addr, {
                let proto = self.protocol.lock().await;
                proto.store().get_latest_seq(&pubkey).unwrap_or(0)
            })
            .await;

        // Load persisted peers from previous sessions.
        {
            let proto = self.protocol.lock().await;
            match proto.store().load_peers() {
                Ok(peers) => {
                    let count = peers.len();
                    for p in peers {
                        self.discovery
                            .add_peer(p.pubkey, p.address, p.latest_seq)
                            .await;
                    }
                    if count > 0 {
                        tracing::info!(count, "loaded persisted peers");
                    }
                }
                Err(e) => tracing::warn!("failed to load persisted peers: {e}"),
            }
        }

        // Register agent endpoint alias so the proxy can resolve it.
        if let Some(ref endpoint) = self.config.agent_endpoint {
            self.discovery
                .add_alias(endpoint.clone(), pubkey.clone())
                .await;
            tracing::info!(
                agent_endpoint = %endpoint,
                "registered agent endpoint alias"
            );
        }

        // If running in sidecar mode, log the agent info.
        if let Some(ref agent_name) = self.config.agent_name {
            tracing::info!(
                agent = %agent_name,
                endpoint = self.config.agent_endpoint.as_deref().unwrap_or("(none)"),
                "sidecar mode — agent registered"
            );
        }

        tracing::info!(
            pubkey = &pubkey[..8],
            quic = %quic_local,
            grpc = %grpc_addr,
            http = %http_addr,
            proxy = %proxy_addr,
            "node fully started"
        );

        // Wait for any service to exit, or graceful shutdown signal.
        tokio::select! {
            _ = grpc_handle => tracing::warn!("gRPC server exited"),
            _ = http_handle => tracing::warn!("HTTP server exited"),
            _ = proxy_handle => tracing::warn!("proxy server exited"),
            _ = quic_accept_handle.0 => tracing::warn!("QUIC accept loop exited"),
            _ = discovery_handle => tracing::warn!("discovery loop exited"),
            _ = checkpoint_handle => tracing::warn!("checkpoint loop exited"),
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("received shutdown signal, shutting down gracefully...");
            }
        }

        quic_accept_handle.1.shutdown();
        tracing::info!("node shut down");
        Ok(())
    }

    /// Route incoming QUIC messages to the protocol engine.
    #[allow(clippy::too_many_arguments)]
    async fn quic_message_router(
        mut rx: mpsc::Receiver<(Vec<u8>, mpsc::Sender<Vec<u8>>)>,
        protocol: Arc<Mutex<TrustChainProtocol<SqliteBlockStore>>>,
        discovery: Arc<PeerDiscovery>,
        tracker: Arc<Mutex<BroadcastTracker>>,
        quic: Arc<QuicTransport>,
        consensus: Arc<Mutex<CHECOConsensus<SqliteBlockStore>>>,
        latest_checkpoint: Arc<Mutex<Option<trustchain_core::Checkpoint>>>,
        delegation_store: Arc<Mutex<SqliteDelegationStore>>,
    ) {
        while let Some((data, resp_tx)) = rx.recv().await {
            let protocol = protocol.clone();
            let discovery = discovery.clone();
            let tracker = tracker.clone();
            let quic = quic.clone();
            let consensus = consensus.clone();
            let latest_checkpoint = latest_checkpoint.clone();
            let delegation_store = delegation_store.clone();
            tokio::spawn(async move {
                let response = Self::handle_quic_message(
                    &data,
                    &protocol,
                    &discovery,
                    &tracker,
                    &quic,
                    &consensus,
                    &latest_checkpoint,
                    &delegation_store,
                )
                .await;
                let _ = resp_tx.send(response).await;
            });
        }
    }

    /// Handle a single incoming QUIC message.
    #[allow(clippy::too_many_arguments)]
    async fn handle_quic_message(
        data: &[u8],
        protocol: &Arc<Mutex<TrustChainProtocol<SqliteBlockStore>>>,
        discovery: &Arc<PeerDiscovery>,
        tracker: &Arc<Mutex<BroadcastTracker>>,
        quic: &Arc<QuicTransport>,
        consensus: &Arc<Mutex<CHECOConsensus<SqliteBlockStore>>>,
        latest_checkpoint: &Arc<Mutex<Option<trustchain_core::Checkpoint>>>,
        delegation_store: &Arc<Mutex<SqliteDelegationStore>>,
    ) -> Vec<u8> {
        // Try to deserialize as TransportMessage.
        let msg: TransportMessage = match serde_json::from_slice(data) {
            Ok(m) => m,
            Err(e) => {
                tracing::warn!("invalid QUIC message: {e}");
                return Self::error_response(&format!("invalid message: {e}"));
            }
        };

        match msg.message_type {
            MessageType::Proposal => {
                // Deserialize the proposal block from payload.
                let proposal: HalfBlock = match bytes_to_block(&msg.payload) {
                    Ok(b) => b,
                    Err(e) => {
                        return Self::error_response(&format!("invalid proposal: {e}"));
                    }
                };

                let sender_pubkey = proposal.public_key.clone();
                let is_delegation =
                    proposal.block_type == trustchain_core::BlockType::Delegation.to_string();
                let is_succession =
                    proposal.block_type == trustchain_core::BlockType::Succession.to_string();

                let (response, agreement_opt) = if is_delegation {
                    // Delegation proposal — use accept_delegation to also store DelegationRecord.
                    let mut proto = protocol.lock().await;

                    // Validate the proposal first.
                    if let Err(e) = proto.receive_proposal(&proposal) {
                        return Self::error_response(&format!("delegation proposal rejected: {e}"));
                    }

                    let mut ds = delegation_store.lock().await;
                    match proto.accept_delegation(&proposal, &mut *ds) {
                        Ok(agreement) => {
                            let resp = TransportMessage::new(
                                MessageType::Agreement,
                                proto.pubkey(),
                                block_to_bytes(&agreement),
                                msg.request_id,
                            );
                            tracing::info!(
                                delegator =
                                    &proposal.public_key[..8.min(proposal.public_key.len())],
                                "accepted delegation via QUIC"
                            );
                            (
                                serde_json::to_vec(&resp).unwrap_or_default(),
                                Some(agreement),
                            )
                        }
                        Err(e) => (
                            Self::error_response(&format!("delegation acceptance failed: {e}")),
                            None,
                        ),
                    }
                } else if is_succession {
                    // Succession proposals require explicit operator approval.
                    // Auto-accepting would allow any peer to rotate our key — that
                    // is equivalent to remote identity theft. The operator MUST
                    // explicitly call POST /accept_succession to rotate keys.
                    tracing::warn!(
                        from = &proposal.public_key[..8.min(proposal.public_key.len())],
                        "rejected auto-succession proposal via QUIC — use POST /accept_succession for explicit approval"
                    );
                    return Self::error_response(
                        "succession proposals require explicit approval via HTTP API",
                    );
                } else {
                    // Regular proposal — create generic agreement.
                    let mut proto = protocol.lock().await;

                    // Receive and validate.
                    if let Err(e) = proto.receive_proposal(&proposal) {
                        return Self::error_response(&format!("proposal rejected: {e}"));
                    }

                    // Create agreement.
                    match proto.create_agreement(&proposal, None) {
                        Ok(agreement) => {
                            let resp = TransportMessage::new(
                                MessageType::Agreement,
                                proto.pubkey(),
                                block_to_bytes(&agreement),
                                msg.request_id,
                            );
                            (
                                serde_json::to_vec(&resp).unwrap_or_default(),
                                Some(agreement),
                            )
                        }
                        Err(e) => (
                            Self::error_response(&format!("agreement failed: {e}")),
                            None,
                        ),
                    }
                };

                // After lock released, broadcast the completed block pair if agreement succeeded.
                if let Some(ref agreement) = agreement_opt {
                    let our_pubkey = {
                        let proto = protocol.lock().await;
                        proto.pubkey()
                    };
                    Self::broadcast_block_pair(
                        &proposal,
                        agreement,
                        &our_pubkey,
                        discovery,
                        quic,
                        tracker,
                    )
                    .await;
                }

                // Check for fraud and broadcast if found.
                Self::check_and_broadcast_fraud(&sender_pubkey, protocol, discovery, quic, tracker)
                    .await;

                response
            }

            MessageType::Agreement => {
                // Deserialize agreement block.
                let agreement: HalfBlock = match bytes_to_block(&msg.payload) {
                    Ok(b) => b,
                    Err(e) => {
                        return Self::error_response(&format!("invalid agreement: {e}"));
                    }
                };

                let sender_pubkey = agreement.public_key.clone();
                let response = {
                    let mut proto = protocol.lock().await;
                    match proto.receive_agreement(&agreement) {
                        Ok(_) => serde_json::to_vec(&serde_json::json!({"accepted": true}))
                            .unwrap_or_default(),
                        Err(e) => Self::error_response(&format!("agreement rejected: {e}")),
                    }
                };

                // After lock released, check for fraud and broadcast if found.
                Self::check_and_broadcast_fraud(&sender_pubkey, protocol, discovery, quic, tracker)
                    .await;

                response
            }

            MessageType::CrawlRequest => {
                let proto = protocol.lock().await;
                // Payload is JSON: {"public_key": "...", "start_seq": N}
                let req: serde_json::Value =
                    serde_json::from_slice(&msg.payload).unwrap_or_default();
                let pubkey = req.get("public_key").and_then(|v| v.as_str()).unwrap_or("");
                let start_seq = req.get("start_seq").and_then(|v| v.as_u64()).unwrap_or(1);

                match proto.store().crawl(pubkey, start_seq) {
                    Ok(blocks) => {
                        let resp = TransportMessage::new(
                            MessageType::CrawlResponse,
                            proto.pubkey(),
                            serde_json::to_vec(&blocks).unwrap_or_default(),
                            msg.request_id,
                        );
                        serde_json::to_vec(&resp).unwrap_or_default()
                    }
                    Err(e) => Self::error_response(&format!("crawl error: {e}")),
                }
            }

            MessageType::StatusRequest => {
                let proto = protocol.lock().await;
                let pubkey = proto.pubkey();
                let latest_seq = proto.store().get_latest_seq(&pubkey).unwrap_or(0);
                let block_count = proto.store().get_block_count().unwrap_or(0);

                serde_json::to_vec(&serde_json::json!({
                    "public_key": pubkey,
                    "latest_seq": latest_seq,
                    "block_count": block_count,
                }))
                .unwrap_or_default()
            }

            MessageType::DiscoveryRequest => {
                // Payload: list of (pubkey, address, seq).
                if let Ok(peers) =
                    serde_json::from_slice::<Vec<(String, String, u64)>>(&msg.payload)
                {
                    discovery.merge_peers(peers).await;
                }

                let our_peers = discovery.get_gossip_peers(20).await;
                let peers: Vec<(String, String, u64)> = our_peers
                    .iter()
                    .map(|p| (p.pubkey.clone(), p.address.clone(), p.latest_seq))
                    .collect();

                let resp = TransportMessage::new(
                    MessageType::DiscoveryResponse,
                    msg.sender_pubkey,
                    serde_json::to_vec(&peers).unwrap_or_default(),
                    msg.request_id,
                );
                serde_json::to_vec(&resp).unwrap_or_default()
            }

            MessageType::Ping => {
                let resp = TransportMessage::new(
                    MessageType::Pong,
                    String::new(),
                    Vec::new(),
                    msg.request_id,
                );
                serde_json::to_vec(&resp).unwrap_or_default()
            }

            MessageType::BlockPairBroadcast => {
                // Deserialize the broadcast payload.
                let payload: BlockPairBroadcastPayload = match serde_json::from_slice(&msg.payload)
                {
                    Ok(p) => p,
                    Err(e) => return Self::error_response(&format!("invalid broadcast: {e}")),
                };

                // Check if we've already seen these blocks.
                let block_id = format!(
                    "{}:{}",
                    payload.block1.block_hash, payload.block2.block_hash
                );
                {
                    let mut t = tracker.lock().await;
                    if !t.mark_if_new(&block_id) {
                        // Already seen — don't process or relay.
                        return serde_json::to_vec(&serde_json::json!({"status": "already_seen"}))
                            .unwrap_or_default();
                    }
                }

                // Validate both blocks.
                let inv1 = validate_block_invariants(&payload.block1);
                let inv2 = validate_block_invariants(&payload.block2);
                if let ValidationResult::Invalid(e) = inv1 {
                    tracing::warn!("broadcast block1 invalid: {:?}", e);
                    return Self::error_response("broadcast block1 invalid");
                }
                if let ValidationResult::Invalid(e) = inv2 {
                    tracing::warn!("broadcast block2 invalid: {:?}", e);
                    return Self::error_response("broadcast block2 invalid");
                }

                // Verify blocks form a valid matched pair before persisting.
                if payload.block1.link_public_key != payload.block2.public_key
                    || payload.block2.link_public_key != payload.block1.public_key
                    || payload.block2.link_sequence_number != payload.block1.sequence_number
                {
                    tracing::warn!("rejected gossip: blocks are not a matched pair");
                    return Self::error_response("blocks are not a matched pair");
                }

                // Persist both blocks (idempotent).
                {
                    let mut proto = protocol.lock().await;
                    if let Err(e) = proto.store_mut().add_block(&payload.block1) {
                        if !e.to_string().to_lowercase().contains("duplicate") {
                            tracing::warn!(error = %e, "failed to store gossipped block1");
                        }
                    }
                    if let Err(e) = proto.store_mut().add_block(&payload.block2) {
                        if !e.to_string().to_lowercase().contains("duplicate") {
                            tracing::warn!(error = %e, "failed to store gossipped block2");
                        }
                    }
                }

                tracing::debug!(
                    "received broadcast: {}:{} seq {}+{}, ttl={}",
                    &payload.block1.public_key[..8],
                    &payload.block2.public_key[..8],
                    payload.block1.sequence_number,
                    payload.block2.sequence_number,
                    payload.ttl,
                );

                // Relay if TTL > 1.
                if payload.ttl > 1 {
                    let relay_payload = BlockPairBroadcastPayload {
                        block1: payload.block1,
                        block2: payload.block2,
                        ttl: payload.ttl - 1,
                    };
                    let our_pubkey = {
                        let proto = protocol.lock().await;
                        proto.pubkey()
                    };
                    Self::broadcast_to_peers(&relay_payload, &our_pubkey, discovery, quic, tracker)
                        .await;
                }

                serde_json::to_vec(&serde_json::json!({"status": "ok"})).unwrap_or_default()
            }

            MessageType::CapabilityRequest => {
                // Deserialize the query.
                let query: discover::CapabilityQuery = match serde_json::from_slice(&msg.payload) {
                    Ok(q) => q,
                    Err(e) => {
                        return Self::error_response(&format!("invalid capability query: {e}"))
                    }
                };

                // Scan local blockstore.
                let agents = {
                    let proto = protocol.lock().await;
                    discover::find_capable_agents(
                        proto.store(),
                        &query.capability,
                        query.max_results,
                    )
                };

                // Enrich with addresses from peer discovery.
                let mut enriched = agents;
                for agent in &mut enriched {
                    if let Some(peer) = discovery.get_peer(&agent.pubkey).await {
                        agent.address = Some(peer.address);
                    }
                }

                let resp = TransportMessage::new(
                    MessageType::CapabilityResponse,
                    {
                        let proto = protocol.lock().await;
                        proto.pubkey()
                    },
                    serde_json::to_vec(&enriched).unwrap_or_default(),
                    msg.request_id,
                );
                serde_json::to_vec(&resp).unwrap_or_default()
            }

            MessageType::FraudProof => {
                let payload: FraudProofPayload = match serde_json::from_slice(&msg.payload) {
                    Ok(p) => p,
                    Err(e) => return Self::error_response(&format!("invalid fraud proof: {e}")),
                };

                // Dedup via broadcast tracker.
                let dedup_key = format!(
                    "fraud:{}:{}",
                    payload.block_a.block_hash, payload.block_b.block_hash
                );
                {
                    let mut t = tracker.lock().await;
                    if !t.mark_if_new(&dedup_key) {
                        return serde_json::to_vec(&serde_json::json!({"status": "already_seen"}))
                            .unwrap_or_default();
                    }
                }

                // Validate: both blocks must have valid signatures and same (pubkey, seq) but different hashes.
                let valid_a = trustchain_core::verify_block(&payload.block_a).unwrap_or(false);
                let valid_b = trustchain_core::verify_block(&payload.block_b).unwrap_or(false);
                if !valid_a || !valid_b {
                    return Self::error_response("fraud proof contains invalid block signatures");
                }
                if payload.block_a.public_key != payload.block_b.public_key
                    || payload.block_a.sequence_number != payload.block_b.sequence_number
                {
                    return Self::error_response("fraud proof blocks not at same (pubkey, seq)");
                }
                if payload.block_a.block_hash == payload.block_b.block_hash {
                    return Self::error_response("fraud proof blocks are identical");
                }

                // Store the double-spend.
                {
                    let mut proto = protocol.lock().await;
                    let _ = proto
                        .store_mut()
                        .add_double_spend(&payload.block_a, &payload.block_b);
                }

                tracing::warn!(
                    pubkey = &payload.block_a.public_key[..8],
                    seq = payload.block_a.sequence_number,
                    "received fraud proof — double-spend recorded"
                );

                // Relay with decremented TTL.
                if payload.ttl > 1 {
                    let relay_payload = FraudProofPayload {
                        block_a: payload.block_a,
                        block_b: payload.block_b,
                        ttl: payload.ttl - 1,
                    };
                    let our_pubkey = {
                        let proto = protocol.lock().await;
                        proto.pubkey()
                    };
                    Self::broadcast_fraud_proof(
                        &relay_payload,
                        &our_pubkey,
                        discovery,
                        quic,
                        tracker,
                    )
                    .await;
                }

                serde_json::to_vec(&serde_json::json!({"status": "fraud_recorded"}))
                    .unwrap_or_default()
            }

            MessageType::HalfBlockBroadcast => {
                // Single half-block broadcast — validate and persist.
                let payload: trustchain_transport::message::HalfBlockBroadcastPayload =
                    match serde_json::from_slice(&msg.payload) {
                        Ok(p) => p,
                        Err(e) => return Self::error_response(&format!("invalid broadcast: {e}")),
                    };

                let block_id = payload.block.block_hash.clone();
                {
                    let mut t = tracker.lock().await;
                    if !t.mark_if_new(&block_id) {
                        return serde_json::to_vec(&serde_json::json!({"status": "already_seen"}))
                            .unwrap_or_default();
                    }
                }

                let inv = validate_block_invariants(&payload.block);
                if let ValidationResult::Invalid(e) = inv {
                    tracing::warn!("broadcast block invalid: {:?}", e);
                    return Self::error_response("broadcast block invalid");
                }

                {
                    let mut proto = protocol.lock().await;
                    if let Err(e) = proto.store_mut().add_block(&payload.block) {
                        // DuplicateSequence is expected during gossip — not an error.
                        if !e.to_string().to_lowercase().contains("duplicate") {
                            tracing::warn!(error = %e, "failed to store gossipped half-block");
                        }
                    }
                }

                serde_json::to_vec(&serde_json::json!({"status": "ok"})).unwrap_or_default()
            }

            MessageType::CheckpointProposal => {
                let payload: CheckpointProposalPayload = match serde_json::from_slice(&msg.payload)
                {
                    Ok(p) => p,
                    Err(e) => {
                        return Self::error_response(&format!("invalid checkpoint proposal: {e}"))
                    }
                };

                // Validate: must be a checkpoint block with valid signature.
                if !payload.checkpoint_block.is_checkpoint() {
                    return Self::error_response("not a checkpoint block");
                }
                if !verify_block(&payload.checkpoint_block).unwrap_or(false) {
                    return Self::error_response("invalid checkpoint block signature");
                }

                // Sign the checkpoint block hash as our vote.
                let proto = protocol.lock().await;
                let voter_pubkey = proto.pubkey();
                let signature_hex = proto
                    .identity()
                    .sign_hex(payload.checkpoint_block.block_hash.as_bytes());

                let vote = CheckpointVotePayload {
                    checkpoint_block_hash: payload.checkpoint_block.block_hash.clone(),
                    voter_pubkey,
                    signature_hex,
                    round: payload.round,
                };

                let resp = TransportMessage::new(
                    MessageType::CheckpointVote,
                    proto.pubkey(),
                    serde_json::to_vec(&vote).unwrap_or_default(),
                    msg.request_id,
                );
                serde_json::to_vec(&resp).unwrap_or_default()
            }

            MessageType::CheckpointFinalized => {
                let payload: CheckpointFinalizedPayload = match serde_json::from_slice(&msg.payload)
                {
                    Ok(p) => p,
                    Err(e) => {
                        return Self::error_response(&format!("invalid checkpoint finalized: {e}"))
                    }
                };

                // Validate the checkpoint block.
                if !verify_block(&payload.checkpoint.checkpoint_block).unwrap_or(false) {
                    return Self::error_response("invalid finalized checkpoint block");
                }

                tracing::info!(
                    facilitator = &payload.checkpoint.facilitator_pubkey[..8],
                    round = payload.round,
                    signers = payload.checkpoint.signatures.len(),
                    "received finalized checkpoint"
                );

                // Persist the finalized checkpoint via the consensus engine.
                {
                    let mut cons = consensus.lock().await;
                    match cons.finalize_checkpoint(
                        payload.checkpoint.checkpoint_block,
                        payload.checkpoint.signatures,
                    ) {
                        Ok(cp) => {
                            // Save to SQLite for restart persistence.
                            if let Err(e) = cons.store().save_checkpoint(&cp) {
                                tracing::warn!("failed to persist checkpoint to SQLite: {e}");
                            }
                            // Update shared latest checkpoint for trust queries.
                            {
                                let mut lc = latest_checkpoint.lock().await;
                                *lc = Some(cp.clone());
                            }
                            tracing::info!(
                                facilitator = &cp.facilitator_pubkey[..8],
                                signers = cp.signatures.len(),
                                "checkpoint persisted from peer"
                            );
                        }
                        Err(e) => {
                            tracing::warn!("failed to persist finalized checkpoint: {e}");
                        }
                    }
                }

                serde_json::to_vec(&serde_json::json!({"status": "checkpoint_accepted"}))
                    .unwrap_or_default()
            }

            _ => Self::error_response("unhandled message type"),
        }
    }

    /// Broadcast a block pair to random peers via QUIC.
    async fn broadcast_to_peers(
        payload: &BlockPairBroadcastPayload,
        our_pubkey: &str,
        discovery: &Arc<PeerDiscovery>,
        quic: &Arc<QuicTransport>,
        _tracker: &Arc<Mutex<BroadcastTracker>>,
    ) {
        let peers = discovery.get_gossip_peers(BROADCAST_FANOUT).await;
        if peers.is_empty() {
            return;
        }

        let msg = TransportMessage::new(
            MessageType::BlockPairBroadcast,
            our_pubkey.to_string(),
            serde_json::to_vec(payload).unwrap_or_default(),
            format!("bc-{}", payload.block1.block_hash.get(..8).unwrap_or("?")),
        );
        let msg_bytes = serde_json::to_vec(&msg).unwrap_or_default();

        for peer in peers {
            // Derive QUIC address from HTTP address (port - QUIC_PORT_OFFSET).
            let quic_addr = match peer
                .address
                .strip_prefix("http://")
                .unwrap_or(&peer.address)
                .parse::<SocketAddr>()
            {
                Ok(a) => SocketAddr::new(a.ip(), a.port().saturating_sub(QUIC_PORT_OFFSET)),
                Err(_) => continue,
            };

            let quic = quic.clone();
            let msg_bytes = msg_bytes.clone();
            tokio::spawn(async move {
                match tokio::time::timeout(
                    Duration::from_secs(5),
                    quic.send_message(quic_addr, &msg_bytes),
                )
                .await
                {
                    Ok(Ok(_)) => {}
                    Ok(Err(e)) => tracing::debug!("broadcast send error: {e}"),
                    Err(_) => tracing::debug!("broadcast send timeout"),
                }
            });
        }
    }

    /// Check for double-spends by a peer and broadcast fraud proof if found.
    async fn check_and_broadcast_fraud(
        sender_pubkey: &str,
        protocol: &Arc<Mutex<TrustChainProtocol<SqliteBlockStore>>>,
        discovery: &Arc<PeerDiscovery>,
        quic: &Arc<QuicTransport>,
        tracker: &Arc<Mutex<BroadcastTracker>>,
    ) {
        let fraud_data = {
            let proto = protocol.lock().await;
            proto.store().get_double_spends(sender_pubkey).ok()
        };
        if let Some(frauds) = fraud_data {
            if let Some(ds) = frauds.first() {
                let fraud_payload = FraudProofPayload {
                    block_a: ds.block_a.clone(),
                    block_b: ds.block_b.clone(),
                    ttl: BROADCAST_TTL,
                };
                let our_pubkey = {
                    let proto = protocol.lock().await;
                    proto.pubkey()
                };
                let disc = discovery.clone();
                let q = quic.clone();
                let t = tracker.clone();
                tokio::spawn(async move {
                    Self::broadcast_fraud_proof(&fraud_payload, &our_pubkey, &disc, &q, &t).await;
                });
            }
        }
    }

    /// Broadcast a fraud proof to random peers via QUIC.
    async fn broadcast_fraud_proof(
        payload: &FraudProofPayload,
        our_pubkey: &str,
        discovery: &Arc<PeerDiscovery>,
        quic: &Arc<QuicTransport>,
        _tracker: &Arc<Mutex<BroadcastTracker>>,
    ) {
        let peers = discovery.get_gossip_peers(BROADCAST_FANOUT).await;
        if peers.is_empty() {
            return;
        }

        let msg = TransportMessage::new(
            MessageType::FraudProof,
            our_pubkey.to_string(),
            serde_json::to_vec(payload).unwrap_or_default(),
            format!(
                "fraud-{}",
                payload.block_a.block_hash.get(..8).unwrap_or("?")
            ),
        );
        let msg_bytes = serde_json::to_vec(&msg).unwrap_or_default();

        for peer in peers {
            let quic_addr = match peer
                .address
                .strip_prefix("http://")
                .unwrap_or(&peer.address)
                .parse::<SocketAddr>()
            {
                Ok(a) => SocketAddr::new(a.ip(), a.port().saturating_sub(QUIC_PORT_OFFSET)),
                Err(_) => continue,
            };

            let quic = quic.clone();
            let msg_bytes = msg_bytes.clone();
            tokio::spawn(async move {
                match tokio::time::timeout(
                    Duration::from_secs(5),
                    quic.send_message(quic_addr, &msg_bytes),
                )
                .await
                {
                    Ok(Ok(_)) => {}
                    Ok(Err(e)) => tracing::debug!("fraud broadcast send error: {e}"),
                    Err(_) => tracing::debug!("fraud broadcast send timeout"),
                }
            });
        }
    }

    /// Broadcast a completed transaction (both halves) to the network.
    pub async fn broadcast_block_pair(
        proposal: &HalfBlock,
        agreement: &HalfBlock,
        our_pubkey: &str,
        discovery: &Arc<PeerDiscovery>,
        quic: &Arc<QuicTransport>,
        tracker: &Arc<Mutex<BroadcastTracker>>,
    ) {
        let payload = BlockPairBroadcastPayload {
            block1: proposal.clone(),
            block2: agreement.clone(),
            ttl: BROADCAST_TTL,
        };

        // Mark as seen so we don't relay our own broadcast back.
        {
            let block_id = format!("{}:{}", proposal.block_hash, agreement.block_hash);
            let mut t = tracker.lock().await;
            t.mark_if_new(&block_id);
        }

        Self::broadcast_to_peers(&payload, our_pubkey, discovery, quic, tracker).await;
    }

    fn error_response(msg: &str) -> Vec<u8> {
        let resp = TransportMessage::new(
            MessageType::Error,
            String::new(),
            msg.as_bytes().to_vec(),
            String::new(),
        );
        serde_json::to_vec(&resp).unwrap_or_default()
    }

    /// Peer discovery: bootstrap then periodic gossip.
    async fn discovery_loop(
        discovery: Arc<PeerDiscovery>,
        protocol: Arc<Mutex<TrustChainProtocol<SqliteBlockStore>>>,
        bootstrap_nodes: Vec<String>,
        // Kept in signature for future delegation-aware sync; not used while
        // auto-accept is disabled (see C7 fix).
        _delegation_store: Arc<Mutex<SqliteDelegationStore>>,
    ) {
        // Phase 1: Bootstrap — connect to known nodes and fetch their peers.
        for addr in &bootstrap_nodes {
            tracing::info!(addr = %addr, "bootstrapping from peer");
            match Self::fetch_status_http(addr).await {
                Ok((pubkey, latest_seq, agent_endpoint)) => {
                    discovery
                        .add_peer(pubkey.clone(), addr.clone(), latest_seq)
                        .await;
                    if let Some(ep) = agent_endpoint {
                        discovery.add_alias(ep, pubkey).await;
                    }
                    tracing::info!(addr = %addr, "bootstrap peer added");
                }
                Err(e) => {
                    tracing::warn!(addr = %addr, err = %e, "bootstrap peer unreachable");
                }
            }

            // Also try to discover more peers from this bootstrap node.
            if let Ok(peers) = Self::fetch_peers_http(addr).await {
                for (pk, address, seq) in peers {
                    discovery.add_peer(pk, address, seq).await;
                }
            }
        }

        let peer_count = discovery.peer_count().await;
        tracing::info!(peer_count, "bootstrap complete");

        // Phase 2: Periodic gossip — exchange peer lists with random peers.
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        loop {
            interval.tick().await;

            let gossip_peers = discovery.get_gossip_peers(3).await;
            for peer in gossip_peers {
                // Refresh peer status.
                match Self::fetch_status_http(&peer.address).await {
                    Ok((pubkey, latest_seq, agent_endpoint)) => {
                        discovery
                            .add_peer(pubkey.clone(), peer.address.clone(), latest_seq)
                            .await;
                        if let Some(ep) = agent_endpoint {
                            discovery.add_alias(ep, pubkey).await;
                        }
                    }
                    Err(_) => {
                        // Stale peer — remove if not seen for 5 minutes.
                        let now = trustchain_transport::discovery::now_unix_ms();
                        if now.saturating_sub(peer.last_seen_unix_ms) > 300_000 {
                            discovery.remove_peer(&peer.pubkey).await;
                        }
                    }
                }

                // Exchange peer lists.
                if let Ok(peers) = Self::fetch_peers_http(&peer.address).await {
                    for (pk, address, seq) in peers {
                        discovery.add_peer(pk, address, seq).await;
                    }
                }
            }

            // Sync chains from peers we know about.
            let all_peers = discovery.get_peers().await;
            for peer in &all_peers {
                let our_seq = {
                    let proto = protocol.lock().await;
                    proto.store().get_latest_seq(&peer.pubkey).unwrap_or(0)
                };
                if peer.latest_seq > our_seq {
                    // Fetch missing blocks.
                    if let Ok(blocks) =
                        Self::fetch_crawl_http(&peer.address, &peer.pubkey, our_seq + 1).await
                    {
                        let mut proto = protocol.lock().await;
                        let our_pubkey = proto.pubkey();
                        for block in &blocks {
                            if let Err(e) = proto.store_mut().add_block(block) {
                                // DuplicateSequence is expected during sync — not an error.
                                if !e.to_string().to_lowercase().contains("duplicate") {
                                    tracing::warn!(error = %e, "failed to store synced block");
                                }
                            }
                        }
                        if !blocks.is_empty() {
                            tracing::info!(
                                peer = &peer.pubkey[..8],
                                synced = blocks.len(),
                                "synced blocks from peer"
                            );
                        }

                        // Notify the operator about pending delegation proposals targeting us.
                        // Do NOT auto-accept: silently accepting delegations during crawl
                        // allows any peer to grant themselves authority over our node without
                        // operator consent. The operator MUST explicitly call
                        // POST /accept_delegation to accept each delegation.
                        for block in &blocks {
                            if block.block_type
                                == trustchain_core::BlockType::Delegation.to_string()
                                && block.link_public_key == our_pubkey
                                && block.link_sequence_number == 0
                            // proposal (not yet accepted)
                            {
                                let delegation_id = block
                                    .transaction
                                    .get("delegation_id")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("<unknown>");
                                tracing::info!(
                                    from = &block.public_key[..8.min(block.public_key.len())],
                                    delegation_id = delegation_id,
                                    "found pending delegation proposal during sync — use POST /accept_delegation to accept"
                                );
                            }
                        }
                    }
                }
            }

            // Persist current peer list for next restart.
            {
                let mut proto = protocol.lock().await;
                for peer in &all_peers {
                    let _ = proto.store_mut().save_peer(&PersistentPeer {
                        pubkey: peer.pubkey.clone(),
                        address: peer.address.clone(),
                        latest_seq: peer.latest_seq,
                        last_seen_unix_ms: peer.last_seen_unix_ms,
                        is_bootstrap: peer.is_bootstrap,
                    });
                }
            }
        }
    }

    /// Fetch status from a peer via HTTP.
    /// Returns (pubkey, latest_seq, optional agent_endpoint).
    async fn fetch_status_http(addr: &str) -> anyhow::Result<(String, u64, Option<String>)> {
        let url = if addr.starts_with("http") {
            format!("{addr}/status")
        } else {
            format!("http://{addr}/status")
        };

        let resp: serde_json::Value = reqwest::Client::new()
            .get(&url)
            .timeout(Duration::from_secs(5))
            .send()
            .await?
            .json()
            .await?;

        let pubkey = resp
            .get("public_key")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("missing public_key"))?
            .to_string();
        let latest_seq = resp.get("latest_seq").and_then(|v| v.as_u64()).unwrap_or(0);
        let agent_endpoint = resp
            .get("agent_endpoint")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        Ok((pubkey, latest_seq, agent_endpoint))
    }

    /// Fetch peer list from a peer via HTTP.
    async fn fetch_peers_http(addr: &str) -> anyhow::Result<Vec<(String, String, u64)>> {
        let url = if addr.starts_with("http") {
            format!("{addr}/peers")
        } else {
            format!("http://{addr}/peers")
        };

        let resp: Vec<serde_json::Value> = reqwest::Client::new()
            .get(&url)
            .timeout(Duration::from_secs(5))
            .send()
            .await?
            .json()
            .await?;

        let peers: Vec<(String, String, u64)> = resp
            .iter()
            .filter_map(|p| {
                let pk = p.get("pubkey")?.as_str()?.to_string();
                let addr = p.get("address")?.as_str()?.to_string();
                let seq = p.get("latest_seq").and_then(|v| v.as_u64()).unwrap_or(0);
                Some((pk, addr, seq))
            })
            .collect();

        Ok(peers)
    }

    /// Fetch blocks from a peer via HTTP crawl endpoint.
    async fn fetch_crawl_http(
        addr: &str,
        pubkey: &str,
        start_seq: u64,
    ) -> anyhow::Result<Vec<HalfBlock>> {
        let url = if addr.starts_with("http") {
            format!("{addr}/crawl/{pubkey}?start_seq={start_seq}")
        } else {
            format!("http://{addr}/crawl/{pubkey}?start_seq={start_seq}")
        };

        let resp: serde_json::Value = reqwest::Client::new()
            .get(&url)
            .timeout(Duration::from_secs(10))
            .send()
            .await?
            .json()
            .await?;

        let blocks: Vec<HalfBlock> = resp
            .get("blocks")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or_default();

        Ok(blocks)
    }

    /// CHECO consensus checkpoint loop.
    ///
    /// Periodically checks if we are the facilitator. If so, proposes a checkpoint,
    /// collects votes from peers via QUIC, and finalizes when enough votes are collected.
    async fn checkpoint_loop(
        consensus: Arc<Mutex<CHECOConsensus<SqliteBlockStore>>>,
        discovery: Arc<PeerDiscovery>,
        quic: Arc<QuicTransport>,
        interval_secs: u64,
        latest_checkpoint: Arc<Mutex<Option<trustchain_core::Checkpoint>>>,
    ) {
        let mut interval = tokio::time::interval(Duration::from_secs(interval_secs));
        let mut round: u64 = 0;

        loop {
            interval.tick().await;
            round += 1;

            // Update known peers from discovery.
            let peers = discovery.get_peers().await;
            let peer_pubkeys: Vec<String> = peers.iter().map(|p| p.pubkey.clone()).collect();
            {
                let mut cons = consensus.lock().await;
                cons.set_known_peers(peer_pubkeys);
            }

            // Check if we are the facilitator.
            let is_facilitator = {
                let cons = consensus.lock().await;
                cons.is_facilitator().unwrap_or(false)
            };

            if !is_facilitator {
                continue;
            }

            tracing::info!(round, "we are the checkpoint facilitator");

            // Propose a checkpoint.
            let checkpoint_block = {
                let mut cons = consensus.lock().await;
                match cons.propose_checkpoint() {
                    Ok(block) => block,
                    Err(e) => {
                        tracing::warn!(round, err = %e, "failed to propose checkpoint");
                        continue;
                    }
                }
            };

            // Send CheckpointProposal to all peers, collect votes.
            let proposal_payload = CheckpointProposalPayload {
                checkpoint_block: checkpoint_block.clone(),
                round,
            };
            let our_pubkey = {
                let cons = consensus.lock().await;
                cons.pubkey()
            };

            let msg = TransportMessage::new(
                MessageType::CheckpointProposal,
                our_pubkey.clone(),
                serde_json::to_vec(&proposal_payload).unwrap_or_default(),
                format!("cp-{round}"),
            );
            let msg_bytes = serde_json::to_vec(&msg).unwrap_or_default();

            let mut signatures = std::collections::HashMap::new();

            // Self-sign first.
            {
                let cons = consensus.lock().await;
                if let Ok(sig) = cons.sign_checkpoint(&checkpoint_block) {
                    signatures.insert(our_pubkey.clone(), sig);
                }
            }

            // Fan out to peers with 10s timeout per peer.
            for peer in &peers {
                let quic_addr = match peer
                    .address
                    .strip_prefix("http://")
                    .unwrap_or(&peer.address)
                    .parse::<SocketAddr>()
                {
                    Ok(a) => SocketAddr::new(a.ip(), a.port().saturating_sub(QUIC_PORT_OFFSET)),
                    Err(_) => continue,
                };

                match tokio::time::timeout(
                    Duration::from_secs(10),
                    quic.send_message(quic_addr, &msg_bytes),
                )
                .await
                {
                    Ok(Ok(resp_bytes)) => {
                        // Parse vote response.
                        if let Ok(resp) = serde_json::from_slice::<TransportMessage>(&resp_bytes) {
                            if resp.message_type == MessageType::CheckpointVote {
                                if let Ok(vote) =
                                    serde_json::from_slice::<CheckpointVotePayload>(&resp.payload)
                                {
                                    if vote.checkpoint_block_hash == checkpoint_block.block_hash {
                                        signatures.insert(vote.voter_pubkey, vote.signature_hex);
                                    }
                                }
                            }
                        }
                    }
                    Ok(Err(e)) => {
                        tracing::debug!(peer = &peer.pubkey[..8], err = %e, "checkpoint vote error")
                    }
                    Err(_) => tracing::debug!(peer = &peer.pubkey[..8], "checkpoint vote timeout"),
                }
            }

            tracing::info!(
                round,
                votes = signatures.len(),
                "collected checkpoint votes"
            );

            // Finalize if we have enough signatures.
            let finalized = {
                let mut cons = consensus.lock().await;
                cons.finalize_checkpoint(checkpoint_block.clone(), signatures.clone())
            };

            match finalized {
                Ok(cp) => {
                    // Persist to SQLite for survival across restarts.
                    {
                        let cons = consensus.lock().await;
                        if let Err(e) = cons.store().save_checkpoint(&cp) {
                            tracing::warn!(round, err = %e, "failed to persist checkpoint");
                        }
                    }

                    // Update shared latest checkpoint for trust queries.
                    {
                        let mut lc = latest_checkpoint.lock().await;
                        *lc = Some(cp.clone());
                    }

                    tracing::info!(
                        round,
                        signers = cp.signatures.len(),
                        "checkpoint finalized!"
                    );

                    // Broadcast finalized checkpoint to all peers (fire-and-forget).
                    let wire = CheckpointWire {
                        checkpoint_block: cp.checkpoint_block,
                        signatures: cp.signatures,
                        chain_heads: cp.chain_heads,
                        facilitator_pubkey: cp.facilitator_pubkey,
                        timestamp: cp.timestamp,
                    };
                    let finalized_payload = CheckpointFinalizedPayload {
                        checkpoint: wire,
                        round,
                    };
                    let finalized_msg = TransportMessage::new(
                        MessageType::CheckpointFinalized,
                        our_pubkey.clone(),
                        serde_json::to_vec(&finalized_payload).unwrap_or_default(),
                        format!("cpf-{round}"),
                    );
                    let finalized_bytes = serde_json::to_vec(&finalized_msg).unwrap_or_default();

                    for peer in &peers {
                        let quic_addr = match peer
                            .address
                            .strip_prefix("http://")
                            .unwrap_or(&peer.address)
                            .parse::<SocketAddr>()
                        {
                            Ok(a) => {
                                SocketAddr::new(a.ip(), a.port().saturating_sub(QUIC_PORT_OFFSET))
                            }
                            Err(_) => continue,
                        };
                        let quic = quic.clone();
                        let bytes = finalized_bytes.clone();
                        tokio::spawn(async move {
                            let _ = tokio::time::timeout(
                                Duration::from_secs(5),
                                quic.send_message(quic_addr, &bytes),
                            )
                            .await;
                        });
                    }
                }
                Err(e) => {
                    tracing::debug!(round, err = %e, "checkpoint not finalized (insufficient votes)");
                }
            }
        }
    }
}
