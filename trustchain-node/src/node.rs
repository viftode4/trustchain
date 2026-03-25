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
        block_to_bytes, bytes_to_block, BlockMetadataPayload, BlockMetadataRequestPayload,
        BlockPairBroadcastPayload, CheckpointFinalizedPayload, CheckpointProposalPayload,
        CheckpointVotePayload, CheckpointWire, FraudProofPayload, MessageType, TransportMessage,
    },
    start_grpc_server, start_proxy_server, AppState, ConnectionPool, PeerDiscovery, ProxyState,
    QuicTransport, QUIC_PORT_OFFSET,
};

use crate::config::NodeConfig;

/// Plumtree eager fanout — send full blocks to K random peers.
const EAGER_FANOUT: usize = 4;
/// Plumtree lazy fanout — send metadata-only to M additional peers.
const LAZY_FANOUT: usize = 3;
/// Legacy broadcast fanout (for fraud proofs and non-Plumtree messages).
const BROADCAST_FANOUT: usize = 10;
/// Default TTL for broadcast messages.
const BROADCAST_TTL: u8 = 3;
/// SWIM: consecutive failures before asking other peers to probe.
const SWIM_SUSPECT_THRESHOLD: u32 = 3;
/// SWIM: number of random peers to ask for indirect probe.
const SWIM_INDIRECT_PROBES: usize = 2;
/// SWIM: total failures (direct + indirect) before eviction.
const SWIM_EVICT_THRESHOLD: u32 = 5;
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
        let mut protocol = TrustChainProtocol::new(identity.clone(), store);

        // Configure audit recording level if specified.
        if let Some(ref level_str) = config.audit_level {
            if let Some(level) = trustchain_core::AuditLevel::from_str_loose(level_str) {
                protocol.set_audit_config(trustchain_core::AuditConfig::with_level(level));
                tracing::info!(audit_level = %level, "audit recording configured");
            }
        }

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

    /// Resolve bootstrap URLs to pubkeys by querying each seed's /status endpoint.
    ///
    /// The trust engine needs pubkey hex strings (not URLs) to identify seed nodes.
    /// Returns the resolved pubkeys; any unresolvable seeds are skipped with a warning.
    async fn resolve_seed_pubkeys(&self) -> Vec<String> {
        let bootstrap = self.config.effective_bootstrap_nodes();
        if bootstrap.is_empty() {
            return vec![];
        }

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap_or_default();

        let mut pubkeys = Vec::new();
        for addr in &bootstrap {
            let url = if addr.contains("/status") {
                addr.clone()
            } else {
                let base = addr.trim_end_matches('/');
                format!("{base}/status")
            };
            match client.get(&url).send().await {
                Ok(resp) => {
                    if let Ok(body) = resp.json::<serde_json::Value>().await {
                        if let Some(pk) = body.get("public_key").and_then(|v| v.as_str()) {
                            tracing::info!(seed = &pk[..8.min(pk.len())], addr = %addr, "resolved seed pubkey");
                            pubkeys.push(pk.to_string());
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(addr = %addr, err = %e, "failed to resolve seed pubkey");
                }
            }
        }

        // Also include any raw pubkeys (64-char hex strings) passed directly.
        for addr in &bootstrap {
            if addr.len() == 64
                && addr.chars().all(|c| c.is_ascii_hexdigit())
                && !pubkeys.contains(addr)
            {
                pubkeys.push(addr.clone());
            }
        }

        pubkeys
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

        // Resolve bootstrap URLs → pubkeys for the trust engine.
        // TrustEngine needs hex pubkeys, not HTTP addresses.
        let seed_pubkeys = self.resolve_seed_pubkeys().await;
        if seed_pubkeys.is_empty() && !self.config.effective_bootstrap_nodes().is_empty() {
            tracing::warn!("could not resolve any seed pubkeys — trust scores may be degraded");
        }

        // Start HTTP REST API (+ MCP if feature enabled).
        let http_addr: SocketAddr = self.config.http_addr.parse()?;
        let http_state = AppState {
            protocol: self.protocol.clone(),
            discovery: self.discovery.clone(),
            quic: Some(quic_accept_handle.1.clone()),
            agent_endpoint: self.config.agent_endpoint.clone(),
            delegation_store: self.delegation_store.clone(),
            latest_checkpoint: self.latest_checkpoint.clone(),
            seed_nodes: seed_pubkeys.clone(),
            agent_name: self.config.agent_name.clone(),
        };

        #[cfg(feature = "mcp")]
        let mcp_protocol = self.protocol.clone();
        #[cfg(feature = "mcp")]
        let mcp_discovery = self.discovery.clone();
        #[cfg(feature = "mcp")]
        let mcp_endpoint = self.config.agent_endpoint.clone();
        #[cfg(feature = "mcp")]
        let mcp_seed_nodes = seed_pubkeys.clone();

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
            seed_nodes: seed_pubkeys.clone(),
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
        let disc_quic = quic_accept_handle.1.clone();
        let discovery_handle = tokio::spawn(async move {
            Self::discovery_loop(
                disc,
                disc_protocol,
                bootstrap_nodes,
                disc_delegation_store,
                disc_quic,
            )
            .await;
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

        // Bootstrap trust: propose a `bootstrap` interaction to each bootstrap peer.
        // This creates a bilateral block that establishes a trust path from the seed
        // to this node, enabling non-zero trust scores via NetFlow/MeritRank.
        {
            let bootstrap_peers = self.config.effective_bootstrap_nodes();
            let boot_protocol = self.protocol.clone();
            let boot_discovery = self.discovery.clone();
            let boot_quic = quic_accept_handle.1.clone();
            tokio::spawn(async move {
                // Wait for discovery to populate peer list from bootstrap nodes.
                tokio::time::sleep(Duration::from_secs(3)).await;

                for boot_addr in &bootstrap_peers {
                    // Find the bootstrap peer's pubkey from discovery.
                    let peers: Vec<_> = boot_discovery.get_peers().await;
                    let boot_peer = peers.iter().find(|p| p.address == *boot_addr);

                    if let Some(peer) = boot_peer {
                        let peer_pubkey = peer.pubkey.clone();
                        let tx = serde_json::json!({
                            "interaction_type": "bootstrap",
                            "outcome": "completed",
                        });

                        // Create and send proposal.
                        let proposal = {
                            let mut proto = boot_protocol.lock().await;
                            match proto.create_proposal(&peer_pubkey, tx, None) {
                                Ok(p) => p,
                                Err(e) => {
                                    tracing::debug!(
                                        peer = &peer_pubkey[..8],
                                        err = %e,
                                        "bootstrap proposal creation failed"
                                    );
                                    continue;
                                }
                            }
                        };

                        // Send via QUIC.
                        // Derive QUIC address from HTTP address (e.g. "http://1.2.3.4:8202").
                        // Strip any scheme prefix, then parse host:port.
                        let quic_addr: Option<SocketAddr> = {
                            let addr_str = peer.address.trim();
                            let host_port = if let Some(rest) = addr_str.strip_prefix("http://") {
                                rest
                            } else if let Some(rest) = addr_str.strip_prefix("https://") {
                                rest
                            } else {
                                addr_str
                            };
                            // host_port is now "host:port" or "host"
                            let (host, http_port): (&str, u16) =
                                if let Some(colon) = host_port.rfind(':') {
                                    let h = &host_port[..colon];
                                    let p: u16 = host_port[colon + 1..].parse().unwrap_or(8202);
                                    (h, p)
                                } else {
                                    (host_port, 8202_u16)
                                };
                            let quic_port = http_port.saturating_sub(QUIC_PORT_OFFSET);
                            format!("{host}:{quic_port}").parse::<SocketAddr>().ok()
                        };
                        if let Some(addr) = quic_addr {
                            let our_pubkey = {
                                let proto = boot_protocol.lock().await;
                                proto.pubkey()
                            };
                            let msg_id = format!("boot-{}", our_pubkey.get(..8).unwrap_or("?"));
                            let msg = TransportMessage::new(
                                MessageType::Proposal,
                                our_pubkey,
                                block_to_bytes(&proposal),
                                msg_id,
                            );
                            let msg_bytes = serde_json::to_vec(&msg).unwrap_or_default();

                            match tokio::time::timeout(
                                Duration::from_secs(10),
                                boot_quic.send_message(addr, &msg_bytes),
                            )
                            .await
                            {
                                Ok(Ok(response_bytes)) => {
                                    if let Ok(resp_msg) =
                                        serde_json::from_slice::<TransportMessage>(&response_bytes)
                                    {
                                        if resp_msg.message_type == MessageType::Agreement {
                                            if let Ok(agreement) = bytes_to_block(&resp_msg.payload)
                                            {
                                                let mut proto = boot_protocol.lock().await;
                                                if proto.receive_agreement(&agreement).is_ok() {
                                                    tracing::info!(
                                                        peer = &peer_pubkey[..8],
                                                        "bootstrap trust established (bilateral)"
                                                    );
                                                }
                                            }
                                        }
                                    }
                                }
                                Ok(Err(e)) => {
                                    tracing::debug!(
                                        peer = &peer_pubkey[..8],
                                        err = %e,
                                        "bootstrap QUIC send failed"
                                    );
                                }
                                Err(_) => {
                                    tracing::debug!(
                                        peer = &peer_pubkey[..8],
                                        "bootstrap proposal timed out"
                                    );
                                }
                            }
                        }
                    }
                }
            });
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

    /// Start in audit-only mode: HTTP + proxy only, no networking.
    ///
    /// Used when `--no-networking` is set. Only the HTTP REST API and transparent
    /// proxy are started. No QUIC, gRPC, STUN, gossip, or peer discovery.
    pub async fn run_audit_only(&self) -> anyhow::Result<()> {
        let pubkey = self.identity.pubkey_hex();
        tracing::info!(
            pubkey = &pubkey[..8],
            "starting TrustChain node in audit-only mode (no networking)"
        );

        // Start HTTP REST API.
        let http_addr: SocketAddr = self.config.http_addr.parse()?;
        let http_state = AppState {
            protocol: self.protocol.clone(),
            discovery: self.discovery.clone(),
            quic: None,
            agent_endpoint: self.config.agent_endpoint.clone(),
            delegation_store: self.delegation_store.clone(),
            latest_checkpoint: self.latest_checkpoint.clone(),
            seed_nodes: vec![], // No seeds in audit-only mode.
            agent_name: self.config.agent_name.clone(),
        };

        let http_handle = tokio::spawn(async move {
            let router = build_router(http_state);
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
        tracing::info!(%http_addr, "HTTP API ready (audit-only)");

        // Start transparent HTTP proxy (QUIC bound to ephemeral port, unused).
        let proxy_addr: SocketAddr = self.config.proxy_addr.parse()?;
        let dummy_quic = Arc::new(
            QuicTransport::bind(SocketAddr::from(([127, 0, 0, 1], 0)), &pubkey)
                .await
                .map_err(|e| anyhow::anyhow!("QUIC ephemeral bind: {e}"))?,
        );
        let proxy_state = ProxyState {
            protocol: self.protocol.clone(),
            discovery: self.discovery.clone(),
            quic: dummy_quic,
            client: reqwest::Client::new(),
            peer_locks: std::sync::Arc::new(tokio::sync::Mutex::new(
                std::collections::HashMap::new(),
            )),
            delegation_store: Some(self.delegation_store.clone()),
            seed_nodes: vec![],
        };
        let proxy_handle = tokio::spawn(async move {
            if let Err(e) = start_proxy_server(proxy_addr, proxy_state).await {
                tracing::error!("proxy server error: {e}");
            }
        });
        tracing::info!(%proxy_addr, "trust proxy ready (audit-only)");

        // Register agent endpoint alias.
        if let Some(ref endpoint) = self.config.agent_endpoint {
            self.discovery
                .add_alias(endpoint.clone(), pubkey.clone())
                .await;
        }

        tracing::info!(
            pubkey = &pubkey[..8],
            http = %http_addr,
            proxy = %proxy_addr,
            "audit-only node started (no networking)"
        );

        tokio::select! {
            _ = http_handle => tracing::warn!("HTTP server exited"),
            _ = proxy_handle => tracing::warn!("proxy server exited"),
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("received shutdown signal");
            }
        }

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

            // Plumtree lazy push: peer sends us metadata about a block pair.
            // If we don't have it, request the full block.
            MessageType::BlockMetadata => {
                let meta: BlockMetadataPayload = match serde_json::from_slice(&msg.payload) {
                    Ok(m) => m,
                    Err(e) => {
                        return Self::error_response(&format!("invalid block metadata: {e}"));
                    }
                };

                let block_id = format!("{}:{}", meta.block1_hash, meta.block2_hash);
                let already_seen = {
                    let mut t = tracker.lock().await;
                    !t.mark_if_new(&block_id)
                };

                if already_seen {
                    // We already have this block pair, ignore.
                    serde_json::to_vec(&serde_json::json!({"status": "already_have"}))
                        .unwrap_or_default()
                } else {
                    // Request the full block pair from the sender.
                    let req_payload = BlockMetadataRequestPayload {
                        block1_hash: meta.block1_hash,
                        block2_hash: meta.block2_hash,
                    };
                    let resp = TransportMessage::new(
                        MessageType::BlockMetadataRequest,
                        {
                            let proto = protocol.lock().await;
                            proto.pubkey()
                        },
                        serde_json::to_vec(&req_payload).unwrap_or_default(),
                        msg.request_id,
                    );
                    serde_json::to_vec(&resp).unwrap_or_default()
                }
            }

            // Plumtree: peer requests full block pair after receiving our metadata.
            // Look up the blocks in our store and return them.
            MessageType::BlockMetadataRequest => {
                let req: BlockMetadataRequestPayload = match serde_json::from_slice(&msg.payload) {
                    Ok(r) => r,
                    Err(e) => {
                        return Self::error_response(&format!(
                            "invalid block metadata request: {e}"
                        ));
                    }
                };

                let proto = protocol.lock().await;
                let block1 = proto.store().get_block_by_hash(&req.block1_hash);
                let block2 = proto.store().get_block_by_hash(&req.block2_hash);

                match (block1, block2) {
                    (Some(b1), Some(b2)) => {
                        let payload = BlockPairBroadcastPayload {
                            block1: b1,
                            block2: b2,
                            ttl: 1, // Don't relay further — the requester already has metadata.
                        };
                        let resp = TransportMessage::new(
                            MessageType::BlockPairBroadcast,
                            proto.pubkey(),
                            serde_json::to_vec(&payload).unwrap_or_default(),
                            msg.request_id,
                        );
                        serde_json::to_vec(&resp).unwrap_or_default()
                    }
                    _ => Self::error_response("block pair not found"),
                }
            }

            _ => Self::error_response("unhandled message type"),
        }
    }

    /// Plumtree broadcast: eager push (full blocks) to K peers, lazy push (metadata) to M more.
    async fn broadcast_to_peers(
        payload: &BlockPairBroadcastPayload,
        our_pubkey: &str,
        discovery: &Arc<PeerDiscovery>,
        quic: &Arc<QuicTransport>,
        _tracker: &Arc<Mutex<BroadcastTracker>>,
    ) {
        let total_needed = EAGER_FANOUT + LAZY_FANOUT;
        let peers = discovery.get_gossip_peers(total_needed).await;
        if peers.is_empty() {
            return;
        }

        // Split peers: first EAGER_FANOUT get full blocks, rest get metadata only.
        let eager_count = EAGER_FANOUT.min(peers.len());
        let (eager_peers, lazy_peers) = peers.split_at(eager_count);

        // Eager push: full block pair.
        let full_msg = TransportMessage::new(
            MessageType::BlockPairBroadcast,
            our_pubkey.to_string(),
            serde_json::to_vec(payload).unwrap_or_default(),
            format!("bc-{}", payload.block1.block_hash.get(..8).unwrap_or("?")),
        );
        let full_msg_bytes = serde_json::to_vec(&full_msg).unwrap_or_default();

        for peer in eager_peers {
            let quic_addr = match Self::derive_quic_addr(&peer.address) {
                Some(a) => a,
                None => continue,
            };
            let quic = quic.clone();
            let bytes = full_msg_bytes.clone();
            tokio::spawn(async move {
                match tokio::time::timeout(
                    Duration::from_secs(5),
                    quic.send_message(quic_addr, &bytes),
                )
                .await
                {
                    Ok(Ok(_)) => {}
                    Ok(Err(e)) => tracing::debug!("eager broadcast error: {e}"),
                    Err(_) => tracing::debug!("eager broadcast timeout"),
                }
            });
        }

        // Lazy push: metadata only (~100 bytes vs ~2KB).
        if !lazy_peers.is_empty() {
            let meta_payload = BlockMetadataPayload {
                block1_hash: payload.block1.block_hash.clone(),
                block2_hash: payload.block2.block_hash.clone(),
                sequence_number: payload.block1.sequence_number,
                creator_pubkey: payload.block1.public_key.clone(),
            };
            let meta_msg = TransportMessage::new(
                MessageType::BlockMetadata,
                our_pubkey.to_string(),
                serde_json::to_vec(&meta_payload).unwrap_or_default(),
                format!("meta-{}", payload.block1.block_hash.get(..8).unwrap_or("?")),
            );
            let meta_msg_bytes = serde_json::to_vec(&meta_msg).unwrap_or_default();

            for peer in lazy_peers {
                let quic_addr = match Self::derive_quic_addr(&peer.address) {
                    Some(a) => a,
                    None => continue,
                };
                let quic = quic.clone();
                let bytes = meta_msg_bytes.clone();
                tokio::spawn(async move {
                    match tokio::time::timeout(
                        Duration::from_secs(5),
                        quic.send_message(quic_addr, &bytes),
                    )
                    .await
                    {
                        Ok(Ok(_)) => {}
                        Ok(Err(e)) => tracing::debug!("lazy broadcast error: {e}"),
                        Err(_) => tracing::debug!("lazy broadcast timeout"),
                    }
                });
            }
        }
    }

    /// Derive QUIC socket address from an HTTP peer address string.
    fn derive_quic_addr(address: &str) -> Option<SocketAddr> {
        let addr_str = address.strip_prefix("http://").unwrap_or(address);
        match addr_str.parse::<SocketAddr>() {
            Ok(a) => Some(SocketAddr::new(
                a.ip(),
                a.port().saturating_sub(QUIC_PORT_OFFSET),
            )),
            Err(_) => None,
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
            let quic_addr = match Self::derive_quic_addr(&peer.address) {
                Some(a) => a,
                None => continue,
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

    /// Peer discovery: bootstrap then periodic gossip via QUIC (with HTTP fallback).
    async fn discovery_loop(
        discovery: Arc<PeerDiscovery>,
        protocol: Arc<Mutex<TrustChainProtocol<SqliteBlockStore>>>,
        bootstrap_nodes: Vec<String>,
        _delegation_store: Arc<Mutex<SqliteDelegationStore>>,
        quic: Arc<QuicTransport>,
    ) {
        // Phase 1: Bootstrap — connect to known nodes via HTTP (QUIC addr unknown yet).
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

        // Phase 2: Periodic gossip — exchange peer lists via QUIC, HTTP fallback.
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        loop {
            interval.tick().await;

            let our_pubkey = {
                let proto = protocol.lock().await;
                proto.pubkey()
            };

            let gossip_peers = discovery.get_gossip_peers(3).await;
            for peer in &gossip_peers {
                let quic_addr = match Self::derive_quic_addr(&peer.address) {
                    Some(a) => a,
                    None => continue,
                };

                // Try QUIC status first, fall back to HTTP.
                match Self::fetch_status_quic(&quic, quic_addr, &our_pubkey).await {
                    Ok((pubkey, latest_seq)) => {
                        discovery
                            .add_peer(pubkey, peer.address.clone(), latest_seq)
                            .await;
                    }
                    Err(_) => {
                        // QUIC failed — try HTTP fallback.
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
                                // Both failed — SWIM failure tracking.
                                discovery.increment_failure(&peer.pubkey).await;
                                let failures = discovery.get_failure_count(&peer.pubkey).await;

                                if (SWIM_SUSPECT_THRESHOLD..SWIM_EVICT_THRESHOLD)
                                    .contains(&failures)
                                {
                                    // Ask indirect probers to check the suspect.
                                    Self::swim_indirect_probe(
                                        &peer.pubkey,
                                        &peer.address,
                                        &discovery,
                                        &quic,
                                        &our_pubkey,
                                    )
                                    .await;
                                } else if failures >= SWIM_EVICT_THRESHOLD {
                                    tracing::warn!(
                                        peer = &peer.pubkey[..8.min(peer.pubkey.len())],
                                        failures,
                                        "evicting unresponsive peer (SWIM)"
                                    );
                                    discovery.remove_peer(&peer.pubkey).await;
                                }
                                continue;
                            }
                        }
                    }
                }

                // Exchange peer lists via QUIC DiscoveryRequest.
                match Self::fetch_peers_quic(&quic, quic_addr, &our_pubkey, &discovery).await {
                    Ok(peers) => {
                        for (pk, address, seq) in peers {
                            discovery.add_peer(pk, address, seq).await;
                        }
                    }
                    Err(_) => {
                        // QUIC peer exchange failed — HTTP fallback.
                        if let Ok(peers) = Self::fetch_peers_http(&peer.address).await {
                            for (pk, address, seq) in peers {
                                discovery.add_peer(pk, address, seq).await;
                            }
                        }
                    }
                }
            }

            // Sync chains from peers we know about via QUIC CrawlRequest.
            let all_peers = discovery.get_peers().await;
            for peer in &all_peers {
                let our_seq = {
                    let proto = protocol.lock().await;
                    proto.store().get_latest_seq(&peer.pubkey).unwrap_or(0)
                };
                if peer.latest_seq > our_seq {
                    let quic_addr = match Self::derive_quic_addr(&peer.address) {
                        Some(a) => a,
                        None => continue,
                    };

                    // Try QUIC crawl first, fall back to HTTP.
                    let blocks = match Self::fetch_crawl_quic(
                        &quic,
                        quic_addr,
                        &our_pubkey,
                        &peer.pubkey,
                        our_seq + 1,
                    )
                    .await
                    {
                        Ok(b) => b,
                        Err(_) => {
                            // HTTP fallback for crawl.
                            Self::fetch_crawl_http(&peer.address, &peer.pubkey, our_seq + 1)
                                .await
                                .unwrap_or_default()
                        }
                    };

                    if !blocks.is_empty() {
                        let mut proto = protocol.lock().await;
                        let our_pk = proto.pubkey();
                        for block in &blocks {
                            if let Err(e) = proto.store_mut().add_block(block) {
                                if !e.to_string().to_lowercase().contains("duplicate") {
                                    tracing::warn!(error = %e, "failed to store synced block");
                                }
                            }
                        }
                        tracing::info!(
                            peer = &peer.pubkey[..8],
                            synced = blocks.len(),
                            "synced blocks from peer"
                        );

                        // Notify about pending delegation proposals targeting us.
                        for block in &blocks {
                            if block.block_type
                                == trustchain_core::BlockType::Delegation.to_string()
                                && block.link_public_key == our_pk
                                && block.link_sequence_number == 0
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

    /// SWIM indirect probe: ask random peers to ping a suspect on our behalf.
    async fn swim_indirect_probe(
        suspect_pubkey: &str,
        _suspect_address: &str,
        discovery: &Arc<PeerDiscovery>,
        quic: &Arc<QuicTransport>,
        our_pubkey: &str,
    ) {
        let probers = discovery.get_gossip_peers(SWIM_INDIRECT_PROBES + 1).await;
        let mut probed = 0;

        for prober in &probers {
            if prober.pubkey == suspect_pubkey {
                continue;
            }
            if probed >= SWIM_INDIRECT_PROBES {
                break;
            }

            let quic_addr = match Self::derive_quic_addr(&prober.address) {
                Some(a) => a,
                None => continue,
            };

            // Send a Ping to the prober — if they can reach the suspect, they'll
            // have recently exchanged with it. We use this as a heuristic.
            let ping = TransportMessage::new(
                MessageType::Ping,
                our_pubkey.to_string(),
                suspect_pubkey.as_bytes().to_vec(),
                format!("swim-{}", &suspect_pubkey[..8.min(suspect_pubkey.len())]),
            );
            let ping_bytes = serde_json::to_vec(&ping).unwrap_or_default();

            match tokio::time::timeout(
                Duration::from_secs(5),
                quic.send_message(quic_addr, &ping_bytes),
            )
            .await
            {
                Ok(Ok(_)) => {
                    // Prober responded — suspect may still be alive via other paths.
                    // Don't escalate failure for this round.
                    tracing::debug!(
                        suspect = &suspect_pubkey[..8.min(suspect_pubkey.len())],
                        prober = &prober.pubkey[..8.min(prober.pubkey.len())],
                        "SWIM indirect probe succeeded"
                    );
                    discovery.reset_failure(suspect_pubkey).await;
                    return;
                }
                _ => {
                    probed += 1;
                }
            }
        }

        // All indirect probes failed — increment failure again.
        if probed > 0 {
            discovery.increment_failure(suspect_pubkey).await;
            tracing::debug!(
                suspect = &suspect_pubkey[..8.min(suspect_pubkey.len())],
                "SWIM indirect probes all failed"
            );
        }
    }

    /// Fetch status from a peer via QUIC StatusRequest.
    async fn fetch_status_quic(
        quic: &Arc<QuicTransport>,
        addr: SocketAddr,
        our_pubkey: &str,
    ) -> anyhow::Result<(String, u64)> {
        let msg = TransportMessage::new(
            MessageType::StatusRequest,
            our_pubkey.to_string(),
            Vec::new(),
            "status-q".to_string(),
        );
        let msg_bytes = serde_json::to_vec(&msg)?;

        let resp_bytes =
            tokio::time::timeout(Duration::from_secs(5), quic.send_message(addr, &msg_bytes))
                .await
                .map_err(|_| anyhow::anyhow!("timeout"))?
                .map_err(|e| anyhow::anyhow!("{e}"))?;

        let resp: serde_json::Value = serde_json::from_slice(&resp_bytes)?;
        let pubkey = resp
            .get("public_key")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("missing public_key"))?
            .to_string();
        let latest_seq = resp.get("latest_seq").and_then(|v| v.as_u64()).unwrap_or(0);
        Ok((pubkey, latest_seq))
    }

    /// Fetch peer list via QUIC DiscoveryRequest.
    async fn fetch_peers_quic(
        quic: &Arc<QuicTransport>,
        addr: SocketAddr,
        our_pubkey: &str,
        discovery: &Arc<PeerDiscovery>,
    ) -> anyhow::Result<Vec<(String, String, u64)>> {
        // Send our peers as payload so the remote can merge them too.
        let our_peers: Vec<(String, String, u64)> = discovery
            .get_gossip_peers(20)
            .await
            .into_iter()
            .map(|p| (p.pubkey, p.address, p.latest_seq))
            .collect();

        let msg = TransportMessage::new(
            MessageType::DiscoveryRequest,
            our_pubkey.to_string(),
            serde_json::to_vec(&our_peers).unwrap_or_default(),
            "disc-q".to_string(),
        );
        let msg_bytes = serde_json::to_vec(&msg)?;

        let resp_bytes =
            tokio::time::timeout(Duration::from_secs(5), quic.send_message(addr, &msg_bytes))
                .await
                .map_err(|_| anyhow::anyhow!("timeout"))?
                .map_err(|e| anyhow::anyhow!("{e}"))?;

        // The response is a DiscoveryResponse TransportMessage with peers as payload.
        let resp: TransportMessage = serde_json::from_slice(&resp_bytes)?;
        let peers: Vec<(String, String, u64)> =
            serde_json::from_slice(&resp.payload).unwrap_or_default();
        Ok(peers)
    }

    /// Fetch blocks via QUIC CrawlRequest.
    async fn fetch_crawl_quic(
        quic: &Arc<QuicTransport>,
        addr: SocketAddr,
        our_pubkey: &str,
        target_pubkey: &str,
        start_seq: u64,
    ) -> anyhow::Result<Vec<HalfBlock>> {
        let crawl_req = serde_json::json!({
            "pubkey": target_pubkey,
            "start_seq": start_seq,
        });
        let msg = TransportMessage::new(
            MessageType::CrawlRequest,
            our_pubkey.to_string(),
            serde_json::to_vec(&crawl_req)?,
            format!("crawl-q-{}", &target_pubkey[..8.min(target_pubkey.len())]),
        );
        let msg_bytes = serde_json::to_vec(&msg)?;

        let resp_bytes =
            tokio::time::timeout(Duration::from_secs(10), quic.send_message(addr, &msg_bytes))
                .await
                .map_err(|_| anyhow::anyhow!("timeout"))?
                .map_err(|e| anyhow::anyhow!("{e}"))?;

        // Response is a CrawlResponse with blocks as payload.
        let resp: TransportMessage = serde_json::from_slice(&resp_bytes)?;
        let blocks: Vec<HalfBlock> = serde_json::from_slice(&resp.payload).unwrap_or_default();
        Ok(blocks)
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
