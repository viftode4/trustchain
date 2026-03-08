//! Transparent HTTP proxy — intercepts all outbound agent-to-agent calls,
//! runs the TrustChain bilateral handshake invisibly, then forwards the call.
//!
//! Agents set `HTTP_PROXY=http://localhost:8203` once and never think about
//! TrustChain again. Every call to a known TC peer is automatically recorded.
//!
//! Flow per outbound call:
//!   1. Resolve destination from the request URI or Host header.
//!   2. Look up destination in PeerDiscovery by address.
//!   3. If known TC peer → run proposal/agreement over QUIC (invisible to caller).
//!   4. Forward the original HTTP call to the destination.
//!   5. Return response to the caller.
//!
//! Non-TC destinations are forwarded transparently with zero overhead.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use axum::{
    extract::State,
    http::{header, HeaderMap, HeaderValue, Method, StatusCode},
    response::{IntoResponse, Response},
    Router,
};
use hyper::upgrade::OnUpgrade;
use reqwest::Client;
use tokio::io::copy_bidirectional;
use tokio::net::TcpStream;
use tokio::sync::Mutex;

use trustchain_core::{BlockStore, DelegationStore, TrustChainProtocol};

use crate::discovery::{PeerDiscovery, PeerRecord};
use crate::http::uuid_v4;
use crate::message::{block_to_bytes, bytes_to_block, MessageType, TransportMessage};
use crate::quic::QuicTransport;

/// Headers that must not be forwarded through a proxy (hop-by-hop per RFC 7230).
const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
];

/// Shared state for the proxy server.
pub struct ProxyState<
    S: BlockStore + 'static,
    D: DelegationStore + 'static = trustchain_core::MemoryDelegationStore,
> {
    pub protocol: Arc<Mutex<TrustChainProtocol<S>>>,
    pub discovery: Arc<PeerDiscovery>,
    pub quic: Arc<QuicTransport>,
    pub client: Client,
    /// Per-peer handshake locks. Only one handshake runs at a time per peer;
    /// concurrent requests to the same peer skip the handshake (the in-flight
    /// one already covers this burst of activity). This matches the TrustChain
    /// paper's model where interactions are sequential per peer pair.
    pub peer_locks: Arc<Mutex<HashMap<String, Arc<Mutex<()>>>>>,
    /// Optional delegation store for enriching proxy transactions with delegation context.
    pub delegation_store: Option<Arc<Mutex<D>>>,
    /// Seed nodes for TrustEngine (empty = no NetFlow).
    pub seed_nodes: Vec<String>,
}

impl<S: BlockStore + 'static, D: DelegationStore + 'static> Clone for ProxyState<S, D> {
    fn clone(&self) -> Self {
        Self {
            protocol: self.protocol.clone(),
            discovery: self.discovery.clone(),
            quic: self.quic.clone(),
            client: self.client.clone(),
            peer_locks: self.peer_locks.clone(),
            delegation_store: self.delegation_store.clone(),
            seed_nodes: self.seed_nodes.clone(),
        }
    }
}

impl<S: BlockStore + 'static, D: DelegationStore + 'static> ProxyState<S, D> {
    /// Get or create the per-peer handshake lock.
    async fn peer_lock(&self, pubkey: &str) -> Arc<Mutex<()>> {
        let mut locks = self.peer_locks.lock().await;
        locks
            .entry(pubkey.to_string())
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    }
}

/// Start the transparent proxy server.
pub async fn start_proxy_server<
    S: BlockStore + Send + 'static,
    D: DelegationStore + Send + 'static,
>(
    addr: SocketAddr,
    state: ProxyState<S, D>,
) -> anyhow::Result<()> {
    let router = Router::new()
        .fallback(proxy_handler::<S, D>)
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    log::info!("Trust proxy listening on {addr}");
    axum::serve(listener, router).await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Core handler
// ---------------------------------------------------------------------------

async fn proxy_handler<S: BlockStore + 'static, D: DelegationStore + 'static>(
    State(state): State<ProxyState<S, D>>,
    req: axum::extract::Request,
) -> Response {
    // Handle HTTPS CONNECT tunneling.
    if req.method() == Method::CONNECT {
        return handle_connect(state, req).await;
    }

    // 1. Resolve target URL from the request.
    let target_url = match resolve_target(&req) {
        Some(u) => u,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                "proxy: cannot determine target URL",
            )
                .into_response();
        }
    };

    // 2. Check if the destination is a known TC peer.
    let authority = extract_authority(&target_url);
    let peer = match &authority {
        Some(auth) => state.discovery.get_peer_by_address(auth).await,
        None => None,
    };

    // 3. If TC peer: run the bilateral TrustChain handshake before forwarding.
    //    Per the TrustChain paper, interactions are sequential per peer pair.
    //    Use try_lock: if a handshake is already in-flight for this peer, skip —
    //    the existing handshake covers this burst of activity.
    if let Some(ref peer) = peer {
        let lock = state.peer_lock(&peer.pubkey).await;
        let acquired = lock.try_lock();
        if acquired.is_ok() {
            let mut tx = serde_json::json!({
                "proxy": true,
                "method": req.method().as_str(),
                "path": req.uri().path(),
            });

            // Enrich with delegation context if local identity has an active delegation.
            if let Some(ref ds) = state.delegation_store {
                let ds_guard = ds.lock().await;
                let our_pubkey = {
                    let proto = state.protocol.lock().await;
                    proto.pubkey()
                };
                if let Ok(Some(deleg)) = ds_guard.get_delegation_by_delegate(&our_pubkey) {
                    let now_ms = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_millis() as u64)
                        .unwrap_or(0);
                    if deleg.is_active(now_ms) {
                        tx["delegation_id"] = serde_json::json!(deleg.delegation_id);
                        tx["delegator_pubkey"] = serde_json::json!(deleg.delegator_pubkey);
                        tx["scope"] = serde_json::json!(deleg.scope);
                    }
                }
            }

            match run_handshake(&state, peer, tx).await {
                Ok(()) => {
                    log::debug!(
                        "TC handshake ok -> {} ({})",
                        &peer.pubkey[..8.min(peer.pubkey.len())],
                        target_url,
                    );
                }
                Err(e) => {
                    // Trust recording is best-effort — log but still forward.
                    log::warn!(
                        "TC handshake failed with {} ({}): {e} — forwarding anyway",
                        &peer.pubkey[..8.min(peer.pubkey.len())],
                        target_url,
                    );
                }
            }
            // acquired (holding the guard) drops here, releasing the peer lock
        } else {
            // Another handshake is in-flight for this peer — skip.
            log::debug!(
                "TC handshake already in-flight for {} — skipping",
                &peer.pubkey[..8.min(peer.pubkey.len())],
            );
        }
    }

    // 3b. If NOT a TC peer, record an audit block (single-player mode).
    //     Classify the request into semantic event types for structured recording.
    if peer.is_none() {
        if let Some(ref auth) = authority {
            let method = req.method().as_str().to_string();
            let path = req.uri().path().to_string();
            let event_type = classify_event(auth, &path);

            let mut proto = state.protocol.lock().await;
            // Check if this event type should be recorded under the current audit config.
            if let Some(et) = trustchain_core::EventType::from_str_loose(&event_type) {
                if !proto.should_record_event(&et) {
                    log::debug!("skipping audit block for {auth} (event_type '{event_type}' disabled)");
                } else {
                    let tx = serde_json::json!({
                        "event_type": event_type,
                        "action": format!("{method} {path}"),
                        "outcome": "forwarded",
                        "destination": auth,
                        "method": method,
                        "path": path,
                    });
                    if let Err(e) = proto.create_audit(tx, None) {
                        log::warn!("audit block creation failed for {auth}: {e}");
                    }
                }
            } else {
                // Unknown event type — record as external_api (always, unless filtered).
                let tx = serde_json::json!({
                    "event_type": event_type,
                    "action": format!("{method} {path}"),
                    "outcome": "forwarded",
                    "destination": auth,
                    "method": method,
                    "path": path,
                });
                if let Err(e) = proto.create_audit(tx, None) {
                    log::warn!("audit block creation failed for {auth}: {e}");
                }
            }
        }
    }

    // 4. Compute trust info for response headers (best-effort).
    let trust_headers = if let Some(ref peer) = peer {
        compute_trust_headers(&state, peer).await
    } else {
        None
    };

    // 5. Forward the original call and return the response with trust headers.
    let mut response = forward_request(state.client, req, &target_url).await;

    if let Some(headers) = trust_headers {
        let resp_headers = response.headers_mut();
        for (name, value) in headers {
            if let (Ok(n), Ok(v)) = (
                axum::http::HeaderName::from_bytes(name.as_bytes()),
                HeaderValue::from_str(&value),
            ) {
                resp_headers.insert(n, v);
            }
        }
    }

    response
}

/// Compute X-TrustChain-* headers for a peer (best-effort).
async fn compute_trust_headers<S: BlockStore + 'static, D: DelegationStore + 'static>(
    state: &ProxyState<S, D>,
    peer: &PeerRecord,
) -> Option<Vec<(String, String)>> {
    let mut headers = Vec::new();

    // Always include the peer's pubkey
    headers.push(("X-TrustChain-Pubkey".to_string(), peer.pubkey.clone()));

    // Compute proper trust score via TrustEngine
    let proto = state.protocol.lock().await;
    let store = proto.store();
    let seed_nodes = if state.seed_nodes.is_empty() {
        None
    } else {
        Some(state.seed_nodes.clone())
    };
    let engine = trustchain_core::TrustEngine::new(store, seed_nodes, None, None);
    if let Ok(evidence) = engine.compute_trust_with_evidence(&peer.pubkey) {
        headers.push((
            "X-TrustChain-Interactions".to_string(),
            evidence.interactions.to_string(),
        ));
        headers.push((
            "X-TrustChain-Score".to_string(),
            format!("{:.3}", evidence.trust_score),
        ));
    }

    Some(headers)
}

// ---------------------------------------------------------------------------
// HTTPS CONNECT tunnel
// ---------------------------------------------------------------------------

/// Return `true` when the resolved IP address is safe to CONNECT to.
///
/// Blocks destinations that could be used for Server-Side Request Forgery (SSRF):
/// - Loopback      (127.0.0.0/8, ::1)
/// - Private       (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
/// - Link-local    (169.254.0.0/16, fe80::/10)
/// - Unspecified   (0.0.0.0, ::)
///
/// If the authority is a hostname rather than an IP literal, this function
/// returns `true` (allow) — the DNS lookup happens at connect time and we
/// cannot pre-check it without an extra resolution round-trip.
fn is_safe_connect_target(authority: &str) -> bool {
    // Strip an optional "[...]" IPv6 bracket wrapper and port suffix.
    let host = if let Some(bracketed) = authority.strip_prefix('[') {
        // IPv6 literal: [::1]:443
        bracketed.split(']').next().unwrap_or(bracketed)
    } else {
        // IPv4 literal or hostname: 1.2.3.4:443 or example.com:443
        authority.split(':').next().unwrap_or(authority)
    };

    let ip: IpAddr = match host.parse() {
        Ok(ip) => ip,
        // Not an IP literal (hostname) — allow and let DNS + connect decide.
        Err(_) => return true,
    };

    match ip {
        IpAddr::V4(v4) => {
            if v4.is_loopback() {
                return false; // 127.0.0.0/8
            }
            let octets = v4.octets();
            // 10.0.0.0/8
            if octets[0] == 10 {
                return false;
            }
            // 172.16.0.0/12 (172.16.x.x – 172.31.x.x)
            if octets[0] == 172 && (octets[1] >= 16 && octets[1] <= 31) {
                return false;
            }
            // 192.168.0.0/16
            if octets[0] == 192 && octets[1] == 168 {
                return false;
            }
            // 169.254.0.0/16 (link-local)
            if octets[0] == 169 && octets[1] == 254 {
                return false;
            }
            // 0.0.0.0
            if v4.is_unspecified() {
                return false;
            }
            true
        }
        IpAddr::V6(v6) => {
            if v6.is_loopback() {
                return false; // ::1
            }
            if v6.is_unspecified() {
                return false; // ::
            }
            // fe80::/10 (link-local)
            let segments = v6.segments();
            if (segments[0] & 0xffc0) == 0xfe80 {
                return false;
            }
            true
        }
    }
}

/// Handle HTTP CONNECT method for HTTPS tunneling.
///
/// Flow:
/// 1. Extract the target authority (host:port) from the request URI.
/// 2. Validate the target is not an internal/loopback/private address (SSRF prevention).
/// 3. Run the TrustChain handshake if the target is a known TC peer.
/// 4. Establish a TCP connection to the target.
/// 5. Respond with 200 Connection Established.
/// 6. Upgrade the connection and relay bytes bidirectionally.
async fn handle_connect<S: BlockStore + 'static, D: DelegationStore + 'static>(
    state: ProxyState<S, D>,
    req: axum::extract::Request,
) -> Response {
    let authority = match req.uri().authority().map(|a| a.to_string()) {
        Some(a) => a,
        None => {
            return (StatusCode::BAD_REQUEST, "CONNECT: missing authority").into_response();
        }
    };

    // SSRF prevention: block CONNECT requests targeting loopback, private, or
    // link-local addresses. Hostnames are allowed (DNS resolves at connect time).
    if !is_safe_connect_target(&authority) {
        log::warn!("CONNECT blocked: target '{authority}' resolves to a disallowed address range");
        return (
            StatusCode::FORBIDDEN,
            "CONNECT to private/loopback addresses is not permitted",
        )
            .into_response();
    }

    // Run TrustChain handshake for known TC peers (best-effort).
    let peer = state.discovery.get_peer_by_address(&authority).await;
    if let Some(ref peer) = peer {
        let lock = state.peer_lock(&peer.pubkey).await;
        let guard = lock.try_lock();
        if guard.is_ok() {
            let tx = serde_json::json!({
                "proxy": true,
                "method": "CONNECT",
                "authority": &authority,
            });
            if let Err(e) = run_handshake(&state, peer, tx).await {
                log::warn!(
                    "TC handshake for CONNECT to {} failed: {e} — tunneling anyway",
                    &peer.pubkey[..8.min(peer.pubkey.len())],
                );
            }
        }
        drop(guard);
    }

    // Connect to the target host.
    let target_addr = if authority.contains(':') {
        authority.clone()
    } else {
        format!("{authority}:443")
    };

    let target_stream = match TcpStream::connect(&target_addr).await {
        Ok(s) => s,
        Err(e) => {
            return (
                StatusCode::BAD_GATEWAY,
                format!("CONNECT: cannot reach {target_addr}: {e}"),
            )
                .into_response();
        }
    };

    // Upgrade the client connection and relay bytes.
    let on_upgrade = hyper::upgrade::on(req);

    tokio::spawn(async move {
        tunnel(on_upgrade, target_stream).await;
    });

    // Return 200 Connection Established to the client.
    Response::builder()
        .status(StatusCode::OK)
        .body(axum::body::Body::empty())
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

/// Bidirectional byte relay for CONNECT tunnels.
async fn tunnel(on_upgrade: OnUpgrade, mut target: TcpStream) {
    match on_upgrade.await {
        Ok(upgraded) => {
            let mut client = hyper_util::rt::TokioIo::new(upgraded);
            match copy_bidirectional(&mut client, &mut target).await {
                Ok((from_client, from_target)) => {
                    log::debug!(
                        "CONNECT tunnel closed: {from_client} bytes up, {from_target} bytes down"
                    );
                }
                Err(e) => {
                    log::debug!("CONNECT tunnel error: {e}");
                }
            }
        }
        Err(e) => {
            log::warn!("CONNECT upgrade failed: {e}");
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers: URL resolution
// ---------------------------------------------------------------------------

/// Extract the full target URL from a proxy request.
///
/// Handles two cases:
/// - Absolute URI (standard HTTP proxy): `GET http://agent-b:8080/task HTTP/1.1`
/// - Relative URI with Host header: `GET /task HTTP/1.1 \n Host: agent-b:8080`
fn resolve_target(req: &axum::extract::Request) -> Option<String> {
    let uri = req.uri();

    if uri.authority().is_some() {
        // Standard HTTP proxy — request URI is already absolute.
        let scheme = uri.scheme_str().unwrap_or("http");
        let authority = uri.authority()?.as_str();
        let path = uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");
        return Some(format!("{scheme}://{authority}{path}"));
    }

    // Fall back to Host header (direct or SDK-wrapped calls).
    let host = req
        .headers()
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())?;
    let path = uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");
    Some(format!("http://{host}{path}"))
}

/// Extract just the `host:port` authority from a URL string.
fn extract_authority(url: &str) -> Option<String> {
    let without_scheme = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or(url);
    // Everything before the first "/" is the authority.
    let authority = without_scheme.split('/').next()?;
    if authority.is_empty() {
        None
    } else {
        Some(authority.to_string())
    }
}

// ---------------------------------------------------------------------------
// Helpers: TrustChain handshake
// ---------------------------------------------------------------------------

/// Run the bilateral TrustChain proposal/agreement handshake with a peer over QUIC.
///
/// Holds the protocol lock for the entire create_proposal → QUIC round-trip →
/// receive_agreement flow, ensuring atomicity per the TrustChain paper's model.
/// The per-peer lock in the caller prevents concurrent handshakes to the same peer,
/// so this only blocks other protocol operations for the duration of one QUIC round-trip.
async fn run_handshake<S: BlockStore + 'static, D: DelegationStore + 'static>(
    state: &ProxyState<S, D>,
    peer: &PeerRecord,
    tx: serde_json::Value,
) -> anyhow::Result<()> {
    // Derive QUIC address from peer's HTTP address (QUIC is HTTP port - QUIC_PORT_OFFSET).
    let quic_addr: SocketAddr = {
        let addr = peer
            .address
            .strip_prefix("http://")
            .unwrap_or(&peer.address);
        let sa: SocketAddr = addr
            .parse()
            .map_err(|e| anyhow::anyhow!("invalid peer address '{addr}': {e}"))?;
        SocketAddr::new(sa.ip(), sa.port().saturating_sub(crate::QUIC_PORT_OFFSET))
    };

    // Hold the protocol lock for the entire handshake to prevent
    // gossip or other operations from modifying chain state mid-flow.
    let mut proto = state.protocol.lock().await;

    // Create proposal block.
    let proposal = proto
        .create_proposal(&peer.pubkey, tx, None)
        .map_err(|e| anyhow::anyhow!("create_proposal: {e}"))?;

    // Wrap proposal in a TransportMessage.
    let our_pubkey = proto.pubkey();
    let msg = TransportMessage::new(
        MessageType::Proposal,
        our_pubkey,
        block_to_bytes(&proposal),
        uuid_v4(),
    );
    let msg_bytes = serde_json::to_vec(&msg)?;

    // Send over QUIC and wait for the agreement response.
    let response_bytes = tokio::time::timeout(
        Duration::from_secs(10),
        state.quic.send_message(quic_addr, &msg_bytes),
    )
    .await
    .map_err(|_| anyhow::anyhow!("handshake timed out after 10s"))?
    .map_err(|e| anyhow::anyhow!("QUIC send error: {e}"))?;

    // Parse the agreement.
    let resp_msg: TransportMessage = serde_json::from_slice(&response_bytes)
        .map_err(|e| anyhow::anyhow!("malformed QUIC response: {e}"))?;

    if resp_msg.message_type == MessageType::Error {
        let err_text = String::from_utf8_lossy(&resp_msg.payload);
        return Err(anyhow::anyhow!("peer returned error: {err_text}"));
    }

    if resp_msg.message_type != MessageType::Agreement {
        return Err(anyhow::anyhow!(
            "expected Agreement, got {:?}",
            resp_msg.message_type
        ));
    }

    let agreement = bytes_to_block(&resp_msg.payload)
        .map_err(|e| anyhow::anyhow!("invalid agreement block: {e}"))?;

    proto
        .receive_agreement(&agreement)
        .map_err(|e| anyhow::anyhow!("receive_agreement: {e}"))?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers: HTTP forwarding
// ---------------------------------------------------------------------------

/// Forward the intercepted HTTP request to the target and return its response.
async fn forward_request(
    client: Client,
    req: axum::extract::Request,
    target_url: &str,
) -> Response {
    let method = reqwest::Method::from_bytes(req.method().as_str().as_bytes())
        .unwrap_or(reqwest::Method::GET);

    // Strip hop-by-hop headers before forwarding.
    let mut fwd_headers = reqwest::header::HeaderMap::new();
    for (name, value) in req.headers() {
        if HOP_BY_HOP.contains(&name.as_str()) {
            continue;
        }
        if let (Ok(n), Ok(v)) = (
            reqwest::header::HeaderName::from_bytes(name.as_str().as_bytes()),
            reqwest::header::HeaderValue::from_bytes(value.as_bytes()),
        ) {
            fwd_headers.insert(n, v);
        }
    }

    // Read the request body (cap at 16 MiB).
    let body = match axum::body::to_bytes(req.into_body(), 16 * 1024 * 1024).await {
        Ok(b) => b,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                format!("proxy: failed to read body: {e}"),
            )
                .into_response();
        }
    };

    // Forward with a 30-second timeout.
    let result = tokio::time::timeout(
        Duration::from_secs(30),
        client
            .request(method, target_url)
            .headers(fwd_headers)
            .body(body)
            .send(),
    )
    .await;

    match result {
        Ok(Ok(resp)) => {
            let status = StatusCode::from_u16(resp.status().as_u16())
                .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);

            // Copy response headers, stripping hop-by-hop.
            let mut headers = HeaderMap::new();
            for (name, value) in resp.headers() {
                if HOP_BY_HOP.contains(&name.as_str()) {
                    continue;
                }
                if let (Ok(n), Ok(v)) = (
                    axum::http::HeaderName::from_bytes(name.as_str().as_bytes()),
                    HeaderValue::from_bytes(value.as_bytes()),
                ) {
                    headers.insert(n, v);
                }
            }

            let body_bytes = resp.bytes().await.unwrap_or_default();
            (status, headers, body_bytes).into_response()
        }

        Ok(Err(e)) => (
            StatusCode::BAD_GATEWAY,
            format!("proxy: upstream error: {e}"),
        )
            .into_response(),

        Err(_) => (StatusCode::GATEWAY_TIMEOUT, "proxy: upstream timed out").into_response(),
    }
}

// ---------------------------------------------------------------------------
// Semantic event classification for audit blocks
// ---------------------------------------------------------------------------

/// Known LLM API host patterns for automatic event classification.
const LLM_HOSTS: &[&str] = &[
    "api.openai.com",
    "api.anthropic.com",
    "generativelanguage.googleapis.com",
    "api.mistral.ai",
    "api.cohere.ai",
    "api.cohere.com",
    "api.together.xyz",
    "api.groq.com",
    "api.deepseek.com",
    "api.fireworks.ai",
];

/// Path patterns that indicate tool/action invocations.
const TOOL_PATH_PATTERNS: &[&str] = &[
    "/tool",
    "/action",
    "/execute",
    "/invoke",
    "/run",
    "/call_tool",
];

/// Classify an outbound HTTP request into a semantic event type.
///
/// Returns one of: "llm_decision", "tool_call", "external_api".
fn classify_event(authority: &str, path: &str) -> String {
    // Check against known LLM API hosts.
    let host = authority.split(':').next().unwrap_or(authority);
    if LLM_HOSTS.contains(&host) {
        return "llm_decision".to_string();
    }

    // Check against known tool/action path patterns.
    let path_lower = path.to_lowercase();
    if TOOL_PATH_PATTERNS
        .iter()
        .any(|&p| path_lower.contains(p))
    {
        return "tool_call".to_string();
    }

    "external_api".to_string()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_target_absolute_uri() {
        // Simulate what Axum gives us for an HTTP proxy request.
        let req = axum::http::Request::builder()
            .method("GET")
            .uri("http://agent-b:8080/task")
            .body(axum::body::Body::empty())
            .unwrap();

        let target = resolve_target(&req);
        assert_eq!(target, Some("http://agent-b:8080/task".to_string()));
    }

    #[test]
    fn test_resolve_target_from_host_header() {
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/compute")
            .header("host", "agent-b:8080")
            .body(axum::body::Body::empty())
            .unwrap();

        let target = resolve_target(&req);
        assert_eq!(target, Some("http://agent-b:8080/compute".to_string()));
    }

    #[test]
    fn test_is_safe_connect_target_blocks_private() {
        // Loopback IPv4
        assert!(!is_safe_connect_target("127.0.0.1:443"));
        assert!(!is_safe_connect_target("127.0.0.1:80"));
        // Loopback IPv6
        assert!(!is_safe_connect_target("[::1]:443"));
        // RFC1918 private ranges
        assert!(!is_safe_connect_target("10.0.0.1:443"));
        assert!(!is_safe_connect_target("10.255.255.255:8080"));
        assert!(!is_safe_connect_target("172.16.0.1:443"));
        assert!(!is_safe_connect_target("172.31.255.1:443"));
        assert!(!is_safe_connect_target("192.168.1.100:443"));
        // Link-local
        assert!(!is_safe_connect_target("169.254.0.1:443"));
        assert!(!is_safe_connect_target("[fe80::1]:443"));
        // Unspecified
        assert!(!is_safe_connect_target("0.0.0.0:443"));
    }

    #[test]
    fn test_is_safe_connect_target_allows_public() {
        // Public IPv4
        assert!(is_safe_connect_target("8.8.8.8:443"));
        assert!(is_safe_connect_target("203.0.113.1:443"));
        // Public hostname — cannot pre-check, allowed
        assert!(is_safe_connect_target("example.com:443"));
        assert!(is_safe_connect_target("agent-b:8080"));
        // 172.15.x.x is NOT in the 172.16-31 private range
        assert!(is_safe_connect_target("172.15.255.255:443"));
        // 172.32.x.x is also outside the private range
        assert!(is_safe_connect_target("172.32.0.1:443"));
    }

    #[test]
    fn test_extract_authority() {
        assert_eq!(
            extract_authority("http://agent-b:8080/task"),
            Some("agent-b:8080".to_string())
        );
        assert_eq!(
            extract_authority("http://localhost:9000/"),
            Some("localhost:9000".to_string())
        );
        assert_eq!(extract_authority("http:///path"), None);
    }

    #[tokio::test]
    async fn test_get_peer_by_address() {
        let disc = PeerDiscovery::new("us".to_string(), vec![]);
        disc.add_peer(
            "peer1pubkey".to_string(),
            "http://127.0.0.1:8202".to_string(),
            0,
        )
        .await;

        // Should find by normalised address (without scheme).
        let found = disc.get_peer_by_address("127.0.0.1:8202").await;
        assert!(found.is_some());
        assert_eq!(found.unwrap().pubkey, "peer1pubkey");

        // Should also find with scheme prefix.
        let found2 = disc.get_peer_by_address("http://127.0.0.1:8202").await;
        assert!(found2.is_some());

        // Unknown address returns None.
        let none = disc.get_peer_by_address("1.2.3.4:9999").await;
        assert!(none.is_none());
    }

    // --- classify_event tests ---

    #[test]
    fn test_classify_event_llm_hosts() {
        assert_eq!(
            classify_event("api.openai.com", "/v1/chat/completions"),
            "llm_decision"
        );
        assert_eq!(
            classify_event("api.anthropic.com", "/v1/messages"),
            "llm_decision"
        );
        assert_eq!(
            classify_event("generativelanguage.googleapis.com", "/v1beta/models"),
            "llm_decision"
        );
        assert_eq!(
            classify_event("api.mistral.ai", "/v1/chat/completions"),
            "llm_decision"
        );
        assert_eq!(
            classify_event("api.openai.com:443", "/v1/chat/completions"),
            "llm_decision"
        );
    }

    #[test]
    fn test_classify_event_tool_paths() {
        assert_eq!(
            classify_event("my-service:8080", "/api/tool/run"),
            "tool_call"
        );
        assert_eq!(
            classify_event("localhost:9000", "/execute"),
            "tool_call"
        );
        assert_eq!(
            classify_event("agent-b:8202", "/v1/invoke"),
            "tool_call"
        );
        assert_eq!(
            classify_event("example.com", "/call_tool"),
            "tool_call"
        );
    }

    #[test]
    fn test_classify_event_external_api() {
        assert_eq!(
            classify_event("api.stripe.com", "/v1/charges"),
            "external_api"
        );
        assert_eq!(
            classify_event("example.com", "/api/data"),
            "external_api"
        );
    }
}
