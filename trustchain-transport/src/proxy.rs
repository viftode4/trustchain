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
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::{
    Router,
    extract::State,
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use reqwest::Client;
use tokio::sync::Mutex;

use trustchain_core::{BlockStore, TrustChainProtocol};

use crate::discovery::{PeerDiscovery, PeerRecord};
use crate::http::uuid_v4;
use crate::message::{MessageType, TransportMessage, block_to_bytes, bytes_to_block};
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
pub struct ProxyState<S: BlockStore + 'static> {
    pub protocol: Arc<Mutex<TrustChainProtocol<S>>>,
    pub discovery: Arc<PeerDiscovery>,
    pub quic: Arc<QuicTransport>,
    pub client: Client,
    /// Per-peer handshake locks. Only one handshake runs at a time per peer;
    /// concurrent requests to the same peer skip the handshake (the in-flight
    /// one already covers this burst of activity). This matches the TrustChain
    /// paper's model where interactions are sequential per peer pair.
    pub peer_locks: Arc<Mutex<HashMap<String, Arc<Mutex<()>>>>>,
}

impl<S: BlockStore + 'static> Clone for ProxyState<S> {
    fn clone(&self) -> Self {
        Self {
            protocol: self.protocol.clone(),
            discovery: self.discovery.clone(),
            quic: self.quic.clone(),
            client: self.client.clone(),
            peer_locks: self.peer_locks.clone(),
        }
    }
}

impl<S: BlockStore + 'static> ProxyState<S> {
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
pub async fn start_proxy_server<S: BlockStore + Send + 'static>(
    addr: SocketAddr,
    state: ProxyState<S>,
) -> anyhow::Result<()> {
    let router = Router::new()
        .fallback(proxy_handler::<S>)
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    log::info!("Trust proxy listening on {addr}");
    axum::serve(listener, router).await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Core handler
// ---------------------------------------------------------------------------

async fn proxy_handler<S: BlockStore + 'static>(
    State(state): State<ProxyState<S>>,
    req: axum::extract::Request,
) -> Response {
    // 1. Resolve target URL from the request.
    let target_url = match resolve_target(&req) {
        Some(u) => u,
        None => {
            return (StatusCode::BAD_REQUEST, "proxy: cannot determine target URL").into_response();
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
            let tx = serde_json::json!({
                "proxy": true,
                "method": req.method().as_str(),
                "path": req.uri().path(),
            });

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

    // 4. Forward the original call and return the response.
    forward_request(state.client, req, &target_url).await
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
async fn run_handshake<S: BlockStore + 'static>(
    state: &ProxyState<S>,
    peer: &PeerRecord,
    tx: serde_json::Value,
) -> anyhow::Result<()> {
    // Derive QUIC address from peer's HTTP address (QUIC is HTTP port - 2 by convention).
    let quic_addr: SocketAddr = {
        let addr = peer.address.strip_prefix("http://").unwrap_or(&peer.address);
        let sa: SocketAddr = addr
            .parse()
            .map_err(|e| anyhow::anyhow!("invalid peer address '{addr}': {e}"))?;
        SocketAddr::new(sa.ip(), sa.port().saturating_sub(2))
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
            return (StatusCode::BAD_REQUEST, format!("proxy: failed to read body: {e}"))
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
}
