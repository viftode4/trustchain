//! QUIC transport implementation using Quinn.
//!
//! Provides low-latency, encrypted node-to-node communication.
//!
//! # Pubkey pinning
//!
//! Connections opened with [`QuicTransport::send_message_pinned`] create a
//! fresh QUIC connection using a [`quinn::ClientConfig`] that pins the peer's
//! TrustChain Ed25519 pubkey via [`crate::tls::PubkeyVerifier`].  The
//! handshake fails immediately if the server's certificate does not carry the
//! expected pubkey in its custom X.509 extension, preventing impersonation.
//!
//! Connections opened with [`QuicTransport::send_message`] (no pinning) use
//! `AcceptAnyCert` — suitable for bootstrap/discovery scenarios where the
//! peer's pubkey is not yet known.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use quinn::Endpoint;
use tokio::sync::mpsc;

use crate::tls;
use crate::transport::TransportError;

/// Maximum number of distinct IPs tracked by the rate limiter at any one time.
///
/// Without a cap the `counters` HashMap grows unboundedly under a flood of
/// unique source IPs (e.g. a distributed reflection attack), consuming memory
/// until the process is OOM-killed.  When the cap is reached we first evict
/// IPs whose rate-limit window has already expired; if the map is still at
/// capacity after eviction the new connection is rejected.
const MAX_TRACKED_IPS: usize = 65_536;

/// Per-IP connection rate limiter.
#[derive(Debug)]
struct RateLimiter {
    /// Map from IP to (count since window start, window start time).
    counters: Mutex<HashMap<IpAddr, (u32, Instant)>>,
    max_per_sec: u32,
}

impl RateLimiter {
    fn new(max_per_sec: u32) -> Self {
        Self {
            counters: Mutex::new(HashMap::new()),
            max_per_sec,
        }
    }

    /// Returns true if the connection should be allowed.
    fn check(&self, ip: IpAddr) -> bool {
        if self.max_per_sec == 0 {
            return true; // Disabled.
        }
        let mut counters = self.counters.lock().unwrap();
        let now = Instant::now();

        // Enforce the size cap: evict entries whose 1-second window has expired.
        if counters.len() >= MAX_TRACKED_IPS {
            counters.retain(|_, (_, ts)| now.duration_since(*ts).as_secs() < 2);
        }
        // If still at or over the cap after eviction, reject the connection to
        // prevent unbounded memory growth from a flood of unique source IPs.
        if counters.len() >= MAX_TRACKED_IPS {
            log::warn!(
                "rate limiter at capacity ({} IPs tracked); rejecting connection from {}",
                MAX_TRACKED_IPS,
                ip,
            );
            return false;
        }

        let entry = counters.entry(ip).or_insert((0, now));
        // Reset window if more than 1 second has passed.
        if now.duration_since(entry.1).as_secs() >= 1 {
            *entry = (0, now);
        }
        entry.0 += 1;
        entry.0 <= self.max_per_sec
    }
}

/// QUIC transport for TrustChain node-to-node communication.
pub struct QuicTransport {
    endpoint: Endpoint,
    our_pubkey: String,
    rate_limiter: Arc<RateLimiter>,
    /// Cache of active QUIC connections keyed by remote address string.
    /// These connections use AcceptAnyCert (bootstrap mode).
    active_connections: Arc<Mutex<HashMap<String, quinn::Connection>>>,
}

impl QuicTransport {
    /// Create a new QUIC transport that listens on the given address.
    pub async fn bind(
        listen_addr: SocketAddr,
        trustchain_pubkey: &str,
    ) -> Result<Self, TransportError> {
        Self::bind_with_rate_limit(listen_addr, trustchain_pubkey, 20).await
    }

    /// Create a new QUIC transport with a specific rate limit.
    pub async fn bind_with_rate_limit(
        listen_addr: SocketAddr,
        trustchain_pubkey: &str,
        max_connections_per_ip_per_sec: u32,
    ) -> Result<Self, TransportError> {
        let server_config = make_server_config(trustchain_pubkey)?;
        // Default client config uses AcceptAnyCert (bootstrap / unknown peers).
        let client_config = make_client_config(None)?;

        let mut endpoint = Endpoint::server(server_config, listen_addr)
            .map_err(|e| TransportError::Connection(format!("failed to bind QUIC: {e}")))?;
        endpoint.set_default_client_config(client_config);

        log::info!(
            "QUIC transport listening on {}",
            endpoint.local_addr().unwrap()
        );

        Ok(Self {
            endpoint,
            our_pubkey: trustchain_pubkey.to_string(),
            rate_limiter: Arc::new(RateLimiter::new(max_connections_per_ip_per_sec)),
            active_connections: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    /// Get the local address this transport is bound to.
    pub fn local_addr(&self) -> Result<SocketAddr, TransportError> {
        self.endpoint
            .local_addr()
            .map_err(|e| TransportError::Connection(e.to_string()))
    }

    /// Send a raw message to a peer without pubkey pinning (bootstrap mode).
    ///
    /// Uses cached connections where available. Suitable for peers whose
    /// Ed25519 pubkey is not yet known (e.g. initial discovery).
    pub async fn send_message(
        &self,
        addr: SocketAddr,
        data: &[u8],
    ) -> Result<Vec<u8>, TransportError> {
        self.send_message_impl(addr, data, None).await
    }

    /// Send a raw message to a known peer with TLS pubkey pinning.
    ///
    /// A fresh QUIC connection is established (bypassing the connection cache)
    /// using a per-connection [`crate::tls::PubkeyVerifier`] that checks the
    /// server's TLS certificate carries `expected_pubkey_hex`.  The TLS
    /// handshake fails immediately if there is a mismatch, preventing
    /// man-in-the-middle attacks from peers presenting forged certificates.
    ///
    /// Returns `Err(TransportError::Tls(...))` when the pubkey does not match.
    pub async fn send_message_pinned(
        &self,
        addr: SocketAddr,
        data: &[u8],
        expected_pubkey_hex: &str,
    ) -> Result<Vec<u8>, TransportError> {
        // Pinned connections are never cached: each call creates a fresh
        // connection with its own client config so that the pin is enforced
        // for every new connection (cached connections could have originated
        // before the pin was known).
        self.send_message_impl(addr, data, Some(expected_pubkey_hex))
            .await
    }

    /// Internal send implementation.
    ///
    /// When `expected_pubkey` is `Some`, a fresh pinned connection is opened
    /// and NOT cached (see security note above).  When it is `None`, cached
    /// bootstrap connections are reused.
    async fn send_message_impl(
        &self,
        addr: SocketAddr,
        data: &[u8],
        expected_pubkey: Option<&str>,
    ) -> Result<Vec<u8>, TransportError> {
        if let Some(pubkey_hex) = expected_pubkey {
            // Pinned path: always open a fresh connection with a dedicated
            // TLS config that enforces the expected pubkey.
            let connection = self.new_pinned_connection(addr, pubkey_hex).await?;
            let streams = connection
                .open_bi()
                .await
                .map_err(|e| TransportError::Send(format!("QUIC stream open error: {e}")))?;
            return self.send_on_streams(streams, data).await;
        }

        // Unpinned bootstrap path — try to reuse a cached connection.
        let addr_key = addr.to_string();

        let cached = {
            let conns = self.active_connections.lock().unwrap();
            conns.get(&addr_key).cloned()
        };
        // MutexGuard dropped here — safe to await below.

        if let Some(conn) = cached {
            match conn.open_bi().await {
                Ok(streams) => {
                    return self.send_on_streams(streams, data).await;
                }
                Err(_) => {
                    // Connection is dead, remove from cache.
                    self.active_connections.lock().unwrap().remove(&addr_key);
                }
            }
        }

        // Open a new bootstrap connection.
        let connection = self.new_connection(addr).await?;

        // Cache it for future use.
        self.active_connections
            .lock()
            .unwrap()
            .insert(addr_key, connection.clone());

        let streams = connection
            .open_bi()
            .await
            .map_err(|e| TransportError::Send(format!("QUIC stream open error: {e}")))?;

        self.send_on_streams(streams, data).await
    }

    /// Open a new QUIC connection to a peer (bootstrap/AcceptAnyCert mode).
    async fn new_connection(&self, addr: SocketAddr) -> Result<quinn::Connection, TransportError> {
        self.endpoint
            .connect(addr, "localhost")
            .map_err(|e| TransportError::Connection(format!("QUIC connect error: {e}")))?
            .await
            .map_err(|e| TransportError::Connection(format!("QUIC handshake error: {e}")))
    }

    /// Open a new QUIC connection with pubkey pinning.
    ///
    /// Creates a transient `quinn::ClientConfig` that pins `expected_pubkey_hex`
    /// using [`tls::PubkeyVerifier`]. The TLS handshake is aborted if the
    /// peer's certificate does not carry a matching TrustChain pubkey extension.
    async fn new_pinned_connection(
        &self,
        addr: SocketAddr,
        expected_pubkey_hex: &str,
    ) -> Result<quinn::Connection, TransportError> {
        let client_config = make_client_config(Some(expected_pubkey_hex))?;

        self.endpoint
            .connect_with(client_config, addr, "localhost")
            .map_err(|e| TransportError::Connection(format!("QUIC pinned connect error: {e}")))?
            .await
            .map_err(|e| {
                // Surface TLS-level failures with a distinct error variant so
                // callers can distinguish a pubkey mismatch from a network error.
                if e.to_string().contains("mismatch") || e.to_string().contains("TrustChain") {
                    TransportError::Tls(format!("pubkey pinning failed: {e}"))
                } else {
                    TransportError::Connection(format!("QUIC pinned handshake error: {e}"))
                }
            })
    }

    /// Send data on an already-opened bidirectional stream pair.
    async fn send_on_streams(
        &self,
        (mut send, mut recv): (quinn::SendStream, quinn::RecvStream),
        data: &[u8],
    ) -> Result<Vec<u8>, TransportError> {
        // Send length-prefixed message.
        let len = (data.len() as u32).to_be_bytes();
        send.write_all(&len)
            .await
            .map_err(|e| TransportError::Send(e.to_string()))?;
        send.write_all(data)
            .await
            .map_err(|e| TransportError::Send(e.to_string()))?;
        send.finish()
            .map_err(|e| TransportError::Send(e.to_string()))?;

        // Read response.
        let response = recv
            .read_to_end(16 * 1024 * 1024) // 16 MB max
            .await
            .map_err(|e| TransportError::Receive(e.to_string()))?;

        Ok(response)
    }

    /// Start accepting incoming connections and dispatch messages.
    pub async fn accept_loop(
        &self,
        tx: mpsc::Sender<(Vec<u8>, mpsc::Sender<Vec<u8>>)>,
    ) -> Result<(), TransportError> {
        loop {
            let incoming = self
                .endpoint
                .accept()
                .await
                .ok_or_else(|| TransportError::Connection("endpoint closed".to_string()))?;

            // Rate limit by remote IP.
            let remote_addr = incoming.remote_address();
            if !self.rate_limiter.check(remote_addr.ip()) {
                log::warn!("rate limited connection from {}", remote_addr.ip());
                incoming.refuse();
                continue;
            }

            let connection = incoming
                .await
                .map_err(|e| TransportError::Connection(format!("accept error: {e}")))?;

            let tx = tx.clone();
            tokio::spawn(async move {
                loop {
                    let stream = match connection.accept_bi().await {
                        Ok(s) => s,
                        Err(_) => break, // Connection closed.
                    };
                    let (send, mut recv) = stream;
                    let tx = tx.clone();

                    tokio::spawn(async move {
                        // Read length-prefixed message.
                        let mut len_buf = [0u8; 4];
                        if recv.read_exact(&mut len_buf).await.is_err() {
                            return;
                        }
                        let len = u32::from_be_bytes(len_buf) as usize;
                        if len > 16 * 1024 * 1024 {
                            return; // Too large.
                        }

                        let data = match recv.read_to_end(len).await {
                            Ok(d) => d,
                            Err(_) => return,
                        };

                        // Set up response channel.
                        let (resp_tx, mut resp_rx) = mpsc::channel::<Vec<u8>>(1);

                        if tx.send((data, resp_tx)).await.is_err() {
                            return;
                        }

                        // Send response back.
                        if let Some(response) = resp_rx.recv().await {
                            let mut send = send;
                            let _ = send.write_all(&response).await;
                            let _ = send.finish();
                        }
                    });
                }
            });
        }
    }

    /// Shut down the QUIC endpoint.
    pub fn shutdown(&self) {
        self.endpoint.close(quinn::VarInt::from_u32(0), b"shutdown");
    }

    /// Get our public key.
    pub fn pubkey(&self) -> &str {
        &self.our_pubkey
    }
}

fn make_server_config(pubkey: &str) -> Result<quinn::ServerConfig, TransportError> {
    let tls_config =
        tls::build_server_config(pubkey).map_err(|e| TransportError::Tls(e.to_string()))?;

    let quic_server_config = quinn::crypto::rustls::QuicServerConfig::try_from(tls_config)
        .map_err(|e| TransportError::Tls(e.to_string()))?;

    let config = quinn::ServerConfig::with_crypto(std::sync::Arc::new(quic_server_config));
    Ok(config)
}

/// Build a quinn ClientConfig.
///
/// `expected_pubkey_hex` is forwarded directly to [`tls::build_client_config`]:
/// - `Some(hex)` → pinned connection using [`tls::PubkeyVerifier`]
/// - `None`       → bootstrap connection using `AcceptAnyCert`
fn make_client_config(
    expected_pubkey_hex: Option<&str>,
) -> Result<quinn::ClientConfig, TransportError> {
    let tls_config = tls::build_client_config(expected_pubkey_hex)
        .map_err(|e| TransportError::Tls(e.to_string()))?;

    let quic_client_config = quinn::crypto::rustls::QuicClientConfig::try_from(tls_config)
        .map_err(|e| TransportError::Tls(e.to_string()))?;

    let config = quinn::ClientConfig::new(std::sync::Arc::new(quic_client_config));
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Helper: spin up a server transport, return (transport, addr).
    async fn make_server(pubkey: &str) -> (QuicTransport, SocketAddr) {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let t = QuicTransport::bind(addr, pubkey).await.unwrap();
        let local = t.local_addr().unwrap();
        (t, local)
    }

    // Helper: start the accept loop as an echo server.
    fn start_echo_server(server: QuicTransport) -> tokio::task::JoinHandle<()> {
        let (tx, mut rx) = mpsc::channel::<(Vec<u8>, mpsc::Sender<Vec<u8>>)>(16);
        tokio::spawn(async move {
            // Echo handler.
            tokio::spawn(async move {
                while let Some((data, resp_tx)) = rx.recv().await {
                    let _ = resp_tx.send(data).await;
                }
            });
            let _ = server.accept_loop(tx).await;
        })
    }

    #[tokio::test]
    async fn test_quic_bind() {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let pubkey = hex::encode([0xaa; 32]);
        let transport = QuicTransport::bind(addr, &pubkey).await.unwrap();
        let local = transport.local_addr().unwrap();
        assert_ne!(local.port(), 0);
        transport.shutdown();
    }

    #[tokio::test]
    async fn test_quic_roundtrip() {
        let server_pubkey = hex::encode([0xab; 32]);
        let (server, server_addr) = make_server(&server_pubkey).await;
        let _handle = start_echo_server(server);

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let client_pubkey = hex::encode([0xcd; 32]);
        let client = QuicTransport::bind("127.0.0.1:0".parse().unwrap(), &client_pubkey)
            .await
            .unwrap();

        let msg = b"hello trustchain";
        let response = client.send_message(server_addr, msg).await.unwrap();
        assert_eq!(response, msg);

        client.shutdown();
    }

    /// Pubkey pinning: client knows the server's pubkey and verifies it.
    /// The handshake must succeed when the certs match.
    #[tokio::test]
    async fn test_pinned_connection_succeeds_when_pubkeys_match() {
        let server_pubkey =
            hex::encode(trustchain_core::identity::Identity::generate().pubkey_bytes());
        let (server, server_addr) = make_server(&server_pubkey).await;
        let _handle = start_echo_server(server);

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let client_pubkey =
            hex::encode(trustchain_core::identity::Identity::generate().pubkey_bytes());
        let client = QuicTransport::bind("127.0.0.1:0".parse().unwrap(), &client_pubkey)
            .await
            .unwrap();

        let msg = b"pinned hello";
        let response = client
            .send_message_pinned(server_addr, msg, &server_pubkey)
            .await
            .unwrap();
        assert_eq!(response, msg, "pinned echo must round-trip correctly");

        client.shutdown();
    }

    /// Pubkey pinning: client expects a wrong pubkey — the handshake MUST fail.
    #[tokio::test]
    async fn test_pinned_connection_fails_when_pubkeys_differ() {
        let server_pubkey =
            hex::encode(trustchain_core::identity::Identity::generate().pubkey_bytes());
        let (server, server_addr) = make_server(&server_pubkey).await;
        let _handle = start_echo_server(server);

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let client_pubkey =
            hex::encode(trustchain_core::identity::Identity::generate().pubkey_bytes());
        let client = QuicTransport::bind("127.0.0.1:0".parse().unwrap(), &client_pubkey)
            .await
            .unwrap();

        // Use a completely different (wrong) expected pubkey.
        let wrong_pubkey =
            hex::encode(trustchain_core::identity::Identity::generate().pubkey_bytes());

        let result = client
            .send_message_pinned(server_addr, b"should fail", &wrong_pubkey)
            .await;

        assert!(
            result.is_err(),
            "pinned connection must fail when pubkeys differ"
        );
        let err_str = format!("{:?}", result.unwrap_err());
        // Error must indicate a TLS/connection-level failure.
        assert!(
            err_str.contains("Tls") || err_str.contains("Connection"),
            "error must be a Tls or Connection variant: {err_str}"
        );
    }

    /// Bootstrap mode (None pubkey): must still work — connects to any server.
    #[tokio::test]
    async fn test_bootstrap_mode_accepts_any_cert() {
        let server_pubkey =
            hex::encode(trustchain_core::identity::Identity::generate().pubkey_bytes());
        let (server, server_addr) = make_server(&server_pubkey).await;
        let _handle = start_echo_server(server);

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let client_pubkey =
            hex::encode(trustchain_core::identity::Identity::generate().pubkey_bytes());
        let client = QuicTransport::bind("127.0.0.1:0".parse().unwrap(), &client_pubkey)
            .await
            .unwrap();

        // send_message uses AcceptAnyCert — must succeed without knowing the server's pubkey.
        let msg = b"bootstrap hello";
        let response = client.send_message(server_addr, msg).await.unwrap();
        assert_eq!(response, msg);

        client.shutdown();
    }
}
