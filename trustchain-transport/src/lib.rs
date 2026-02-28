//! TrustChain Transport — networking layer for QUIC, gRPC, and HTTP.
//!
//! Provides multiple transport options for node-to-node communication:
//! - **QUIC**: Low-latency encrypted transport (Quinn)
//! - **gRPC**: Structured RPC service (Tonic)
//! - **HTTP**: REST API for external access (Axum)
//! - **Discovery**: Peer finding via bootstrap + gossip
//! - **Pool**: Connection pooling for efficient reuse

pub mod discover;
pub mod discovery;
pub mod grpc;
pub mod http;
#[cfg(feature = "mcp")]
pub mod mcp;
pub mod message;
pub mod pool;
pub mod proxy;
pub mod quic;
pub mod stun;
pub mod tls;
pub mod transport;

/// Generated protobuf types from trustchain.proto.
pub mod proto {
    tonic::include_proto!("trustchain");
}

// Re-exports.
pub use discovery::PeerDiscovery;
pub use grpc::{TrustChainGrpcService, start_grpc_server};
pub use http::{AppState, build_router, start_http_server};
pub use pool::ConnectionPool;
pub use proxy::{ProxyState, start_proxy_server};
pub use quic::QuicTransport;
pub use transport::{Transport, TransportError};
