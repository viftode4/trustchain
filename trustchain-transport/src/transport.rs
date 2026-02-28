//! Transport trait — abstract interface for sending/receiving messages.

use async_trait::async_trait;

use crate::message::TransportMessage;

/// Errors from transport operations.
#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error("connection error: {0}")]
    Connection(String),

    #[error("send error: {0}")]
    Send(String),

    #[error("receive error: {0}")]
    Receive(String),

    #[error("timeout")]
    Timeout,

    #[error("peer not found: {0}")]
    PeerNotFound(String),

    #[error("tls error: {0}")]
    Tls(String),

    #[error("transport error: {0}")]
    Other(String),
}

/// Abstract transport interface for node-to-node communication.
#[async_trait]
pub trait Transport: Send + Sync {
    /// Send a message to a peer at the given address.
    async fn send(&self, addr: &str, msg: TransportMessage) -> Result<(), TransportError>;

    /// Send a message and wait for a response.
    async fn request(
        &self,
        addr: &str,
        msg: TransportMessage,
    ) -> Result<TransportMessage, TransportError>;

    /// Start listening for incoming messages. Returns a receiver channel.
    async fn listen(
        &self,
        addr: &str,
    ) -> Result<tokio::sync::mpsc::Receiver<TransportMessage>, TransportError>;

    /// Shut down the transport.
    async fn shutdown(&self) -> Result<(), TransportError>;
}
