//! Transport message types for TrustChain networking.

use serde::{Deserialize, Serialize};
use trustchain_core::HalfBlock;

/// Types of messages that can be sent between nodes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MessageType {
    Proposal,
    Agreement,
    CrawlRequest,
    CrawlResponse,
    StatusRequest,
    StatusResponse,
    DiscoveryRequest,
    DiscoveryResponse,
    Ping,
    Pong,
    /// A single half-block broadcast with TTL.
    HalfBlockBroadcast,
    /// A block pair broadcast (both halves of a completed transaction) with TTL.
    BlockPairBroadcast,
    /// P2P capability discovery: "which agents have you seen doing X?"
    CapabilityRequest,
    /// Response with discovered agents.
    CapabilityResponse,
    /// Fraud proof: two conflicting blocks at the same (pubkey, seq).
    FraudProof,
    /// CHECO: checkpoint proposal from facilitator.
    CheckpointProposal,
    /// CHECO: vote (co-signature) for a checkpoint.
    CheckpointVote,
    /// CHECO: finalized checkpoint broadcast.
    CheckpointFinalized,
    /// Error response — wraps an error message so the sender can parse it.
    Error,
}

impl std::fmt::Display for MessageType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MessageType::Proposal => write!(f, "proposal"),
            MessageType::Agreement => write!(f, "agreement"),
            MessageType::CrawlRequest => write!(f, "crawl_request"),
            MessageType::CrawlResponse => write!(f, "crawl_response"),
            MessageType::StatusRequest => write!(f, "status_request"),
            MessageType::StatusResponse => write!(f, "status_response"),
            MessageType::DiscoveryRequest => write!(f, "discovery_request"),
            MessageType::DiscoveryResponse => write!(f, "discovery_response"),
            MessageType::Ping => write!(f, "ping"),
            MessageType::Pong => write!(f, "pong"),
            MessageType::HalfBlockBroadcast => write!(f, "half_block_broadcast"),
            MessageType::BlockPairBroadcast => write!(f, "block_pair_broadcast"),
            MessageType::CapabilityRequest => write!(f, "capability_request"),
            MessageType::CapabilityResponse => write!(f, "capability_response"),
            MessageType::FraudProof => write!(f, "fraud_proof"),
            MessageType::CheckpointProposal => write!(f, "checkpoint_proposal"),
            MessageType::CheckpointVote => write!(f, "checkpoint_vote"),
            MessageType::CheckpointFinalized => write!(f, "checkpoint_finalized"),
            MessageType::Error => write!(f, "error"),
        }
    }
}

/// A transport message envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransportMessage {
    pub message_type: MessageType,
    pub sender_pubkey: String,
    pub payload: Vec<u8>,
    pub request_id: String,
}

impl TransportMessage {
    pub fn new(
        message_type: MessageType,
        sender_pubkey: String,
        payload: Vec<u8>,
        request_id: String,
    ) -> Self {
        Self {
            message_type,
            sender_pubkey,
            payload,
            request_id,
        }
    }
}

/// Convert HalfBlock to/from protobuf wire format (JSON for now).
pub fn block_to_bytes(block: &HalfBlock) -> Vec<u8> {
    serde_json::to_vec(block).expect("HalfBlock serialization cannot fail")
}

pub fn bytes_to_block(bytes: &[u8]) -> Result<HalfBlock, serde_json::Error> {
    serde_json::from_slice(bytes)
}

/// Serialize a list of blocks.
pub fn blocks_to_bytes(blocks: &[HalfBlock]) -> Vec<u8> {
    serde_json::to_vec(blocks).expect("Vec<HalfBlock> serialization cannot fail")
}

pub fn bytes_to_blocks(bytes: &[u8]) -> Result<Vec<HalfBlock>, serde_json::Error> {
    serde_json::from_slice(bytes)
}

/// Payload for a block pair broadcast: both halves of a completed transaction + TTL.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockPairBroadcastPayload {
    pub block1: HalfBlock,
    pub block2: HalfBlock,
    pub ttl: u8,
}

/// Payload for a single half-block broadcast + TTL.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HalfBlockBroadcastPayload {
    pub block: HalfBlock,
    pub ttl: u8,
}

/// Payload for a fraud proof: two conflicting blocks at the same (pubkey, seq).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FraudProofPayload {
    pub block_a: HalfBlock,
    pub block_b: HalfBlock,
    pub ttl: u8,
}

/// Payload for a CHECO checkpoint proposal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckpointProposalPayload {
    pub checkpoint_block: HalfBlock,
    pub round: u64,
}

/// Payload for a CHECO checkpoint vote (co-signature).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckpointVotePayload {
    pub checkpoint_block_hash: String,
    pub voter_pubkey: String,
    pub signature_hex: String,
    pub round: u64,
}

/// Wire format for a finalized CHECO checkpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckpointWire {
    pub checkpoint_block: HalfBlock,
    pub signatures: std::collections::HashMap<String, String>,
    pub chain_heads: std::collections::HashMap<String, u64>,
    pub facilitator_pubkey: String,
    pub timestamp: u64,
}

/// Payload for a finalized checkpoint broadcast.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckpointFinalizedPayload {
    pub checkpoint: CheckpointWire,
    pub round: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use trustchain_core::{Identity, create_half_block, verify_block};
    use trustchain_core::types::{BlockType, GENESIS_HASH};

    /// Verify that a HalfBlock survives the TransportMessage round-trip
    /// (block → bytes → TransportMessage → JSON → deserialize → extract → block)
    /// with its hash still valid.
    #[test]
    fn test_block_roundtrip_through_transport_message() {
        test_roundtrip_with_timestamp(Some(1000));
    }

    #[test]
    fn test_block_roundtrip_real_timestamp() {
        test_roundtrip_with_timestamp(None);
    }

    fn test_roundtrip_with_timestamp(ts: Option<u64>) {
        let id = Identity::from_bytes(&[42u8; 32]);
        let block = create_half_block(
            &id, 1, &"b".repeat(64), 0, GENESIS_HASH,
            BlockType::Proposal,
            serde_json::json!({"proxy": true, "method": "GET", "path": "/"}),
            ts,
        );

        assert!(verify_block(&block).unwrap(), "block should verify before transport");

        // Simulate the exact proxy transport path.
        let payload = block_to_bytes(&block);
        let msg = TransportMessage::new(
            MessageType::Proposal,
            id.pubkey_hex(),
            payload.clone(),
            "test-request-id".to_string(),
        );
        let wire_bytes = serde_json::to_vec(&msg).unwrap();
        let received_msg: TransportMessage = serde_json::from_slice(&wire_bytes).unwrap();
        let received_block: HalfBlock = bytes_to_block(&received_msg.payload).unwrap();

        // Payload bytes must survive Vec<u8> → JSON array → Vec<u8> losslessly.
        assert_eq!(payload, received_msg.payload, "payload bytes changed");

        // Block must be identical after round-trip.
        assert_eq!(block, received_block, "block changed after TransportMessage round-trip");

        // Hash must still verify.
        assert!(verify_block(&received_block).unwrap(), "block should verify after round-trip");
    }
}
