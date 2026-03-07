//! TrustChain community handler for IPv8 packets.

use super::packet::{Ipv8Packet, PacketError, TRUSTCHAIN_COMMUNITY_ID};
use super::payload::{
    CrawlRequest, HalfBlockPairPayload, HalfBlockPayload, MessageType, PayloadError,
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CommunityError {
    #[error("community ID mismatch")]
    CommunityMismatch,
    #[error("packet error: {0}")]
    Packet(#[from] PacketError),
    #[error("payload error: {0}")]
    Payload(#[from] PayloadError),
}

/// Structured response after handling an inbound packet.
#[derive(Debug)]
pub enum CommunityResponse {
    CrawlRequest(CrawlRequest),
    HalfBlock(HalfBlockPayload),
    HalfBlockPair(HalfBlockPairPayload),
    HalfBlockBroadcast(HalfBlockPayload),
    EmptyBloomFilter,
}

pub struct TrustChainCommunity {
    community_id: [u8; 20],
}

impl TrustChainCommunity {
    pub fn new() -> Self {
        Self {
            community_id: *TRUSTCHAIN_COMMUNITY_ID,
        }
    }

    pub fn community_id(&self) -> &[u8; 20] {
        &self.community_id
    }

    /// Verify the community ID and dispatch by message type.
    pub fn handle_packet(&self, packet: &Ipv8Packet) -> Result<CommunityResponse, CommunityError> {
        if packet.header.community_id != self.community_id {
            return Err(CommunityError::CommunityMismatch);
        }

        let msg_type = MessageType::from_u8(packet.header.message_type)?;
        match msg_type {
            MessageType::CrawlRequest => {
                let req = CrawlRequest::from_bytes(&packet.payload)?;
                Ok(CommunityResponse::CrawlRequest(req))
            }
            MessageType::HalfBlock => {
                let block = HalfBlockPayload::from_bytes(&packet.payload)?;
                Ok(CommunityResponse::HalfBlock(block))
            }
            MessageType::HalfBlockPair => {
                let pair = HalfBlockPairPayload::from_bytes(&packet.payload)?;
                Ok(CommunityResponse::HalfBlockPair(pair))
            }
            MessageType::HalfBlockBroadcast => {
                let block = HalfBlockPayload::from_bytes(&packet.payload)?;
                Ok(CommunityResponse::HalfBlockBroadcast(block))
            }
            MessageType::EmptyBloomFilter => Ok(CommunityResponse::EmptyBloomFilter),
        }
    }
}

impl Default for TrustChainCommunity {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipv8::packet::{Ipv8Header, Ipv8Packet};
    use crate::ipv8::payload::CrawlRequest;

    #[test]
    fn correct_community_id() {
        let community = TrustChainCommunity::new();
        assert_eq!(community.community_id(), &*TRUSTCHAIN_COMMUNITY_ID);
    }

    #[test]
    fn community_mismatch() {
        let community = TrustChainCommunity::new();
        let header = Ipv8Header::new([0xFF; 20], MessageType::CrawlRequest as u8);
        let packet = Ipv8Packet::new(header, vec![]);
        assert!(matches!(
            community.handle_packet(&packet),
            Err(CommunityError::CommunityMismatch)
        ));
    }

    #[test]
    fn unknown_message_type() {
        let community = TrustChainCommunity::new();
        let header = Ipv8Header::new(*TRUSTCHAIN_COMMUNITY_ID, 255);
        let packet = Ipv8Packet::new(header, vec![]);
        assert!(matches!(
            community.handle_packet(&packet),
            Err(CommunityError::Payload(_))
        ));
    }

    #[test]
    fn dispatch_crawl_request() {
        let community = TrustChainCommunity::new();
        let req = CrawlRequest {
            public_key: "aa".repeat(32),
            requested_seq: 5,
            limit: 20,
        };
        let header = Ipv8Header::new(*TRUSTCHAIN_COMMUNITY_ID, MessageType::CrawlRequest as u8);
        let packet = Ipv8Packet::new(header, req.to_bytes());
        let resp = community.handle_packet(&packet).unwrap();
        match resp {
            CommunityResponse::CrawlRequest(decoded) => assert_eq!(decoded, req),
            _ => panic!("expected CrawlRequest response"),
        }
    }
}
