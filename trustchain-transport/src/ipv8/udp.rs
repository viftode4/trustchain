//! Async UDP transport for IPv8 packets.

use std::collections::HashMap;
use std::net::SocketAddr;

use tokio::net::UdpSocket;

use super::community::{CommunityError, TrustChainCommunity};
use super::packet::{Ipv8Header, Ipv8Packet, PacketError, TRUSTCHAIN_COMMUNITY_ID};
use super::payload::{HalfBlockPayload, MessageType, PayloadError};
use thiserror::Error;

/// Default port matching py-ipv8.
pub const DEFAULT_IPV8_PORT: u16 = 8000;

/// Maximum UDP datagram size we will attempt to receive.
const MAX_PACKET_SIZE: usize = 65535;

#[derive(Debug, Error)]
pub enum UdpTransportError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("packet error: {0}")]
    Packet(#[from] PacketError),
    #[error("community error: {0}")]
    Community(#[from] CommunityError),
    #[error("payload error: {0}")]
    Payload(#[from] PayloadError),
}

pub struct Ipv8UdpTransport {
    socket: UdpSocket,
    community: TrustChainCommunity,
    peers: HashMap<String, SocketAddr>,
}

impl Ipv8UdpTransport {
    /// Bind a UDP socket and create the transport.
    pub async fn bind(addr: SocketAddr) -> Result<Self, UdpTransportError> {
        let socket = UdpSocket::bind(addr).await?;
        Ok(Self {
            socket,
            community: TrustChainCommunity::new(),
            peers: HashMap::new(),
        })
    }

    /// Register a known peer address.
    pub fn add_peer(&mut self, pubkey: String, addr: SocketAddr) {
        self.peers.insert(pubkey, addr);
    }

    /// Send a raw [`Ipv8Packet`] to the given address.
    pub async fn send_packet(
        &self,
        addr: SocketAddr,
        packet: &Ipv8Packet,
    ) -> Result<(), UdpTransportError> {
        self.socket.send_to(&packet.to_bytes(), addr).await?;
        Ok(())
    }

    /// Receive one [`Ipv8Packet`] from the socket.
    pub async fn recv_packet(&self) -> Result<(Ipv8Packet, SocketAddr), UdpTransportError> {
        let mut buf = vec![0u8; MAX_PACKET_SIZE];
        let (n, addr) = self.socket.recv_from(&mut buf).await?;
        let packet = Ipv8Packet::from_bytes(&buf[..n])?;
        Ok((packet, addr))
    }

    /// Send a crawl request to the given address.
    pub async fn send_crawl_request(
        &self,
        addr: SocketAddr,
        pubkey: &str,
        start_seq: u64,
    ) -> Result<(), UdpTransportError> {
        let req = super::payload::CrawlRequest {
            public_key: pubkey.to_string(),
            requested_seq: start_seq,
            limit: 100,
        };
        let header = Ipv8Header::new(*TRUSTCHAIN_COMMUNITY_ID, MessageType::CrawlRequest as u8);
        let packet = Ipv8Packet::new(header, req.to_bytes());
        self.send_packet(addr, &packet).await
    }

    /// Send a half block to the given address.
    pub async fn send_half_block(
        &self,
        addr: SocketAddr,
        block: &HalfBlockPayload,
    ) -> Result<(), UdpTransportError> {
        let header = Ipv8Header::new(*TRUSTCHAIN_COMMUNITY_ID, MessageType::HalfBlock as u8);
        let packet = Ipv8Packet::new(header, block.to_bytes());
        self.send_packet(addr, &packet).await
    }

    /// Return a reference to the inner community handler.
    pub fn community(&self) -> &TrustChainCommunity {
        &self.community
    }

    /// Return the local socket address.
    pub fn local_addr(&self) -> Result<SocketAddr, UdpTransportError> {
        Ok(self.socket.local_addr()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};

    #[tokio::test]
    async fn two_sockets_exchange_packets() {
        let addr1 = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0));
        let addr2 = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0));

        let transport1 = Ipv8UdpTransport::bind(addr1).await.unwrap();
        let transport2 = Ipv8UdpTransport::bind(addr2).await.unwrap();

        let addr2_actual = transport2.local_addr().unwrap();

        // Send a crawl request from transport1 → transport2.
        let pubkey = "aa".repeat(32);
        transport1
            .send_crawl_request(addr2_actual, &pubkey, 1)
            .await
            .unwrap();

        // Receive on transport2.
        let (packet, from_addr) = transport2.recv_packet().await.unwrap();
        assert_eq!(from_addr.ip(), Ipv4Addr::LOCALHOST);
        assert_eq!(packet.header.message_type, MessageType::CrawlRequest as u8);

        // Parse via community handler.
        let resp = transport2.community().handle_packet(&packet).unwrap();
        match resp {
            super::super::community::CommunityResponse::CrawlRequest(req) => {
                assert_eq!(req.public_key, pubkey);
                assert_eq!(req.requested_seq, 1);
            }
            _ => panic!("expected CrawlRequest"),
        }
    }

    #[tokio::test]
    async fn send_and_receive_half_block() {
        let addr1 = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0));
        let addr2 = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0));

        let transport1 = Ipv8UdpTransport::bind(addr1).await.unwrap();
        let transport2 = Ipv8UdpTransport::bind(addr2).await.unwrap();

        let block = HalfBlockPayload {
            public_key: "aa".repeat(32),
            sequence_number: 1,
            link_public_key: "bb".repeat(32),
            link_sequence_number: 0,
            previous_hash: "00".repeat(32),
            signature: "cc".repeat(64),
            block_type: "proposal".into(),
            transaction: r#"{"test":true}"#.into(),
            block_hash: "dd".repeat(32),
            timestamp: 1_700_000_000_000,
        };

        let addr2_actual = transport2.local_addr().unwrap();
        transport1
            .send_half_block(addr2_actual, &block)
            .await
            .unwrap();

        let (packet, _) = transport2.recv_packet().await.unwrap();
        assert_eq!(packet.header.message_type, MessageType::HalfBlock as u8);

        let decoded = HalfBlockPayload::from_bytes(&packet.payload).unwrap();
        assert_eq!(decoded, block);
    }
}
