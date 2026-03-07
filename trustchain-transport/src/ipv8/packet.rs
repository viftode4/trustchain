//! IPv8 binary packet format.
//!
//! Wire layout (big-endian / network byte order):
//! ```text
//! [2 bytes] prefix:       0x0000
//! [1 byte]  version:      2
//! [20 bytes] community_id: SHA-1 of community name
//! [1 byte]  message_type
//! [variable] payload
//! ```
//!
//! NOTE: The real py-ipv8 header is slightly more complex (it includes a
//! source LAN/WAN address block). This initial implementation uses a
//! simplified 24-byte header that is sufficient for TrustChain-only traffic.
//! Full py-ipv8 compatibility will be added in a follow-up.

use sha1::{Digest, Sha1};
use thiserror::Error;

/// Fixed header size in bytes: 2 (prefix) + 1 (version) + 20 (community) + 1 (msg type).
pub const HEADER_SIZE: usize = 24;

/// Prefix bytes that start every IPv8 packet.
pub const IPV8_PREFIX: [u8; 2] = [0x00, 0x00];

/// Protocol version.
pub const IPV8_VERSION: u8 = 2;

/// Precomputed SHA-1 community ID for `"TrustChainCommunity"`.
pub static TRUSTCHAIN_COMMUNITY_ID: std::sync::LazyLock<[u8; 20]> =
    std::sync::LazyLock::new(|| compute_community_id("TrustChainCommunity"));

#[derive(Debug, Error)]
pub enum PacketError {
    #[error("packet too short: need at least {HEADER_SIZE} bytes, got {0}")]
    TooShort(usize),
    #[error("invalid prefix: expected 0x0000, got 0x{0:02x}{1:02x}")]
    InvalidPrefix(u8, u8),
    #[error("unsupported version: expected {IPV8_VERSION}, got {0}")]
    UnsupportedVersion(u8),
}

/// Compute the SHA-1 community ID for a given community name.
pub fn compute_community_id(name: &str) -> [u8; 20] {
    let mut hasher = Sha1::new();
    hasher.update(name.as_bytes());
    hasher.finalize().into()
}

/// The 24-byte IPv8 header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv8Header {
    pub community_id: [u8; 20],
    pub message_type: u8,
}

impl Ipv8Header {
    pub fn new(community_id: [u8; 20], message_type: u8) -> Self {
        Self {
            community_id,
            message_type,
        }
    }

    /// Serialize the header into exactly [`HEADER_SIZE`] bytes.
    pub fn to_bytes(&self) -> [u8; HEADER_SIZE] {
        let mut buf = [0u8; HEADER_SIZE];
        buf[0..2].copy_from_slice(&IPV8_PREFIX);
        buf[2] = IPV8_VERSION;
        buf[3..23].copy_from_slice(&self.community_id);
        buf[23] = self.message_type;
        buf
    }

    /// Deserialize a header from the first [`HEADER_SIZE`] bytes of `data`.
    pub fn from_bytes(data: &[u8]) -> Result<Self, PacketError> {
        if data.len() < HEADER_SIZE {
            return Err(PacketError::TooShort(data.len()));
        }
        if data[0] != IPV8_PREFIX[0] || data[1] != IPV8_PREFIX[1] {
            return Err(PacketError::InvalidPrefix(data[0], data[1]));
        }
        if data[2] != IPV8_VERSION {
            return Err(PacketError::UnsupportedVersion(data[2]));
        }
        let mut community_id = [0u8; 20];
        community_id.copy_from_slice(&data[3..23]);
        Ok(Self {
            community_id,
            message_type: data[23],
        })
    }
}

/// A complete IPv8 packet: header + payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv8Packet {
    pub header: Ipv8Header,
    pub payload: Vec<u8>,
}

impl Ipv8Packet {
    pub fn new(header: Ipv8Header, payload: Vec<u8>) -> Self {
        Self { header, payload }
    }

    /// Serialize to wire bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let header_bytes = self.header.to_bytes();
        let mut buf = Vec::with_capacity(HEADER_SIZE + self.payload.len());
        buf.extend_from_slice(&header_bytes);
        buf.extend_from_slice(&self.payload);
        buf
    }

    /// Deserialize from wire bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self, PacketError> {
        let header = Ipv8Header::from_bytes(data)?;
        let payload = data[HEADER_SIZE..].to_vec();
        Ok(Self { header, payload })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_round_trip() {
        let header = Ipv8Header::new(*TRUSTCHAIN_COMMUNITY_ID, 1);
        let bytes = header.to_bytes();
        let decoded = Ipv8Header::from_bytes(&bytes).unwrap();
        assert_eq!(header, decoded);
    }

    #[test]
    fn packet_round_trip() {
        let header = Ipv8Header::new(*TRUSTCHAIN_COMMUNITY_ID, 2);
        let payload = b"hello trustchain".to_vec();
        let packet = Ipv8Packet::new(header, payload.clone());
        let bytes = packet.to_bytes();
        let decoded = Ipv8Packet::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.header, packet.header);
        assert_eq!(decoded.payload, payload);
    }

    #[test]
    fn community_id_deterministic() {
        let id1 = compute_community_id("TrustChainCommunity");
        let id2 = compute_community_id("TrustChainCommunity");
        assert_eq!(id1, id2);
        // Different name → different ID.
        let id3 = compute_community_id("OtherCommunity");
        assert_ne!(id1, id3);
    }

    #[test]
    fn too_short_packet() {
        let data = [0u8; 10];
        assert!(matches!(
            Ipv8Header::from_bytes(&data),
            Err(PacketError::TooShort(10))
        ));
    }

    #[test]
    fn invalid_prefix() {
        let mut data = [0u8; HEADER_SIZE];
        data[0] = 0xFF;
        data[1] = 0xFF;
        assert!(matches!(
            Ipv8Header::from_bytes(&data),
            Err(PacketError::InvalidPrefix(0xFF, 0xFF))
        ));
    }

    #[test]
    fn unsupported_version() {
        let mut data = [0u8; HEADER_SIZE];
        data[2] = 99;
        assert!(matches!(
            Ipv8Header::from_bytes(&data),
            Err(PacketError::UnsupportedVersion(99))
        ));
    }
}
