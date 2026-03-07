//! TrustChain community message payloads.
//!
//! Binary serialization uses big-endian (network) byte order with
//! length-prefixed variable fields:
//! - `[4 bytes] length + [length bytes] data` for variable-length fields
//! - `[8 bytes]` for u64 fields
//!
//! NOTE: py-ipv8 uses its own `Serializable` framework with type annotations.
//! This implementation uses a clean length-prefixed binary format. Exact
//! py-ipv8 wire compatibility will be validated and adjusted in a follow-up.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum PayloadError {
    #[error("payload too short: need {needed} bytes at offset {offset}, have {available}")]
    TooShort {
        needed: usize,
        offset: usize,
        available: usize,
    },
    #[error("invalid message type: {0}")]
    InvalidMessageType(u8),
    #[error("utf-8 decode error: {0}")]
    Utf8(#[from] std::string::FromUtf8Error),
}

/// TrustChain community message types matching py-ipv8.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MessageType {
    CrawlRequest = 1,
    HalfBlock = 2,
    HalfBlockPair = 3,
    HalfBlockBroadcast = 4,
    EmptyBloomFilter = 5,
}

impl MessageType {
    pub fn from_u8(v: u8) -> Result<Self, PayloadError> {
        match v {
            1 => Ok(Self::CrawlRequest),
            2 => Ok(Self::HalfBlock),
            3 => Ok(Self::HalfBlockPair),
            4 => Ok(Self::HalfBlockBroadcast),
            5 => Ok(Self::EmptyBloomFilter),
            _ => Err(PayloadError::InvalidMessageType(v)),
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn read_u32(data: &[u8], offset: usize) -> Result<(u32, usize), PayloadError> {
    if data.len() < offset + 4 {
        return Err(PayloadError::TooShort {
            needed: 4,
            offset,
            available: data.len(),
        });
    }
    let val = u32::from_be_bytes(data[offset..offset + 4].try_into().unwrap());
    Ok((val, offset + 4))
}

fn read_u64(data: &[u8], offset: usize) -> Result<(u64, usize), PayloadError> {
    if data.len() < offset + 8 {
        return Err(PayloadError::TooShort {
            needed: 8,
            offset,
            available: data.len(),
        });
    }
    let val = u64::from_be_bytes(data[offset..offset + 8].try_into().unwrap());
    Ok((val, offset + 8))
}

fn read_bytes(data: &[u8], offset: usize) -> Result<(Vec<u8>, usize), PayloadError> {
    let (len, offset) = read_u32(data, offset)?;
    let len = len as usize;
    if data.len() < offset + len {
        return Err(PayloadError::TooShort {
            needed: len,
            offset,
            available: data.len(),
        });
    }
    let val = data[offset..offset + len].to_vec();
    Ok((val, offset + len))
}

fn read_string(data: &[u8], offset: usize) -> Result<(String, usize), PayloadError> {
    let (bytes, offset) = read_bytes(data, offset)?;
    Ok((String::from_utf8(bytes)?, offset))
}

fn write_u32(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_be_bytes());
}

fn write_u64(buf: &mut Vec<u8>, v: u64) {
    buf.extend_from_slice(&v.to_be_bytes());
}

fn write_bytes(buf: &mut Vec<u8>, data: &[u8]) {
    write_u32(buf, data.len() as u32);
    buf.extend_from_slice(data);
}

fn write_string(buf: &mut Vec<u8>, s: &str) {
    write_bytes(buf, s.as_bytes());
}

// ---------------------------------------------------------------------------
// CrawlRequest
// ---------------------------------------------------------------------------

/// Request blocks from a peer starting at a given sequence number.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrawlRequest {
    pub public_key: String,
    pub requested_seq: u64,
    pub limit: u32,
}

impl CrawlRequest {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        write_string(&mut buf, &self.public_key);
        write_u64(&mut buf, self.requested_seq);
        write_u32(&mut buf, self.limit);
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, PayloadError> {
        let (public_key, offset) = read_string(data, 0)?;
        let (requested_seq, offset) = read_u64(data, offset)?;
        let (limit, _) = read_u32(data, offset)?;
        Ok(Self {
            public_key,
            requested_seq,
            limit,
        })
    }
}

// ---------------------------------------------------------------------------
// HalfBlockPayload
// ---------------------------------------------------------------------------

/// Binary representation of a HalfBlock for IPv8 wire transport.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HalfBlockPayload {
    pub public_key: String,
    pub sequence_number: u64,
    pub link_public_key: String,
    pub link_sequence_number: u64,
    pub previous_hash: String,
    pub signature: String,
    pub block_type: String,
    pub transaction: String,
    pub block_hash: String,
    pub timestamp: u64,
}

impl HalfBlockPayload {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        write_string(&mut buf, &self.public_key);
        write_u64(&mut buf, self.sequence_number);
        write_string(&mut buf, &self.link_public_key);
        write_u64(&mut buf, self.link_sequence_number);
        write_string(&mut buf, &self.previous_hash);
        write_string(&mut buf, &self.signature);
        write_string(&mut buf, &self.block_type);
        write_string(&mut buf, &self.transaction);
        write_string(&mut buf, &self.block_hash);
        write_u64(&mut buf, self.timestamp);
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, PayloadError> {
        let (public_key, offset) = read_string(data, 0)?;
        let (sequence_number, offset) = read_u64(data, offset)?;
        let (link_public_key, offset) = read_string(data, offset)?;
        let (link_sequence_number, offset) = read_u64(data, offset)?;
        let (previous_hash, offset) = read_string(data, offset)?;
        let (signature, offset) = read_string(data, offset)?;
        let (block_type, offset) = read_string(data, offset)?;
        let (transaction, offset) = read_string(data, offset)?;
        let (block_hash, offset) = read_string(data, offset)?;
        let (timestamp, _) = read_u64(data, offset)?;
        Ok(Self {
            public_key,
            sequence_number,
            link_public_key,
            link_sequence_number,
            previous_hash,
            signature,
            block_type,
            transaction,
            block_hash,
            timestamp,
        })
    }
}

// ---------------------------------------------------------------------------
// HalfBlockPairPayload
// ---------------------------------------------------------------------------

/// A proposal + agreement pair serialized consecutively.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HalfBlockPairPayload {
    pub proposal: HalfBlockPayload,
    pub agreement: HalfBlockPayload,
}

impl HalfBlockPairPayload {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = self.proposal.to_bytes();
        buf.extend_from_slice(&self.agreement.to_bytes());
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, PayloadError> {
        // Deserialize proposal, then use remaining bytes for agreement.
        let proposal = HalfBlockPayload::from_bytes(data)?;
        let proposal_bytes = proposal.to_bytes();
        let offset = proposal_bytes.len();
        let agreement = HalfBlockPayload::from_bytes(&data[offset..])?;
        Ok(Self {
            proposal,
            agreement,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_type_round_trip() {
        for &mt in &[
            MessageType::CrawlRequest,
            MessageType::HalfBlock,
            MessageType::HalfBlockPair,
            MessageType::HalfBlockBroadcast,
            MessageType::EmptyBloomFilter,
        ] {
            assert_eq!(MessageType::from_u8(mt as u8).unwrap(), mt);
        }
    }

    #[test]
    fn invalid_message_type() {
        assert!(MessageType::from_u8(0).is_err());
        assert!(MessageType::from_u8(255).is_err());
    }

    #[test]
    fn crawl_request_round_trip() {
        let req = CrawlRequest {
            public_key: "ab".repeat(32),
            requested_seq: 42,
            limit: 100,
        };
        let bytes = req.to_bytes();
        let decoded = CrawlRequest::from_bytes(&bytes).unwrap();
        assert_eq!(req, decoded);
    }

    #[test]
    fn half_block_payload_round_trip() {
        let block = sample_block();
        let bytes = block.to_bytes();
        let decoded = HalfBlockPayload::from_bytes(&bytes).unwrap();
        assert_eq!(block, decoded);
    }

    #[test]
    fn half_block_pair_round_trip() {
        let pair = HalfBlockPairPayload {
            proposal: sample_block(),
            agreement: HalfBlockPayload {
                sequence_number: 2,
                link_sequence_number: 1,
                ..sample_block()
            },
        };
        let bytes = pair.to_bytes();
        let decoded = HalfBlockPairPayload::from_bytes(&bytes).unwrap();
        assert_eq!(pair, decoded);
    }

    fn sample_block() -> HalfBlockPayload {
        HalfBlockPayload {
            public_key: "aa".repeat(32),
            sequence_number: 1,
            link_public_key: "bb".repeat(32),
            link_sequence_number: 0,
            previous_hash: "00".repeat(32),
            signature: "cc".repeat(64),
            block_type: "proposal".into(),
            transaction: r#"{"amount":10}"#.into(),
            block_hash: "dd".repeat(32),
            timestamp: 1_700_000_000_000,
        }
    }
}
