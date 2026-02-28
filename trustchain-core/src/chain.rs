//! Personal chain validation and management.
//!
//! A `PersonalChain` represents one agent's linear chain of half-blocks,
//! providing append-only validation and integrity checking.

use std::collections::BTreeMap;

use crate::blockstore::BlockStore;
use crate::error::{Result, TrustChainError};
use crate::halfblock::{verify_block, HalfBlock};
use crate::types::GENESIS_HASH;

/// A personal chain for one agent, maintaining validated blocks.
#[derive(Debug, Clone)]
pub struct PersonalChain {
    pubkey: String,
    blocks: BTreeMap<u64, HalfBlock>,
}

impl PersonalChain {
    /// Create an empty personal chain for the given public key.
    pub fn new(pubkey: impl Into<String>) -> Self {
        Self {
            pubkey: pubkey.into(),
            blocks: BTreeMap::new(),
        }
    }

    /// Get the public key this chain belongs to.
    pub fn pubkey(&self) -> &str {
        &self.pubkey
    }

    /// Get the head (latest) block, if any.
    pub fn head(&self) -> Option<&HalfBlock> {
        self.blocks.values().next_back()
    }

    /// Get the hash of the head block (or GENESIS_HASH if empty).
    pub fn head_hash(&self) -> String {
        self.head()
            .map(|b| b.block_hash.clone())
            .unwrap_or_else(|| GENESIS_HASH.to_string())
    }

    /// Get the next expected sequence number (1 if empty).
    pub fn next_seq(&self) -> u64 {
        self.blocks
            .keys()
            .next_back()
            .map(|&seq| seq + 1)
            .unwrap_or(1)
    }

    /// Get the number of blocks in the chain.
    pub fn length(&self) -> usize {
        self.blocks.len()
    }

    /// Check if the chain is empty.
    pub fn is_empty(&self) -> bool {
        self.blocks.is_empty()
    }

    /// Get a block by sequence number.
    pub fn get(&self, seq: u64) -> Option<&HalfBlock> {
        self.blocks.get(&seq)
    }

    /// Get all blocks sorted by sequence number.
    pub fn blocks(&self) -> Vec<&HalfBlock> {
        self.blocks.values().collect()
    }

    /// Append a block to the chain with full validation.
    ///
    /// Checks:
    /// 1. Block belongs to this agent (public_key matches)
    /// 2. Sequence number is the next expected
    /// 3. Previous hash links correctly
    /// 4. Signature is valid
    pub fn append(&mut self, block: HalfBlock) -> Result<()> {
        // Must belong to this chain.
        if block.public_key != self.pubkey {
            return Err(TrustChainError::chain(
                format!(
                    "block belongs to {}, not {}",
                    &block.public_key[..8],
                    &self.pubkey[..8]
                ),
                &self.pubkey,
            ));
        }

        // Sequence check.
        let expected_seq = self.next_seq();
        if block.sequence_number != expected_seq {
            return Err(TrustChainError::sequence_gap(
                &self.pubkey,
                expected_seq,
                block.sequence_number,
            ));
        }

        // Previous hash check.
        let expected_prev = self.head_hash();
        if block.previous_hash != expected_prev {
            return Err(TrustChainError::prev_hash_mismatch(
                &self.pubkey,
                block.sequence_number,
                &expected_prev,
                &block.previous_hash,
            ));
        }

        // Signature check.
        if !verify_block(&block)? {
            return Err(TrustChainError::signature(
                &self.pubkey,
                block.sequence_number,
                "invalid signature",
            ));
        }

        self.blocks.insert(block.sequence_number, block);
        Ok(())
    }

    /// Validate the entire chain (all blocks contiguous and valid).
    pub fn validate(&self) -> Result<bool> {
        if self.blocks.is_empty() {
            return Ok(true);
        }

        let mut expected_seq = 1u64;
        let mut expected_prev = GENESIS_HASH.to_string();

        for (&seq, block) in &self.blocks {
            if seq != expected_seq {
                return Err(TrustChainError::sequence_gap(
                    &self.pubkey,
                    expected_seq,
                    seq,
                ));
            }

            if block.previous_hash != expected_prev {
                return Err(TrustChainError::prev_hash_mismatch(
                    &self.pubkey,
                    seq,
                    &expected_prev,
                    &block.previous_hash,
                ));
            }

            if !verify_block(block)? {
                return Err(TrustChainError::signature(
                    &self.pubkey,
                    seq,
                    "invalid signature",
                ));
            }

            expected_prev = block.block_hash.clone();
            expected_seq = seq + 1;
        }

        Ok(true)
    }

    /// Compute integrity score (fraction of valid blocks before first error).
    pub fn integrity_score(&self) -> f64 {
        if self.blocks.is_empty() {
            return 1.0;
        }

        let total = self.blocks.len() as f64;
        let mut expected_seq = 1u64;
        let mut expected_prev = GENESIS_HASH.to_string();
        let mut valid_count = 0usize;

        for (&seq, block) in &self.blocks {
            if seq != expected_seq {
                break;
            }
            if block.previous_hash != expected_prev {
                break;
            }
            if !verify_block(block).unwrap_or(false) {
                break;
            }

            valid_count += 1;
            expected_prev = block.block_hash.clone();
            expected_seq = seq + 1;
        }

        valid_count as f64 / total
    }

    /// Load a personal chain from a block store.
    pub fn from_store(pubkey: &str, store: &dyn BlockStore) -> Result<Self> {
        let mut chain = Self::new(pubkey);
        let blocks = store.get_chain(pubkey)?;
        for block in blocks {
            // Use insert directly (blocks from store are assumed ordered).
            chain.blocks.insert(block.sequence_number, block);
        }
        Ok(chain)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blockstore::MemoryBlockStore;
    use crate::halfblock::create_half_block;
    use crate::identity::Identity;
    use crate::types::BlockType;

    fn test_id() -> Identity {
        Identity::from_bytes(&[1u8; 32])
    }

    #[test]
    fn test_empty_chain() {
        let id = test_id();
        let chain = PersonalChain::new(id.pubkey_hex());
        assert!(chain.is_empty());
        assert_eq!(chain.length(), 0);
        assert_eq!(chain.next_seq(), 1);
        assert_eq!(chain.head_hash(), GENESIS_HASH);
        assert!(chain.head().is_none());
        assert!(chain.validate().unwrap());
        assert_eq!(chain.integrity_score(), 1.0);
    }

    #[test]
    fn test_append_single_block() {
        let id = test_id();
        let mut chain = PersonalChain::new(id.pubkey_hex());

        let block = create_half_block(
            &id, 1, &"b".repeat(64), 0, GENESIS_HASH,
            BlockType::Proposal, serde_json::json!({}), Some(1000),
        );

        chain.append(block.clone()).unwrap();
        assert_eq!(chain.length(), 1);
        assert_eq!(chain.next_seq(), 2);
        assert_eq!(chain.head_hash(), block.block_hash);
        assert!(chain.validate().unwrap());
    }

    #[test]
    fn test_append_multiple_blocks() {
        let id = test_id();
        let peer = "b".repeat(64);
        let mut chain = PersonalChain::new(id.pubkey_hex());

        let b1 = create_half_block(
            &id, 1, &peer, 0, GENESIS_HASH,
            BlockType::Proposal, serde_json::json!({}), Some(1000),
        );
        chain.append(b1.clone()).unwrap();

        let b2 = create_half_block(
            &id, 2, &peer, 0, &b1.block_hash,
            BlockType::Proposal, serde_json::json!({}), Some(1001),
        );
        chain.append(b2.clone()).unwrap();

        let b3 = create_half_block(
            &id, 3, &peer, 0, &b2.block_hash,
            BlockType::Proposal, serde_json::json!({}), Some(1002),
        );
        chain.append(b3).unwrap();

        assert_eq!(chain.length(), 3);
        assert!(chain.validate().unwrap());
        assert_eq!(chain.integrity_score(), 1.0);
    }

    #[test]
    fn test_wrong_pubkey_rejected() {
        let id1 = test_id();
        let id2 = Identity::from_bytes(&[2u8; 32]);
        let mut chain = PersonalChain::new(id1.pubkey_hex());

        let block = create_half_block(
            &id2, 1, &"b".repeat(64), 0, GENESIS_HASH,
            BlockType::Proposal, serde_json::json!({}), Some(1000),
        );

        assert!(chain.append(block).is_err());
    }

    #[test]
    fn test_wrong_sequence_rejected() {
        let id = test_id();
        let mut chain = PersonalChain::new(id.pubkey_hex());

        // Try to append seq 2 without seq 1.
        let block = create_half_block(
            &id, 2, &"b".repeat(64), 0, GENESIS_HASH,
            BlockType::Proposal, serde_json::json!({}), Some(1000),
        );

        assert!(chain.append(block).is_err());
    }

    #[test]
    fn test_wrong_prev_hash_rejected() {
        let id = test_id();
        let mut chain = PersonalChain::new(id.pubkey_hex());

        let b1 = create_half_block(
            &id, 1, &"b".repeat(64), 0, GENESIS_HASH,
            BlockType::Proposal, serde_json::json!({}), Some(1000),
        );
        chain.append(b1).unwrap();

        // Wrong previous hash.
        let b2 = create_half_block(
            &id, 2, &"b".repeat(64), 0, GENESIS_HASH, // should be b1.block_hash
            BlockType::Proposal, serde_json::json!({}), Some(1001),
        );

        assert!(chain.append(b2).is_err());
    }

    #[test]
    fn test_from_store() {
        let id = test_id();
        let peer = "b".repeat(64);
        let mut store = MemoryBlockStore::new();

        let b1 = create_half_block(
            &id, 1, &peer, 0, GENESIS_HASH,
            BlockType::Proposal, serde_json::json!({}), Some(1000),
        );
        store.add_block(&b1).unwrap();

        let b2 = create_half_block(
            &id, 2, &peer, 0, &b1.block_hash,
            BlockType::Proposal, serde_json::json!({}), Some(1001),
        );
        store.add_block(&b2).unwrap();

        let chain = PersonalChain::from_store(&id.pubkey_hex(), &store).unwrap();
        assert_eq!(chain.length(), 2);
    }

    #[test]
    fn test_get_block_by_seq() {
        let id = test_id();
        let mut chain = PersonalChain::new(id.pubkey_hex());

        let block = create_half_block(
            &id, 1, &"b".repeat(64), 0, GENESIS_HASH,
            BlockType::Proposal, serde_json::json!({"data": 42}), Some(1000),
        );
        chain.append(block.clone()).unwrap();

        let fetched = chain.get(1).unwrap();
        assert_eq!(fetched.block_hash, block.block_hash);
        assert!(chain.get(2).is_none());
    }
}
