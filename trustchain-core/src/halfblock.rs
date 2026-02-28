//! HalfBlock — the fundamental data structure of TrustChain.
//!
//! Each interaction produces two half-blocks: a proposal and an agreement.
//! Together they form a bilateral, cryptographically signed record.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::blockstore::BlockStore;
use crate::error::{Result, TrustChainError};
use crate::identity::Identity;
use crate::types::{BlockType, GENESIS_HASH, GENESIS_SEQ, UNKNOWN_SEQ, ValidationResult};

/// A half-block in the TrustChain protocol.
///
/// Each agent maintains a personal chain of half-blocks. A complete interaction
/// consists of a proposal half-block (from initiator) and an agreement half-block
/// (from responder), linked by cross-chain pointers.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HalfBlock {
    /// Public key of the block creator (64 hex chars).
    pub public_key: String,
    /// Sequence number in the creator's personal chain (1-based).
    pub sequence_number: u64,
    /// Public key of the counterparty (64 hex chars).
    pub link_public_key: String,
    /// Counterparty's sequence number: 0 for proposals, >0 for agreements.
    pub link_sequence_number: u64,
    /// Hash of the previous block in this agent's chain (or GENESIS_HASH).
    pub previous_hash: String,
    /// Ed25519 signature over the block hash (128 hex chars, empty before signing).
    pub signature: String,
    /// Block type: proposal, agreement, or checkpoint.
    pub block_type: String,
    /// Application-level transaction payload.
    pub transaction: serde_json::Value,
    /// SHA-256 hash of the block (64 hex chars).
    pub block_hash: String,
    /// Unix timestamp in milliseconds since epoch.
    pub timestamp: u64,
}

impl HalfBlock {
    /// Compute the SHA-256 hash of this block.
    ///
    /// The hash is computed over a JSON-canonical representation with `signature` set
    /// to an empty string and keys sorted alphabetically. This matches the Python
    /// implementation for wire compatibility.
    pub fn compute_hash(&self) -> String {
        // Build the hashable map with sorted keys (BTreeMap is sorted).
        let mut map = BTreeMap::new();
        map.insert("block_type", serde_json::Value::String(self.block_type.clone()));
        map.insert(
            "link_public_key",
            serde_json::Value::String(self.link_public_key.clone()),
        );
        map.insert(
            "link_sequence_number",
            serde_json::json!(self.link_sequence_number),
        );
        map.insert(
            "previous_hash",
            serde_json::Value::String(self.previous_hash.clone()),
        );
        map.insert(
            "public_key",
            serde_json::Value::String(self.public_key.clone()),
        );
        map.insert(
            "sequence_number",
            serde_json::json!(self.sequence_number),
        );
        // Signature is always empty string for hashing.
        map.insert("signature", serde_json::Value::String(String::new()));
        map.insert(
            "timestamp",
            serde_json::json!(self.timestamp),
        );
        map.insert("transaction", self.transaction.clone());

        // Compact JSON with sorted keys (BTreeMap guarantees order).
        let payload = serde_json::to_string(&map).expect("BTreeMap serialization cannot fail");
        let hash = Sha256::digest(payload.as_bytes());
        hex::encode(hash)
    }

    /// Verify that the stored `block_hash` matches a fresh computation.
    pub fn verify_hash(&self) -> bool {
        self.block_hash == self.compute_hash()
    }

    /// Verify the Ed25519 signature over the block hash.
    pub fn verify_signature(&self) -> Result<bool> {
        if self.signature.is_empty() {
            return Ok(false);
        }
        Identity::verify_hex(
            self.block_hash.as_bytes(),
            &self.signature,
            &self.public_key,
        )
    }

    /// Full verification: hash integrity + signature validity.
    pub fn verify(&self) -> Result<bool> {
        if !self.verify_hash() {
            return Ok(false);
        }
        self.verify_signature()
    }

    /// Get the block type as the typed enum.
    pub fn block_type_enum(&self) -> Option<BlockType> {
        BlockType::from_str_loose(&self.block_type)
    }

    /// Check if this is a proposal block.
    pub fn is_proposal(&self) -> bool {
        self.block_type == "proposal"
    }

    /// Check if this is an agreement block.
    pub fn is_agreement(&self) -> bool {
        self.block_type == "agreement"
    }

    /// Check if this is a checkpoint block.
    pub fn is_checkpoint(&self) -> bool {
        self.block_type == "checkpoint"
    }
}

impl std::fmt::Display for HalfBlock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "HalfBlock({} seq={} type={} link={}:{})",
            &self.public_key[..8],
            self.sequence_number,
            self.block_type,
            &self.link_public_key[..std::cmp::min(8, self.link_public_key.len())],
            self.link_sequence_number,
        )
    }
}

/// Get the current Unix timestamp in milliseconds.
pub fn now_timestamp_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before UNIX epoch")
        .as_millis() as u64
}

/// Create, hash, and sign a half-block in one call.
pub fn create_half_block(
    identity: &Identity,
    sequence_number: u64,
    link_public_key: &str,
    link_sequence_number: u64,
    previous_hash: &str,
    block_type: BlockType,
    transaction: serde_json::Value,
    timestamp: Option<u64>,
) -> HalfBlock {
    let mut block = HalfBlock {
        public_key: identity.pubkey_hex(),
        sequence_number,
        link_public_key: link_public_key.to_string(),
        link_sequence_number,
        previous_hash: previous_hash.to_string(),
        signature: String::new(),
        block_type: block_type.to_string(),
        transaction,
        block_hash: String::new(),
        timestamp: timestamp.unwrap_or_else(now_timestamp_ms),
    };

    // Compute hash (with signature="").
    block.block_hash = block.compute_hash();

    // Sign the hash.
    block.signature = identity.sign_hex(block.block_hash.as_bytes());

    block
}

/// Verify an existing block: recompute hash and check signature.
pub fn verify_block(block: &HalfBlock) -> Result<bool> {
    let recomputed = block.compute_hash();
    if recomputed != block.block_hash {
        return Err(TrustChainError::signature(
            &block.public_key,
            block.sequence_number,
            format!(
                "hash mismatch: computed {}, stored {}",
                recomputed, block.block_hash
            ),
        ));
    }
    block.verify_signature()
}

/// Validate block invariants (self-contained checks, no database needed).
///
/// Matches py-ipv8's `update_block_invariant`:
/// 1. Sequence number must be >= GENESIS_SEQ (1)
/// 2. Link sequence number must be UNKNOWN_SEQ (0) or >= GENESIS_SEQ
/// 3. Timestamp must be non-negative
/// 4. Public key must be 64 hex chars
/// 5. Signature must be valid (hash + sig check)
/// 6. No self-signed blocks (public_key != link_public_key)
/// 7. Genesis consistency: seq==1 ↔ previous_hash==GENESIS_HASH
pub fn validate_block_invariants(block: &HalfBlock) -> ValidationResult {
    let mut errors = Vec::new();

    // 1. Sequence number sanity.
    if block.sequence_number < GENESIS_SEQ {
        errors.push(format!(
            "Sequence number {} is prior to genesis",
            block.sequence_number
        ));
    }

    // 2. Link sequence number: 0 (unknown) or >= 1.
    if block.link_sequence_number != UNKNOWN_SEQ && block.link_sequence_number < GENESIS_SEQ {
        errors.push(format!(
            "Link sequence number {} not empty and is prior to genesis",
            block.link_sequence_number
        ));
    }

    // 3. Timestamp sanity (u64 — always non-negative, no check needed).

    // 4. Public key format (64 hex chars = 32 bytes).
    if block.public_key.len() != 64 || !block.public_key.chars().all(|c| c.is_ascii_hexdigit()) {
        errors.push("Public key is not valid".to_string());
    }

    // 5. Signature verification.
    if errors.iter().all(|e| e != "Public key is not valid") {
        match verify_block(block) {
            Ok(false) => errors.push("Invalid signature".to_string()),
            Err(e) => errors.push(format!("Signature verification failed: {e}")),
            Ok(true) => {}
        }
    }

    // 6. Link public key validation (if not empty/unknown).
    if !block.link_public_key.is_empty()
        && block.link_public_key.len() != 64
    {
        errors.push("Linked public key is not valid".to_string());
    }

    // 7. No self-signed blocks.
    if block.public_key == block.link_public_key && !block.is_checkpoint() {
        errors.push("Self signed block".to_string());
    }

    // 8. Genesis consistency: seq==1 must have GENESIS_HASH, and vice versa.
    if block.sequence_number == GENESIS_SEQ && block.previous_hash != GENESIS_HASH {
        errors.push("Sequence number implies previous hash should be Genesis ID".to_string());
    }
    if block.sequence_number != GENESIS_SEQ && block.previous_hash == GENESIS_HASH {
        errors.push(
            "Sequence number implies previous hash should not be Genesis ID".to_string(),
        );
    }

    if errors.is_empty() {
        ValidationResult::Valid
    } else {
        ValidationResult::Invalid(errors)
    }
}

/// Full block validation against a database, matching py-ipv8's `TrustChainBlock.validate()`.
///
/// Checks invariants, block consistency (double-sign), linked consistency (double-countersign),
/// and chain consistency (previous/next hash links). Returns a tiered `ValidationResult`.
///
/// This is the read-only version — use `validate_and_record` to also persist fraud evidence.
pub fn validate_block<S: BlockStore>(block: &HalfBlock, store: &S) -> ValidationResult {
    // Step 1: Check invariants (self-contained).
    let invariants = validate_block_invariants(block);
    if let ValidationResult::Invalid(errors) = invariants {
        return ValidationResult::Invalid(errors);
    }

    let mut errors: Vec<String> = Vec::new();

    // Step 2: Determine validation level based on available chain context.
    let prev_blk = if block.sequence_number > GENESIS_SEQ {
        store.get_block(&block.public_key, block.sequence_number - 1).ok().flatten()
    } else {
        None
    };
    let next_blk = store.get_block(&block.public_key, block.sequence_number + 1).ok().flatten();

    let is_prev_gap = prev_blk.as_ref()
        .map_or(true, |p| p.sequence_number != block.sequence_number - 1);
    let is_next_gap = next_blk.as_ref()
        .map_or(true, |n| n.sequence_number != block.sequence_number + 1);

    let level = match (prev_blk.is_some() || block.sequence_number == GENESIS_SEQ, next_blk.is_some()) {
        (false, false) => ValidationResult::NoInfo,
        (false, true) if is_next_gap => ValidationResult::Partial,
        (false, true) => ValidationResult::PartialPrevious,
        (true, false) if is_prev_gap && block.sequence_number != GENESIS_SEQ => ValidationResult::Partial,
        (true, false) => ValidationResult::PartialNext,
        (true, true) => {
            if is_prev_gap && is_next_gap {
                ValidationResult::Partial
            } else if is_prev_gap {
                ValidationResult::PartialPrevious
            } else if is_next_gap {
                ValidationResult::PartialNext
            } else {
                ValidationResult::Valid
            }
        }
    };

    // Step 3: Block consistency — if we already have a block at this position, it must match.
    if let Ok(Some(existing)) = store.get_block(&block.public_key, block.sequence_number) {
        if existing.block_hash != block.block_hash {
            // Two different blocks at the same position with valid signatures = double-sign fraud.
            if verify_block(&existing).unwrap_or(false) {
                errors.push("Double sign fraud".to_string());
            } else {
                errors.push("Block hash does not match known block".to_string());
            }
        }
    }

    // Step 4: Linked consistency — if the linked block exists, cross-check.
    if block.link_sequence_number != UNKNOWN_SEQ {
        if let Ok(Some(link)) = store.get_block(&block.link_public_key, block.link_sequence_number) {
            // The linked block (proposal) must point back to us — regardless of whether
            // its own link_sequence_number is known. Proposals always have UNKNOWN_SEQ
            // for their link, so the original `&&` guard was dead code that silently
            // let pubkey mismatches through.
            if link.link_public_key != block.public_key {
                errors.push("Public key mismatch on linked block".to_string());
            }
            // Check for double-countersign: if link already has a different linked block.
            // Proposals always have UNKNOWN_SEQ for their own link_sequence_number, so the
            // original `&& link.link_sequence_number != UNKNOWN_SEQ` guard was dead code that
            // silently allowed double-countersign through — removed to match paper §3.3.
            if let Ok(Some(link_linked)) = store.get_linked_block(&link) {
                if link_linked.block_hash != block.block_hash {
                    errors.push("Double countersign fraud".to_string());
                }
            }
        }
    }

    // Step 5: Chain consistency — previous and next hash links.
    if let Some(ref prev) = prev_blk {
        if prev.public_key != block.public_key {
            errors.push("Previous block public key mismatch".to_string());
        }
        if !is_prev_gap && prev.block_hash != block.previous_hash {
            errors.push("Previous hash is not equal to the hash id of the previous block".to_string());
        }
    }
    if let Some(ref next) = next_blk {
        if next.public_key != block.public_key {
            errors.push("Next block public key mismatch".to_string());
        }
        if !is_next_gap && next.previous_hash != block.block_hash {
            errors.push("Next hash is not equal to the hash id of the block".to_string());
        }
    }

    if errors.is_empty() {
        level
    } else {
        ValidationResult::Invalid(errors)
    }
}

/// Validate a block and record any fraud evidence to the store.
///
/// Same as `validate_block` but also persists double-spend records.
pub fn validate_and_record<S: BlockStore>(block: &HalfBlock, store: &mut S) -> ValidationResult {
    // Run read-only validation first.
    let result = validate_block(block, store);

    // If double-sign fraud was detected, record it.
    if let ValidationResult::Invalid(ref errors) = result {
        if errors.iter().any(|e| e.contains("Double sign fraud")) {
            if let Ok(Some(existing)) = store.get_block(&block.public_key, block.sequence_number) {
                let _ = store.add_double_spend(&existing, block);
            }
        }
        if errors.iter().any(|e| e.contains("Double countersign fraud")) {
            // Record the double-countersign evidence.
            if block.link_sequence_number != UNKNOWN_SEQ {
                if let Ok(Some(link)) = store.get_block(&block.link_public_key, block.link_sequence_number) {
                    if let Ok(Some(link_linked)) = store.get_linked_block(&link) {
                        let _ = store.add_double_spend(&link_linked, block);
                    }
                }
            }
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::GENESIS_HASH;

    fn test_identity() -> Identity {
        Identity::from_bytes(&[1u8; 32])
    }

    #[test]
    fn test_create_and_verify_block() {
        let id = test_identity();
        let block = create_half_block(
            &id,
            1,
            &"b".repeat(64),
            0,
            GENESIS_HASH,
            BlockType::Proposal,
            serde_json::json!({"service": "compute"}),
            Some(1000),
        );

        assert_eq!(block.public_key, id.pubkey_hex());
        assert_eq!(block.sequence_number, 1);
        assert_eq!(block.block_type, "proposal");
        assert!(!block.signature.is_empty());
        assert!(!block.block_hash.is_empty());
        assert_eq!(block.block_hash.len(), 64);
        assert_eq!(block.signature.len(), 128);
    }

    #[test]
    fn test_verify_block_ok() {
        let id = test_identity();
        let block = create_half_block(
            &id,
            1,
            &"b".repeat(64),
            0,
            GENESIS_HASH,
            BlockType::Proposal,
            serde_json::json!({}),
            Some(1000),
        );

        assert!(verify_block(&block).unwrap());
    }

    #[test]
    fn test_tampered_block_fails_verification() {
        let id = test_identity();
        let mut block = create_half_block(
            &id,
            1,
            &"b".repeat(64),
            0,
            GENESIS_HASH,
            BlockType::Proposal,
            serde_json::json!({}),
            Some(1000),
        );

        // Tamper with the transaction.
        block.transaction = serde_json::json!({"tampered": true});

        assert!(verify_block(&block).is_err());
    }

    #[test]
    fn test_hash_determinism() {
        let id = test_identity();
        let block = create_half_block(
            &id,
            1,
            &"b".repeat(64),
            0,
            GENESIS_HASH,
            BlockType::Proposal,
            serde_json::json!({"key": "value"}),
            Some(1000),
        );

        // Hash should be the same when recomputed.
        assert_eq!(block.compute_hash(), block.block_hash);
        assert_eq!(block.compute_hash(), block.compute_hash());
    }

    #[test]
    fn test_different_transactions_different_hashes() {
        let id = test_identity();
        let block1 = create_half_block(
            &id,
            1,
            &"b".repeat(64),
            0,
            GENESIS_HASH,
            BlockType::Proposal,
            serde_json::json!({"a": 1}),
            Some(1000),
        );
        let block2 = create_half_block(
            &id,
            1,
            &"b".repeat(64),
            0,
            GENESIS_HASH,
            BlockType::Proposal,
            serde_json::json!({"b": 2}),
            Some(1000),
        );

        assert_ne!(block1.block_hash, block2.block_hash);
    }

    #[test]
    fn test_wrong_signer_fails() {
        let id1 = test_identity();
        let id2 = Identity::from_bytes(&[2u8; 32]);

        let mut block = create_half_block(
            &id1,
            1,
            &"b".repeat(64),
            0,
            GENESIS_HASH,
            BlockType::Proposal,
            serde_json::json!({}),
            Some(1000),
        );

        // Replace public key but keep id1's signature.
        block.public_key = id2.pubkey_hex();
        block.block_hash = block.compute_hash();
        // Signature was made by id1, but block claims id2.
        let valid = block.verify_signature().unwrap();
        assert!(!valid);
    }

    #[test]
    fn test_block_display() {
        let id = test_identity();
        let block = create_half_block(
            &id,
            1,
            &"b".repeat(64),
            0,
            GENESIS_HASH,
            BlockType::Proposal,
            serde_json::json!({}),
            Some(1000),
        );
        let s = format!("{block}");
        assert!(s.contains("seq=1"));
        assert!(s.contains("proposal"));
    }

    #[test]
    fn test_block_type_checks() {
        let id = test_identity();

        let proposal = create_half_block(
            &id, 1, &"b".repeat(64), 0, GENESIS_HASH,
            BlockType::Proposal, serde_json::json!({}), Some(1000),
        );
        assert!(proposal.is_proposal());
        assert!(!proposal.is_agreement());
        assert!(!proposal.is_checkpoint());

        let agreement = create_half_block(
            &id, 2, &"b".repeat(64), 1, &proposal.block_hash,
            BlockType::Agreement, serde_json::json!({}), Some(1001),
        );
        assert!(agreement.is_agreement());
        assert!(!agreement.is_proposal());
    }

    #[test]
    fn test_genesis_hash_as_previous() {
        let id = test_identity();
        let block = create_half_block(
            &id,
            1,
            &"b".repeat(64),
            0,
            GENESIS_HASH,
            BlockType::Proposal,
            serde_json::json!({}),
            Some(1000),
        );
        assert_eq!(block.previous_hash, GENESIS_HASH);
        assert!(verify_block(&block).unwrap());
    }

    #[test]
    fn test_invariant_valid_block() {
        let id = test_identity();
        let block = create_half_block(
            &id, 1, &"b".repeat(64), 0, GENESIS_HASH,
            BlockType::Proposal, serde_json::json!({}), Some(1000),
        );
        let result = validate_block_invariants(&block);
        assert_eq!(result, ValidationResult::Valid);
    }

    #[test]
    fn test_invariant_self_signed_rejected() {
        let id = test_identity();
        let block = create_half_block(
            &id, 1, &id.pubkey_hex(), 0, GENESIS_HASH,
            BlockType::Proposal, serde_json::json!({}), Some(1000),
        );
        let result = validate_block_invariants(&block);
        assert!(matches!(result, ValidationResult::Invalid(_)));
        if let ValidationResult::Invalid(errors) = &result {
            assert!(errors.iter().any(|e| e.contains("Self signed")));
        }
    }

    #[test]
    fn test_invariant_genesis_hash_consistency() {
        let id = test_identity();
        // seq=1 but previous_hash is NOT genesis → invalid
        let mut block = create_half_block(
            &id, 1, &"b".repeat(64), 0, &"a".repeat(64),
            BlockType::Proposal, serde_json::json!({}), Some(1000),
        );
        // Re-sign with the wrong previous hash
        block.block_hash = block.compute_hash();
        block.signature = id.sign_hex(block.block_hash.as_bytes());
        let result = validate_block_invariants(&block);
        assert!(matches!(result, ValidationResult::Invalid(_)));
    }

    #[test]
    fn test_invariant_seq2_with_genesis_hash() {
        let id = test_identity();
        // seq=2 but previous_hash is GENESIS → invalid
        let mut block = create_half_block(
            &id, 2, &"b".repeat(64), 0, GENESIS_HASH,
            BlockType::Proposal, serde_json::json!({}), Some(1000),
        );
        block.block_hash = block.compute_hash();
        block.signature = id.sign_hex(block.block_hash.as_bytes());
        let result = validate_block_invariants(&block);
        assert!(matches!(result, ValidationResult::Invalid(_)));
        if let ValidationResult::Invalid(errors) = &result {
            assert!(errors.iter().any(|e| e.contains("should not be Genesis")));
        }
    }

    #[test]
    fn test_timestamp_zero_is_valid() {
        // u64 timestamps can't be negative; zero is allowed (e.g., test fixtures).
        let id = test_identity();
        let block = create_half_block(
            &id, 1, &"b".repeat(64), 0, GENESIS_HASH,
            BlockType::Proposal, serde_json::json!({}), Some(0),
        );
        let result = validate_block_invariants(&block);
        assert!(!matches!(result, ValidationResult::Invalid(_)));
    }

    #[test]
    fn test_invariant_checkpoint_self_ref_allowed() {
        // Checkpoint blocks reference self — should NOT trigger "self signed" error.
        let id = test_identity();
        let block = create_half_block(
            &id, 1, &id.pubkey_hex(), 0, GENESIS_HASH,
            BlockType::Checkpoint, serde_json::json!({"checkpoint": true}), Some(1000),
        );
        let result = validate_block_invariants(&block);
        // Should NOT have self-sign error (checkpoints are self-referencing).
        if let ValidationResult::Invalid(errors) = &result {
            assert!(!errors.iter().any(|e| e.contains("Self signed")), "checkpoint self-ref should be allowed");
        }
    }

    #[test]
    fn test_validate_block_no_info() {
        // Genesis block in empty store → PartialNext (genesis acts as "prev exists").
        let id = test_identity();
        let store = crate::blockstore::MemoryBlockStore::new();
        let block = create_half_block(
            &id, 1, &"b".repeat(64), 0, GENESIS_HASH,
            BlockType::Proposal, serde_json::json!({}), Some(1000),
        );
        let result = validate_block(&block, &store);
        assert_eq!(result, ValidationResult::PartialNext);
    }

    #[test]
    fn test_validate_block_with_prev() {
        let id = test_identity();
        let mut store = crate::blockstore::MemoryBlockStore::new();
        let b1 = create_half_block(
            &id, 1, &"b".repeat(64), 0, GENESIS_HASH,
            BlockType::Proposal, serde_json::json!({}), Some(1000),
        );
        store.add_block(&b1).unwrap();

        let b2 = create_half_block(
            &id, 2, &"b".repeat(64), 0, &b1.block_hash,
            BlockType::Proposal, serde_json::json!({}), Some(1001),
        );
        let result = validate_block(&b2, &store);
        // Has prev (b1), no next → PartialNext.
        assert_eq!(result, ValidationResult::PartialNext);
    }

    #[test]
    fn test_validate_block_double_sign_fraud() {
        let id = test_identity();
        let mut store = crate::blockstore::MemoryBlockStore::new();
        let b1 = create_half_block(
            &id, 1, &"b".repeat(64), 0, GENESIS_HASH,
            BlockType::Proposal, serde_json::json!({"tx": "original"}), Some(1000),
        );
        store.add_block(&b1).unwrap();

        // Different block at same seq = double-sign fraud.
        let b1_fraud = create_half_block(
            &id, 1, &"b".repeat(64), 0, GENESIS_HASH,
            BlockType::Proposal, serde_json::json!({"tx": "fraud"}), Some(1000),
        );
        let result = validate_block(&b1_fraud, &store);
        assert!(matches!(result, ValidationResult::Invalid(_)));
        if let ValidationResult::Invalid(errors) = &result {
            assert!(errors.iter().any(|e| e.contains("Double sign fraud")));
        }
    }

    #[test]
    fn test_validate_and_record_stores_fraud() {
        let id = test_identity();
        let mut store = crate::blockstore::MemoryBlockStore::new();
        let b1 = create_half_block(
            &id, 1, &"b".repeat(64), 0, GENESIS_HASH,
            BlockType::Proposal, serde_json::json!({"tx": "original"}), Some(1000),
        );
        store.add_block(&b1).unwrap();

        // Double-sign fraud.
        let b1_fraud = create_half_block(
            &id, 1, &"b".repeat(64), 0, GENESIS_HASH,
            BlockType::Proposal, serde_json::json!({"tx": "fraud"}), Some(1000),
        );
        let result = validate_and_record(&b1_fraud, &mut store);
        assert!(matches!(result, ValidationResult::Invalid(_)));

        // Fraud should be recorded.
        let frauds = store.get_double_spends(&id.pubkey_hex()).unwrap();
        assert_eq!(frauds.len(), 1);
        assert_eq!(frauds[0].block_a.block_hash, b1.block_hash);
        assert_eq!(frauds[0].block_b.block_hash, b1_fraud.block_hash);
    }

    #[test]
    fn test_serde_roundtrip() {
        let id = test_identity();
        let block = create_half_block(
            &id,
            1,
            &"b".repeat(64),
            0,
            GENESIS_HASH,
            BlockType::Proposal,
            serde_json::json!({"nested": {"key": "val"}}),
            Some(1000),
        );

        let json = serde_json::to_string(&block).unwrap();
        let parsed: HalfBlock = serde_json::from_str(&json).unwrap();
        assert_eq!(block, parsed);
        assert!(verify_block(&parsed).unwrap());
    }

    /// Verify that a block with a u64 timestamp survives multiple
    /// JSON round-trips with its hash intact. u64 integers have no
    /// precision issues in JSON (unlike f64).
    #[test]
    fn test_block_hash_stable_across_multiple_roundtrips() {
        let id = test_identity();
        let mut block = create_half_block(
            &id,
            1,
            &"b".repeat(64),
            0,
            GENESIS_HASH,
            BlockType::Proposal,
            serde_json::json!({"proxy": true, "method": "GET", "path": "/task"}),
            None, // real timestamp
        );

        // Round-trip 10 times — hash must remain stable.
        for i in 0..10 {
            let json = serde_json::to_string(&block).unwrap();
            let parsed: HalfBlock = serde_json::from_str(&json).unwrap();
            assert_eq!(
                block.block_hash, parsed.compute_hash(),
                "hash changed on round-trip {i}"
            );
            assert!(verify_block(&parsed).unwrap(), "verification failed on round-trip {i}");
            block = parsed;
        }
    }
}
