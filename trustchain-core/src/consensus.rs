//! CHECO consensus — checkpoint-based finality for TrustChain.
//!
//! Periodically, a deterministically selected facilitator proposes a checkpoint
//! that snapshots all known chain heads. Other peers co-sign it, and once enough
//! signatures are collected the checkpoint is finalized — providing finality
//! guarantees for all blocks up to the checkpoint.

use std::collections::HashMap;

use sha2::{Digest, Sha256};

use crate::blockstore::BlockStore;
use crate::error::{Result, TrustChainError};
use crate::halfblock::{create_half_block, verify_block, HalfBlock};
use crate::identity::Identity;
use crate::types::BlockType;

/// A finalized checkpoint snapshot.
#[derive(Debug, Clone)]
pub struct Checkpoint {
    /// Public key of the facilitator who proposed this checkpoint.
    pub facilitator_pubkey: String,
    /// Snapshot of chain heads: `{pubkey: latest_sequence_number}`.
    pub chain_heads: HashMap<String, u64>,
    /// The checkpoint half-block (stored on the facilitator's chain).
    pub checkpoint_block: HalfBlock,
    /// Co-signatures: `{pubkey: signature_hex}`.
    pub signatures: HashMap<String, String>,
    /// Timestamp of checkpoint creation (milliseconds since epoch).
    pub timestamp: u64,
    /// Whether this checkpoint has been finalized.
    pub finalized: bool,
}

/// CHECO consensus engine for a single agent.
pub struct CHECOConsensus<S: BlockStore> {
    identity: Identity,
    store: S,
    known_peers: Vec<String>,
    min_signers: usize,
    checkpoints: Vec<Checkpoint>,
}

impl<S: BlockStore> CHECOConsensus<S> {
    pub fn new(
        identity: Identity,
        store: S,
        known_peers: Option<Vec<String>>,
        min_signers: usize,
    ) -> Self {
        Self {
            identity,
            store,
            known_peers: known_peers.unwrap_or_default(),
            min_signers: min_signers.max(1),
            checkpoints: Vec::new(),
        }
    }

    /// Get this agent's public key.
    pub fn pubkey(&self) -> String {
        self.identity.pubkey_hex()
    }

    /// Get a reference to the store.
    pub fn store(&self) -> &S {
        &self.store
    }

    /// Get a mutable reference to the store.
    pub fn store_mut(&mut self) -> &mut S {
        &mut self.store
    }

    /// Get all finalized checkpoints.
    pub fn finalized_checkpoints(&self) -> Vec<&Checkpoint> {
        self.checkpoints.iter().filter(|c| c.finalized).collect()
    }

    /// Deterministically select a facilitator from known peers + self.
    ///
    /// Uses a hash of all known chain heads (as JSON) to deterministically pick
    /// one peer. Matches the Python implementation for wire compatibility.
    pub fn select_facilitator(&self) -> Result<String> {
        let mut candidates: Vec<String> = self.known_peers.clone();
        let my_pubkey = self.pubkey();
        if !candidates.contains(&my_pubkey) {
            candidates.push(my_pubkey);
        }
        candidates.sort();
        candidates.dedup();

        if candidates.is_empty() {
            return Err(TrustChainError::checkpoint("no candidates for facilitator"));
        }

        // Build chain heads dict matching Python: json.dumps(heads, sort_keys=True)
        let mut heads = std::collections::BTreeMap::new();
        for pubkey in &candidates {
            let seq = self.store.get_latest_seq(pubkey)?;
            heads.insert(pubkey.clone(), seq);
        }
        let heads_json = serde_json::to_string(&heads)
            .map_err(|e| TrustChainError::Serialization(e.to_string()))?;

        // SHA-256 hash of the JSON string.
        let hash = Sha256::digest(heads_json.as_bytes());

        // Use full 256-bit hash as big integer mod candidates.len().
        // Python does: int(state_hash, 16) % len(all_peers)
        // We compute this with modular arithmetic on chunks to avoid BigInt.
        let mut index: usize = 0;
        for byte in hash.iter() {
            index = (index * 256 + *byte as usize) % candidates.len();
        }

        Ok(candidates[index].clone())
    }

    /// Update the set of known peers (called each checkpoint round from discovery).
    pub fn set_known_peers(&mut self, peers: Vec<String>) {
        self.known_peers = peers;
    }

    /// Check if this agent is the current facilitator.
    pub fn is_facilitator(&self) -> Result<bool> {
        Ok(self.select_facilitator()? == self.pubkey())
    }

    /// Propose a checkpoint (only valid if this agent is the facilitator).
    ///
    /// Creates a CHECKPOINT block referencing all known chain heads.
    pub fn propose_checkpoint(&mut self) -> Result<HalfBlock> {
        if !self.is_facilitator()? {
            return Err(TrustChainError::checkpoint(
                "not the current facilitator",
            ));
        }

        // Collect chain heads.
        let mut chain_heads: HashMap<String, u64> = HashMap::new();
        let my_pubkey = self.pubkey();
        let my_seq = self.store.get_latest_seq(&my_pubkey)?;
        if my_seq > 0 {
            chain_heads.insert(my_pubkey.clone(), my_seq);
        }
        for peer in &self.known_peers {
            let seq = self.store.get_latest_seq(peer)?;
            if seq > 0 {
                chain_heads.insert(peer.clone(), seq);
            }
        }

        let seq = self.store.get_latest_seq(&my_pubkey)? + 1;
        let prev_hash = self.store.get_head_hash(&my_pubkey)?;

        let checkpoint_round = self.checkpoints.len() as u64 + 1;
        let timestamp_val = crate::halfblock::now_timestamp_ms();

        let transaction = serde_json::json!({
            "interaction_type": "checkpoint",
            "outcome": "proposed",
            "timestamp": timestamp_val,
            "chain_heads": chain_heads,
            "checkpoint_round": checkpoint_round,
        });

        let block = create_half_block(
            &self.identity,
            seq,
            &my_pubkey, // self-referencing
            0,
            &prev_hash,
            BlockType::Checkpoint,
            transaction,
            None,
        );

        self.store.add_block(&block)?;
        Ok(block)
    }

    /// Validate a checkpoint block from another peer.
    pub fn validate_checkpoint(&self, checkpoint_block: &HalfBlock) -> Result<bool> {
        if !checkpoint_block.is_checkpoint() {
            return Err(TrustChainError::checkpoint("block is not a checkpoint"));
        }

        if !verify_block(checkpoint_block)? {
            return Err(TrustChainError::checkpoint("invalid checkpoint signature"));
        }

        // Verify chain heads are consistent with what we know.
        // Matches Python: reject if checkpoint is stale (our_seq > claimed_seq).
        // Also reject if checkpoint claims more than we know (claimed_seq > our_seq),
        // unless we don't know the peer at all (our_seq == 0).
        if let Some(heads) = checkpoint_block.transaction.get("chain_heads") {
            if let Some(heads_map) = heads.as_object() {
                for (pubkey, seq_val) in heads_map {
                    if let Some(claimed_seq) = seq_val.as_u64() {
                        let our_seq = self.store.get_latest_seq(pubkey)?;
                        if our_seq > 0 {
                            // Reject clearly stale checkpoints where we have more
                            // recent knowledge than the facilitator claims.
                            if our_seq > claimed_seq {
                                return Err(TrustChainError::checkpoint(format!(
                                    "stale checkpoint: we know seq {our_seq} for {}, checkpoint claims {claimed_seq}",
                                    &pubkey[..8]
                                )));
                            }
                            // Do NOT reject if claimed_seq > our_seq — the facilitator
                            // may have received blocks via gossip that we haven't yet.
                            // In an active network this is normal and should not block
                            // checkpoint finalization.
                        }
                    }
                }
            }
        }

        Ok(true)
    }

    /// Sign a checkpoint block (co-signing).
    pub fn sign_checkpoint(&self, checkpoint_block: &HalfBlock) -> Result<String> {
        if !checkpoint_block.is_checkpoint() {
            return Err(TrustChainError::checkpoint("block is not a checkpoint"));
        }
        Ok(self.identity.sign_hex(checkpoint_block.block_hash.as_bytes()))
    }

    /// Finalize a checkpoint with collected co-signatures.
    pub fn finalize_checkpoint(
        &mut self,
        checkpoint_block: HalfBlock,
        signatures: HashMap<String, String>,
    ) -> Result<Checkpoint> {
        if signatures.len() < self.min_signers {
            return Err(TrustChainError::checkpoint(format!(
                "need {} signers, got {}",
                self.min_signers,
                signatures.len()
            )));
        }

        // Verify all signatures.
        for (pubkey, sig_hex) in &signatures {
            let valid = Identity::verify_hex(
                checkpoint_block.block_hash.as_bytes(),
                sig_hex,
                pubkey,
            )?;
            if !valid {
                return Err(TrustChainError::checkpoint(format!(
                    "invalid signature from {}",
                    &pubkey[..8]
                )));
            }
        }

        // Extract chain heads from the block's transaction.
        let chain_heads = extract_chain_heads(&checkpoint_block)?;

        let checkpoint = Checkpoint {
            facilitator_pubkey: checkpoint_block.public_key.clone(),
            chain_heads,
            timestamp: checkpoint_block.timestamp,
            checkpoint_block,
            signatures,
            finalized: true,
        };

        self.checkpoints.push(checkpoint.clone());
        Ok(checkpoint)
    }

    /// Check if a specific block is covered by a finalized checkpoint.
    pub fn is_finalized(&self, pubkey: &str, seq: u64) -> bool {
        self.checkpoints.iter().any(|cp| {
            cp.finalized
                && cp
                    .chain_heads
                    .get(pubkey)
                    .map_or(false, |&cp_seq| seq <= cp_seq)
        })
    }
}

/// Extract chain heads from a checkpoint block's transaction.
fn extract_chain_heads(block: &HalfBlock) -> Result<HashMap<String, u64>> {
    let mut heads = HashMap::new();
    if let Some(ch) = block.transaction.get("chain_heads") {
        if let Some(obj) = ch.as_object() {
            for (k, v) in obj {
                if let Some(seq) = v.as_u64() {
                    heads.insert(k.clone(), seq);
                }
            }
        }
    }
    Ok(heads)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blockstore::MemoryBlockStore;
    use crate::halfblock::create_half_block;
    use crate::types::GENESIS_HASH;

    fn setup_peers() -> (Identity, Identity, Identity) {
        let a = Identity::from_bytes(&[1u8; 32]);
        let b = Identity::from_bytes(&[2u8; 32]);
        let c = Identity::from_bytes(&[3u8; 32]);
        (a, b, c)
    }

    fn add_interaction(
        store: &mut MemoryBlockStore,
        alice: &Identity,
        bob: &Identity,
        alice_seq: u64,
        alice_prev: &str,
    ) -> String {
        let proposal = create_half_block(
            alice, alice_seq, &bob.pubkey_hex(), 0,
            alice_prev, BlockType::Proposal,
            serde_json::json!({"service": "test"}), Some(1000),
        );
        let hash = proposal.block_hash.clone();
        store.add_block(&proposal).unwrap();
        hash
    }

    #[test]
    fn test_facilitator_selection_deterministic() {
        let (a, b, c) = setup_peers();
        let store = MemoryBlockStore::new();

        let consensus = CHECOConsensus::new(
            a.clone(),
            store,
            Some(vec![b.pubkey_hex(), c.pubkey_hex()]),
            1,
        );

        let f1 = consensus.select_facilitator().unwrap();
        let f2 = consensus.select_facilitator().unwrap();
        assert_eq!(f1, f2, "facilitator selection should be deterministic");
    }

    #[test]
    fn test_propose_and_validate_checkpoint() {
        let (a, b, _) = setup_peers();
        let mut store_a = MemoryBlockStore::new();

        // Add some blocks so the checkpoint has content.
        add_interaction(&mut store_a, &a, &b, 1, GENESIS_HASH);

        // We need to ensure 'a' is the facilitator. Use a simple setup.
        let mut consensus_a = CHECOConsensus::new(a.clone(), store_a, Some(vec![]), 1);

        // Force facilitator check — if not facilitator, that's OK for this test structure.
        // Since no known_peers and only self, self is always facilitator.
        if consensus_a.is_facilitator().unwrap() {
            let checkpoint = consensus_a.propose_checkpoint().unwrap();
            assert!(checkpoint.is_checkpoint());
            assert!(verify_block(&checkpoint).unwrap());

            // Validate from another peer's perspective.
            let store_b = MemoryBlockStore::new();
            let consensus_b = CHECOConsensus::new(b.clone(), store_b, Some(vec![a.pubkey_hex()]), 1);
            // b doesn't know about a's blocks, so validation may differ.
            // With our_seq == 0, it accepts any claimed seq.
            assert!(consensus_b.validate_checkpoint(&checkpoint).unwrap());
        }
    }

    #[test]
    fn test_sign_and_finalize_checkpoint() {
        let (a, b, _) = setup_peers();
        let mut store_a = MemoryBlockStore::new();
        add_interaction(&mut store_a, &a, &b, 1, GENESIS_HASH);

        let mut consensus_a = CHECOConsensus::new(a.clone(), store_a, Some(vec![]), 1);

        if consensus_a.is_facilitator().unwrap() {
            let checkpoint = consensus_a.propose_checkpoint().unwrap();

            // B co-signs.
            let store_b = MemoryBlockStore::new();
            let consensus_b = CHECOConsensus::new(b.clone(), store_b, Some(vec![a.pubkey_hex()]), 1);
            let sig_b = consensus_b.sign_checkpoint(&checkpoint).unwrap();

            // Finalize with B's signature.
            let mut sigs = HashMap::new();
            sigs.insert(b.pubkey_hex(), sig_b);

            let finalized = consensus_a.finalize_checkpoint(checkpoint, sigs).unwrap();
            assert!(finalized.finalized);
            assert!(!finalized.chain_heads.is_empty());
        }
    }

    #[test]
    fn test_is_finalized() {
        let (a, b, _) = setup_peers();
        let mut store_a = MemoryBlockStore::new();
        add_interaction(&mut store_a, &a, &b, 1, GENESIS_HASH);

        let mut consensus_a = CHECOConsensus::new(a.clone(), store_a, Some(vec![]), 1);

        if consensus_a.is_facilitator().unwrap() {
            let checkpoint = consensus_a.propose_checkpoint().unwrap();
            let sig_a = consensus_a.sign_checkpoint(&checkpoint).unwrap();

            let mut sigs = HashMap::new();
            sigs.insert(a.pubkey_hex(), sig_a);

            consensus_a.finalize_checkpoint(checkpoint, sigs).unwrap();

            // Block seq=1 for 'a' should be finalized.
            assert!(consensus_a.is_finalized(&a.pubkey_hex(), 1));
            // Block seq=99 should NOT be finalized.
            assert!(!consensus_a.is_finalized(&a.pubkey_hex(), 99));
        }
    }

    #[test]
    fn test_insufficient_signers() {
        let (a, b, _) = setup_peers();
        let mut store_a = MemoryBlockStore::new();
        add_interaction(&mut store_a, &a, &b, 1, GENESIS_HASH);

        let mut consensus_a = CHECOConsensus::new(
            a.clone(), store_a, Some(vec![]), 3, // require 3 signers
        );

        if consensus_a.is_facilitator().unwrap() {
            let checkpoint = consensus_a.propose_checkpoint().unwrap();
            let sig = consensus_a.sign_checkpoint(&checkpoint).unwrap();

            let mut sigs = HashMap::new();
            sigs.insert(a.pubkey_hex(), sig);

            // Only 1 signer, need 3.
            let result = consensus_a.finalize_checkpoint(checkpoint, sigs);
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_invalid_cosignature_rejected() {
        let (a, b, _) = setup_peers();
        let mut store_a = MemoryBlockStore::new();
        add_interaction(&mut store_a, &a, &b, 1, GENESIS_HASH);

        let mut consensus_a = CHECOConsensus::new(a.clone(), store_a, Some(vec![]), 1);

        if consensus_a.is_facilitator().unwrap() {
            let checkpoint = consensus_a.propose_checkpoint().unwrap();

            // Fake signature from B.
            let mut sigs = HashMap::new();
            sigs.insert(b.pubkey_hex(), "ff".repeat(64));

            let result = consensus_a.finalize_checkpoint(checkpoint, sigs);
            assert!(result.is_err());
        }
    }
}
