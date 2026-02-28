//! DAG traversal and tampering detection for the TrustChain network.
//!
//! The crawler builds a DAG view of the entire blockchain by loading all
//! personal chains and identifying cross-chain links (proposal/agreement pairs).

use std::collections::HashMap;

use crate::blockstore::BlockStore;
use crate::chain::PersonalChain;
use crate::error::Result;
use crate::halfblock::verify_block;
use crate::types::GENESIS_HASH;

/// A cross-chain link between two agents (a proposal and its matching agreement).
#[derive(Debug, Clone)]
pub struct CrossChainLink {
    /// Public key of the first agent (proposer).
    pub pubkey_a: String,
    /// Sequence number in agent A's chain.
    pub seq_a: u64,
    /// Public key of the second agent (responder).
    pub pubkey_b: String,
    /// Sequence number in agent B's chain.
    pub seq_b: u64,
    /// Block hash of the proposal.
    pub block_hash: String,
    /// Whether both sides of the link exist and verify.
    pub verified: bool,
}

/// A view of the entire TrustChain DAG.
#[derive(Debug, Clone)]
pub struct DAGView {
    /// Personal chains for all known agents.
    pub chains: HashMap<String, PersonalChain>,
    /// Cross-chain links (proposal/agreement pairs).
    pub cross_links: Vec<CrossChainLink>,
    /// Proposals with no matching agreement.
    pub orphan_proposals: Vec<String>,
}

impl DAGView {
    /// Ratio of verified cross-links to total cross-links.
    /// Returns 1.0 if there are no cross-links.
    pub fn entanglement_ratio(&self) -> f64 {
        if self.cross_links.is_empty() {
            return 1.0;
        }
        let verified = self.cross_links.iter().filter(|l| l.verified).count();
        verified as f64 / self.cross_links.len() as f64
    }

    /// Total number of blocks across all chains.
    pub fn total_blocks(&self) -> usize {
        self.chains.values().map(|c| c.length()).sum()
    }
}

/// Tampering detection report.
#[derive(Debug, Clone, Default)]
pub struct TamperingReport {
    /// Chains with sequence number gaps.
    pub chain_gaps: Vec<String>,
    /// Chains with broken hash links.
    pub hash_breaks: Vec<String>,
    /// Blocks with invalid signatures.
    pub signature_failures: Vec<String>,
    /// Cross-links where both sides don't verify.
    pub entanglement_issues: Vec<String>,
    /// Proposals without matching agreements.
    pub orphan_proposals: Vec<String>,
}

impl TamperingReport {
    /// Check if the report is clean (no issues found).
    pub fn is_clean(&self) -> bool {
        self.chain_gaps.is_empty()
            && self.hash_breaks.is_empty()
            && self.signature_failures.is_empty()
            && self.entanglement_issues.is_empty()
            && self.orphan_proposals.is_empty()
    }

    /// Total number of issues found.
    pub fn issue_count(&self) -> usize {
        self.chain_gaps.len()
            + self.hash_breaks.len()
            + self.signature_failures.len()
            + self.entanglement_issues.len()
            + self.orphan_proposals.len()
    }
}

/// Crawler for building DAG views and detecting tampering.
pub struct BlockStoreCrawler<'a, S: BlockStore> {
    store: &'a S,
}

impl<'a, S: BlockStore> BlockStoreCrawler<'a, S> {
    pub fn new(store: &'a S) -> Self {
        Self { store }
    }

    /// Build a complete DAG view of the blockchain.
    pub fn build_dag(&self) -> Result<DAGView> {
        let pubkeys = self.store.get_all_pubkeys()?;

        // Build personal chains.
        let mut chains: HashMap<String, PersonalChain> = HashMap::new();
        for pubkey in &pubkeys {
            let chain = PersonalChain::from_store(pubkey, self.store)?;
            chains.insert(pubkey.clone(), chain);
        }

        // Find cross-chain links and orphan proposals.
        let mut cross_links = Vec::new();
        let mut orphan_proposals = Vec::new();

        for pubkey in &pubkeys {
            let chain_blocks = self.store.get_chain(pubkey)?;
            for block in &chain_blocks {
                if !block.is_proposal() {
                    continue;
                }

                // Look for matching agreement.
                match self.store.get_linked_block(block)? {
                    Some(agreement) => {
                        // Verify both sides.
                        let proposal_ok = verify_block(block).unwrap_or(false);
                        let agreement_ok = verify_block(&agreement).unwrap_or(false);

                        cross_links.push(CrossChainLink {
                            pubkey_a: block.public_key.clone(),
                            seq_a: block.sequence_number,
                            pubkey_b: agreement.public_key.clone(),
                            seq_b: agreement.sequence_number,
                            block_hash: block.block_hash.clone(),
                            verified: proposal_ok && agreement_ok,
                        });
                    }
                    None => {
                        orphan_proposals.push(format!(
                            "{}:{}",
                            &block.public_key[..8],
                            block.sequence_number
                        ));
                    }
                }
            }
        }

        Ok(DAGView {
            chains,
            cross_links,
            orphan_proposals,
        })
    }

    /// Detect tampering across the entire blockchain.
    pub fn detect_tampering(&self) -> Result<TamperingReport> {
        let mut report = TamperingReport::default();
        let pubkeys = self.store.get_all_pubkeys()?;

        for pubkey in &pubkeys {
            let chain = self.store.get_chain(pubkey)?;
            let short = &pubkey[..8];

            let mut expected_seq = 1u64;
            let mut expected_prev = GENESIS_HASH.to_string();

            for block in &chain {
                // Sequence gap check.
                if block.sequence_number != expected_seq {
                    report.chain_gaps.push(format!(
                        "{short}: expected seq {expected_seq}, got {}",
                        block.sequence_number
                    ));
                }

                // Hash link check.
                if block.previous_hash != expected_prev {
                    report.hash_breaks.push(format!(
                        "{short}: hash break at seq {}",
                        block.sequence_number
                    ));
                }

                // Signature check.
                if !verify_block(block).unwrap_or(false) {
                    report.signature_failures.push(format!(
                        "{short}: invalid signature at seq {}",
                        block.sequence_number
                    ));
                }

                expected_prev = block.block_hash.clone();
                expected_seq = block.sequence_number + 1;
            }

            // Check cross-links for proposals.
            for block in &chain {
                if !block.is_proposal() {
                    continue;
                }
                match self.store.get_linked_block(block)? {
                    Some(agreement) => {
                        if !verify_block(&agreement).unwrap_or(false) {
                            report.entanglement_issues.push(format!(
                                "{short}:{} ↔ {} - agreement signature invalid",
                                block.sequence_number,
                                &agreement.public_key[..8],
                            ));
                        }
                    }
                    None => {
                        report.orphan_proposals.push(format!(
                            "{short}:{}",
                            block.sequence_number
                        ));
                    }
                }
            }
        }

        Ok(report)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blockstore::MemoryBlockStore;
    use crate::halfblock::create_half_block;
    use crate::identity::Identity;
    use crate::types::BlockType;

    fn create_full_interaction(
        store: &mut MemoryBlockStore,
        alice: &Identity,
        bob: &Identity,
        alice_seq: u64,
        bob_seq: u64,
        alice_prev: &str,
        bob_prev: &str,
    ) -> (String, String) {
        let proposal = create_half_block(
            alice, alice_seq, &bob.pubkey_hex(), 0,
            alice_prev, BlockType::Proposal,
            serde_json::json!({"service": "test"}), Some(1000),
        );
        store.add_block(&proposal).unwrap();

        let agreement = create_half_block(
            bob, bob_seq, &alice.pubkey_hex(), alice_seq,
            bob_prev, BlockType::Agreement,
            serde_json::json!({"service": "test"}), Some(1001),
        );
        store.add_block(&agreement).unwrap();

        (proposal.block_hash, agreement.block_hash)
    }

    #[test]
    fn test_build_dag_empty() {
        let store = MemoryBlockStore::new();
        let crawler = BlockStoreCrawler::new(&store);
        let dag = crawler.build_dag().unwrap();

        assert!(dag.chains.is_empty());
        assert!(dag.cross_links.is_empty());
        assert!(dag.orphan_proposals.is_empty());
        assert_eq!(dag.entanglement_ratio(), 1.0);
        assert_eq!(dag.total_blocks(), 0);
    }

    #[test]
    fn test_build_dag_with_interaction() {
        let mut store = MemoryBlockStore::new();
        let alice = Identity::from_bytes(&[1u8; 32]);
        let bob = Identity::from_bytes(&[2u8; 32]);

        create_full_interaction(&mut store, &alice, &bob, 1, 1, GENESIS_HASH, GENESIS_HASH);

        let crawler = BlockStoreCrawler::new(&store);
        let dag = crawler.build_dag().unwrap();

        assert_eq!(dag.chains.len(), 2);
        assert_eq!(dag.cross_links.len(), 1);
        assert!(dag.cross_links[0].verified);
        assert_eq!(dag.entanglement_ratio(), 1.0);
        assert_eq!(dag.total_blocks(), 2);
        assert!(dag.orphan_proposals.is_empty());
    }

    #[test]
    fn test_orphan_proposal() {
        let mut store = MemoryBlockStore::new();
        let alice = Identity::from_bytes(&[1u8; 32]);
        let bob = Identity::from_bytes(&[2u8; 32]);

        // Only add the proposal, no agreement.
        let proposal = create_half_block(
            &alice, 1, &bob.pubkey_hex(), 0, GENESIS_HASH,
            BlockType::Proposal, serde_json::json!({}), Some(1000),
        );
        store.add_block(&proposal).unwrap();

        let crawler = BlockStoreCrawler::new(&store);
        let dag = crawler.build_dag().unwrap();

        assert_eq!(dag.orphan_proposals.len(), 1);
        assert!(dag.cross_links.is_empty());
    }

    #[test]
    fn test_detect_tampering_clean() {
        let mut store = MemoryBlockStore::new();
        let alice = Identity::from_bytes(&[1u8; 32]);
        let bob = Identity::from_bytes(&[2u8; 32]);

        create_full_interaction(&mut store, &alice, &bob, 1, 1, GENESIS_HASH, GENESIS_HASH);

        let crawler = BlockStoreCrawler::new(&store);
        let report = crawler.detect_tampering().unwrap();

        assert!(report.is_clean());
        assert_eq!(report.issue_count(), 0);
    }

    #[test]
    fn test_detect_tampering_orphan() {
        let mut store = MemoryBlockStore::new();
        let alice = Identity::from_bytes(&[1u8; 32]);
        let bob = Identity::from_bytes(&[2u8; 32]);

        let proposal = create_half_block(
            &alice, 1, &bob.pubkey_hex(), 0, GENESIS_HASH,
            BlockType::Proposal, serde_json::json!({}), Some(1000),
        );
        store.add_block(&proposal).unwrap();

        let crawler = BlockStoreCrawler::new(&store);
        let report = crawler.detect_tampering().unwrap();

        assert!(!report.is_clean());
        assert_eq!(report.orphan_proposals.len(), 1);
    }

    #[test]
    fn test_multiple_interactions_dag() {
        let mut store = MemoryBlockStore::new();
        let alice = Identity::from_bytes(&[1u8; 32]);
        let bob = Identity::from_bytes(&[2u8; 32]);
        let charlie = Identity::from_bytes(&[3u8; 32]);

        let (a_hash, _b_hash) = create_full_interaction(
            &mut store, &alice, &bob, 1, 1, GENESIS_HASH, GENESIS_HASH,
        );
        create_full_interaction(
            &mut store, &alice, &charlie, 2, 1, &a_hash, GENESIS_HASH,
        );

        let crawler = BlockStoreCrawler::new(&store);
        let dag = crawler.build_dag().unwrap();

        assert_eq!(dag.chains.len(), 3);
        assert_eq!(dag.cross_links.len(), 2);
        assert_eq!(dag.total_blocks(), 4); // 2 proposals + 2 agreements
        assert!(dag.orphan_proposals.is_empty());
    }

    #[test]
    fn test_entanglement_ratio() {
        let mut store = MemoryBlockStore::new();
        let alice = Identity::from_bytes(&[1u8; 32]);
        let bob = Identity::from_bytes(&[2u8; 32]);
        let charlie = Identity::from_bytes(&[3u8; 32]);

        // One complete interaction.
        let (a_hash, _) = create_full_interaction(
            &mut store, &alice, &bob, 1, 1, GENESIS_HASH, GENESIS_HASH,
        );

        // One orphan proposal.
        let proposal = create_half_block(
            &alice, 2, &charlie.pubkey_hex(), 0, &a_hash,
            BlockType::Proposal, serde_json::json!({}), Some(1002),
        );
        store.add_block(&proposal).unwrap();

        let crawler = BlockStoreCrawler::new(&store);
        let dag = crawler.build_dag().unwrap();

        assert_eq!(dag.cross_links.len(), 1);
        assert_eq!(dag.orphan_proposals.len(), 1);
        assert_eq!(dag.entanglement_ratio(), 1.0); // 1 verified out of 1
    }
}
