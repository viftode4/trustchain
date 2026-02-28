//! TrustChain Core — protocol engine, storage, and trust computation.
//!
//! This crate implements the core TrustChain protocol:
//! - **Identity**: Ed25519 keypair management
//! - **HalfBlock**: The fundamental data structure — bilateral signed records
//! - **BlockStore**: Pluggable storage (memory, SQLite)
//! - **Protocol**: Two-phase proposal/agreement state machine
//! - **NetFlow**: Max-flow Sybil-resistant trust computation
//! - **Trust**: Unified trust engine (integrity + netflow + statistical)
//! - **Consensus**: CHECO checkpoint finality
//! - **Chain**: Personal chain validation
//! - **Crawler**: DAG traversal and tampering detection

pub mod blockstore;
pub mod chain;
pub mod consensus;
pub mod crawler;
pub mod delegation;
pub mod error;
pub mod halfblock;
pub mod identity;
pub mod netflow;
pub mod protocol;
pub mod trust;
pub mod types;

// Re-export key types at crate root for convenience.
pub use blockstore::{BlockStore, DoubleSpend, MemoryBlockStore, PersistentPeer, SqliteBlockStore};
pub use chain::PersonalChain;
pub use consensus::{CHECOConsensus, Checkpoint};
pub use crawler::{BlockStoreCrawler, CrossChainLink, DAGView, TamperingReport};
pub use delegation::{
    DelegationRecord, DelegationStore, MemoryDelegationStore, SqliteDelegationStore, SuccessionRecord,
};
pub use error::{Result, TrustChainError};
pub use halfblock::{create_half_block, validate_and_record, validate_block, validate_block_invariants, verify_block, HalfBlock};
pub use identity::Identity;
pub use netflow::{CachedNetFlow, NetFlowTrust};
pub use protocol::TrustChainProtocol;
pub use trust::{DelegationContext, TrustEngine, TrustWeights};
pub use types::{BlockType, ValidationResult, GENESIS_HASH, GENESIS_SEQ, UNKNOWN_SEQ};
