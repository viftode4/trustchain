//! TrustChain Core — protocol engine, storage, and trust computation.
//!
//! This crate implements the core TrustChain protocol:
//! - **Identity**: Ed25519 keypair management
//! - **HalfBlock**: The fundamental data structure — bilateral signed records
//! - **BlockStore**: Pluggable storage (memory, SQLite)
//! - **Protocol**: Two-phase proposal/agreement state machine
//! - **NetFlow**: Max-flow Sybil-resistant trust computation
//! - **Trust**: Unified trust engine (integrity + netflow)
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
#[cfg(feature = "meritrank")]
pub mod meritrank;
pub mod netflow;
pub mod protocol;
pub mod trust;
pub mod types;

// Re-export key types at crate root for convenience.
#[cfg(feature = "sqlite")]
pub use blockstore::SqliteBlockStore;
pub use blockstore::{BlockStore, DoubleSpend, MemoryBlockStore, PersistentPeer};
pub use chain::PersonalChain;
pub use consensus::{CHECOConsensus, Checkpoint};
pub use crawler::{BlockStoreCrawler, CrossChainLink, DAGView, TamperingReport};
#[cfg(feature = "sqlite")]
pub use delegation::SqliteDelegationStore;
pub use delegation::{DelegationRecord, DelegationStore, MemoryDelegationStore, SuccessionRecord};
pub use error::{Result, TrustChainError};
pub use halfblock::{
    create_half_block, validate_and_record, validate_block, validate_block_invariants,
    verify_block, HalfBlock,
};
pub use identity::Identity;
#[cfg(feature = "meritrank")]
pub use meritrank::MeritRankTrust;
pub use netflow::{CachedNetFlow, NetFlowTrust};
pub use protocol::TrustChainProtocol;
pub use trust::{
    DelegationContext, TrustAlgorithm, TrustConfig, TrustEngine, TrustEvidence, TrustWeights,
    DEFAULT_CONNECTIVITY_THRESHOLD, DEFAULT_DIVERSITY_THRESHOLD, DEFAULT_RECENCY_LAMBDA,
};
pub use types::{
    BlockType, ValidationResult, GENESIS_HASH, GENESIS_SEQ, MAX_DELEGATION_TTL_MS, UNKNOWN_SEQ,
};
