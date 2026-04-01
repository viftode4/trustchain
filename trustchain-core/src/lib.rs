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

pub mod behavioral;
pub mod blockstore;
pub mod chain;
pub mod collusion;
pub mod consensus;
pub mod correlation;
pub mod crawler;
pub mod delegation;
pub mod error;
pub mod forgiveness;
pub mod halfblock;
pub mod identity;
#[cfg(feature = "meritrank")]
pub mod meritrank;
pub mod netflow;
pub mod protocol;
pub mod sanctions;
pub mod schema;
pub mod sealed_rating;
pub mod thresholds;
pub mod tiers;
pub mod trust;
pub mod types;

// Re-export key types at crate root for convenience.
pub use behavioral::{
    detect_behavioral_change, detect_selective_targeting, failure_rate, BehavioralAnalysis,
    BehavioralConfig, SelectiveTargetingResult,
};
#[cfg(feature = "sqlite")]
pub use blockstore::SqliteBlockStore;
pub use blockstore::{BlockStore, DoubleSpend, MemoryBlockStore, PersistentPeer};
pub use chain::PersonalChain;
pub use collusion::{
    detect_collusion, has_reciprocity_anomaly, peer_concentration, CollusionConfig,
    CollusionSignals,
};
pub use consensus::{CHECOConsensus, Checkpoint};
pub use correlation::{
    compute_delegator_correlation_penalty, delegation_tree_penalty, delegator_penalty,
    CorrelationConfig,
};
pub use crawler::{BlockStoreCrawler, CrossChainLink, DAGView, TamperingReport};
#[cfg(feature = "sqlite")]
pub use delegation::SqliteDelegationStore;
pub use delegation::{DelegationRecord, DelegationStore, MemoryDelegationStore, SuccessionRecord};
pub use error::{Result, TrustChainError};
pub use forgiveness::{
    apply_forgiveness, asymmetric_decay_weight, recovery_ceiling, ForgivenessConfig,
    RecoverySeverity,
};
pub use halfblock::{
    create_half_block, validate_and_record, validate_block, validate_block_invariants,
    verify_block, HalfBlock,
};
pub use identity::Identity;
#[cfg(feature = "meritrank")]
pub use meritrank::MeritRankTrust;
pub use netflow::{CachedNetFlow, NetFlowTrust};
pub use protocol::TrustChainProtocol;
pub use sanctions::{SanctionConfig, SanctionResult, Violation, ViolationSeverity};
pub use schema::{validate_transaction, SchemaId};
pub use sealed_rating::{
    create_commitment, effective_sealed_rating, extract_sealed_rating, is_reveal_timed_out,
    verify_reveal, RatingCommitment, RatingReveal, SealedRatingConfig,
};
pub use thresholds::{min_trust_threshold, required_deposit, risk_threshold};
pub use tiers::TrustTier;
pub use trust::{
    AuditReport, DelegationContext, TrustAlgorithm, TrustConfig, TrustEngine, TrustEvidence,
    TrustWeights, DEFAULT_CONNECTIVITY_THRESHOLD, DEFAULT_DIVERSITY_THRESHOLD,
    DEFAULT_RECENCY_LAMBDA,
};
pub use types::{
    AuditConfig, AuditLevel, BlockType, EventType, ValidationResult, GENESIS_HASH, GENESIS_SEQ,
    MAX_ACTIVE_DELEGATIONS, MAX_DELEGATION_TTL_MS, UNKNOWN_SEQ,
};
