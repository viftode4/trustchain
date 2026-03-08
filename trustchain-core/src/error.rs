//! Error types for the TrustChain protocol.
//!
//! Maps to Python's `exceptions.py` — provides a structured error hierarchy
//! for chain validation, protocol operations, and trust computation.

use thiserror::Error;

/// Top-level error type for all TrustChain operations.
#[derive(Debug, Error)]
pub enum TrustChainError {
    #[error("chain error for {pubkey}: {message}")]
    Chain {
        message: String,
        pubkey: String,
        seq: Option<u64>,
    },

    #[error("sequence gap for {pubkey}: expected {expected}, got {got}")]
    SequenceGap {
        pubkey: String,
        expected: u64,
        got: u64,
    },

    #[error("previous hash mismatch for {pubkey} at seq {seq}: expected {expected}, got {got}")]
    PrevHashMismatch {
        pubkey: String,
        seq: u64,
        expected: String,
        got: String,
    },

    #[error("signature verification failed for {pubkey} at seq {seq}: {detail}")]
    Signature {
        pubkey: String,
        seq: u64,
        detail: String,
    },

    #[error("duplicate block for {pubkey} at seq {seq}")]
    DuplicateSequence { pubkey: String, seq: u64 },

    #[error("proposal error for {pubkey} at seq {seq}: {detail}")]
    Proposal {
        pubkey: String,
        seq: u64,
        detail: String,
    },

    #[error("agreement error for {pubkey} at seq {seq}: {detail}")]
    Agreement {
        pubkey: String,
        seq: u64,
        detail: String,
    },

    #[error("orphan block for {pubkey} at seq {seq}")]
    OrphanBlock { pubkey: String, seq: u64 },

    #[error("checkpoint error: {detail}")]
    Checkpoint {
        detail: String,
        pubkey: Option<String>,
        seq: Option<u64>,
    },

    #[error("netflow error: {detail}")]
    NetFlow {
        detail: String,
        pubkey: Option<String>,
    },

    #[error("delegation error for {pubkey}: {detail}")]
    Delegation { pubkey: String, detail: String },

    #[error("succession error for {old_pubkey} -> {new_pubkey}: {detail}")]
    Succession {
        old_pubkey: String,
        new_pubkey: String,
        detail: String,
    },

    #[error("identity error: {0}")]
    Identity(String),

    #[error("storage error: {0}")]
    Storage(String),

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("validation error: {0}")]
    Validation(String),
}

impl TrustChainError {
    pub fn chain(message: impl Into<String>, pubkey: impl Into<String>) -> Self {
        Self::Chain {
            message: message.into(),
            pubkey: pubkey.into(),
            seq: None,
        }
    }

    pub fn sequence_gap(pubkey: impl Into<String>, expected: u64, got: u64) -> Self {
        Self::SequenceGap {
            pubkey: pubkey.into(),
            expected,
            got,
        }
    }

    pub fn prev_hash_mismatch(
        pubkey: impl Into<String>,
        seq: u64,
        expected: impl Into<String>,
        got: impl Into<String>,
    ) -> Self {
        Self::PrevHashMismatch {
            pubkey: pubkey.into(),
            seq,
            expected: expected.into(),
            got: got.into(),
        }
    }

    pub fn signature(pubkey: impl Into<String>, seq: u64, detail: impl Into<String>) -> Self {
        Self::Signature {
            pubkey: pubkey.into(),
            seq,
            detail: detail.into(),
        }
    }

    pub fn proposal(pubkey: impl Into<String>, seq: u64, detail: impl Into<String>) -> Self {
        Self::Proposal {
            pubkey: pubkey.into(),
            seq,
            detail: detail.into(),
        }
    }

    pub fn agreement(pubkey: impl Into<String>, seq: u64, detail: impl Into<String>) -> Self {
        Self::Agreement {
            pubkey: pubkey.into(),
            seq,
            detail: detail.into(),
        }
    }

    pub fn checkpoint(detail: impl Into<String>) -> Self {
        Self::Checkpoint {
            detail: detail.into(),
            pubkey: None,
            seq: None,
        }
    }

    pub fn netflow(detail: impl Into<String>) -> Self {
        Self::NetFlow {
            detail: detail.into(),
            pubkey: None,
        }
    }

    pub fn delegation(pubkey: impl Into<String>, detail: impl Into<String>) -> Self {
        Self::Delegation {
            pubkey: pubkey.into(),
            detail: detail.into(),
        }
    }

    pub fn validation(detail: impl Into<String>) -> Self {
        Self::Validation(detail.into())
    }

    pub fn succession(
        old_pubkey: impl Into<String>,
        new_pubkey: impl Into<String>,
        detail: impl Into<String>,
    ) -> Self {
        Self::Succession {
            old_pubkey: old_pubkey.into(),
            new_pubkey: new_pubkey.into(),
            detail: detail.into(),
        }
    }
}

#[cfg(feature = "sqlite")]
impl From<rusqlite::Error> for TrustChainError {
    fn from(e: rusqlite::Error) -> Self {
        Self::Storage(e.to_string())
    }
}

impl From<serde_json::Error> for TrustChainError {
    fn from(e: serde_json::Error) -> Self {
        Self::Serialization(e.to_string())
    }
}

impl From<ed25519_dalek::SignatureError> for TrustChainError {
    fn from(e: ed25519_dalek::SignatureError) -> Self {
        Self::Identity(e.to_string())
    }
}

impl From<hex::FromHexError> for TrustChainError {
    fn from(e: hex::FromHexError) -> Self {
        Self::Serialization(format!("hex decode error: {e}"))
    }
}

pub type Result<T> = std::result::Result<T, TrustChainError>;
