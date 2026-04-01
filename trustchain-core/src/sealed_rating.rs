//! Simultaneous-reveal rating protocol (commit-reveal).
//!
//! Prevents retaliatory rating by requiring both parties to commit their
//! ratings before either can see the other's. This eliminates the eBay
//! pathology where >99% of feedback is positive due to fear of retaliation.
//!
//! Protocol:
//! 1. **Commit**: Both parties include `hash(rating || nonce)` in the
//!    agreement block's transaction JSON.
//! 2. **Reveal**: Each party submits their rating + nonce in a subsequent block.
//! 3. **Verify**: `hash(rating || nonce) == commitment_hash`.
//! 4. **Timeout**: If either party doesn't reveal within the timeout window,
//!    their rating defaults to 0.5 (uncertain/neutral).
//!
//! The sealed rating data is embedded in the transaction JSON (the extensible
//! field), not in the HalfBlock struct, preserving backward compatibility.
//! Old blocks without commitment fields are treated as unsealed (traditional)
//! ratings.
//!
//! Research: Bolton, Greiner, Ockenfels 2013 — "Engineering Trust: Reciprocity
//! in the Production of Reputation Information", Management Science 59(2).

use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

// ─── Constants ──────────────────────────────────────────────────────────────

/// Default timeout for reveal phase (milliseconds). 1 hour.
pub const DEFAULT_REVEAL_TIMEOUT_MS: u64 = 3_600_000;

/// Default rating when reveal times out (uncertain/neutral).
pub const DEFAULT_TIMEOUT_RATING: f64 = 0.5;

/// Minimum valid nonce length in bytes (hex-encoded = 2× this).
pub const MIN_NONCE_LENGTH: usize = 16;

// ─── Types ──────────────────────────────────────────────────────────────────

/// Configuration for the sealed rating protocol.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealedRatingConfig {
    /// Timeout for reveal phase (ms). Default: 1 hour.
    pub reveal_timeout_ms: u64,
    /// Default rating if reveal times out. Default: 0.5.
    pub timeout_default_rating: f64,
}

impl Default for SealedRatingConfig {
    fn default() -> Self {
        Self {
            reveal_timeout_ms: DEFAULT_REVEAL_TIMEOUT_MS,
            timeout_default_rating: DEFAULT_TIMEOUT_RATING,
        }
    }
}

/// A rating commitment: SHA-256 of (formatted rating || nonce).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RatingCommitment {
    /// SHA-256 hash hex string of `f"{rating:.6f}{nonce_hex}"`.
    pub commitment_hash: String,
    /// Timestamp when commitment was created (ms since epoch).
    pub committed_at: u64,
}

/// A revealed rating with its nonce for verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RatingReveal {
    /// The actual rating value \[0.0, 1.0\].
    pub rating: f64,
    /// The nonce used in the commitment (hex-encoded).
    pub nonce: String,
}

// ─── Functions ──────────────────────────────────────────────────────────────

/// Compute the commitment hash for a rating and nonce.
///
/// Format: `SHA-256(f"{rating:.6f}{nonce_hex}")` as UTF-8 bytes → hex string.
///
/// This format is canonical across Rust and Python SDKs.
fn compute_commitment_hash(rating: f64, nonce_hex: &str) -> String {
    let input = format!("{rating:.6}{nonce_hex}");
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    hex::encode(hasher.finalize())
}

/// Create a commitment for a rating.
///
/// Generates a cryptographically random nonce and computes the commitment hash.
/// Returns `(commitment, nonce_hex)`. The caller must store the nonce secretly
/// until the reveal phase.
///
/// # Panics
///
/// Panics if the system random number generator is unavailable.
pub fn create_commitment(rating: f64, timestamp_ms: u64) -> (RatingCommitment, String) {
    let mut nonce_bytes = [0u8; MIN_NONCE_LENGTH];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce_hex = hex::encode(nonce_bytes);

    let commitment_hash = compute_commitment_hash(rating, &nonce_hex);

    let commitment = RatingCommitment {
        commitment_hash,
        committed_at: timestamp_ms,
    };

    (commitment, nonce_hex)
}

/// Verify that a reveal matches a commitment.
///
/// Recomputes `SHA-256(f"{rating:.6f}{nonce_hex}")` and compares to the
/// stored commitment hash. Returns `true` if they match.
pub fn verify_reveal(commitment: &RatingCommitment, reveal: &RatingReveal) -> bool {
    let expected = compute_commitment_hash(reveal.rating, &reveal.nonce);
    expected == commitment.commitment_hash
}

/// Extract a verified sealed rating from a transaction JSON object.
///
/// Handles three cases:
/// 1. `revealed_rating` + `rating_nonce` + `rating_commitment` present and valid → `Some(rating)`
/// 2. Only `rating_commitment` present (sealed but not revealed) → `None`
/// 3. No sealed rating fields → `None`
///
/// Returns `None` if the reveal doesn't match the commitment (invalid nonce).
pub fn extract_sealed_rating(transaction: &serde_json::Value) -> Option<f64> {
    let commitment_hash = transaction.get("rating_commitment")?.as_str()?;
    let revealed_rating = transaction.get("revealed_rating")?.as_f64()?;
    let nonce = transaction.get("rating_nonce")?.as_str()?;

    // Verify the reveal matches the commitment
    let commitment = RatingCommitment {
        commitment_hash: commitment_hash.to_string(),
        committed_at: 0, // not needed for verification
    };
    let reveal = RatingReveal {
        rating: revealed_rating,
        nonce: nonce.to_string(),
    };

    if verify_reveal(&commitment, &reveal) {
        Some(revealed_rating.clamp(0.0, 1.0))
    } else {
        None // Invalid reveal — nonce doesn't match
    }
}

/// Check if a rating commitment has timed out.
///
/// Returns `true` if `now_ms > committed_at + reveal_timeout_ms`.
pub fn is_reveal_timed_out(
    commitment: &RatingCommitment,
    now_ms: u64,
    config: &SealedRatingConfig,
) -> bool {
    now_ms
        > commitment
            .committed_at
            .saturating_add(config.reveal_timeout_ms)
}

/// Get the effective rating from a sealed rating transaction.
///
/// Handles three cases:
/// 1. Revealed and verified → use revealed rating.
/// 2. Timed out → use default rating (0.5).
/// 3. Sealed but within reveal window → `None` (pending).
pub fn effective_sealed_rating(
    transaction: &serde_json::Value,
    now_ms: u64,
    config: &SealedRatingConfig,
) -> Option<f64> {
    let commitment_hash = transaction
        .get("rating_commitment")
        .and_then(|v| v.as_str())?;

    // Check if revealed
    if let (Some(rating), Some(nonce)) = (
        transaction.get("revealed_rating").and_then(|v| v.as_f64()),
        transaction.get("rating_nonce").and_then(|v| v.as_str()),
    ) {
        let commitment = RatingCommitment {
            commitment_hash: commitment_hash.to_string(),
            committed_at: 0,
        };
        let reveal = RatingReveal {
            rating,
            nonce: nonce.to_string(),
        };
        if verify_reveal(&commitment, &reveal) {
            return Some(rating.clamp(0.0, 1.0));
        }
        // Invalid reveal falls through to timeout check
    }

    // Check timeout
    let committed_at = transaction
        .get("rating_committed_at")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let commitment = RatingCommitment {
        commitment_hash: commitment_hash.to_string(),
        committed_at,
    };

    if is_reveal_timed_out(&commitment, now_ms, config) {
        Some(config.timeout_default_rating)
    } else {
        None // Pending reveal
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_defaults() {
        let c = SealedRatingConfig::default();
        assert_eq!(c.reveal_timeout_ms, 3_600_000);
        assert!((c.timeout_default_rating - 0.5).abs() < 1e-12);
    }

    #[test]
    fn test_create_commitment_unique_nonces() {
        let (c1, n1) = create_commitment(0.8, 1000);
        let (c2, n2) = create_commitment(0.8, 1000);
        assert_ne!(n1, n2, "nonces should be unique");
        assert_ne!(
            c1.commitment_hash, c2.commitment_hash,
            "different nonces → different hashes"
        );
    }

    #[test]
    fn test_create_commitment_deterministic_hash() {
        // Same rating + nonce → same hash
        let hash1 = compute_commitment_hash(0.85, "deadbeef");
        let hash2 = compute_commitment_hash(0.85, "deadbeef");
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_verify_reveal_valid() {
        let (commitment, nonce) = create_commitment(0.75, 5000);
        let reveal = RatingReveal {
            rating: 0.75,
            nonce,
        };
        assert!(verify_reveal(&commitment, &reveal));
    }

    #[test]
    fn test_verify_reveal_wrong_rating() {
        let (commitment, nonce) = create_commitment(0.75, 5000);
        let reveal = RatingReveal {
            rating: 0.80, // wrong
            nonce,
        };
        assert!(!verify_reveal(&commitment, &reveal));
    }

    #[test]
    fn test_verify_reveal_wrong_nonce() {
        let (commitment, _nonce) = create_commitment(0.75, 5000);
        let reveal = RatingReveal {
            rating: 0.75,
            nonce: "wrong_nonce".to_string(),
        };
        assert!(!verify_reveal(&commitment, &reveal));
    }

    #[test]
    fn test_extract_sealed_rating_revealed() {
        let (commitment, nonce) = create_commitment(0.9, 1000);
        let tx = serde_json::json!({
            "rating_commitment": commitment.commitment_hash,
            "revealed_rating": 0.9,
            "rating_nonce": nonce,
        });
        let result = extract_sealed_rating(&tx);
        assert_eq!(result, Some(0.9));
    }

    #[test]
    fn test_extract_sealed_rating_sealed_only() {
        let (commitment, _nonce) = create_commitment(0.9, 1000);
        let tx = serde_json::json!({
            "rating_commitment": commitment.commitment_hash,
        });
        let result = extract_sealed_rating(&tx);
        assert_eq!(result, None, "sealed but not revealed → None");
    }

    #[test]
    fn test_extract_sealed_rating_no_commitment() {
        let tx = serde_json::json!({
            "quality": 0.85,
        });
        let result = extract_sealed_rating(&tx);
        assert_eq!(result, None, "no commitment → None");
    }

    #[test]
    fn test_extract_sealed_rating_invalid_nonce() {
        let (commitment, _nonce) = create_commitment(0.9, 1000);
        let tx = serde_json::json!({
            "rating_commitment": commitment.commitment_hash,
            "revealed_rating": 0.9,
            "rating_nonce": "totally_wrong_nonce",
        });
        let result = extract_sealed_rating(&tx);
        assert_eq!(result, None, "invalid nonce → None");
    }

    #[test]
    fn test_is_reveal_timed_out() {
        let c = SealedRatingConfig::default();
        let commitment = RatingCommitment {
            commitment_hash: "abc".to_string(),
            committed_at: 1000,
        };
        // 1000 + 3_600_000 = 3_601_000. Check at 3_601_001 → timed out
        assert!(is_reveal_timed_out(&commitment, 3_601_001, &c));
    }

    #[test]
    fn test_is_reveal_within_window() {
        let c = SealedRatingConfig::default();
        let commitment = RatingCommitment {
            commitment_hash: "abc".to_string(),
            committed_at: 1000,
        };
        // Within timeout window
        assert!(!is_reveal_timed_out(&commitment, 2_000_000, &c));
    }

    #[test]
    fn test_effective_rating_revealed() {
        let c = SealedRatingConfig::default();
        let (commitment, nonce) = create_commitment(0.7, 1000);
        let tx = serde_json::json!({
            "rating_commitment": commitment.commitment_hash,
            "rating_committed_at": 1000_u64,
            "revealed_rating": 0.7,
            "rating_nonce": nonce,
        });
        let result = effective_sealed_rating(&tx, 2000, &c);
        assert_eq!(result, Some(0.7));
    }

    #[test]
    fn test_effective_rating_timed_out() {
        let c = SealedRatingConfig::default();
        let (commitment, _nonce) = create_commitment(0.7, 1000);
        let tx = serde_json::json!({
            "rating_commitment": commitment.commitment_hash,
            "rating_committed_at": 1000_u64,
        });
        // Well past timeout
        let result = effective_sealed_rating(&tx, 100_000_000, &c);
        assert_eq!(result, Some(0.5), "timed out → default 0.5");
    }

    #[test]
    fn test_effective_rating_pending() {
        let c = SealedRatingConfig::default();
        let (commitment, _nonce) = create_commitment(0.7, 1000);
        let tx = serde_json::json!({
            "rating_commitment": commitment.commitment_hash,
            "rating_committed_at": 1000_u64,
        });
        // Within timeout window
        let result = effective_sealed_rating(&tx, 2000, &c);
        assert_eq!(result, None, "pending → None");
    }

    #[test]
    fn test_rating_precision() {
        // Verify f64 precision is preserved through commit-reveal
        let precise_rating = 0.123456;
        let (commitment, nonce) = create_commitment(precise_rating, 1000);
        let reveal = RatingReveal {
            rating: precise_rating,
            nonce,
        };
        assert!(verify_reveal(&commitment, &reveal));
    }

    #[test]
    fn test_nonce_minimum_length() {
        let (_commitment, nonce) = create_commitment(0.5, 1000);
        // Nonce is hex-encoded, so length = 2 × MIN_NONCE_LENGTH
        assert!(
            nonce.len() >= MIN_NONCE_LENGTH * 2,
            "nonce hex length should be >= {}, got {}",
            MIN_NONCE_LENGTH * 2,
            nonce.len()
        );
    }

    #[test]
    fn test_no_sealed_fields_returns_none() {
        let c = SealedRatingConfig::default();
        let tx = serde_json::json!({"outcome": "completed"});
        assert_eq!(effective_sealed_rating(&tx, 5000, &c), None);
    }
}
