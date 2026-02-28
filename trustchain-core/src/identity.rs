//! Ed25519 identity management for TrustChain agents.
//!
//! Each agent has an Ed25519 keypair. The public key (hex-encoded) serves as the
//! agent's unique identifier throughout the protocol.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use std::fs;
use std::path::Path;

use crate::error::{Result, TrustChainError};

/// An Ed25519 identity (keypair) for a TrustChain agent.
#[derive(Debug, Clone)]
pub struct Identity {
    signing_key: SigningKey,
}

impl Identity {
    /// Generate a new random identity.
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        Self { signing_key }
    }

    /// Create an identity from raw 32-byte private key bytes.
    pub fn from_bytes(secret: &[u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(secret);
        Self { signing_key }
    }

    /// Get the verifying (public) key.
    pub fn public_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// Get the raw 32-byte public key.
    pub fn pubkey_bytes(&self) -> [u8; 32] {
        self.public_key().to_bytes()
    }

    /// Get the hex-encoded public key (64 hex chars). This is the agent's identifier.
    pub fn pubkey_hex(&self) -> String {
        hex::encode(self.pubkey_bytes())
    }

    /// Get a short identifier (first 8 hex chars) for logging.
    pub fn short_id(&self) -> String {
        self.pubkey_hex()[..8].to_string()
    }

    /// Sign arbitrary data, returning a 64-byte signature.
    pub fn sign(&self, data: &[u8]) -> Vec<u8> {
        let signature: Signature = self.signing_key.sign(data);
        signature.to_bytes().to_vec()
    }

    /// Sign data and return the signature as a hex string (128 hex chars).
    pub fn sign_hex(&self, data: &[u8]) -> String {
        hex::encode(self.sign(data))
    }

    /// Verify a signature against data and a public key.
    pub fn verify(data: &[u8], signature_bytes: &[u8], pubkey_bytes: &[u8; 32]) -> Result<bool> {
        let verifying_key = VerifyingKey::from_bytes(pubkey_bytes)
            .map_err(|e| TrustChainError::Identity(format!("invalid public key: {e}")))?;
        let signature = Signature::from_slice(signature_bytes)
            .map_err(|e| TrustChainError::Identity(format!("invalid signature: {e}")))?;

        match verifying_key.verify(data, &signature) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    /// Verify using hex-encoded signature and public key strings.
    pub fn verify_hex(data: &[u8], signature_hex: &str, pubkey_hex: &str) -> Result<bool> {
        let sig_bytes = hex::decode(signature_hex)?;
        let pk_bytes = hex::decode(pubkey_hex)?;
        if pk_bytes.len() != 32 {
            return Err(TrustChainError::Identity(format!(
                "public key must be 32 bytes, got {}",
                pk_bytes.len()
            )));
        }
        let pk_arr: [u8; 32] = pk_bytes.try_into().unwrap();
        Self::verify(data, &sig_bytes, &pk_arr)
    }

    /// Save the 32-byte private key to a file.
    pub fn save(&self, path: impl AsRef<Path>) -> Result<()> {
        fs::write(path, self.signing_key.to_bytes())
            .map_err(|e| TrustChainError::Identity(format!("failed to save identity: {e}")))
    }

    /// Load an identity from a 32-byte private key file.
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let bytes = fs::read(path)
            .map_err(|e| TrustChainError::Identity(format!("failed to load identity: {e}")))?;
        if bytes.len() != 32 {
            return Err(TrustChainError::Identity(format!(
                "identity file must be 32 bytes, got {}",
                bytes.len()
            )));
        }
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&bytes);
        Ok(Self::from_bytes(&key_bytes))
    }

    /// Get the raw 32-byte secret key (for serialization only).
    pub fn secret_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_identity() {
        let id = Identity::generate();
        assert_eq!(id.pubkey_hex().len(), 64);
        assert_eq!(id.short_id().len(), 8);
    }

    #[test]
    fn test_pubkey_hex_format() {
        let id = Identity::generate();
        let hex_str = id.pubkey_hex();
        // Must be valid hex
        assert!(hex::decode(&hex_str).is_ok());
        assert_eq!(hex_str.len(), 64);
    }

    #[test]
    fn test_sign_and_verify() {
        let id = Identity::generate();
        let data = b"hello trustchain";
        let sig = id.sign(data);

        assert_eq!(sig.len(), 64);
        let valid = Identity::verify(data, &sig, &id.pubkey_bytes()).unwrap();
        assert!(valid);

        // Wrong data should fail
        let valid = Identity::verify(b"wrong data", &sig, &id.pubkey_bytes()).unwrap();
        assert!(!valid);
    }

    #[test]
    fn test_sign_and_verify_hex() {
        let id = Identity::generate();
        let data = b"test data";
        let sig_hex = id.sign_hex(data);

        assert_eq!(sig_hex.len(), 128);
        let valid = Identity::verify_hex(data, &sig_hex, &id.pubkey_hex()).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_different_keys_fail_verification() {
        let id1 = Identity::generate();
        let id2 = Identity::generate();
        let data = b"test";
        let sig = id1.sign(data);

        let valid = Identity::verify(data, &sig, &id2.pubkey_bytes()).unwrap();
        assert!(!valid);
    }

    #[test]
    fn test_from_bytes_roundtrip() {
        let id1 = Identity::generate();
        let secret = id1.secret_bytes();
        let id2 = Identity::from_bytes(&secret);
        assert_eq!(id1.pubkey_hex(), id2.pubkey_hex());
    }

    #[test]
    fn test_save_and_load() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test_key");

        let id1 = Identity::generate();
        id1.save(&path).unwrap();

        let id2 = Identity::load(&path).unwrap();
        assert_eq!(id1.pubkey_hex(), id2.pubkey_hex());

        // Sign with loaded key, verify with original
        let data = b"persistence test";
        let sig = id2.sign(data);
        let valid = Identity::verify(data, &sig, &id1.pubkey_bytes()).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_deterministic_key_derivation() {
        let secret = [42u8; 32];
        let id1 = Identity::from_bytes(&secret);
        let id2 = Identity::from_bytes(&secret);
        assert_eq!(id1.pubkey_hex(), id2.pubkey_hex());
    }
}
