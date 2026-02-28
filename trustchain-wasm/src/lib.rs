//! TrustChain WASM bindings for browser nodes.
//!
//! Exports core protocol types to JavaScript via wasm-bindgen,
//! enabling browsers to verify blocks, compute trust, run the full
//! proposal/agreement protocol, and compute trust scores — all in-browser.
//!
//! # Usage from JavaScript
//!
//! ```js
//! import { WasmIdentity, WasmProtocol, genesisHash } from "trustchain-wasm";
//!
//! const alice = new WasmProtocol();
//! const bob = new WasmProtocol();
//!
//! const proposal = alice.createProposal(bob.pubkeyHex, '{"service":"compute"}');
//! bob.receiveProposal(proposal);
//! const agreement = bob.createAgreement(proposal);
//! alice.receiveAgreement(agreement);
//!
//! console.log(alice.trustScore(bob.pubkeyHex)); // trust grows with interactions
//! ```

use wasm_bindgen::prelude::*;

use trustchain_core::blockstore::{BlockStore, MemoryBlockStore};
use trustchain_core::halfblock::{create_half_block, verify_block};
use trustchain_core::identity::Identity as CoreIdentity;
use trustchain_core::protocol::TrustChainProtocol;
use trustchain_core::trust::TrustEngine;
use trustchain_core::types::{BlockType, GENESIS_HASH};
use trustchain_core::HalfBlock;

// ---------------------------------------------------------------------------
// Identity
// ---------------------------------------------------------------------------

/// WASM-exported Ed25519 identity.
#[wasm_bindgen]
pub struct WasmIdentity {
    inner: CoreIdentity,
}

#[wasm_bindgen]
impl WasmIdentity {
    /// Generate a new random identity.
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self {
            inner: CoreIdentity::generate(),
        }
    }

    /// Create from raw 32-byte private key (as hex string).
    #[wasm_bindgen(js_name = fromHex)]
    pub fn from_hex(secret_hex: &str) -> Result<WasmIdentity, JsValue> {
        let bytes = hex::decode(secret_hex)
            .map_err(|e| JsValue::from_str(&format!("invalid hex: {e}")))?;
        if bytes.len() != 32 {
            return Err(JsValue::from_str("secret key must be 32 bytes"));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Self {
            inner: CoreIdentity::from_bytes(&arr),
        })
    }

    /// Get the hex-encoded public key.
    #[wasm_bindgen(getter, js_name = pubkeyHex)]
    pub fn pubkey_hex(&self) -> String {
        self.inner.pubkey_hex()
    }

    /// Get short identifier (first 8 hex chars).
    #[wasm_bindgen(getter, js_name = shortId)]
    pub fn short_id(&self) -> String {
        self.inner.short_id()
    }

    /// Sign data (UTF-8 string) and return hex-encoded signature.
    pub fn sign(&self, data: &str) -> String {
        self.inner.sign_hex(data.as_bytes())
    }

    /// Verify a signature (hex) against data and public key (hex).
    #[wasm_bindgen(js_name = verify)]
    pub fn verify_static(
        data: &str,
        signature_hex: &str,
        pubkey_hex: &str,
    ) -> Result<bool, JsValue> {
        CoreIdentity::verify_hex(data.as_bytes(), signature_hex, pubkey_hex)
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }
}

// ---------------------------------------------------------------------------
// Block creation & verification (stateless)
// ---------------------------------------------------------------------------

/// WASM-exported HalfBlock creation and verification.
#[wasm_bindgen]
pub struct WasmBlock;

#[wasm_bindgen]
impl WasmBlock {
    /// Create a half-block and return it as JSON.
    #[wasm_bindgen(js_name = createBlock)]
    pub fn create_block(
        identity_hex: &str,
        seq: u64,
        link_pubkey: &str,
        link_seq: u64,
        prev_hash: &str,
        block_type: &str,
        transaction_json: &str,
        timestamp: u64,
    ) -> Result<String, JsValue> {
        let identity = identity_from_hex(identity_hex)?;
        let bt = BlockType::from_str_loose(block_type)
            .ok_or_else(|| JsValue::from_str("invalid block type"))?;
        let tx: serde_json::Value = serde_json::from_str(transaction_json)
            .map_err(|e| JsValue::from_str(&format!("invalid transaction JSON: {e}")))?;

        let block = create_half_block(
            &identity, seq, link_pubkey, link_seq, prev_hash, bt, tx,
            Some(timestamp),
        );

        serde_json::to_string(&block)
            .map_err(|e| JsValue::from_str(&format!("serialization error: {e}")))
    }

    /// Verify a block (given as JSON). Returns true if valid.
    #[wasm_bindgen(js_name = verifyBlock)]
    pub fn verify_block_json(block_json: &str) -> Result<bool, JsValue> {
        let block: HalfBlock = serde_json::from_str(block_json)
            .map_err(|e| JsValue::from_str(&format!("invalid block JSON: {e}")))?;
        verify_block(&block).map_err(|e| JsValue::from_str(&format!("verification error: {e}")))
    }
}

// ---------------------------------------------------------------------------
// Protocol (full proposal/agreement lifecycle)
// ---------------------------------------------------------------------------

/// Full TrustChain protocol instance with in-memory block store.
///
/// Each `WasmProtocol` represents one agent — it holds an identity and a
/// `MemoryBlockStore`. Use this to run the complete proposal/agreement flow
/// in the browser.
#[wasm_bindgen]
pub struct WasmProtocol {
    protocol: TrustChainProtocol<MemoryBlockStore>,
}

#[wasm_bindgen]
impl WasmProtocol {
    /// Create a new protocol instance with a random identity.
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self {
            protocol: TrustChainProtocol::new(
                CoreIdentity::generate(),
                MemoryBlockStore::new(),
            ),
        }
    }

    /// Create a protocol instance from an existing identity (hex-encoded secret key).
    #[wasm_bindgen(js_name = fromIdentity)]
    pub fn from_identity(secret_hex: &str) -> Result<WasmProtocol, JsValue> {
        let identity = identity_from_hex(secret_hex)?;
        Ok(Self {
            protocol: TrustChainProtocol::new(identity, MemoryBlockStore::new()),
        })
    }

    /// Get this agent's public key (hex).
    #[wasm_bindgen(getter, js_name = pubkeyHex)]
    pub fn pubkey_hex(&self) -> String {
        self.protocol.pubkey()
    }

    /// Get short identifier (first 8 hex chars).
    #[wasm_bindgen(getter, js_name = shortId)]
    pub fn short_id(&self) -> String {
        self.protocol.identity().short_id()
    }

    /// Create a proposal for a counterparty. Returns the block as JSON.
    #[wasm_bindgen(js_name = createProposal)]
    pub fn create_proposal(
        &mut self,
        counterparty_pubkey: &str,
        transaction_json: &str,
    ) -> Result<String, JsValue> {
        let tx: serde_json::Value = serde_json::from_str(transaction_json)
            .map_err(|e| JsValue::from_str(&format!("invalid transaction JSON: {e}")))?;

        let block = self
            .protocol
            .create_proposal(counterparty_pubkey, tx, None)
            .map_err(|e| JsValue::from_str(&format!("create_proposal failed: {e}")))?;

        serde_json::to_string(&block)
            .map_err(|e| JsValue::from_str(&format!("serialization error: {e}")))
    }

    /// Receive a proposal from another agent. The proposal block JSON is stored.
    /// Returns true if this was a new proposal, false if already known.
    #[wasm_bindgen(js_name = receiveProposal)]
    pub fn receive_proposal(&mut self, proposal_json: &str) -> Result<bool, JsValue> {
        let block: HalfBlock = serde_json::from_str(proposal_json)
            .map_err(|e| JsValue::from_str(&format!("invalid proposal JSON: {e}")))?;

        self.protocol
            .receive_proposal(&block)
            .map_err(|e| JsValue::from_str(&format!("receive_proposal failed: {e}")))
    }

    /// Create an agreement for a received proposal. Returns the agreement block as JSON.
    #[wasm_bindgen(js_name = createAgreement)]
    pub fn create_agreement(&mut self, proposal_json: &str) -> Result<String, JsValue> {
        let proposal: HalfBlock = serde_json::from_str(proposal_json)
            .map_err(|e| JsValue::from_str(&format!("invalid proposal JSON: {e}")))?;

        let block = self
            .protocol
            .create_agreement(&proposal, None)
            .map_err(|e| JsValue::from_str(&format!("create_agreement failed: {e}")))?;

        serde_json::to_string(&block)
            .map_err(|e| JsValue::from_str(&format!("serialization error: {e}")))
    }

    /// Receive an agreement from another agent. The agreement block JSON is stored.
    /// Returns true if this was a new agreement, false if already known.
    #[wasm_bindgen(js_name = receiveAgreement)]
    pub fn receive_agreement(&mut self, agreement_json: &str) -> Result<bool, JsValue> {
        let block: HalfBlock = serde_json::from_str(agreement_json)
            .map_err(|e| JsValue::from_str(&format!("invalid agreement JSON: {e}")))?;

        self.protocol
            .receive_agreement(&block)
            .map_err(|e| JsValue::from_str(&format!("receive_agreement failed: {e}")))
    }

    /// Compute the trust score for a given public key using this node's block store.
    #[wasm_bindgen(js_name = trustScore)]
    pub fn trust_score(&self, pubkey: &str) -> Result<f64, JsValue> {
        let engine = TrustEngine::new(self.protocol.store(), None, None);
        engine
            .compute_trust(pubkey)
            .map_err(|e| JsValue::from_str(&format!("trust computation failed: {e}")))
    }

    /// Compute trust with seed nodes for NetFlow Sybil resistance.
    #[wasm_bindgen(js_name = trustScoreWithSeeds)]
    pub fn trust_score_with_seeds(
        &self,
        pubkey: &str,
        seed_pubkeys_json: &str,
    ) -> Result<f64, JsValue> {
        let seeds: Vec<String> = serde_json::from_str(seed_pubkeys_json)
            .map_err(|e| JsValue::from_str(&format!("invalid seed_pubkeys JSON: {e}")))?;

        let engine = TrustEngine::new(self.protocol.store(), Some(seeds), None);
        engine
            .compute_trust(pubkey)
            .map_err(|e| JsValue::from_str(&format!("trust computation failed: {e}")))
    }

    /// Get the latest sequence number for a public key.
    #[wasm_bindgen(js_name = latestSeq)]
    pub fn latest_seq(&self, pubkey: &str) -> Result<u64, JsValue> {
        self.protocol
            .store()
            .get_latest_seq(pubkey)
            .map_err(|e| JsValue::from_str(&format!("store error: {e}")))
    }

    /// Get a block by (pubkey, seq) as JSON. Returns null if not found.
    #[wasm_bindgen(js_name = getBlock)]
    pub fn get_block(&self, pubkey: &str, seq: u64) -> Result<JsValue, JsValue> {
        let block = self
            .protocol
            .store()
            .get_block(pubkey, seq)
            .map_err(|e| JsValue::from_str(&format!("store error: {e}")))?;

        match block {
            Some(b) => {
                let json = serde_json::to_string(&b)
                    .map_err(|e| JsValue::from_str(&format!("serialization error: {e}")))?;
                Ok(JsValue::from_str(&json))
            }
            None => Ok(JsValue::NULL),
        }
    }

    /// Get the total block count in the store.
    #[wasm_bindgen(js_name = blockCount)]
    pub fn block_count(&self) -> Result<usize, JsValue> {
        self.protocol
            .store()
            .get_block_count()
            .map_err(|e| JsValue::from_str(&format!("store error: {e}")))
    }

    /// Get all blocks for a given public key as a JSON array.
    #[wasm_bindgen(js_name = getChain)]
    pub fn get_chain(&self, pubkey: &str) -> Result<String, JsValue> {
        let blocks = self
            .protocol
            .store()
            .get_chain(pubkey)
            .map_err(|e| JsValue::from_str(&format!("store error: {e}")))?;

        serde_json::to_string(&blocks)
            .map_err(|e| JsValue::from_str(&format!("serialization error: {e}")))
    }
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Get the genesis hash constant.
#[wasm_bindgen(js_name = genesisHash)]
pub fn genesis_hash() -> String {
    GENESIS_HASH.to_string()
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn identity_from_hex(secret_hex: &str) -> Result<CoreIdentity, JsValue> {
    let bytes = hex::decode(secret_hex)
        .map_err(|e| JsValue::from_str(&format!("invalid identity hex: {e}")))?;
    if bytes.len() != 32 {
        return Err(JsValue::from_str("identity must be 32 bytes"));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(CoreIdentity::from_bytes(&arr))
}
