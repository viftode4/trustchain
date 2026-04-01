//! Core type definitions and constants for the TrustChain protocol.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fmt;

/// Hash of the imaginary block 0 — used as `previous_hash` for the first block in a chain.
pub const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// First valid sequence number.
pub const GENESIS_SEQ: u64 = 1;

/// Unknown/unlinked sequence number (used in proposals before the responder replies).
pub const UNKNOWN_SEQ: u64 = 0;

/// Maximum allowed TTL for a delegation proposal: 30 days in milliseconds.
///
/// Enforced at the core protocol level in `create_delegation_proposal()` so that
/// direct library callers cannot bypass the cap (not just the HTTP API layer).
pub const MAX_DELEGATION_TTL_MS: u64 = 30 * 24 * 3600 * 1000;

/// Maximum number of concurrently active delegations per delegator.
///
/// Prevents Sybil identity flooding via unbounded delegation creation.
/// Research: ATTACK-TAXONOMY §1.1, network-ecology-control principle #3.
pub const MAX_ACTIVE_DELEGATIONS: usize = 10;

// ---------------------------------------------------------------------------
// ValidationResult — tiered validation matching py-ipv8
// ---------------------------------------------------------------------------

/// Tiered validation result matching py-ipv8's ValidationResult.
///
/// Validation levels, from most to least confidence:
/// - `Valid` — block and full chain context verified
/// - `PartialNext` — valid but we don't know (or have gaps after) the next block
/// - `PartialPrevious` — valid but we don't know the previous block
/// - `Partial` — valid but we have gaps on both sides
/// - `NoInfo` — we have no chain context for this public key at all
/// - `Invalid` — the block violates at least one invariant
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ValidationResult {
    Valid,
    PartialNext,
    PartialPrevious,
    Partial,
    NoInfo,
    Invalid(Vec<String>),
}

impl ValidationResult {
    pub fn is_valid(&self) -> bool {
        !matches!(self, ValidationResult::Invalid(_))
    }

    pub fn is_fully_valid(&self) -> bool {
        matches!(self, ValidationResult::Valid)
    }

    pub fn errors(&self) -> &[String] {
        match self {
            ValidationResult::Invalid(errs) => errs,
            _ => &[],
        }
    }
}

/// Block types in the TrustChain protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BlockType {
    /// Initiator's half-block (link_sequence_number = 0).
    Proposal,
    /// Responder's half-block (links back to proposal).
    Agreement,
    /// Consensus checkpoint block (self-referencing).
    Checkpoint,
    /// Delegation of authority to another identity.
    Delegation,
    /// Revocation of a previously granted delegation.
    Revocation,
    /// Identity succession (key rotation).
    Succession,
    /// Single-player audit record (self-referencing, no counterparty).
    Audit,
}

impl fmt::Display for BlockType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BlockType::Proposal => write!(f, "proposal"),
            BlockType::Agreement => write!(f, "agreement"),
            BlockType::Checkpoint => write!(f, "checkpoint"),
            BlockType::Delegation => write!(f, "delegation"),
            BlockType::Revocation => write!(f, "revocation"),
            BlockType::Succession => write!(f, "succession"),
            BlockType::Audit => write!(f, "audit"),
        }
    }
}

impl BlockType {
    /// Parse from string (case-insensitive).
    pub fn from_str_loose(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "proposal" => Some(BlockType::Proposal),
            "agreement" => Some(BlockType::Agreement),
            "checkpoint" => Some(BlockType::Checkpoint),
            "delegation" => Some(BlockType::Delegation),
            "revocation" => Some(BlockType::Revocation),
            "succession" => Some(BlockType::Succession),
            "audit" => Some(BlockType::Audit),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Audit configuration — recording levels and event types
// ---------------------------------------------------------------------------

/// Recording level controlling which event types are captured automatically.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuditLevel {
    /// Only `tool_call` and `error` events (~10-50 blocks per task).
    Minimal,
    /// Default. Adds `llm_decision`, `state_change`, `human_override` (~50-200 blocks).
    #[default]
    Standard,
    /// Everything including `external_api` and `raw_http` (~500+ blocks).
    Comprehensive,
}

impl fmt::Display for AuditLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuditLevel::Minimal => write!(f, "minimal"),
            AuditLevel::Standard => write!(f, "standard"),
            AuditLevel::Comprehensive => write!(f, "comprehensive"),
        }
    }
}

impl AuditLevel {
    /// Parse from string (case-insensitive).
    pub fn from_str_loose(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "minimal" => Some(AuditLevel::Minimal),
            "standard" => Some(AuditLevel::Standard),
            "comprehensive" => Some(AuditLevel::Comprehensive),
            _ => None,
        }
    }
}

/// Semantic event types for audit recording.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventType {
    /// Agent invoked a tool (name, args hash, result hash).
    ToolCall,
    /// LLM completion (model, I/O hashes, token count, latency).
    LlmDecision,
    /// Failures, exceptions, retries.
    Error,
    /// Configuration changes, permission grants, mode switches.
    StateChange,
    /// Human-in-the-loop intervention.
    HumanOverride,
    /// Third-party API calls (URL, status, timing).
    ExternalApi,
    /// Every HTTP request/response (debug/forensics).
    RawHttp,
}

impl fmt::Display for EventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EventType::ToolCall => write!(f, "tool_call"),
            EventType::LlmDecision => write!(f, "llm_decision"),
            EventType::Error => write!(f, "error"),
            EventType::StateChange => write!(f, "state_change"),
            EventType::HumanOverride => write!(f, "human_override"),
            EventType::ExternalApi => write!(f, "external_api"),
            EventType::RawHttp => write!(f, "raw_http"),
        }
    }
}

impl EventType {
    /// Parse from string (case-insensitive).
    pub fn from_str_loose(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "tool_call" => Some(EventType::ToolCall),
            "llm_decision" => Some(EventType::LlmDecision),
            "error" => Some(EventType::Error),
            "state_change" => Some(EventType::StateChange),
            "human_override" => Some(EventType::HumanOverride),
            "external_api" => Some(EventType::ExternalApi),
            "raw_http" => Some(EventType::RawHttp),
            _ => None,
        }
    }
}

/// Configuration for audit recording.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditConfig {
    /// Recording level determining default enabled event types.
    pub level: AuditLevel,
    /// Explicitly enabled event types (overrides level defaults).
    pub enabled_events: HashSet<EventType>,
    /// Optional schema validator name (e.g. "base", "ai_act", "aiuc1").
    pub schema: Option<String>,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self::with_level(AuditLevel::Standard)
    }
}

impl AuditConfig {
    /// Create a config for the given level with its default event types.
    pub fn with_level(level: AuditLevel) -> Self {
        Self {
            level,
            enabled_events: Self::default_events(level),
            schema: None,
        }
    }

    /// Default event types for each recording level.
    pub fn default_events(level: AuditLevel) -> HashSet<EventType> {
        let mut events = HashSet::new();
        // Minimal: tool_call + error
        events.insert(EventType::ToolCall);
        events.insert(EventType::Error);

        if matches!(level, AuditLevel::Standard | AuditLevel::Comprehensive) {
            events.insert(EventType::LlmDecision);
            events.insert(EventType::StateChange);
            events.insert(EventType::HumanOverride);
        }

        if matches!(level, AuditLevel::Comprehensive) {
            events.insert(EventType::ExternalApi);
            events.insert(EventType::RawHttp);
        }

        events
    }

    /// Check if a given event type is enabled in this config.
    pub fn is_event_enabled(&self, event_type: &EventType) -> bool {
        self.enabled_events.contains(event_type)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_genesis_hash_length() {
        assert_eq!(GENESIS_HASH.len(), 64);
        assert!(GENESIS_HASH.chars().all(|c| c == '0'));
    }

    #[test]
    fn test_block_type_display() {
        assert_eq!(BlockType::Proposal.to_string(), "proposal");
        assert_eq!(BlockType::Agreement.to_string(), "agreement");
        assert_eq!(BlockType::Checkpoint.to_string(), "checkpoint");
        assert_eq!(BlockType::Delegation.to_string(), "delegation");
        assert_eq!(BlockType::Revocation.to_string(), "revocation");
        assert_eq!(BlockType::Succession.to_string(), "succession");
        assert_eq!(BlockType::Audit.to_string(), "audit");
    }

    #[test]
    fn test_block_type_serde() {
        let json = serde_json::to_string(&BlockType::Proposal).unwrap();
        assert_eq!(json, "\"proposal\"");

        let parsed: BlockType = serde_json::from_str("\"agreement\"").unwrap();
        assert_eq!(parsed, BlockType::Agreement);

        let delegation: BlockType = serde_json::from_str("\"delegation\"").unwrap();
        assert_eq!(delegation, BlockType::Delegation);

        let revocation: BlockType = serde_json::from_str("\"revocation\"").unwrap();
        assert_eq!(revocation, BlockType::Revocation);

        let succession: BlockType = serde_json::from_str("\"succession\"").unwrap();
        assert_eq!(succession, BlockType::Succession);

        let audit: BlockType = serde_json::from_str("\"audit\"").unwrap();
        assert_eq!(audit, BlockType::Audit);
    }

    #[test]
    fn test_block_type_from_str_loose() {
        assert_eq!(
            BlockType::from_str_loose("Proposal"),
            Some(BlockType::Proposal)
        );
        assert_eq!(
            BlockType::from_str_loose("AGREEMENT"),
            Some(BlockType::Agreement)
        );
        assert_eq!(
            BlockType::from_str_loose("checkpoint"),
            Some(BlockType::Checkpoint)
        );
        assert_eq!(
            BlockType::from_str_loose("Delegation"),
            Some(BlockType::Delegation)
        );
        assert_eq!(
            BlockType::from_str_loose("REVOCATION"),
            Some(BlockType::Revocation)
        );
        assert_eq!(
            BlockType::from_str_loose("succession"),
            Some(BlockType::Succession)
        );
        assert_eq!(BlockType::from_str_loose("AUDIT"), Some(BlockType::Audit));
        assert_eq!(BlockType::from_str_loose("invalid"), None);
    }

    #[test]
    fn test_validation_result_valid() {
        let r = ValidationResult::Valid;
        assert!(r.is_valid());
        assert!(r.is_fully_valid());
        assert!(r.errors().is_empty());
    }

    #[test]
    fn test_validation_result_partial() {
        let r = ValidationResult::Partial;
        assert!(r.is_valid());
        assert!(!r.is_fully_valid());
    }

    #[test]
    fn test_validation_result_invalid() {
        let r = ValidationResult::Invalid(vec!["bad sig".to_string()]);
        assert!(!r.is_valid());
        assert!(!r.is_fully_valid());
        assert_eq!(r.errors().len(), 1);
    }

    #[test]
    fn test_constants() {
        assert_eq!(GENESIS_SEQ, 1);
        assert_eq!(UNKNOWN_SEQ, 0);
        assert_eq!(GENESIS_HASH.len(), 64);
    }

    // --- AuditLevel tests ---

    #[test]
    fn test_audit_level_default() {
        assert_eq!(AuditLevel::default(), AuditLevel::Standard);
    }

    #[test]
    fn test_audit_level_serde() {
        let json = serde_json::to_string(&AuditLevel::Minimal).unwrap();
        assert_eq!(json, "\"minimal\"");

        let parsed: AuditLevel = serde_json::from_str("\"comprehensive\"").unwrap();
        assert_eq!(parsed, AuditLevel::Comprehensive);
    }

    #[test]
    fn test_audit_level_from_str_loose() {
        assert_eq!(
            AuditLevel::from_str_loose("minimal"),
            Some(AuditLevel::Minimal)
        );
        assert_eq!(
            AuditLevel::from_str_loose("STANDARD"),
            Some(AuditLevel::Standard)
        );
        assert_eq!(
            AuditLevel::from_str_loose("Comprehensive"),
            Some(AuditLevel::Comprehensive)
        );
        assert_eq!(AuditLevel::from_str_loose("invalid"), None);
    }

    // --- EventType tests ---

    #[test]
    fn test_event_type_serde() {
        let json = serde_json::to_string(&EventType::ToolCall).unwrap();
        assert_eq!(json, "\"tool_call\"");

        let parsed: EventType = serde_json::from_str("\"llm_decision\"").unwrap();
        assert_eq!(parsed, EventType::LlmDecision);
    }

    #[test]
    fn test_event_type_from_str_loose() {
        assert_eq!(
            EventType::from_str_loose("tool_call"),
            Some(EventType::ToolCall)
        );
        assert_eq!(
            EventType::from_str_loose("HUMAN_OVERRIDE"),
            Some(EventType::HumanOverride)
        );
        assert_eq!(EventType::from_str_loose("unknown"), None);
    }

    // --- AuditConfig tests ---

    #[test]
    fn test_audit_config_default() {
        let config = AuditConfig::default();
        assert_eq!(config.level, AuditLevel::Standard);
        assert!(config.is_event_enabled(&EventType::ToolCall));
        assert!(config.is_event_enabled(&EventType::Error));
        assert!(config.is_event_enabled(&EventType::LlmDecision));
        assert!(config.is_event_enabled(&EventType::StateChange));
        assert!(config.is_event_enabled(&EventType::HumanOverride));
        assert!(!config.is_event_enabled(&EventType::ExternalApi));
        assert!(!config.is_event_enabled(&EventType::RawHttp));
        assert!(config.schema.is_none());
    }

    #[test]
    fn test_audit_config_minimal() {
        let config = AuditConfig::with_level(AuditLevel::Minimal);
        assert!(config.is_event_enabled(&EventType::ToolCall));
        assert!(config.is_event_enabled(&EventType::Error));
        assert!(!config.is_event_enabled(&EventType::LlmDecision));
        assert!(!config.is_event_enabled(&EventType::StateChange));
        assert!(!config.is_event_enabled(&EventType::ExternalApi));
    }

    #[test]
    fn test_audit_config_comprehensive() {
        let config = AuditConfig::with_level(AuditLevel::Comprehensive);
        assert!(config.is_event_enabled(&EventType::ToolCall));
        assert!(config.is_event_enabled(&EventType::Error));
        assert!(config.is_event_enabled(&EventType::LlmDecision));
        assert!(config.is_event_enabled(&EventType::StateChange));
        assert!(config.is_event_enabled(&EventType::HumanOverride));
        assert!(config.is_event_enabled(&EventType::ExternalApi));
        assert!(config.is_event_enabled(&EventType::RawHttp));
    }

    #[test]
    fn test_audit_config_serde_roundtrip() {
        let config = AuditConfig::with_level(AuditLevel::Standard);
        let json = serde_json::to_string(&config).unwrap();
        let parsed: AuditConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.level, AuditLevel::Standard);
        assert_eq!(parsed.enabled_events.len(), config.enabled_events.len());
    }
}
