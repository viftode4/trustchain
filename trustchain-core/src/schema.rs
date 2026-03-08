//! Pluggable schema validation for audit block transactions.
//!
//! Schemas define required fields in audit block `transaction` JSON payloads.
//! Three built-in schemas are provided:
//! - **Base**: Minimal fields (`action`, `outcome`, `timestamp`)
//! - **AiAct**: EU AI Act Article 12 compliance fields
//! - **Aiuc1**: AIUC-1 agent standard fields
//!
//! When no schema is configured, audit transactions are freeform JSON.

use crate::error::{Result, TrustChainError};
use serde::{Deserialize, Serialize};

/// Identifies a built-in schema validator.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SchemaId {
    /// Minimal: `action`, `outcome`, `timestamp`.
    Base,
    /// EU AI Act Article 12 compliance fields.
    AiAct,
    /// AIUC-1 agent standard fields.
    Aiuc1,
}

impl SchemaId {
    /// Parse from string (case-insensitive).
    pub fn from_str_loose(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "base" => Some(SchemaId::Base),
            "ai_act" | "aiact" => Some(SchemaId::AiAct),
            "aiuc1" | "aiuc-1" => Some(SchemaId::Aiuc1),
            _ => None,
        }
    }
}

/// Validate an audit transaction against the given schema.
///
/// Returns `Ok(())` if valid, or an error listing missing/invalid fields.
pub fn validate_transaction(schema: &SchemaId, transaction: &serde_json::Value) -> Result<()> {
    let obj = transaction
        .as_object()
        .ok_or_else(|| TrustChainError::validation("transaction must be a JSON object"))?;

    let missing: Vec<&str> = match schema {
        SchemaId::Base => {
            let required = ["action", "outcome"];
            required
                .iter()
                .filter(|&&f| !obj.contains_key(f))
                .copied()
                .collect()
        }
        SchemaId::AiAct => {
            // Base fields + AI Act Article 12 traceability fields
            let required = [
                "action",
                "outcome",
                "model",
                "input_hash",
                "output_hash",
            ];
            required
                .iter()
                .filter(|&&f| !obj.contains_key(f))
                .copied()
                .collect()
        }
        SchemaId::Aiuc1 => {
            // Base fields + AIUC-1 governance fields
            let required = ["action", "outcome", "policy_id", "compliance_status"];
            required
                .iter()
                .filter(|&&f| !obj.contains_key(f))
                .copied()
                .collect()
        }
    };

    if missing.is_empty() {
        Ok(())
    } else {
        Err(TrustChainError::validation(format!(
            "schema '{}' requires missing fields: {}",
            serde_json::to_string(schema).unwrap_or_default().trim_matches('"'),
            missing.join(", ")
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_base_schema_valid() {
        let tx = json!({"action": "read_file", "outcome": "completed"});
        assert!(validate_transaction(&SchemaId::Base, &tx).is_ok());
    }

    #[test]
    fn test_base_schema_extra_fields_ok() {
        let tx = json!({"action": "read_file", "outcome": "completed", "extra": 42});
        assert!(validate_transaction(&SchemaId::Base, &tx).is_ok());
    }

    #[test]
    fn test_base_schema_missing_action() {
        let tx = json!({"outcome": "completed"});
        let err = validate_transaction(&SchemaId::Base, &tx).unwrap_err();
        assert!(err.to_string().contains("action"));
    }

    #[test]
    fn test_base_schema_missing_outcome() {
        let tx = json!({"action": "test"});
        let err = validate_transaction(&SchemaId::Base, &tx).unwrap_err();
        assert!(err.to_string().contains("outcome"));
    }

    #[test]
    fn test_base_schema_not_object() {
        let tx = json!("just a string");
        let err = validate_transaction(&SchemaId::Base, &tx).unwrap_err();
        assert!(err.to_string().contains("JSON object"));
    }

    #[test]
    fn test_ai_act_schema_valid() {
        let tx = json!({
            "action": "classify_image",
            "outcome": "completed",
            "model": "vision-v2",
            "input_hash": "sha256:abc123",
            "output_hash": "sha256:def456"
        });
        assert!(validate_transaction(&SchemaId::AiAct, &tx).is_ok());
    }

    #[test]
    fn test_ai_act_schema_missing_model() {
        let tx = json!({
            "action": "classify_image",
            "outcome": "completed",
            "input_hash": "sha256:abc123",
            "output_hash": "sha256:def456"
        });
        let err = validate_transaction(&SchemaId::AiAct, &tx).unwrap_err();
        assert!(err.to_string().contains("model"));
    }

    #[test]
    fn test_aiuc1_schema_valid() {
        let tx = json!({
            "action": "process_pii",
            "outcome": "completed",
            "policy_id": "strict-enterprise",
            "compliance_status": "passed"
        });
        assert!(validate_transaction(&SchemaId::Aiuc1, &tx).is_ok());
    }

    #[test]
    fn test_aiuc1_schema_missing_fields() {
        let tx = json!({"action": "process_pii", "outcome": "completed"});
        let err = validate_transaction(&SchemaId::Aiuc1, &tx).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("policy_id"));
        assert!(msg.contains("compliance_status"));
    }

    #[test]
    fn test_schema_id_from_str_loose() {
        assert_eq!(SchemaId::from_str_loose("base"), Some(SchemaId::Base));
        assert_eq!(SchemaId::from_str_loose("ai_act"), Some(SchemaId::AiAct));
        assert_eq!(SchemaId::from_str_loose("aiact"), Some(SchemaId::AiAct));
        assert_eq!(SchemaId::from_str_loose("aiuc1"), Some(SchemaId::Aiuc1));
        assert_eq!(SchemaId::from_str_loose("AIUC-1"), Some(SchemaId::Aiuc1));
        assert_eq!(SchemaId::from_str_loose("unknown"), None);
    }

    #[test]
    fn test_schema_id_serde() {
        let json = serde_json::to_string(&SchemaId::Base).unwrap();
        assert_eq!(json, "\"base\"");

        let parsed: SchemaId = serde_json::from_str("\"ai_act\"").unwrap();
        assert_eq!(parsed, SchemaId::AiAct);
    }
}
