//! TOML-based node configuration.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Node configuration, loadable from a TOML file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeConfig {
    /// Listen address for QUIC transport.
    #[serde(default = "default_quic_addr")]
    pub quic_addr: String,

    /// Listen address for gRPC service.
    #[serde(default = "default_grpc_addr")]
    pub grpc_addr: String,

    /// Listen address for HTTP REST API.
    #[serde(default = "default_http_addr")]
    pub http_addr: String,

    /// Listen address for the transparent HTTP proxy (agent sidecar).
    /// Agents set HTTP_PROXY=http://<this address> to get automatic trust recording.
    #[serde(default = "default_proxy_addr")]
    pub proxy_addr: String,

    /// Path to the Ed25519 identity key file.
    #[serde(default = "default_key_path")]
    pub key_path: PathBuf,

    /// Path to the SQLite database.
    #[serde(default = "default_db_path")]
    pub db_path: PathBuf,

    /// Bootstrap node addresses for peer discovery.
    /// Falls back to built-in seed nodes when empty.
    #[serde(default)]
    pub bootstrap_nodes: Vec<String>,

    /// Minimum signers for CHECO consensus checkpoints.
    #[serde(default = "default_min_signers")]
    pub min_signers: usize,

    /// Maximum new QUIC connections per IP per second (rate limiting).
    #[serde(default = "default_max_connections_per_ip_per_sec")]
    pub max_connections_per_ip_per_sec: u32,

    /// Interval between CHECO consensus checkpoint rounds (seconds).
    #[serde(default = "default_checkpoint_interval_secs")]
    pub checkpoint_interval_secs: u64,

    /// STUN server for NAT traversal (None to disable).
    #[serde(default = "default_stun_server")]
    pub stun_server: Option<String>,

    /// Log level.
    #[serde(default = "default_log_level")]
    pub log_level: String,

    /// Agent name (set by sidecar mode).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_name: Option<String>,

    /// Agent's own HTTP endpoint (set by sidecar mode).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_endpoint: Option<String>,

    /// Public HTTP address to advertise to peers.
    /// Required when running on a public server so peers can reach you.
    /// Example: "http://203.0.113.5:8202"
    /// If not set, STUN is used to discover the public IP. Falls back to
    /// 127.0.0.1 (only suitable for single-machine testing).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub advertise_addr: Option<String>,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            quic_addr: default_quic_addr(),
            grpc_addr: default_grpc_addr(),
            http_addr: default_http_addr(),
            proxy_addr: default_proxy_addr(),
            key_path: default_key_path(),
            db_path: default_db_path(),
            bootstrap_nodes: vec![],
            min_signers: default_min_signers(),
            max_connections_per_ip_per_sec: default_max_connections_per_ip_per_sec(),
            checkpoint_interval_secs: default_checkpoint_interval_secs(),
            stun_server: default_stun_server(),
            log_level: default_log_level(),
            agent_name: None,
            agent_endpoint: None,
            advertise_addr: None,
        }
    }
}

impl NodeConfig {
    /// Load configuration from a TOML file.
    pub fn load(path: &str) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let config: Self = toml::from_str(&content)?;
        Ok(config)
    }

    /// Generate a default config file as a string.
    pub fn default_toml() -> String {
        toml::to_string_pretty(&Self::default()).unwrap()
    }

    /// Get effective bootstrap nodes (user-configured or built-in defaults).
    pub fn effective_bootstrap_nodes(&self) -> Vec<String> {
        if self.bootstrap_nodes.is_empty() {
            default_seed_nodes()
        } else {
            self.bootstrap_nodes.clone()
        }
    }
}

fn default_quic_addr() -> String {
    "0.0.0.0:8200".to_string()
}

fn default_grpc_addr() -> String {
    "0.0.0.0:8201".to_string()
}

fn default_http_addr() -> String {
    "0.0.0.0:8202".to_string()
}

fn default_proxy_addr() -> String {
    "127.0.0.1:8203".to_string()
}

fn default_key_path() -> PathBuf {
    PathBuf::from("identity.key")
}

fn default_db_path() -> PathBuf {
    PathBuf::from("trustchain.db")
}

fn default_min_signers() -> usize {
    1
}

fn default_max_connections_per_ip_per_sec() -> u32 {
    20
}

fn default_checkpoint_interval_secs() -> u64 {
    60
}

fn default_stun_server() -> Option<String> {
    Some("stun.l.google.com:19302".to_string())
}

fn default_log_level() -> String {
    "info".to_string()
}

/// Built-in seed nodes for initial network bootstrap.
/// Used when `bootstrap_nodes` config is empty.
pub fn default_seed_nodes() -> Vec<String> {
    vec![
        // Placeholder — replace with real seed nodes when deployed.
        // "http://seed1.trustchain.network:8202".to_string(),
        // "http://seed2.trustchain.network:8202".to_string(),
    ]
}

