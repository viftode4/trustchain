//! Peer discovery — bootstrap, random walk, and gossip-based peer finding.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::sync::RwLock;

/// Get the current time as milliseconds since Unix epoch.
pub fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Information about a known peer.
#[derive(Debug, Clone)]
pub struct PeerRecord {
    pub pubkey: String,
    pub address: String,
    pub latest_seq: u64,
    /// Last seen timestamp in milliseconds since Unix epoch.
    pub last_seen_unix_ms: u64,
    pub is_bootstrap: bool,
}

/// Peer discovery service.
#[derive(Debug, Clone)]
pub struct PeerDiscovery {
    /// Known peers by public key.
    peers: Arc<RwLock<HashMap<String, PeerRecord>>>,
    /// Bootstrap nodes to connect to initially.
    bootstrap_nodes: Vec<String>,
    /// Our own public key.
    our_pubkey: String,
    /// Address aliases: maps normalized address (e.g. "127.0.0.1:9002") → pubkey.
    /// Used by the proxy to resolve agent endpoints to TC peer identities.
    aliases: Arc<RwLock<HashMap<String, String>>>,
}

impl PeerDiscovery {
    pub fn new(our_pubkey: String, bootstrap_nodes: Vec<String>) -> Self {
        Self {
            peers: Arc::new(RwLock::new(HashMap::new())),
            bootstrap_nodes,
            our_pubkey,
            aliases: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Register a peer we've discovered.
    pub async fn add_peer(&self, pubkey: String, address: String, latest_seq: u64) {
        if pubkey == self.our_pubkey {
            return; // Don't add ourselves.
        }
        let mut peers = self.peers.write().await;
        let entry = peers.entry(pubkey.clone()).or_insert_with(|| PeerRecord {
            pubkey: pubkey.clone(),
            address: address.clone(),
            latest_seq,
            last_seen_unix_ms: now_unix_ms(),
            is_bootstrap: self.bootstrap_nodes.contains(&address),
        });
        entry.address = address;
        entry.latest_seq = latest_seq;
        entry.last_seen_unix_ms = now_unix_ms();
    }

    /// Get all known peers.
    pub async fn get_peers(&self) -> Vec<PeerRecord> {
        self.peers.read().await.values().cloned().collect()
    }

    /// Get a specific peer by public key.
    pub async fn get_peer(&self, pubkey: &str) -> Option<PeerRecord> {
        self.peers.read().await.get(pubkey).cloned()
    }

    /// Look up a peer by their HTTP address (e.g. "127.0.0.1:8202" or "http://127.0.0.1:8202").
    /// Used by the proxy to check whether an outbound call targets a known TC peer.
    /// Falls back to alias lookup if no direct match is found.
    pub async fn get_peer_by_address(&self, address: &str) -> Option<PeerRecord> {
        let normalized = normalize_address(address);

        // Direct match against registered peer addresses.
        {
            let peers = self.peers.read().await;
            for peer in peers.values() {
                if normalize_address(&peer.address) == normalized {
                    return Some(peer.clone());
                }
            }
        }

        // Fallback: check aliases.
        let pubkey = {
            let aliases = self.aliases.read().await;
            aliases.get(&normalized).cloned()
        };

        if let Some(pk) = pubkey {
            return self.get_peer(&pk).await;
        }

        None
    }

    /// Register an address alias mapping to a peer's public key.
    ///
    /// This lets the proxy resolve agent endpoints (e.g. `localhost:9002`)
    /// to the correct TC peer identity, even though peers register with
    /// their sidecar HTTP address (e.g. `127.0.0.1:8212`).
    pub async fn add_alias(&self, alias_address: String, pubkey: String) {
        let normalized = normalize_address(&alias_address);
        self.aliases.write().await.insert(normalized, pubkey);
    }

    /// Get the number of known peers.
    pub async fn peer_count(&self) -> usize {
        self.peers.read().await.len()
    }

    /// Remove a peer.
    pub async fn remove_peer(&self, pubkey: &str) {
        self.peers.write().await.remove(pubkey);
    }

    /// Get bootstrap node addresses.
    pub fn bootstrap_addresses(&self) -> &[String] {
        &self.bootstrap_nodes
    }

    /// Get peer addresses for gossip exchange.
    pub async fn get_gossip_peers(&self, max_count: usize) -> Vec<PeerRecord> {
        let peers = self.peers.read().await;
        let mut list: Vec<PeerRecord> = peers.values().cloned().collect();
        // Sort by most recently seen first (highest unix_ms first).
        list.sort_by(|a, b| b.last_seen_unix_ms.cmp(&a.last_seen_unix_ms));
        list.truncate(max_count);
        list
    }

    /// Merge peers received from another node.
    pub async fn merge_peers(&self, incoming: Vec<(String, String, u64)>) {
        for (pubkey, address, seq) in incoming {
            self.add_peer(pubkey, address, seq).await;
        }
    }
}

/// Normalize an address for matching: strip scheme, lowercase, resolve localhost.
fn normalize_address(addr: &str) -> String {
    let s = addr
        .trim()
        .to_lowercase()
        .replace("http://", "")
        .replace("https://", "");
    s.replace("localhost", "127.0.0.1")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_add_and_get_peer() {
        let disc = PeerDiscovery::new("us".to_string(), vec![]);
        disc.add_peer("peer1".to_string(), "127.0.0.1:8200".to_string(), 5).await;

        let peer = disc.get_peer("peer1").await.unwrap();
        assert_eq!(peer.address, "127.0.0.1:8200");
        assert_eq!(peer.latest_seq, 5);
    }

    #[tokio::test]
    async fn test_dont_add_self() {
        let disc = PeerDiscovery::new("us".to_string(), vec![]);
        disc.add_peer("us".to_string(), "127.0.0.1:8200".to_string(), 0).await;
        assert_eq!(disc.peer_count().await, 0);
    }

    #[tokio::test]
    async fn test_peer_count() {
        let disc = PeerDiscovery::new("us".to_string(), vec![]);
        disc.add_peer("a".to_string(), "addr1".to_string(), 0).await;
        disc.add_peer("b".to_string(), "addr2".to_string(), 0).await;
        assert_eq!(disc.peer_count().await, 2);
    }

    #[tokio::test]
    async fn test_remove_peer() {
        let disc = PeerDiscovery::new("us".to_string(), vec![]);
        disc.add_peer("a".to_string(), "addr1".to_string(), 0).await;
        disc.remove_peer("a").await;
        assert_eq!(disc.peer_count().await, 0);
    }

    #[tokio::test]
    async fn test_merge_peers() {
        let disc = PeerDiscovery::new("us".to_string(), vec![]);
        disc.merge_peers(vec![
            ("a".to_string(), "addr1".to_string(), 1),
            ("b".to_string(), "addr2".to_string(), 2),
        ]).await;
        assert_eq!(disc.peer_count().await, 2);
    }

    #[tokio::test]
    async fn test_gossip_peers_limit() {
        let disc = PeerDiscovery::new("us".to_string(), vec![]);
        for i in 0..10 {
            disc.add_peer(format!("p{i}"), format!("addr{i}"), 0).await;
        }
        let gossip = disc.get_gossip_peers(3).await;
        assert_eq!(gossip.len(), 3);
    }

    #[tokio::test]
    async fn test_get_peer_by_address_direct() {
        let disc = PeerDiscovery::new("us".to_string(), vec![]);
        disc.add_peer("peer1".to_string(), "http://127.0.0.1:8212".to_string(), 5).await;

        let peer = disc.get_peer_by_address("http://127.0.0.1:8212").await.unwrap();
        assert_eq!(peer.pubkey, "peer1");
    }

    #[tokio::test]
    async fn test_get_peer_by_address_alias() {
        let disc = PeerDiscovery::new("us".to_string(), vec![]);
        disc.add_peer("peer1".to_string(), "http://127.0.0.1:8212".to_string(), 5).await;
        disc.add_alias("http://localhost:9002".to_string(), "peer1".to_string()).await;

        let peer = disc.get_peer_by_address("http://localhost:9002").await.unwrap();
        assert_eq!(peer.pubkey, "peer1");
        assert_eq!(peer.address, "http://127.0.0.1:8212");
    }

    #[tokio::test]
    async fn test_get_peer_by_address_localhost_normalization() {
        let disc = PeerDiscovery::new("us".to_string(), vec![]);
        disc.add_peer("peer1".to_string(), "http://localhost:8212".to_string(), 5).await;

        let peer = disc.get_peer_by_address("http://127.0.0.1:8212").await.unwrap();
        assert_eq!(peer.pubkey, "peer1");
    }

    #[tokio::test]
    async fn test_get_peer_by_address_miss() {
        let disc = PeerDiscovery::new("us".to_string(), vec![]);
        disc.add_peer("peer1".to_string(), "http://127.0.0.1:8212".to_string(), 5).await;

        assert!(disc.get_peer_by_address("http://127.0.0.1:9999").await.is_none());
    }
}
