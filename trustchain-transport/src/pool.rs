//! Connection pool for managing persistent connections to peers.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// Information about a pooled connection.
#[derive(Debug, Clone)]
pub struct PooledConnection {
    pub address: String,
    pub pubkey: Option<String>,
    pub last_used: Instant,
    pub created_at: Instant,
}

/// Connection pool for managing peer connections.
#[derive(Debug, Clone)]
pub struct ConnectionPool {
    connections: Arc<RwLock<HashMap<String, PooledConnection>>>,
    max_idle_duration: Duration,
    max_connections: usize,
}

impl ConnectionPool {
    pub fn new(max_connections: usize, max_idle_seconds: u64) -> Self {
        Self {
            connections: Arc::new(RwLock::new(HashMap::new())),
            max_idle_duration: Duration::from_secs(max_idle_seconds),
            max_connections,
        }
    }

    /// Register or update a connection in the pool.
    pub async fn put(&self, address: String, pubkey: Option<String>) {
        let mut conns = self.connections.write().await;

        // Evict if at capacity.
        if conns.len() >= self.max_connections && !conns.contains_key(&address) {
            self.evict_oldest(&mut conns);
        }

        let entry = conns.entry(address.clone()).or_insert_with(|| PooledConnection {
            address: address.clone(),
            pubkey: pubkey.clone(),
            last_used: Instant::now(),
            created_at: Instant::now(),
        });
        entry.last_used = Instant::now();
        if pubkey.is_some() {
            entry.pubkey = pubkey;
        }
    }

    /// Get a connection from the pool.
    pub async fn get(&self, address: &str) -> Option<PooledConnection> {
        let mut conns = self.connections.write().await;
        if let Some(conn) = conns.get_mut(address) {
            if conn.last_used.elapsed() > self.max_idle_duration {
                conns.remove(address);
                return None;
            }
            conn.last_used = Instant::now();
            return Some(conn.clone());
        }
        None
    }

    /// Remove a connection from the pool.
    pub async fn remove(&self, address: &str) {
        self.connections.write().await.remove(address);
    }

    /// Get all active connections.
    pub async fn active_connections(&self) -> Vec<PooledConnection> {
        let conns = self.connections.read().await;
        conns.values().cloned().collect()
    }

    /// Number of connections in the pool.
    pub async fn len(&self) -> usize {
        self.connections.read().await.len()
    }

    /// Clean up idle connections.
    pub async fn cleanup(&self) {
        let mut conns = self.connections.write().await;
        conns.retain(|_, conn| conn.last_used.elapsed() <= self.max_idle_duration);
    }

    fn evict_oldest(
        &self,
        conns: &mut HashMap<String, PooledConnection>,
    ) {
        if let Some(oldest_key) = conns
            .iter()
            .min_by_key(|(_, c)| c.last_used)
            .map(|(k, _)| k.clone())
        {
            conns.remove(&oldest_key);
        }
    }
}

impl Default for ConnectionPool {
    fn default() -> Self {
        Self::new(100, 300) // 100 connections, 5 min idle timeout
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_pool_put_get() {
        let pool = ConnectionPool::new(10, 60);
        pool.put("127.0.0.1:8200".to_string(), Some("aaa".to_string())).await;

        let conn = pool.get("127.0.0.1:8200").await.unwrap();
        assert_eq!(conn.address, "127.0.0.1:8200");
        assert_eq!(conn.pubkey, Some("aaa".to_string()));
    }

    #[tokio::test]
    async fn test_pool_miss() {
        let pool = ConnectionPool::new(10, 60);
        assert!(pool.get("nonexistent").await.is_none());
    }

    #[tokio::test]
    async fn test_pool_remove() {
        let pool = ConnectionPool::new(10, 60);
        pool.put("addr1".to_string(), None).await;
        pool.remove("addr1").await;
        assert!(pool.get("addr1").await.is_none());
    }

    #[tokio::test]
    async fn test_pool_len() {
        let pool = ConnectionPool::new(10, 60);
        pool.put("a".to_string(), None).await;
        pool.put("b".to_string(), None).await;
        assert_eq!(pool.len().await, 2);
    }

    #[tokio::test]
    async fn test_pool_eviction() {
        let pool = ConnectionPool::new(2, 60);
        pool.put("a".to_string(), None).await;
        pool.put("b".to_string(), None).await;
        pool.put("c".to_string(), None).await; // Should evict oldest.
        assert_eq!(pool.len().await, 2);
    }
}
