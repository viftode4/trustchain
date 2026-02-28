//! Delegation management — records, storage, and validation.
//!
//! Tracks active delegations, revocations, and identity successions.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;

use crate::error::{Result, TrustChainError};

/// A stored delegation record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationRecord {
    pub delegation_id: String,
    pub delegator_pubkey: String,
    pub delegate_pubkey: String,
    pub scope: Vec<String>,
    pub max_depth: u32,
    pub issued_at: u64,
    pub expires_at: u64,
    pub delegation_block_hash: String,
    pub agreement_block_hash: Option<String>,
    pub parent_delegation_id: Option<String>,
    pub revoked: bool,
    pub revocation_block_hash: Option<String>,
}

impl DelegationRecord {
    /// Whether this delegation is currently active (not expired, not revoked).
    pub fn is_active(&self, now_ms: u64) -> bool {
        !self.revoked && now_ms < self.expires_at
    }
}

/// A succession record linking old identity to new identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuccessionRecord {
    pub old_pubkey: String,
    pub new_pubkey: String,
    pub succession_block_hash: String,
}

/// Trait for delegation storage backends.
pub trait DelegationStore: Send + Sync {
    /// Store a delegation record.
    fn add_delegation(&mut self, record: DelegationRecord) -> Result<()>;

    /// Get a delegation by its ID.
    fn get_delegation(&self, delegation_id: &str) -> Result<Option<DelegationRecord>>;

    /// Get the delegation where the given pubkey is the delegate.
    fn get_delegation_by_delegate(&self, delegate_pubkey: &str) -> Result<Option<DelegationRecord>>;

    /// List all active delegations where the given pubkey is the delegator.
    fn get_delegations_by_delegator(&self, delegator_pubkey: &str) -> Result<Vec<DelegationRecord>>;

    /// List all delegations (active and revoked) involving a pubkey (as delegator or delegate).
    fn get_delegations_for_pubkey(&self, pubkey: &str) -> Result<Vec<DelegationRecord>>;

    /// Revoke a delegation by ID.
    fn revoke_delegation(&mut self, delegation_id: &str, revocation_block_hash: &str) -> Result<()>;

    /// Check if a delegation has been revoked.
    fn is_revoked(&self, delegation_id: &str) -> Result<bool>;

    /// Store a succession record.
    fn add_succession(&mut self, record: SuccessionRecord) -> Result<()>;

    /// Resolve identity: follow succession chain to find the current pubkey.
    fn resolve_identity(&self, pubkey: &str) -> Result<String>;

    /// Check if a pubkey has ever been a delegate (active, revoked, or expired).
    fn is_delegate(&self, pubkey: &str) -> Result<bool>;

    /// Get the delegation count.
    fn delegation_count(&self) -> Result<usize>;
}

// ---------------------------------------------------------------------------
// MemoryDelegationStore
// ---------------------------------------------------------------------------

/// In-memory delegation store for tests.
#[derive(Debug, Default)]
pub struct MemoryDelegationStore {
    delegations: HashMap<String, DelegationRecord>,
    successions: Vec<SuccessionRecord>,
}

impl MemoryDelegationStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl DelegationStore for MemoryDelegationStore {
    fn add_delegation(&mut self, record: DelegationRecord) -> Result<()> {
        self.delegations.insert(record.delegation_id.clone(), record);
        Ok(())
    }

    fn get_delegation(&self, delegation_id: &str) -> Result<Option<DelegationRecord>> {
        Ok(self.delegations.get(delegation_id).cloned())
    }

    fn get_delegation_by_delegate(&self, delegate_pubkey: &str) -> Result<Option<DelegationRecord>> {
        Ok(self
            .delegations
            .values()
            .find(|d| d.delegate_pubkey == delegate_pubkey && !d.revoked)
            .cloned())
    }

    fn get_delegations_by_delegator(&self, delegator_pubkey: &str) -> Result<Vec<DelegationRecord>> {
        Ok(self
            .delegations
            .values()
            .filter(|d| d.delegator_pubkey == delegator_pubkey)
            .cloned()
            .collect())
    }

    fn get_delegations_for_pubkey(&self, pubkey: &str) -> Result<Vec<DelegationRecord>> {
        Ok(self
            .delegations
            .values()
            .filter(|d| d.delegator_pubkey == pubkey || d.delegate_pubkey == pubkey)
            .cloned()
            .collect())
    }

    fn revoke_delegation(&mut self, delegation_id: &str, revocation_block_hash: &str) -> Result<()> {
        if let Some(d) = self.delegations.get_mut(delegation_id) {
            d.revoked = true;
            d.revocation_block_hash = Some(revocation_block_hash.to_string());
            Ok(())
        } else {
            Err(TrustChainError::delegation("", format!("Unknown delegation: {delegation_id}")))
        }
    }

    fn is_revoked(&self, delegation_id: &str) -> Result<bool> {
        match self.delegations.get(delegation_id) {
            Some(d) => Ok(d.revoked),
            None => Err(TrustChainError::delegation("", format!("Unknown delegation: {delegation_id}"))),
        }
    }

    fn add_succession(&mut self, record: SuccessionRecord) -> Result<()> {
        self.successions.push(record);
        Ok(())
    }

    fn resolve_identity(&self, pubkey: &str) -> Result<String> {
        let mut current = pubkey.to_string();
        let mut seen = std::collections::HashSet::new();
        loop {
            if !seen.insert(current.clone()) {
                break; // cycle guard
            }
            if let Some(s) = self.successions.iter().find(|s| s.old_pubkey == current) {
                current = s.new_pubkey.clone();
            } else {
                break;
            }
        }
        Ok(current)
    }

    fn is_delegate(&self, pubkey: &str) -> Result<bool> {
        Ok(self.delegations.values().any(|d| d.delegate_pubkey == pubkey))
    }

    fn delegation_count(&self) -> Result<usize> {
        Ok(self.delegations.len())
    }
}

// ---------------------------------------------------------------------------
// SqliteDelegationStore
// ---------------------------------------------------------------------------

/// SQLite-backed delegation store. Shares a connection with SqliteBlockStore
/// (or uses its own).
pub struct SqliteDelegationStore {
    conn: Mutex<rusqlite::Connection>,
}

impl SqliteDelegationStore {
    /// Open or create a SQLite delegation store at the given path.
    pub fn open(path: impl AsRef<std::path::Path>) -> Result<Self> {
        let conn = rusqlite::Connection::open(path)?;
        let store = Self {
            conn: Mutex::new(conn),
        };
        store.init_schema()?;
        Ok(store)
    }

    /// Create an in-memory SQLite delegation store (for tests).
    pub fn in_memory() -> Result<Self> {
        let conn = rusqlite::Connection::open_in_memory()?;
        let store = Self {
            conn: Mutex::new(conn),
        };
        store.init_schema()?;
        Ok(store)
    }

    fn init_schema(&self) -> Result<()> {
        let conn = self.conn.lock().map_err(|_| TrustChainError::Storage("delegation store lock poisoned".to_string()))?;
        conn.execute_batch("PRAGMA journal_mode=WAL;")?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS delegations (
                delegation_id TEXT PRIMARY KEY,
                delegator_pubkey TEXT NOT NULL,
                delegate_pubkey TEXT NOT NULL,
                scope TEXT NOT NULL,
                max_depth INTEGER NOT NULL,
                issued_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                delegation_block_hash TEXT NOT NULL,
                agreement_block_hash TEXT,
                parent_delegation_id TEXT,
                revoked INTEGER NOT NULL DEFAULT 0,
                revocation_block_hash TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_deleg_delegator ON delegations(delegator_pubkey);
            CREATE INDEX IF NOT EXISTS idx_deleg_delegate ON delegations(delegate_pubkey);
            CREATE INDEX IF NOT EXISTS idx_deleg_delegator_revoked ON delegations(delegator_pubkey, revoked);
            CREATE INDEX IF NOT EXISTS idx_deleg_expires ON delegations(expires_at);

            CREATE TABLE IF NOT EXISTS successions (
                old_pubkey TEXT NOT NULL,
                new_pubkey TEXT NOT NULL,
                succession_block_hash TEXT NOT NULL,
                PRIMARY KEY (old_pubkey)
            );",
        )?;
        Ok(())
    }
}

impl DelegationStore for SqliteDelegationStore {
    fn add_delegation(&mut self, record: DelegationRecord) -> Result<()> {
        let conn = self.conn.lock().map_err(|_| TrustChainError::Storage("delegation store lock poisoned".to_string()))?;
        let scope_json = serde_json::to_string(&record.scope)?;
        conn.execute(
            "INSERT OR REPLACE INTO delegations
             (delegation_id, delegator_pubkey, delegate_pubkey, scope, max_depth,
              issued_at, expires_at, delegation_block_hash, agreement_block_hash,
              parent_delegation_id, revoked, revocation_block_hash)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            rusqlite::params![
                record.delegation_id,
                record.delegator_pubkey,
                record.delegate_pubkey,
                scope_json,
                record.max_depth,
                record.issued_at,
                record.expires_at,
                record.delegation_block_hash,
                record.agreement_block_hash,
                record.parent_delegation_id,
                record.revoked as i32,
                record.revocation_block_hash,
            ],
        )?;
        Ok(())
    }

    fn get_delegation(&self, delegation_id: &str) -> Result<Option<DelegationRecord>> {
        let conn = self.conn.lock().map_err(|_| TrustChainError::Storage("delegation store lock poisoned".to_string()))?;
        let mut stmt = conn.prepare(
            "SELECT delegation_id, delegator_pubkey, delegate_pubkey, scope, max_depth,
                    issued_at, expires_at, delegation_block_hash, agreement_block_hash,
                    parent_delegation_id, revoked, revocation_block_hash
             FROM delegations WHERE delegation_id = ?1",
        )?;
        let mut rows = stmt.query(rusqlite::params![delegation_id])?;
        match rows.next()? {
            Some(row) => Ok(Some(row_to_delegation(row)?)),
            None => Ok(None),
        }
    }

    fn get_delegation_by_delegate(&self, delegate_pubkey: &str) -> Result<Option<DelegationRecord>> {
        let conn = self.conn.lock().map_err(|_| TrustChainError::Storage("delegation store lock poisoned".to_string()))?;
        let mut stmt = conn.prepare(
            "SELECT delegation_id, delegator_pubkey, delegate_pubkey, scope, max_depth,
                    issued_at, expires_at, delegation_block_hash, agreement_block_hash,
                    parent_delegation_id, revoked, revocation_block_hash
             FROM delegations WHERE delegate_pubkey = ?1 AND revoked = 0
             ORDER BY issued_at DESC LIMIT 1",
        )?;
        let mut rows = stmt.query(rusqlite::params![delegate_pubkey])?;
        match rows.next()? {
            Some(row) => Ok(Some(row_to_delegation(row)?)),
            None => Ok(None),
        }
    }

    fn get_delegations_by_delegator(&self, delegator_pubkey: &str) -> Result<Vec<DelegationRecord>> {
        let conn = self.conn.lock().map_err(|_| TrustChainError::Storage("delegation store lock poisoned".to_string()))?;
        let mut stmt = conn.prepare(
            "SELECT delegation_id, delegator_pubkey, delegate_pubkey, scope, max_depth,
                    issued_at, expires_at, delegation_block_hash, agreement_block_hash,
                    parent_delegation_id, revoked, revocation_block_hash
             FROM delegations WHERE delegator_pubkey = ?1",
        )?;
        let rows = stmt.query_map(rusqlite::params![delegator_pubkey], |row| row_to_delegation(row))?;
        let mut result = Vec::new();
        for row in rows {
            result.push(row.map_err(|e| TrustChainError::Storage(e.to_string()))?);
        }
        Ok(result)
    }

    fn get_delegations_for_pubkey(&self, pubkey: &str) -> Result<Vec<DelegationRecord>> {
        let conn = self.conn.lock().map_err(|_| TrustChainError::Storage("delegation store lock poisoned".to_string()))?;
        let mut stmt = conn.prepare(
            "SELECT delegation_id, delegator_pubkey, delegate_pubkey, scope, max_depth,
                    issued_at, expires_at, delegation_block_hash, agreement_block_hash,
                    parent_delegation_id, revoked, revocation_block_hash
             FROM delegations WHERE delegator_pubkey = ?1 OR delegate_pubkey = ?1",
        )?;
        let rows = stmt.query_map(rusqlite::params![pubkey], |row| row_to_delegation(row))?;
        let mut result = Vec::new();
        for row in rows {
            result.push(row.map_err(|e| TrustChainError::Storage(e.to_string()))?);
        }
        Ok(result)
    }

    fn revoke_delegation(&mut self, delegation_id: &str, revocation_block_hash: &str) -> Result<()> {
        let conn = self.conn.lock().map_err(|_| TrustChainError::Storage("delegation store lock poisoned".to_string()))?;
        let updated = conn.execute(
            "UPDATE delegations SET revoked = 1, revocation_block_hash = ?2 WHERE delegation_id = ?1",
            rusqlite::params![delegation_id, revocation_block_hash],
        )?;
        if updated == 0 {
            return Err(TrustChainError::delegation("", format!("Unknown delegation: {delegation_id}")));
        }
        Ok(())
    }

    fn is_revoked(&self, delegation_id: &str) -> Result<bool> {
        let conn = self.conn.lock().map_err(|_| TrustChainError::Storage("delegation store lock poisoned".to_string()))?;
        let revoked: bool = conn
            .query_row(
                "SELECT revoked FROM delegations WHERE delegation_id = ?1",
                rusqlite::params![delegation_id],
                |row| row.get(0),
            )
            .map_err(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => {
                    TrustChainError::delegation("", format!("Unknown delegation: {delegation_id}"))
                }
                other => TrustChainError::Storage(other.to_string()),
            })?;
        Ok(revoked)
    }

    fn add_succession(&mut self, record: SuccessionRecord) -> Result<()> {
        let conn = self.conn.lock().map_err(|_| TrustChainError::Storage("delegation store lock poisoned".to_string()))?;
        conn.execute(
            "INSERT OR REPLACE INTO successions (old_pubkey, new_pubkey, succession_block_hash)
             VALUES (?1, ?2, ?3)",
            rusqlite::params![record.old_pubkey, record.new_pubkey, record.succession_block_hash],
        )?;
        Ok(())
    }

    fn resolve_identity(&self, pubkey: &str) -> Result<String> {
        let conn = self.conn.lock().map_err(|_| TrustChainError::Storage("delegation store lock poisoned".to_string()))?;
        let mut current = pubkey.to_string();
        let mut seen = std::collections::HashSet::new();
        loop {
            if !seen.insert(current.clone()) {
                break;
            }
            let next: Option<String> = conn
                .query_row(
                    "SELECT new_pubkey FROM successions WHERE old_pubkey = ?1",
                    rusqlite::params![&current],
                    |row| row.get(0),
                )
                .ok();
            match next {
                Some(new) => current = new,
                None => break,
            }
        }
        Ok(current)
    }

    fn is_delegate(&self, pubkey: &str) -> Result<bool> {
        let conn = self.conn.lock().map_err(|_| TrustChainError::Storage("lock poisoned".to_string()))?;
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM delegations WHERE delegate_pubkey = ?1",
            rusqlite::params![pubkey],
            |row| row.get(0),
        ).unwrap_or(0);
        Ok(count > 0)
    }

    fn delegation_count(&self) -> Result<usize> {
        let conn = self.conn.lock().map_err(|_| TrustChainError::Storage("delegation store lock poisoned".to_string()))?;
        let count: i64 = conn.query_row("SELECT COUNT(*) FROM delegations", [], |row| row.get(0))?;
        Ok(count as usize)
    }
}

fn row_to_delegation(row: &rusqlite::Row<'_>) -> rusqlite::Result<DelegationRecord> {
    let scope_json: String = row.get(3)?;
    let scope: Vec<String> =
        serde_json::from_str(&scope_json).unwrap_or_default();
    let revoked_int: i32 = row.get(10)?;
    Ok(DelegationRecord {
        delegation_id: row.get(0)?,
        delegator_pubkey: row.get(1)?,
        delegate_pubkey: row.get(2)?,
        scope,
        max_depth: row.get(4)?,
        issued_at: row.get(5)?,
        expires_at: row.get(6)?,
        delegation_block_hash: row.get(7)?,
        agreement_block_hash: row.get(8)?,
        parent_delegation_id: row.get(9)?,
        revoked: revoked_int != 0,
        revocation_block_hash: row.get(11)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_delegation_store_roundtrip() {
        let mut store = MemoryDelegationStore::new();

        let record = DelegationRecord {
            delegation_id: "deleg-1".to_string(),
            delegator_pubkey: "aaa".to_string(),
            delegate_pubkey: "bbb".to_string(),
            scope: vec!["compute".to_string()],
            max_depth: 1,
            issued_at: 1000,
            expires_at: 5000,
            delegation_block_hash: "hash1".to_string(),
            agreement_block_hash: Some("hash2".to_string()),
            parent_delegation_id: None,
            revoked: false,
            revocation_block_hash: None,
        };

        store.add_delegation(record).unwrap();
        assert_eq!(store.delegation_count().unwrap(), 1);

        let fetched = store.get_delegation("deleg-1").unwrap().unwrap();
        assert_eq!(fetched.delegator_pubkey, "aaa");
        assert_eq!(fetched.delegate_pubkey, "bbb");
        assert!(fetched.is_active(2000));
        assert!(!fetched.is_active(6000)); // expired

        let by_delegate = store.get_delegation_by_delegate("bbb").unwrap().unwrap();
        assert_eq!(by_delegate.delegation_id, "deleg-1");

        store.revoke_delegation("deleg-1", "rev-hash").unwrap();
        assert!(store.is_revoked("deleg-1").unwrap());

        let revoked = store.get_delegation("deleg-1").unwrap().unwrap();
        assert!(!revoked.is_active(2000)); // revoked
    }

    #[test]
    fn test_memory_succession_resolve() {
        let mut store = MemoryDelegationStore::new();
        store
            .add_succession(SuccessionRecord {
                old_pubkey: "key1".to_string(),
                new_pubkey: "key2".to_string(),
                succession_block_hash: "h1".to_string(),
            })
            .unwrap();
        store
            .add_succession(SuccessionRecord {
                old_pubkey: "key2".to_string(),
                new_pubkey: "key3".to_string(),
                succession_block_hash: "h2".to_string(),
            })
            .unwrap();

        assert_eq!(store.resolve_identity("key1").unwrap(), "key3");
        assert_eq!(store.resolve_identity("key3").unwrap(), "key3");
    }

    #[test]
    fn test_sqlite_delegation_store_roundtrip() {
        let mut store = SqliteDelegationStore::in_memory().unwrap();

        let record = DelegationRecord {
            delegation_id: "deleg-1".to_string(),
            delegator_pubkey: "aaa".to_string(),
            delegate_pubkey: "bbb".to_string(),
            scope: vec!["compute".to_string(), "storage".to_string()],
            max_depth: 2,
            issued_at: 1000,
            expires_at: 5000,
            delegation_block_hash: "hash1".to_string(),
            agreement_block_hash: Some("hash2".to_string()),
            parent_delegation_id: None,
            revoked: false,
            revocation_block_hash: None,
        };

        store.add_delegation(record).unwrap();
        assert_eq!(store.delegation_count().unwrap(), 1);

        let fetched = store.get_delegation("deleg-1").unwrap().unwrap();
        assert_eq!(fetched.scope, vec!["compute", "storage"]);

        let for_pubkey = store.get_delegations_for_pubkey("aaa").unwrap();
        assert_eq!(for_pubkey.len(), 1);

        store.revoke_delegation("deleg-1", "rev-hash").unwrap();
        assert!(store.is_revoked("deleg-1").unwrap());
    }

    #[test]
    fn test_sqlite_succession_resolve() {
        let mut store = SqliteDelegationStore::in_memory().unwrap();
        store
            .add_succession(SuccessionRecord {
                old_pubkey: "key1".to_string(),
                new_pubkey: "key2".to_string(),
                succession_block_hash: "h1".to_string(),
            })
            .unwrap();

        assert_eq!(store.resolve_identity("key1").unwrap(), "key2");
        assert_eq!(store.resolve_identity("key2").unwrap(), "key2");
    }
}
