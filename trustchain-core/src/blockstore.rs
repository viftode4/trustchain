//! Block storage backends for TrustChain.
//!
//! Provides a `BlockStore` trait with two implementations:
//! - `MemoryBlockStore` — in-memory HashMap (for tests and ephemeral use)
//! - `SqliteBlockStore` — SQLite-backed persistent storage

use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;

use rusqlite::{params, Connection};

use crate::error::{Result, TrustChainError};
use crate::halfblock::HalfBlock;
use crate::types::GENESIS_HASH;

/// A pair of conflicting blocks at the same `(public_key, sequence_number)`.
#[derive(Debug, Clone)]
pub struct DoubleSpend {
    pub block_a: HalfBlock,
    pub block_b: HalfBlock,
}

/// A persisted peer record for loading/saving peer state across restarts.
#[derive(Debug, Clone)]
pub struct PersistentPeer {
    pub pubkey: String,
    pub address: String,
    pub latest_seq: u64,
    pub last_seen_unix_ms: u64,
    pub is_bootstrap: bool,
}

/// Trait for block storage backends.
pub trait BlockStore: Send {
    /// Store a block. Returns error on duplicate `(public_key, sequence_number)`.
    fn add_block(&mut self, block: &HalfBlock) -> Result<()>;

    /// Retrieve a block by public key and sequence number.
    fn get_block(&self, pubkey: &str, seq: u64) -> Result<Option<HalfBlock>>;

    /// Get all blocks for an agent, sorted by sequence number ascending.
    fn get_chain(&self, pubkey: &str) -> Result<Vec<HalfBlock>>;

    /// Find the linked counterpart of a block:
    /// - For a proposal: find the agreement from `link_public_key` that links back.
    /// - For an agreement: find the proposal at `(link_public_key, link_sequence_number)`.
    fn get_linked_block(&self, block: &HalfBlock) -> Result<Option<HalfBlock>>;

    /// Get the highest sequence number for an agent (0 if no blocks).
    fn get_latest_seq(&self, pubkey: &str) -> Result<u64>;

    /// Get the block hash of the latest block (or GENESIS_HASH if chain is empty).
    fn get_head_hash(&self, pubkey: &str) -> Result<String>;

    /// Get blocks from `start_seq` onwards, sorted ascending.
    fn crawl(&self, pubkey: &str, start_seq: u64) -> Result<Vec<HalfBlock>>;

    /// Get all known public keys.
    fn get_all_pubkeys(&self) -> Result<Vec<String>>;

    /// Get total number of blocks stored.
    fn get_block_count(&self) -> Result<usize>;

    /// Record a double-spend: two different blocks at the same (pubkey, seq).
    fn add_double_spend(&mut self, block_a: &HalfBlock, block_b: &HalfBlock) -> Result<()>;

    /// Get all recorded double-spends for a public key.
    fn get_double_spends(&self, pubkey: &str) -> Result<Vec<DoubleSpend>>;

    /// Save or update a peer record.
    fn save_peer(&mut self, peer: &PersistentPeer) -> Result<()>;

    /// Load all persisted peer records.
    fn load_peers(&self) -> Result<Vec<PersistentPeer>>;

    /// Remove a peer record by public key.
    fn remove_stale_peer(&mut self, pubkey: &str) -> Result<()>;
}

// ---------------------------------------------------------------------------
// MemoryBlockStore
// ---------------------------------------------------------------------------

/// In-memory block store using a HashMap. Suitable for tests and ephemeral nodes.
#[derive(Debug, Default)]
pub struct MemoryBlockStore {
    blocks: HashMap<(String, u64), HalfBlock>,
    double_spends: Vec<DoubleSpend>,
    peers: HashMap<String, PersistentPeer>,
}

impl MemoryBlockStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl BlockStore for MemoryBlockStore {
    fn add_block(&mut self, block: &HalfBlock) -> Result<()> {
        let key = (block.public_key.clone(), block.sequence_number);
        if self.blocks.contains_key(&key) {
            return Err(TrustChainError::DuplicateSequence {
                pubkey: block.public_key.clone(),
                seq: block.sequence_number,
            });
        }
        self.blocks.insert(key, block.clone());
        Ok(())
    }

    fn get_block(&self, pubkey: &str, seq: u64) -> Result<Option<HalfBlock>> {
        Ok(self.blocks.get(&(pubkey.to_string(), seq)).cloned())
    }

    fn get_chain(&self, pubkey: &str) -> Result<Vec<HalfBlock>> {
        let mut chain: Vec<_> = self
            .blocks
            .values()
            .filter(|b| b.public_key == pubkey)
            .cloned()
            .collect();
        chain.sort_by_key(|b| b.sequence_number);
        Ok(chain)
    }

    fn get_linked_block(&self, block: &HalfBlock) -> Result<Option<HalfBlock>> {
        if block.is_agreement() {
            // Agreement links to a specific proposal.
            return self.get_block(&block.link_public_key, block.link_sequence_number);
        }
        // Proposal: find agreement from counterparty that links back to this block.
        let found = self.blocks.values().find(|b| {
            b.is_agreement()
                && b.public_key == block.link_public_key
                && b.link_public_key == block.public_key
                && b.link_sequence_number == block.sequence_number
        });
        Ok(found.cloned())
    }

    fn get_latest_seq(&self, pubkey: &str) -> Result<u64> {
        let max_seq = self
            .blocks
            .keys()
            .filter(|(pk, _)| pk == pubkey)
            .map(|(_, seq)| *seq)
            .max()
            .unwrap_or(0);
        Ok(max_seq)
    }

    fn get_head_hash(&self, pubkey: &str) -> Result<String> {
        let latest_seq = self.get_latest_seq(pubkey)?;
        if latest_seq == 0 {
            return Ok(GENESIS_HASH.to_string());
        }
        match self.get_block(pubkey, latest_seq)? {
            Some(block) => Ok(block.block_hash.clone()),
            None => Ok(GENESIS_HASH.to_string()),
        }
    }

    fn crawl(&self, pubkey: &str, start_seq: u64) -> Result<Vec<HalfBlock>> {
        let mut blocks: Vec<_> = self
            .blocks
            .values()
            .filter(|b| b.public_key == pubkey && b.sequence_number >= start_seq)
            .cloned()
            .collect();
        blocks.sort_by_key(|b| b.sequence_number);
        Ok(blocks)
    }

    fn get_all_pubkeys(&self) -> Result<Vec<String>> {
        let mut keys: Vec<String> = self.blocks.keys().map(|(pk, _)| pk.clone()).collect();
        keys.sort();
        keys.dedup();
        Ok(keys)
    }

    fn get_block_count(&self) -> Result<usize> {
        Ok(self.blocks.len())
    }

    fn add_double_spend(&mut self, block_a: &HalfBlock, block_b: &HalfBlock) -> Result<()> {
        self.double_spends.push(DoubleSpend {
            block_a: block_a.clone(),
            block_b: block_b.clone(),
        });
        Ok(())
    }

    fn get_double_spends(&self, pubkey: &str) -> Result<Vec<DoubleSpend>> {
        Ok(self
            .double_spends
            .iter()
            .filter(|ds| ds.block_a.public_key == pubkey || ds.block_b.public_key == pubkey)
            .cloned()
            .collect())
    }

    fn save_peer(&mut self, peer: &PersistentPeer) -> Result<()> {
        self.peers.insert(peer.pubkey.clone(), peer.clone());
        Ok(())
    }

    fn load_peers(&self) -> Result<Vec<PersistentPeer>> {
        Ok(self.peers.values().cloned().collect())
    }

    fn remove_stale_peer(&mut self, pubkey: &str) -> Result<()> {
        self.peers.remove(pubkey);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// SqliteBlockStore
// ---------------------------------------------------------------------------

/// SQLite-backed persistent block store.
///
/// Wraps `Connection` in a `Mutex` for thread-safe access.
pub struct SqliteBlockStore {
    conn: Mutex<Connection>,
}

impl SqliteBlockStore {
    /// Open or create a SQLite database at the given path.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let conn = Connection::open(path)?;
        let store = Self {
            conn: Mutex::new(conn),
        };
        store.init_schema()?;
        Ok(store)
    }

    /// Create an in-memory SQLite database (useful for tests).
    pub fn in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        let store = Self {
            conn: Mutex::new(conn),
        };
        store.init_schema()?;
        Ok(store)
    }

    fn init_schema(&self) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        // Enable WAL mode for concurrent readers (needed for dual-store in consensus).
        conn.execute_batch("PRAGMA journal_mode=WAL;")?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS blocks (
                public_key TEXT NOT NULL,
                sequence_number INTEGER NOT NULL,
                link_public_key TEXT NOT NULL,
                link_sequence_number INTEGER NOT NULL,
                previous_hash TEXT NOT NULL,
                signature TEXT NOT NULL,
                block_type TEXT NOT NULL,
                tx_data TEXT NOT NULL,
                block_hash TEXT NOT NULL,
                timestamp INTEGER NOT NULL,
                insert_time REAL NOT NULL,
                PRIMARY KEY (public_key, sequence_number)
            );
            CREATE INDEX IF NOT EXISTS idx_link ON blocks(link_public_key, link_sequence_number);
            CREATE INDEX IF NOT EXISTS idx_hash ON blocks(block_hash);
            CREATE INDEX IF NOT EXISTS idx_block_type ON blocks(block_type);

            CREATE TABLE IF NOT EXISTS double_spends (
                public_key TEXT NOT NULL,
                sequence_number INTEGER NOT NULL,
                block_hash_a TEXT NOT NULL,
                block_hash_b TEXT NOT NULL,
                block_data_a TEXT NOT NULL,
                block_data_b TEXT NOT NULL,
                detected_at REAL NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_ds_pubkey ON double_spends(public_key);

            CREATE TABLE IF NOT EXISTS peers (
                pubkey TEXT PRIMARY KEY,
                address TEXT NOT NULL,
                latest_seq INTEGER NOT NULL DEFAULT 0,
                last_seen_unix_ms INTEGER NOT NULL,
                is_bootstrap INTEGER NOT NULL DEFAULT 0
            );",
        )?;
        Ok(())
    }

    fn row_to_block(row: &rusqlite::Row<'_>) -> rusqlite::Result<HalfBlock> {
        let tx_data: String = row.get(7)?;
        let transaction: serde_json::Value =
            serde_json::from_str(&tx_data).unwrap_or(serde_json::Value::Null);
        Ok(HalfBlock {
            public_key: row.get(0)?,
            sequence_number: row.get(1)?,
            link_public_key: row.get(2)?,
            link_sequence_number: row.get(3)?,
            previous_hash: row.get(4)?,
            signature: row.get(5)?,
            block_type: row.get(6)?,
            transaction,
            block_hash: row.get(8)?,
            timestamp: row.get(9)?,
        })
    }

    fn insert_time() -> f64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs_f64()
    }
}

impl BlockStore for SqliteBlockStore {
    fn add_block(&mut self, block: &HalfBlock) -> Result<()> {
        let tx_data = serde_json::to_string(&block.transaction)?;
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO blocks (public_key, sequence_number, link_public_key,
             link_sequence_number, previous_hash, signature, block_type, tx_data,
             block_hash, timestamp, insert_time)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                block.public_key,
                block.sequence_number,
                block.link_public_key,
                block.link_sequence_number,
                block.previous_hash,
                block.signature,
                block.block_type,
                tx_data,
                block.block_hash,
                block.timestamp,
                Self::insert_time(),
            ],
        )
        .map_err(|e| {
            if let rusqlite::Error::SqliteFailure(ref err, _) = e {
                if err.code == rusqlite::ErrorCode::ConstraintViolation {
                    return TrustChainError::DuplicateSequence {
                        pubkey: block.public_key.clone(),
                        seq: block.sequence_number,
                    };
                }
            }
            TrustChainError::Storage(e.to_string())
        })?;
        Ok(())
    }

    fn get_block(&self, pubkey: &str, seq: u64) -> Result<Option<HalfBlock>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT public_key, sequence_number, link_public_key, link_sequence_number,
             previous_hash, signature, block_type, tx_data, block_hash, timestamp
             FROM blocks WHERE public_key = ?1 AND sequence_number = ?2",
        )?;
        let mut rows = stmt.query_map(params![pubkey, seq], Self::row_to_block)?;
        match rows.next() {
            Some(Ok(block)) => Ok(Some(block)),
            Some(Err(e)) => Err(TrustChainError::Storage(e.to_string())),
            None => Ok(None),
        }
    }

    fn get_chain(&self, pubkey: &str) -> Result<Vec<HalfBlock>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT public_key, sequence_number, link_public_key, link_sequence_number,
             previous_hash, signature, block_type, tx_data, block_hash, timestamp
             FROM blocks WHERE public_key = ?1 ORDER BY sequence_number ASC",
        )?;
        let rows = stmt.query_map(params![pubkey], Self::row_to_block)?;
        let mut blocks = Vec::new();
        for row in rows {
            blocks.push(row.map_err(|e| TrustChainError::Storage(e.to_string()))?);
        }
        Ok(blocks)
    }

    fn get_linked_block(&self, block: &HalfBlock) -> Result<Option<HalfBlock>> {
        if block.is_agreement() {
            return self.get_block(&block.link_public_key, block.link_sequence_number);
        }
        // Proposal: find the agreement that links back.
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT public_key, sequence_number, link_public_key, link_sequence_number,
             previous_hash, signature, block_type, tx_data, block_hash, timestamp
             FROM blocks WHERE block_type = 'agreement'
             AND public_key = ?1 AND link_public_key = ?2 AND link_sequence_number = ?3
             LIMIT 1",
        )?;
        let mut rows = stmt.query_map(
            params![block.link_public_key, block.public_key, block.sequence_number],
            Self::row_to_block,
        )?;
        match rows.next() {
            Some(Ok(b)) => Ok(Some(b)),
            Some(Err(e)) => Err(TrustChainError::Storage(e.to_string())),
            None => Ok(None),
        }
    }

    fn get_latest_seq(&self, pubkey: &str) -> Result<u64> {
        let conn = self.conn.lock().unwrap();
        let seq: u64 = conn
            .query_row(
                "SELECT COALESCE(MAX(sequence_number), 0) FROM blocks WHERE public_key = ?1",
                params![pubkey],
                |row| row.get(0),
            )
            .map_err(|e| TrustChainError::Storage(e.to_string()))?;
        Ok(seq)
    }

    fn get_head_hash(&self, pubkey: &str) -> Result<String> {
        let conn = self.conn.lock().unwrap();
        let result: rusqlite::Result<String> = conn.query_row(
            "SELECT block_hash FROM blocks WHERE public_key = ?1
             ORDER BY sequence_number DESC LIMIT 1",
            params![pubkey],
            |row| row.get(0),
        );
        match result {
            Ok(hash) => Ok(hash),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(GENESIS_HASH.to_string()),
            Err(e) => Err(TrustChainError::Storage(e.to_string())),
        }
    }

    fn crawl(&self, pubkey: &str, start_seq: u64) -> Result<Vec<HalfBlock>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT public_key, sequence_number, link_public_key, link_sequence_number,
             previous_hash, signature, block_type, tx_data, block_hash, timestamp
             FROM blocks WHERE public_key = ?1 AND sequence_number >= ?2
             ORDER BY sequence_number ASC",
        )?;
        let rows = stmt.query_map(params![pubkey, start_seq], Self::row_to_block)?;
        let mut blocks = Vec::new();
        for row in rows {
            blocks.push(row.map_err(|e| TrustChainError::Storage(e.to_string()))?);
        }
        Ok(blocks)
    }

    fn get_all_pubkeys(&self) -> Result<Vec<String>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare("SELECT DISTINCT public_key FROM blocks ORDER BY public_key")?;
        let rows = stmt.query_map([], |row| row.get(0))?;
        let mut keys = Vec::new();
        for row in rows {
            keys.push(row.map_err(|e| TrustChainError::Storage(e.to_string()))?);
        }
        Ok(keys)
    }

    fn get_block_count(&self) -> Result<usize> {
        let conn = self.conn.lock().unwrap();
        let count: u64 = conn
            .query_row("SELECT COUNT(*) FROM blocks", [], |row| row.get(0))
            .map_err(|e| TrustChainError::Storage(e.to_string()))?;
        Ok(count as usize)
    }

    fn add_double_spend(&mut self, block_a: &HalfBlock, block_b: &HalfBlock) -> Result<()> {
        let data_a = serde_json::to_string(block_a)?;
        let data_b = serde_json::to_string(block_b)?;
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO double_spends (public_key, sequence_number, block_hash_a, block_hash_b,
             block_data_a, block_data_b, detected_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                block_a.public_key,
                block_a.sequence_number,
                block_a.block_hash,
                block_b.block_hash,
                data_a,
                data_b,
                Self::insert_time(),
            ],
        )?;
        Ok(())
    }

    fn get_double_spends(&self, pubkey: &str) -> Result<Vec<DoubleSpend>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT block_data_a, block_data_b FROM double_spends WHERE public_key = ?1",
        )?;
        let rows = stmt.query_map(params![pubkey], |row| {
            let a: String = row.get(0)?;
            let b: String = row.get(1)?;
            Ok((a, b))
        })?;
        let mut result = Vec::new();
        for row in rows {
            let (a_json, b_json) = row.map_err(|e| TrustChainError::Storage(e.to_string()))?;
            let block_a: HalfBlock = serde_json::from_str(&a_json)?;
            let block_b: HalfBlock = serde_json::from_str(&b_json)?;
            result.push(DoubleSpend { block_a, block_b });
        }
        Ok(result)
    }

    fn save_peer(&mut self, peer: &PersistentPeer) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO peers (pubkey, address, latest_seq, last_seen_unix_ms, is_bootstrap)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                peer.pubkey,
                peer.address,
                peer.latest_seq,
                peer.last_seen_unix_ms,
                peer.is_bootstrap as i32,
            ],
        )?;
        Ok(())
    }

    fn load_peers(&self) -> Result<Vec<PersistentPeer>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT pubkey, address, latest_seq, last_seen_unix_ms, is_bootstrap FROM peers",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(PersistentPeer {
                pubkey: row.get(0)?,
                address: row.get(1)?,
                latest_seq: row.get(2)?,
                last_seen_unix_ms: row.get(3)?,
                is_bootstrap: row.get::<_, i32>(4)? != 0,
            })
        })?;
        let mut result = Vec::new();
        for row in rows {
            result.push(row.map_err(|e| TrustChainError::Storage(e.to_string()))?);
        }
        Ok(result)
    }

    fn remove_stale_peer(&mut self, pubkey: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM peers WHERE pubkey = ?1", params![pubkey])?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::halfblock::create_half_block;
    use crate::identity::Identity;
    use crate::types::BlockType;

    fn setup_identity() -> Identity {
        Identity::from_bytes(&[1u8; 32])
    }

    fn make_proposal(
        id: &Identity,
        seq: u64,
        prev_hash: &str,
        counterparty: &str,
    ) -> HalfBlock {
        create_half_block(
            id,
            seq,
            counterparty,
            0,
            prev_hash,
            BlockType::Proposal,
            serde_json::json!({"service": "test"}),
            Some(1000 + seq),
        )
    }

    // Run test suite against a given BlockStore implementation.
    fn test_store(store: &mut dyn BlockStore) {
        let id = setup_identity();
        let counterparty = "b".repeat(64);

        // Empty store.
        assert_eq!(store.get_block_count().unwrap(), 0);
        assert_eq!(store.get_latest_seq(&id.pubkey_hex()).unwrap(), 0);
        assert_eq!(
            store.get_head_hash(&id.pubkey_hex()).unwrap(),
            GENESIS_HASH
        );

        // Add first block.
        let block1 = make_proposal(&id, 1, GENESIS_HASH, &counterparty);
        store.add_block(&block1).unwrap();
        assert_eq!(store.get_block_count().unwrap(), 1);
        assert_eq!(store.get_latest_seq(&id.pubkey_hex()).unwrap(), 1);
        assert_eq!(
            store.get_head_hash(&id.pubkey_hex()).unwrap(),
            block1.block_hash
        );

        // Retrieve it.
        let fetched = store.get_block(&id.pubkey_hex(), 1).unwrap().unwrap();
        assert_eq!(fetched.block_hash, block1.block_hash);
        assert_eq!(fetched.transaction, serde_json::json!({"service": "test"}));

        // Add second block.
        let block2 = make_proposal(&id, 2, &block1.block_hash, &counterparty);
        store.add_block(&block2).unwrap();
        assert_eq!(store.get_block_count().unwrap(), 2);
        assert_eq!(store.get_latest_seq(&id.pubkey_hex()).unwrap(), 2);

        // Get chain.
        let chain = store.get_chain(&id.pubkey_hex()).unwrap();
        assert_eq!(chain.len(), 2);
        assert_eq!(chain[0].sequence_number, 1);
        assert_eq!(chain[1].sequence_number, 2);

        // Crawl from seq 2.
        let crawled = store.crawl(&id.pubkey_hex(), 2).unwrap();
        assert_eq!(crawled.len(), 1);
        assert_eq!(crawled[0].sequence_number, 2);

        // Duplicate should fail.
        let dup_result = store.add_block(&block1);
        assert!(dup_result.is_err());

        // All pubkeys.
        let keys = store.get_all_pubkeys().unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0], id.pubkey_hex());

        // Non-existent block.
        assert!(store.get_block("nonexistent", 1).unwrap().is_none());
    }

    fn test_linked_blocks(store: &mut dyn BlockStore) {
        let alice = Identity::from_bytes(&[1u8; 32]);
        let bob = Identity::from_bytes(&[2u8; 32]);

        // Alice creates a proposal for Bob.
        let proposal = create_half_block(
            &alice,
            1,
            &bob.pubkey_hex(),
            0,
            GENESIS_HASH,
            BlockType::Proposal,
            serde_json::json!({"service": "compute"}),
            Some(1000),
        );
        store.add_block(&proposal).unwrap();

        // Bob creates an agreement linking to Alice's proposal.
        let agreement = create_half_block(
            &bob,
            1,
            &alice.pubkey_hex(),
            1, // links to Alice's seq 1
            GENESIS_HASH,
            BlockType::Agreement,
            serde_json::json!({"service": "compute"}),
            Some(1001),
        );
        store.add_block(&agreement).unwrap();

        // From proposal, find agreement.
        let linked = store.get_linked_block(&proposal).unwrap().unwrap();
        assert_eq!(linked.block_hash, agreement.block_hash);

        // From agreement, find proposal.
        let linked = store.get_linked_block(&agreement).unwrap().unwrap();
        assert_eq!(linked.block_hash, proposal.block_hash);
    }

    #[test]
    fn test_memory_store() {
        let mut store = MemoryBlockStore::new();
        test_store(&mut store);
    }

    #[test]
    fn test_memory_store_linked() {
        let mut store = MemoryBlockStore::new();
        test_linked_blocks(&mut store);
    }

    #[test]
    fn test_sqlite_store() {
        let mut store = SqliteBlockStore::in_memory().unwrap();
        test_store(&mut store);
    }

    #[test]
    fn test_sqlite_store_linked() {
        let mut store = SqliteBlockStore::in_memory().unwrap();
        test_linked_blocks(&mut store);
    }

    #[test]
    fn test_sqlite_persistent() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");

        let id = setup_identity();
        let counterparty = "b".repeat(64);

        // Write blocks.
        {
            let mut store = SqliteBlockStore::open(&db_path).unwrap();
            let block = make_proposal(&id, 1, GENESIS_HASH, &counterparty);
            store.add_block(&block).unwrap();
        }

        // Reopen and verify.
        {
            let store = SqliteBlockStore::open(&db_path).unwrap();
            let block = store.get_block(&id.pubkey_hex(), 1).unwrap().unwrap();
            assert_eq!(block.sequence_number, 1);
            assert_eq!(store.get_block_count().unwrap(), 1);
        }
    }

    #[test]
    fn test_peer_persistence_sqlite() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("peers.db");

        // Save peers.
        {
            let mut store = SqliteBlockStore::open(&db_path).unwrap();
            store.save_peer(&PersistentPeer {
                pubkey: "aaa".to_string(),
                address: "http://127.0.0.1:8202".to_string(),
                latest_seq: 5,
                last_seen_unix_ms: 1700000000000,
                is_bootstrap: true,
            }).unwrap();
            store.save_peer(&PersistentPeer {
                pubkey: "bbb".to_string(),
                address: "http://127.0.0.1:8212".to_string(),
                latest_seq: 3,
                last_seen_unix_ms: 1700000001000,
                is_bootstrap: false,
            }).unwrap();
        }

        // Reopen and load.
        {
            let store = SqliteBlockStore::open(&db_path).unwrap();
            let peers = store.load_peers().unwrap();
            assert_eq!(peers.len(), 2);
            let aaa = peers.iter().find(|p| p.pubkey == "aaa").unwrap();
            assert_eq!(aaa.address, "http://127.0.0.1:8202");
            assert_eq!(aaa.latest_seq, 5);
            assert!(aaa.is_bootstrap);
        }
    }

    #[test]
    fn test_peer_persistence_memory() {
        let mut store = MemoryBlockStore::new();
        store.save_peer(&PersistentPeer {
            pubkey: "aaa".to_string(),
            address: "addr1".to_string(),
            latest_seq: 1,
            last_seen_unix_ms: 1000,
            is_bootstrap: false,
        }).unwrap();

        let peers = store.load_peers().unwrap();
        assert_eq!(peers.len(), 1);

        store.remove_stale_peer("aaa").unwrap();
        let peers = store.load_peers().unwrap();
        assert_eq!(peers.len(), 0);
    }

    #[test]
    fn test_peer_remove_sqlite() {
        let mut store = SqliteBlockStore::in_memory().unwrap();
        store.save_peer(&PersistentPeer {
            pubkey: "aaa".to_string(),
            address: "addr1".to_string(),
            latest_seq: 1,
            last_seen_unix_ms: 1000,
            is_bootstrap: false,
        }).unwrap();

        assert_eq!(store.load_peers().unwrap().len(), 1);
        store.remove_stale_peer("aaa").unwrap();
        assert_eq!(store.load_peers().unwrap().len(), 0);
    }
}
