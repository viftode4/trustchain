use std::path::PathBuf;

use anyhow::{bail, Context};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use trustchain_core::{HalfBlock, GENESIS_HASH};

#[derive(Deserialize)]
struct Export {
    pubkey: String,
    chain: Vec<HalfBlock>,
    chain_hash: String,
}

fn main() -> anyhow::Result<()> {
    let path = std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .context("usage: verify-export <export-chain.json>")?;
    let raw = std::fs::read(&path).with_context(|| format!("read {}", path.display()))?;
    let export: Export = serde_json::from_slice(&raw).context("parse export JSON")?;

    let mut aggregate = Sha256::new();
    for (index, block) in export.chain.iter().enumerate() {
        let expected_sequence = index as u64 + 1;
        if block.public_key != export.pubkey {
            bail!("block {expected_sequence}: unexpected public key");
        }
        if block.sequence_number != expected_sequence {
            bail!("block {expected_sequence}: sequence mismatch");
        }
        let expected_previous = if index == 0 {
            GENESIS_HASH
        } else {
            export.chain[index - 1].block_hash.as_str()
        };
        if block.previous_hash != expected_previous {
            bail!("block {expected_sequence}: previous_hash mismatch");
        }
        if !block.verify().context("Ed25519 verification")? {
            bail!("block {expected_sequence}: hash/signature verification failed");
        }
        aggregate.update(block.block_hash.as_bytes());
    }
    if hex::encode(aggregate.finalize()) != export.chain_hash {
        bail!("aggregate chain_hash mismatch");
    }
    println!(
        "verified {} blocks for {} chain_hash={}",
        export.chain.len(),
        export.pubkey,
        export.chain_hash
    );
    Ok(())
}
