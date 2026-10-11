## Local Notes
- Read `CLAUDE.md` here before making non-trivial changes; it is the detailed Rust-side guide.
- Verification: `cargo build`, `cargo test --workspace`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo fmt --all`.
- Keep timestamps as `u64` milliseconds, preserve canonical JSON hashing, and do not change `GENESIS_HASH`, `GENESIS_SEQ`, or `UNKNOWN_SEQ`.
- `BlockStore` must remain `Send` but not `Sync`; do not add a `Sync` bound.
- Any wire-format, block-field, hash, or delegation-constant change requires matching updates in `../trustchain-py` and `../trustchain-js`.
