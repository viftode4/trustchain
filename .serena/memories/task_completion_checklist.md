# After Completing a Task

1. `cargo test --workspace` — all 224+ tests must pass
2. `cargo clippy --workspace -- -D warnings` — must be clean
3. `cargo fmt --all -- --check` — formatting check
4. No wire-format breaking changes without updating Python SDK + TS SDK
