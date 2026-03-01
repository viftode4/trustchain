mod helpers;

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use trustchain_core::{
    halfblock::create_half_block,
    types::{BlockType, GENESIS_HASH},
    Identity,
};

fn bench_ed25519_sign(c: &mut Criterion) {
    let identity = Identity::from_bytes(&[1u8; 32]);
    let data = b"benchmark payload data for signing";

    c.bench_function("ed25519_sign", |b| {
        b.iter(|| identity.sign(black_box(data)))
    });
}

fn bench_ed25519_verify(c: &mut Criterion) {
    let identity = Identity::from_bytes(&[1u8; 32]);
    let data = b"benchmark payload data for signing";
    let signature = identity.sign(data);
    let pubkey = identity.pubkey_bytes();

    c.bench_function("ed25519_verify", |b| {
        b.iter(|| Identity::verify(black_box(data), black_box(&signature), black_box(&pubkey)))
    });
}

fn bench_block_hash(c: &mut Criterion) {
    let identity = Identity::from_bytes(&[1u8; 32]);
    let bob = Identity::from_bytes(&[2u8; 32]);
    let block = create_half_block(
        &identity,
        1,
        &bob.pubkey_hex(),
        0,
        GENESIS_HASH,
        BlockType::Proposal,
        serde_json::json!({"interaction_type": "service"}),
        Some(1000),
    );

    c.bench_function("block_compute_hash", |b| {
        b.iter(|| black_box(&block).compute_hash())
    });
}

fn bench_block_create_sign(c: &mut Criterion) {
    let identity = Identity::from_bytes(&[1u8; 32]);
    let bob_pk = Identity::from_bytes(&[2u8; 32]).pubkey_hex();
    let tx = serde_json::json!({"interaction_type": "service", "outcome": "completed"});

    c.bench_function("block_create_sign", |b| {
        b.iter(|| {
            create_half_block(
                black_box(&identity),
                1,
                black_box(&bob_pk),
                0,
                GENESIS_HASH,
                BlockType::Proposal,
                tx.clone(),
                Some(1000),
            )
        })
    });
}

fn bench_block_verify(c: &mut Criterion) {
    let identity = Identity::from_bytes(&[1u8; 32]);
    let bob = Identity::from_bytes(&[2u8; 32]);
    let block = create_half_block(
        &identity,
        1,
        &bob.pubkey_hex(),
        0,
        GENESIS_HASH,
        BlockType::Proposal,
        serde_json::json!({"interaction_type": "service"}),
        Some(1000),
    );

    c.bench_function("block_verify", |b| b.iter(|| black_box(&block).verify()));
}

fn bench_identity_generate(c: &mut Criterion) {
    c.bench_function("identity_generate", |b| b.iter(Identity::generate));
}

criterion_group!(
    benches,
    bench_ed25519_sign,
    bench_ed25519_verify,
    bench_block_hash,
    bench_block_create_sign,
    bench_block_verify,
    bench_identity_generate,
);
criterion_main!(benches);
