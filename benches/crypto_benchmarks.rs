use criterion::{black_box, criterion_group, criterion_main, Criterion};
use obex_primitives::{merkle_root, Hash256};
use obex_alpha_i::{chal_index, OBEX_ALPHA_I_VERSION};
use obex_alpha_i::vrf::{ecvrf_verify_beta_tai, VrfPi, VrfPk};
use obex_alpha_iii::{enc_ticket_leaf, TicketRecord};
use ed25519_dalek::{SigningKey, Signer};
use rand_core::OsRng;

fn bench_merkle_root(c: &mut Criterion) {
    let leaves: Vec<Vec<u8>> = (0..1024).map(|i| vec![i as u8; 32]).collect();
    c.bench_function("merkle_root_1024_leaves", |b| {
        b.iter(|| {
            let _ = merkle_root(black_box(&leaves));
        });
    });
}

fn bench_vrf_verify(c: &mut Criterion) {
    let vk: VrfPk = [0u8; 32];
    let alpha = [0u8; 32];
    let pi: VrfPi = [0u8; 80];
    c.bench_function("ecvrf_tai_verify", |b| {
        b.iter(|| {
            let _ = ecvrf_verify_beta_tai(black_box(&vk), black_box(&alpha), black_box(&pi));
        });
    });
}

fn bench_challenge_index(c: &mut Criterion) {
    let y_prev: Hash256 = [1u8; 32];
    let root: Hash256 = [2u8; 32];
    let vrf_y: Vec<u8> = vec![3u8; 64];
    c.bench_function("chal_index", |b| {
        b.iter(|| {
            let _ = chal_index(black_box(&y_prev), black_box(&root), black_box(&vrf_y), black_box(7u32));
        });
    });
}

fn bench_ticket_leaf(c: &mut Criterion) {
    let rec = TicketRecord {
        ticket_id: [0u8; 32],
        txid: [1u8; 32],
        sender: [2u8; 32],
        nonce: 0,
        amount_u: 1000,
        fee_u: 10,
        s_admit: 1,
        s_exec: 1,
        commit_hash: [3u8; 32],
    };
    c.bench_function("ticket_leaf_encode", |b| {
        b.iter(|| {
            let _ = enc_ticket_leaf(black_box(&rec));
        });
    });
}

// Drop legacy registration benches; covered by crate tests and E2E.

criterion_group!(
    benches,
    bench_merkle_root,
    bench_vrf_verify,
    bench_challenge_index,
    bench_ticket_leaf
);
criterion_main!(benches);