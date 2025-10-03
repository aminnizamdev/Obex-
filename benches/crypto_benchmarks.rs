use criterion::{black_box, criterion_group, criterion_main, Criterion};
use obex_primitives::{merkle_root, Hash256};
use obex_alpha_i::{chal_index, OBEX_ALPHA_I_VERSION};
use obex_alpha_i::vrf::{ecvrf_verify_beta_tai, VrfPi, VrfPk};
use obex_alpha_iii::{enc_ticket_leaf, TicketRecord};
use obex_alpha_ii::{validate_header, build_header, Header, BeaconInputs, BeaconVerifier, PartRootProvider, TicketRootProvider, TxRootProvider, OBEX_ALPHA_II_VERSION};
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

fn bench_ticket_root(c: &mut Criterion) {
    use obex_primitives::h_tag as h;
    let mut recs: Vec<TicketRecord> = Vec::new();
    for i in 0..200u64 {
        recs.push(TicketRecord {
            ticket_id: [0u8; 32],
            txid: [i as u8; 32],
            sender: [1u8; 32],
            nonce: i,
            amount_u: 1000,
            fee_u: 10,
            s_admit: 1,
            s_exec: 1,
            commit_hash: [2u8; 32],
        });
    }
    let leaves: Vec<Vec<u8>> = recs.iter().map(enc_ticket_leaf).collect();
    c.bench_function("ticket_root_200", |b| {
        b.iter(|| {
            let _ = merkle_root(black_box(&leaves));
        });
    });
}

fn bench_validate_header(c: &mut Criterion) {
    struct BeaconOk;
    impl BeaconVerifier for BeaconOk {
        fn verify(&self, _i: &BeaconInputs<'_>) -> bool { true }
    }
    struct Zero;
    impl TicketRootProvider for Zero { fn compute_ticket_root(&self, _s: u64) -> Hash256 { [0u8;32] } }
    impl PartRootProvider for Zero { fn compute_part_root(&self, _s: u64) -> Hash256 { [0u8;32] } }
    impl TxRootProvider for Zero { fn compute_txroot(&self, _s: u64) -> Hash256 { [0u8;32] } }

    let parent = Header {
        parent_id: [9u8; 32],
        slot: 7,
        obex_version: OBEX_ALPHA_II_VERSION,
        seed_commit: [1u8; 32],
        vdf_y_core: [2u8; 32],
        vdf_y_edge: [3u8; 32],
        vdf_pi: vec![],
        vdf_ell: vec![],
        ticket_root: [0u8; 32],
        part_root: [0u8; 32],
        txroot_prev: [0u8; 32],
    };
    let providers = Zero;
    let h = build_header(&parent, ([4u8;32],[5u8;32],[6u8;32],vec![],vec![]), &providers, &providers, &providers, OBEX_ALPHA_II_VERSION);
    let beacon = BeaconOk;
    c.bench_function("validate_header_ok", |b| {
        b.iter(|| {
            let _ = validate_header(black_box(&h), black_box(&parent), &beacon, &providers, &providers, &providers, OBEX_ALPHA_II_VERSION).unwrap();
        });
    });
}

// Drop legacy registration benches; covered by crate tests and E2E.

criterion_group!(
    benches,
    bench_merkle_root,
    bench_vrf_verify,
    bench_challenge_index,
    bench_ticket_leaf,
    bench_ticket_root,
    bench_validate_header
);
criterion_main!(benches);