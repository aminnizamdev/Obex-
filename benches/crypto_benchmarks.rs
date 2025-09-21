use criterion::{black_box, criterion_group, criterion_main, Criterion};
use obex_engine_i::{MerklePath, MerkleRoot, verify_merkle_path, mk_chain_vrf, VrfProof, Vrf, ChainId, EpochNonce, VrfOutput, EpochHash, Registration, derive_challenge_indices, compute_leaf, verify_registration};
use obex_engine_i::types::N_LOG2;
use ed25519_dalek::{SigningKey, Signer};
use rand_core::OsRng;

fn bench_merkle_verify(c: &mut Criterion) {
    let index = 12345u32;
    let leaf = [0u8; 32];
    let path = MerklePath {
        path: vec![[0u8; 32]; N_LOG2 as usize],
    };
    let root = MerkleRoot([0u8; 32]);
    
    c.bench_function("merkle_verify", |b| {
        b.iter(|| {
            let _ = verify_merkle_path(
                black_box(index),
                black_box(&leaf),
                black_box(&path),
                black_box(&root)
            );
        });
    });
}

fn bench_vrf_verify(c: &mut Criterion) {
    let pk_bytes = [0u8; 32];
    let vrf = mk_chain_vrf(pk_bytes);
    let input = [0u8; 86];
    let proof = VrfProof([0u8; 80]);
    
    c.bench_function("vrf_verify", |b| {
        b.iter(|| {
            let _ = vrf.verify(
                black_box(&input),
                black_box(&proof)
            );
        });
    });
}

fn bench_challenge_derivation(c: &mut Criterion) {
    let chain_id = ChainId([0u8; 32]);
    let epoch_nonce = EpochNonce([1u8; 32]);
    let vrf_output = VrfOutput([2u8; 64]);
    let vrf_proof = VrfProof([3u8; 80]);
    let epoch_hash = EpochHash([4u8; 32]);
    let root = MerkleRoot([5u8; 32]);
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    let signature = signing_key.sign(b"test");
    
    let reg = Registration {
        chain_id: &chain_id,
        epoch_number: 42u64,
        epoch_nonce: &epoch_nonce,
        vrf_proof: &vrf_proof,
        vrf_output: &vrf_output,
        epoch_hash: &epoch_hash,
        pk: &verifying_key,
        sig: &signature,
        root: &root,
    };
    let epoch = 1u32;
    
    c.bench_function("challenge_derivation", |b| {
        b.iter(|| {
            let _ = derive_challenge_indices(
                black_box(&reg),
                black_box(epoch)
            );
        });
    });
}

fn bench_dataset_generation(c: &mut Criterion) {
    let key = [0u8; 32];
    
    c.bench_function("dataset_leaf_compute", |b| {
        b.iter(|| {
            let _ = compute_leaf(
                black_box(&key),
                black_box(12345u32)
            );
        });
    });
}

fn bench_registration_verify(c: &mut Criterion) {
    let chain_id = ChainId([0u8; 32]);
    let epoch_nonce = EpochNonce([1u8; 32]);
    let vrf_output = VrfOutput([2u8; 64]);
    let vrf_proof = VrfProof([3u8; 80]);
    let epoch_hash = EpochHash([4u8; 32]);
    let root = MerkleRoot([5u8; 32]);
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    let signature = signing_key.sign(b"test");
    
    let reg = Registration {
        chain_id: &chain_id,
        epoch_number: 42u64,
        epoch_nonce: &epoch_nonce,
        vrf_proof: &vrf_proof,
        vrf_output: &vrf_output,
        epoch_hash: &epoch_hash,
        pk: &verifying_key,
        sig: &signature,
        root: &root,
    };
    let epoch = 1u32;
    let pk_bytes = [0u8; 32];
    let vrf = mk_chain_vrf(pk_bytes);
    let merkle_root = MerkleRoot([0u8; 32]);
    let challenge_opens = vec![];
    
    c.bench_function("registration_verify", |b| {
        b.iter(|| {
            let _ = verify_registration(
                black_box(&reg),
                black_box(epoch),
                black_box(&vrf),
                black_box(&merkle_root),
                black_box(&challenge_opens)
            );
        });
    });
}

criterion_group!(
    benches,
    bench_merkle_verify,
    bench_vrf_verify,
    bench_challenge_derivation,
    bench_dataset_generation,
    bench_registration_verify
);
criterion_main!(benches);