use sha3::{Digest, Sha3_256};
use ed25519_dalek as ed25519;
use crate::{types::{ChainId, DOMAIN_TAG, EpochHash, EpochNonce, MerkleRoot, VrfOutput, VrfProof}, ser::le64, domain::{TAG_CHAL, TAG_EPOCH, TAG_KDF, TAG_SEED, TAG_VRFOUT}};

/// E = SHA3_256( DOMAIN_TAG || "VRFOUT" || CHAIN_ID || LE64(epoch_number) || epoch_nonce || y || π )
#[must_use]
pub fn compute_epoch_hash(
    chain_id: &ChainId,
    epoch_number: u64,
    epoch_nonce: &EpochNonce,
    y: &VrfOutput,
    pi: &VrfProof,
) -> EpochHash {
    let mut h = Sha3_256::new();
    h.update(DOMAIN_TAG);
    h.update(TAG_VRFOUT);
    h.update(&chain_id.0);
    h.update(&le64(epoch_number));
    h.update(&epoch_nonce.0);
    h.update(&y.0);
    h.update(&pi.0);
    let digest = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    EpochHash(out)
}

/// M = `DOMAIN_TAG` || "EPOCH" || E || `epoch_nonce` || pk
#[must_use]
pub fn build_m(epoch_hash: &EpochHash, epoch_nonce: &EpochNonce, pk: &ed25519::VerifyingKey) -> Vec<u8> {
    let mut v = Vec::with_capacity(14+5 + 32 + 32 + 32);
    v.extend_from_slice(DOMAIN_TAG);
    v.extend_from_slice(TAG_EPOCH);
    v.extend_from_slice(&epoch_hash.0);
    v.extend_from_slice(&epoch_nonce.0);
    v.extend_from_slice(pk.as_bytes());
    v
}

// Note: A `build_M` alias is intentionally omitted to satisfy pedantic naming lints.

/// SEED = SHA3_256( DOMAIN_TAG || "SEED" || M || σ )
/// K    = SHA3_256( DOMAIN_TAG || "KDF"  || SEED )
#[must_use]
pub fn derive_seed_and_key(m: &[u8], sigma: &ed25519::Signature) -> ([u8; 32], [u8; 32]) {
    let mut h = Sha3_256::new();
    h.update(DOMAIN_TAG);
    h.update(TAG_SEED);
    h.update(m);
    h.update(&sigma.to_bytes());
    let seed_digest = h.finalize();

    let mut h2 = Sha3_256::new();
    h2.update(DOMAIN_TAG);
    h2.update(TAG_KDF);
    h2.update(&seed_digest);
    let k_digest = h2.finalize();

    let mut seed_out = [0u8; 32];
    let mut k_out = [0u8; 32];
    seed_out.copy_from_slice(&seed_digest);
    k_out.copy_from_slice(&k_digest);
    (seed_out, k_out)
}

/// C = SHA3_256( DOMAIN_TAG || "CHAL" || E || epoch_nonce || pk || root )
#[must_use]
pub fn build_challenge_seed(
    epoch_hash: &EpochHash,
    epoch_nonce: &EpochNonce,
    pk: &ed25519::VerifyingKey,
    root: &MerkleRoot,
) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(DOMAIN_TAG);
    h.update(TAG_CHAL);
    h.update(&epoch_hash.0);
    h.update(&epoch_nonce.0);
    h.update(pk.as_bytes());
    h.update(&root.0);
    let digest = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}