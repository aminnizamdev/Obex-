use crate::{
    types::{CHALLENGE_COUNT, ChallengeOpen, EpochHash, MerkleRoot, Registration}, errors::Step1Error, vrf::Vrf, merkle::verify_merkle_path,
    challenge::derive_challenge_indices, dataset::compute_leaf, ser::build_alpha, hashers::{compute_epoch_hash, build_m, derive_seed_and_key}
};

/// Complete Step-1 registration verification pipeline.
/// Verify a registration with VRF proof and challenge openings.
///
/// # Errors
///
/// Returns `Step1Error` if VRF verification fails, challenge indices are invalid, or challenge openings are incorrect.
pub fn verify_registration<V: Vrf>(
    reg: &Registration,
    epoch: u32,
    vrf: &V,
    merkle_root: &MerkleRoot,
    challenge_opens: &[ChallengeOpen]
) -> Result<(), Step1Error> {
    verify_registration_succinct(vrf, reg, challenge_opens, epoch, merkle_root)
}

/// Verify a single challenge opening.
///
/// # Errors
///
/// Returns `Step1Error` if the Merkle path verification fails or the computed leaf doesn't match.
pub fn verify_challenge_open(
    dataset_key: &[u8; 32],
    index: u32,
    open: &ChallengeOpen,
    merkle_root: &MerkleRoot
) -> Result<(), Step1Error> {
    let expected_leaf = compute_leaf(dataset_key, index);
    verify_merkle_path(index, &expected_leaf, open.path, merkle_root)
}

/// Batch verification for multiple registrations.
///
/// # Errors
///
/// Returns `Step1Error` if any individual registration verification fails during the batch process.
pub fn verify_registrations_batch<V: Vrf>(
    registrations: &[(Registration, Vec<ChallengeOpen>)],
    epoch: u32,
    vrf: &V,
    merkle_root: &MerkleRoot
) -> Result<Vec<bool>, Step1Error> {
    let mut results = Vec::with_capacity(registrations.len());
    
    for (reg, opens) in registrations {
        let is_valid = verify_registration(reg, epoch, vrf, merkle_root, opens).is_ok();
        results.push(is_valid);
    }
    
    Ok(results)
}

/// Verify a succinct registration per the Step-1 spec.
/// Steps: α build → VRF verify → E → M → signature check → (seed,K) → challenge C → indices → verify openings.
///
/// # Errors
/// Returns `Step1Error` when input sizes are invalid, cryptographic checks fail,
/// challenge indices mismatch, Merkle paths don't authenticate to the declared root,
/// or the signature/VRF verification fails.
pub fn verify_registration_succinct<V: Vrf>(
    vrf: &V,
    reg: &Registration,
    openings: &[ChallengeOpen],
    epoch: u32,
    declared_root: &MerkleRoot,
) -> Result<(), Step1Error> {
    if openings.len() != CHALLENGE_COUNT { return Err(Step1Error::InvalidLength { expected: CHALLENGE_COUNT, got: openings.len() }); }

    // α
    let alpha = build_alpha(reg.chain_id, reg.epoch_number, reg.epoch_nonce);
    // VRF verify
    let y = vrf.verify(&alpha, reg.vrf_proof)?;
    // E
    let e: EpochHash = compute_epoch_hash(reg.chain_id, reg.epoch_number, reg.epoch_nonce, &y, reg.vrf_proof);
    // M
    let m = build_m(&e, reg.epoch_nonce, reg.pk);
    // Signature
    reg.pk.verify_strict(&m, reg.sig).map_err(|_| Step1Error::InvalidSignature)?;
    // (seed, K)
    let (_seed, k) = derive_seed_and_key(&m, reg.sig);
    // Derive challenge indices
    let indices = derive_challenge_indices(reg, epoch)?;
    if indices.len() != CHALLENGE_COUNT { return Err(Step1Error::InvalidLength { expected: CHALLENGE_COUNT, got: indices.len() }); }

    // Verify each opening
    for (open, idx) in openings.iter().zip(indices.iter()) {
        if open.index != *idx { return Err(Step1Error::ChallengeIndicesMismatch); }
        // Recompute leaf from K
        let expected_leaf = compute_leaf(&k, open.index);
        if &expected_leaf != open.leaf { return Err(Step1Error::MerklePathMismatch); }
        verify_merkle_path(open.index, open.leaf, open.path, declared_root)?;
    }
    Ok(())
}