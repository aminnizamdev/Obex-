use sha3::{Digest, Sha3_256};
use crate::{types::{MerklePath, MerkleRoot, N_LEAVES}, errors::Step1Error};

#[inline]
fn parent_hash(left: &[u8;32], right: &[u8;32]) -> [u8;32] {
    let mut h = Sha3_256::new();
    h.update(left);
    h.update(right);
    let digest = h.finalize();
    let mut out = [0u8;32];
    out.copy_from_slice(&digest);
    out
}

/// Verify a Merkle authentication path for (index, leaf) up to root.
/// Verify a Merkle path for a given leaf.
///
/// # Errors
///
/// Returns `Step1Error` if the computed root doesn't match the expected root.
pub fn verify_merkle_path(index: u32, leaf: &[u8;32], path: &MerklePath, root: &MerkleRoot) -> Result<(), Step1Error> {
    if index >= N_LEAVES { return Err(Step1Error::OutOfRangeIndex { index, max: N_LEAVES }); }
    // Expected path length is depth (26), but allow equal or greater and ignore surplus if any.
    let mut acc = *leaf;
    let mut idx = u64::from(index);
    for sib in &path.path {
        if (idx & 1) == 0 {
            acc = parent_hash(&acc, sib);
        } else {
            acc = parent_hash(sib, &acc);
        }
        idx >>= 1;
    }
    if acc != root.0 { return Err(Step1Error::MerklePathMismatch); }
    Ok(())
}