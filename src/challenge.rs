use crate::{types::{Registration, N_LEAVES, CHALLENGE_COUNT}, errors::Step1Error, hashers::build_challenge_seed};
use sha3::{Digest, Sha3_256};

/// Derive challenge indices using uniform rejection sampling.
/// Derive challenge indices from registration data.
///
/// # Errors
///
/// Returns `Step1Error` if the challenge seed generation fails or insufficient valid indices are found.
pub fn derive_challenge_indices(reg: &Registration, _epoch: u32) -> Result<Vec<u32>, Step1Error> {
    let seed = build_challenge_seed(reg.epoch_hash, reg.epoch_nonce, reg.pk, reg.root);
    let mut indices = Vec::with_capacity(CHALLENGE_COUNT);
    let mut counter = 0u64;
    
    while indices.len() < CHALLENGE_COUNT {
        let mut hasher = Sha3_256::new();
        hasher.update(&seed);
        hasher.update(&counter.to_le_bytes());
        let digest = hasher.finalize();
        let bytes: [u8; 32] = digest.into();
        // Extract 4 bytes and interpret as u32
        let candidate = u32::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3]
        ]);
        
        // Uniform rejection sampling: accept if candidate < N_LEAVES
        if candidate < N_LEAVES {
            indices.push(candidate);
        }
        
        counter += 1;
        
        // Safety check to prevent infinite loops
        if counter > 1_000_000 {
            return Err(Step1Error::ChallengeDerivationFailed);
        }
    }
    
    Ok(indices)
}

/// Verify that challenge indices are properly derived.
/// Verify that challenge indices match the expected derivation.
///
/// # Errors
///
/// Returns `Step1Error` if the derived indices don't match the provided indices.
pub fn verify_challenge_indices(reg: &Registration, epoch: u32, indices: &[u32]) -> Result<(), Step1Error> {
    if indices.len() != CHALLENGE_COUNT {
        return Err(Step1Error::InvalidLength {
            expected: CHALLENGE_COUNT,
            got: indices.len()
        });
    }
    
    let expected = derive_challenge_indices(reg, epoch)?;
    if indices != expected {
        return Err(Step1Error::ChallengeIndicesMismatch);
    }
    
    Ok(())
}