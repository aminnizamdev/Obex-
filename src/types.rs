use core::convert::TryFrom;
use crate::errors::Step1Error;

pub const DOMAIN_TAG: &[u8; 14] = br#"[Iota]_|::"v1""#; // 14-byte ASCII per README
pub const ALPHA_LEN: usize = 14 + 32 + 8 + 32; // 86 bytes
pub const VRF_OUTPUT_LEN: usize = 64;          // y
pub const VRF_PROOF_LEN: usize  = 80;          // π = γ(32)||c(16)||s(32)
pub const LEAF_LEN: usize = 32;                // 32-byte leaves
pub const MERKLE_ROOT_LEN: usize = 32;         // BLAKE3 root
pub const N_LOG2: u8 = 26;                     // tree depth 26
pub const N_LEAVES: u32 = 1u32 << N_LOG2;      // 67,108,864
pub const CHALLENGE_COUNT: usize = 32;          // number of challenges per registration

// Fixed-size newtypes prevent misuse
#[repr(transparent)] pub struct ChainId(pub [u8; 32]);
#[repr(transparent)] pub struct EpochNonce(pub [u8; 32]);
#[repr(transparent)] pub struct VrfOutput(pub [u8; VRF_OUTPUT_LEN]);
#[repr(transparent)] pub struct VrfProof(pub  [u8; VRF_PROOF_LEN]);
#[repr(transparent)] pub struct MerkleRoot(pub [u8; MERKLE_ROOT_LEN]);
#[repr(transparent)] pub struct EpochHash(pub [u8; 32]);

// Exact-sized decode helpers
macro_rules! impl_tryfrom_slice {
    ($t:ty, $len:expr, $name:literal) => {
        impl TryFrom<&[u8]> for $t {
            type Error = Step1Error;
            fn try_from(b: &[u8]) -> Result<Self, Self::Error> {
                if b.len() != $len {
                    return Err(Step1Error::InvalidLength { expected: $len, got: b.len() });
                }
                let mut arr = [0u8; $len];
                arr.copy_from_slice(b);
                Ok(Self(arr))
            }
        }
    }
}
impl_tryfrom_slice!(ChainId, 32, "ChainId");
impl_tryfrom_slice!(EpochNonce, 32, "EpochNonce");
impl_tryfrom_slice!(VrfOutput, VRF_OUTPUT_LEN, "VrfOutput");
impl_tryfrom_slice!(VrfProof,  VRF_PROOF_LEN,  "VrfProof");
impl_tryfrom_slice!(MerkleRoot, MERKLE_ROOT_LEN, "MerkleRoot");
impl_tryfrom_slice!(EpochHash, 32, "EpochHash");

// Protocol structs per README/API table
pub struct Registration<'a> {
    pub chain_id: &'a ChainId,
    pub epoch_number: u64,
    pub epoch_nonce: &'a EpochNonce,
    pub vrf_proof: &'a VrfProof,
    pub vrf_output: &'a VrfOutput,
    pub epoch_hash: &'a EpochHash, // 32-byte BLAKE3 digest
    pub pk: &'a ed25519_dalek::VerifyingKey,
    pub sig: &'a ed25519_dalek::Signature,
    pub root: &'a MerkleRoot,
}

pub struct MerklePath {
    pub path: Vec<[u8; 32]>, // from leaf up to but not including the root
}

pub struct ChallengeOpen<'a> {
    pub index: u32,          // must be < N_LEAVES
    pub leaf: &'a [u8; 32],  // exact leaf bytes
    pub path: &'a MerklePath,
}

#[derive(Clone, Copy)]
pub struct Ticket {
    pub chain_id: [u8; 32],
    pub epoch_number: u64,
    pub epoch_hash: [u8; 32],
    pub epoch_nonce: [u8; 32],
    pub pk: [u8; 32],
    pub root: [u8; 32],
    pub valid_from: u64,
    pub valid_to: u64,
}