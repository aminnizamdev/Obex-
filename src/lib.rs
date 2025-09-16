#![expect(
    clippy::implicit_return,
    clippy::min_ident_chars,
    clippy::question_mark_used,
    reason = "These lints are disabled for better code readability and conciseness in cryptographic implementations"
)]
//! Step 1: Sybil-deterrence (byte-precise, exact to agreed spec)
//!
//! Fixed cryptographic choices agreed:
//! - Hash/XOF: BLAKE3 (32-byte output).
//! - Signature: Ed25519 (pk = 32 B, sig = 64 B).
//! - Domain tag (ASCII bytes): `[Iota]_|::"v1"`
//! - Chain identifier: exactly 32 bytes (no 0x prefix when rendered).
//! - Epoch number: u64 LITTLE-ENDIAN when encoded into digests.
//! - Epoch nonce: 32 bytes (fresh each epoch).
//! - Dataset: 2 GiB = `2_147_483_648` bytes, leaf size = 32 bytes,
//!   N = `67_108_864` (= 2^26) leaves. Merkle depth = 26.
//!
//! Leaves:
//!   Leaf[i] = BLAKE3(key=K, input=LE64(i))
//!
//! Merkle internal nodes:
//!   node = BLAKE3( left || right ), each child exactly 32 bytes.
//!
//! Epoch hash E (in BLAKE3) from VRF transcript:
//!   E = BLAKE3( `DOMAIN_TAG` || "VRFOUT" || `CHAIN_ID` || `LE64(epoch_number)` || `epoch_nonce` || y || π )
//!   where y is the 64-byte VRF output and π is the 80-byte VRF proof
//
//! Identity binding message to sign (Ed25519):
//!   M = `DOMAIN_TAG` || "EPOCH" || E || `epoch_nonce` || pk
//!   σ = `Sign_sk(M)`
//
//! Seed / key:
//!   SEED = BLAKE3( `DOMAIN_TAG` || "SEED" || M || σ )
//!   K    = BLAKE3( `DOMAIN_TAG` || "KDF"  || SEED )
//
//! Challenge seed and indices:
//!   C = BLAKE3( `DOMAIN_TAG` || "CHAL" || E || `epoch_nonce` || pk || root )
//!   Expand to distinct indices in [0, N-1] by hashing with LE64(counter) and rejection of duplicates.
//
//! Ticket (issuer-signed):
//!   Serialize(TICKET) = `DOMAIN_TAG` || `CHAIN_ID` || `LE64(epoch_number)` || E || `epoch_nonce`
//!                        || pk || root || `LE64(valid_from)` || `LE64(valid_to)`
//!   `ticket_sig` = `Ed25519_Sign(issuer_sk, BLAKE3("TICKET" || Serialize(TICKET)))`
//
//! NOTE: VRF scheme itself is abstracted via a trait so you can plug your concrete VRF.
//!       Default implementation uses ECVRF-RISTRETTO255-SHA512 (RFC 9381).

use blake3::{hash as blake3_hash, keyed_hash as blake3_keyed_hash, Hasher};
use ed25519_dalek::{Signer as _, Verifier as _, Signature, SigningKey, VerifyingKey};
use std::collections::hash_set::HashSet;

// ECVRF modules
pub mod ecvrf_traits;
pub mod ecvrf_ristretto255;



// Re-export VRF types and traits
pub use ecvrf_traits::{Vrf as NewVrf, VrfError, VrfOutput as VrfOutputNew, VrfProof as VrfProofNew};
pub use ecvrf_ristretto255::EcVrfRistretto255;

/// Create a VRF instance for chain validation.
/// 
/// Creates a VRF instance with full proving and verification capabilities.
/// Uses real cryptographic operations for both proving and verification.
/// 
/// # Arguments
/// * `_pk_bytes` - Public key bytes (currently unused, reserved for verification-only mode)
/// 
/// # Returns
/// A VRF instance implementing the `NewVrf` trait with real cryptographic capabilities
#[must_use]
pub fn mk_chain_vrf(_pk_bytes: [u8; 32]) -> impl NewVrf {
     // Create a new VRF instance with real cryptographic keypair
     // This enables both proving and verification with actual ECVRF operations
     EcVrfRistretto255::new()
}

/// Create a VRF instance from a specific secret key for deterministic proving.
/// 
/// This allows creating a VRF instance with a known secret key for consistent
/// proof generation across multiple runs.
/// 
/// # Arguments
/// * `secret_bytes` - 32-byte secret key
/// 
/// # Returns
/// A VRF instance with the specified secret key
/// 
/// # Errors
/// Returns `VrfError` if the secret key bytes are invalid
pub fn mk_chain_vrf_from_secret(secret_bytes: &[u8; 32]) -> Result<impl NewVrf, VrfError> {
    EcVrfRistretto255::from_secret_bytes(secret_bytes)
}

// ---------- Constants (exact bytes / sizes) ----------

/// `DOMAIN_TAG` = ASCII bytes of `[Iota]_|::"v1"` (exactly 14 bytes)
pub const DOMAIN_TAG: &[u8; 14] = b"[Iota]_|::\"v1\"";

/// Dataset size: 2 GiB total dataset size
pub const DATASET_BYTES: u64 = 0x8000_0000; // 2 GiB
/// Leaf size: 32 bytes per leaf
pub const LEAF_BYTES: usize = 32;
/// Leaf size as u64 for arithmetic without casts
pub const LEAF_BYTES_U64: u64 = 32;
/// Number of leaves: 67,108,864 leaves (2^26)
pub const N_LEAVES: u64 = 0x0400_0000; // 67_108_864 (2^26)
/// Merkle tree depth: 26 levels (perfect binary tree)
pub const MERKLE_DEPTH: usize = 26; // perfect tree since N = 2^26

// ---------- Types ----------

/// Chain identifier: exactly 32 bytes
pub type ChainId = [u8; 32];       // exactly 32 bytes
/// Epoch nonce: exactly 32 bytes (fresh each epoch)
pub type EpochNonce = [u8; 32];    // exactly 32 bytes
/// Epoch hash: 32-byte hash derived from VRF transcript
pub type EpochHash = [u8; 32];     // E
/// Merkle tree leaf: 32-byte leaf node
pub type Leaf = [u8; 32];          // 32-byte leaf
/// Merkle tree internal node: 32-byte internal node
pub type Node = [u8; 32];          // 32-byte merkle node
/// Merkle tree root: 32-byte root hash
pub type Root = [u8; 32];          // 32-byte merkle root
/// VRF output: 64-byte output from ECVRF-RISTRETTO255-SHA512
pub type VrfOutput = [u8; 64];     // ECVRF-RISTRETTO255-SHA512: exactly 64 bytes
/// VRF proof: 80-byte proof (gamma(32) || c(16) || s(32))
pub type VrfProof = [u8; 80];      // ECVRF proof: gamma(32) || c(16) || s(32)

/// Error type for verification failures / malformed inputs
#[derive(Debug)]
pub enum Step1Error {
    BadVrf,
    BadEpochHash,
    BadSignature,
    BadLeafOpen,
    BadMerklePathLength,
    DuplicateChallenge,
    IndexOutOfRange,
    TicketBadSig,
    TicketExpired,
}

impl std::fmt::Display for Step1Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadVrf => write!(f, "VRF verification failed"),
            Self::BadEpochHash => write!(f, "Bad epoch hash"),
            Self::BadSignature => write!(f, "Invalid signature"),
            Self::BadLeafOpen => write!(f, "Bad leaf opening"),
            Self::BadMerklePathLength => write!(f, "Invalid Merkle path length"),
            Self::DuplicateChallenge => write!(f, "Duplicate challenge"),
            Self::IndexOutOfRange => write!(f, "Index out of range"),
            Self::TicketBadSig => write!(f, "Invalid ticket signature"),
            Self::TicketExpired => write!(f, "Ticket expired"),
        }
    }
}



impl std::error::Error for Step1Error {}

// ---------- Helpers (LE64 encoding & concat) ----------

/// Convert a u64 to little-endian byte array.
/// 
/// # Arguments
/// * `x` - The u64 value to convert
/// 
/// # Returns
/// 8-byte array in little-endian format
#[inline]
#[must_use]
pub const fn le64(x: u64) -> [u8; 8] {
    x.to_le_bytes()
}

#[inline]
fn cat(bytes: &[&[u8]]) -> Vec<u8> {
    let total: usize = bytes.iter().map(|b| b.len()).sum();
    let mut out = Vec::with_capacity(total);
    for b in bytes {
        out.extend_from_slice(b);
    }
    out
}

// ---------- Legacy VRF trait compatibility ----------

/// Legacy VRF trait for backward compatibility with existing code
/// New code should use `vrf::Vrf` directly
pub trait Vrf {
    /// Verify a VRF proof.
    /// 
    /// # Arguments
    /// * `alpha` - The VRF input
    /// * `proof` - The VRF proof to verify
    /// 
    /// # Returns
    /// The VRF output if verification succeeds
    /// 
    /// # Errors
    /// Returns `Step1Error::BadVrf` if verification fails
    fn verify(&self, alpha: &[u8], proof: &VrfProof) -> Result<VrfOutput, Step1Error>;
}

/// Adapter to bridge between legacy VRF interface and new VRF trait.
/// 
/// Provides compatibility layer for existing code while transitioning to new VRF interface.
pub struct LegacyVrfAdapter<T: NewVrf> {
    inner: T,
}

impl<T: NewVrf> LegacyVrfAdapter<T> {
    /// Create a new adapter wrapping a VRF implementation.
    /// 
    /// # Arguments
    /// * `vrf` - The VRF implementation to wrap
    /// 
    /// # Returns
    /// A new adapter instance
    pub const fn new(vrf: T) -> Self {
        Self { inner: vrf }
    }
}

impl<T: NewVrf> Vrf for LegacyVrfAdapter<T> {
    fn verify(&self, alpha: &[u8], proof: &VrfProof) -> Result<VrfOutput, Step1Error> {
        match self.inner.verify(alpha, proof) {
            Ok(output) => Ok(output.0), // Convert from vrf::VrfOutput struct to [u8; 64]
            Err(VrfError::BadLength | VrfError::VerifyFailed | VrfError::InternalError | VrfError::InvalidPublicKey | VrfError::InvalidProof | VrfError::VerificationFailed) => Err(Step1Error::BadVrf),
        }
    }
}

/// Build VRF input alpha from chain parameters.
/// 
/// alpha = `DOMAIN_TAG` || `CHAIN_ID` || `LE64(epoch_number)` || `epoch_nonce`
/// 
/// # Arguments
/// * `chain_id` - The chain identifier (32 bytes)
/// * `epoch_number` - The epoch number as u64
/// * `epoch_nonce` - The epoch nonce (32 bytes)
/// 
/// # Returns
/// The VRF input alpha (86 bytes total)
#[must_use]
pub fn build_alpha(chain_id: &ChainId, epoch_number: u64, epoch_nonce: &EpochNonce) -> Vec<u8> {
    cat(&[
        DOMAIN_TAG,
        chain_id,
        &le64(epoch_number),
        epoch_nonce,
    ])
}

/// Compute epoch hash E from VRF transcript.
/// 
/// E = `BLAKE3(DOMAIN_TAG` || "VRFOUT" || `CHAIN_ID` || `LE64(epoch_number)` || `epoch_nonce` || y || π)
/// 
/// # Arguments
/// * `chain_id` - The chain identifier (32 bytes)
/// * `epoch_number` - The epoch number as u64
/// * `epoch_nonce` - The epoch nonce (32 bytes)
/// * `y` - The VRF output (64 bytes)
/// * `pi` - The VRF proof (80 bytes)
/// 
/// # Returns
/// The epoch hash E (32 bytes)
#[must_use]
pub fn compute_epoch_hash(
    chain_id: &ChainId,
    epoch_number: u64,
    epoch_nonce: &EpochNonce,
    y: &[u8],
    pi: &[u8],
) -> EpochHash {
    let mut h = Hasher::new();
    h.update(DOMAIN_TAG);
    h.update(b"VRFOUT");
    h.update(chain_id);
    h.update(&le64(epoch_number));
    h.update(epoch_nonce);
    h.update(y);
    h.update(pi);
    h.finalize().into()
}

// ---------- Identity binding (Ed25519) ----------

/// Build message M to sign for identity binding.
/// 
/// M = `DOMAIN_TAG` || "EPOCH" || E || `epoch_nonce` || pk
/// 
/// # Arguments
/// * `epoch_hash` - The epoch hash E (32 bytes)
/// * `epoch_nonce` - The epoch nonce (32 bytes)
/// * `pk` - The Ed25519 public key (32 bytes)
/// 
/// # Returns
/// The message M to be signed (115 bytes total)
#[expect(non_snake_case, reason = "Function name follows cryptographic protocol specification")]
#[must_use]
pub fn build_M(epoch_hash: &EpochHash, epoch_nonce: &EpochNonce, pk: &VerifyingKey) -> Vec<u8> {
    cat(&[
        DOMAIN_TAG,
        b"EPOCH",
        epoch_hash,
        epoch_nonce,
        pk.as_bytes(), // 32 B
    ])
}

/// Verify Ed25519 signature for identity binding.
/// 
/// # Arguments
/// * `pk` - The Ed25519 public key
/// * `message` - The message that was signed
/// * `sig` - The Ed25519 signature to verify
/// 
/// # Returns
/// Ok(()) if signature is valid, `Err(Step1Error::BadSignature)` otherwise
/// 
/// # Errors
/// Returns `Step1Error::BadSignature` if the signature verification fails
#[expect(non_snake_case, reason = "Variable name follows cryptographic protocol specification")]
pub fn verify_identity_sig(
    pk: &VerifyingKey,
    M: &[u8],
    sig: &Signature,
) -> Result<(), Step1Error> {
    pk.verify(M, sig).map_err(|_| Step1Error::BadSignature)
}

/// Derive SEED and K
/// Derive SEED and key K from signed message.
/// 
/// SEED = `BLAKE3(DOMAIN_TAG || "SEED" || M || σ)`
/// K = `BLAKE3(DOMAIN_TAG || "KDF" || SEED)`
/// 
/// # Arguments
/// * `M` - The signed message
/// * `sig` - The Ed25519 signature
/// 
/// # Returns
/// Tuple of (SEED, K) both 32 bytes each
#[expect(non_snake_case, reason = "Variable name follows cryptographic protocol specification")]
#[must_use]
pub fn derive_seed_and_key(M: &[u8], sig: &Signature) -> ( [u8; 32], [u8; 32] ) {
    // SEED
    let mut h_seed = Hasher::new();
    h_seed.update(DOMAIN_TAG);
    h_seed.update(b"SEED");
    h_seed.update(M);
    h_seed.update(&sig.to_bytes()); // 64 B
    let seed: [u8; 32] = h_seed.finalize().into();

    // K
    let mut h_k = Hasher::new();
    h_k.update(DOMAIN_TAG);
    h_k.update(b"KDF");
    h_k.update(&seed);
    let k: [u8; 32] = h_k.finalize().into();

    (seed, k)
}

// ---------- Leaves & Merkle ----------

/// Compute a dataset leaf using keyed BLAKE3.
/// 
/// Leaf[i] = BLAKE3(key=K, input=LE64(i))
/// 
/// # Arguments
/// * `k` - The 32-byte key K
/// * `i` - The leaf index
/// 
/// # Returns
/// The computed leaf (32 bytes)
#[inline]
#[must_use]
pub fn compute_leaf(k: &[u8; 32], i: u64) -> Leaf {
    let v = blake3_keyed_hash(k, &le64(i));
    *v.as_bytes()
}

/// Compute parent node from two child nodes.
/// 
/// parent = BLAKE3(left || right)
/// 
/// # Arguments
/// * `left` - The left child node (32 bytes)
/// * `right` - The right child node (32 bytes)
/// 
/// # Returns
/// The parent node (32 bytes)
#[inline]
#[must_use]
pub fn parent(left: &Node, right: &Node) -> Node {
    blake3_hash(&cat(&[left, right])).into()
}

/// Build Merkle root from an iterator of leaves (exact length `N_LEAVES`).
///
/// Note: For an actual 2 GiB dataset (67,108,864 leaves), this requires processing at scale.
/// This function expresses the *exact* hashing rules; production systems should implement
/// level-by-level reduction to avoid storing all leaves at once.
///
/// The hashing rule itself (child order, concatenation) is byte-precise here.
/// 
/// # Arguments
/// * `leaves` - Iterator over leaf values
/// 
/// # Returns
/// The computed Merkle root
/// 
/// # Errors
/// Returns `Step1Error::IndexOutOfRange` if the tree structure is invalid
/// 
/// # Panics
/// Panics if the tree size becomes odd (should not happen with perfect binary trees)
pub fn merkle_root_from_leaves<I>(mut leaves: I) -> Result<Root, Step1Error>
where
    I: Iterator<Item = Leaf>,
{
    // Collect leaves level (must be exactly N_LEAVES)
    let mut level: Vec<Node> = Vec::with_capacity(usize::try_from(N_LEAVES).expect("N_LEAVES should fit in usize"));
    for (idx, leaf) in (0_u64..N_LEAVES).zip(&mut leaves) {
        let _ = idx; // ensure caller actually provides N_LEAVES
        level.push(leaf);
    }
    if level.len() != usize::try_from(N_LEAVES).expect("N_LEAVES should fit in usize") {
        return Err(Step1Error::IndexOutOfRange);
    }

    // Reduce level by level
    let mut size = level.len();
    while size > 1 {
        assert!((size % 2 == 0), "Level size must remain even (perfect tree)");
        let mut next = Vec::with_capacity(size / 2);
        for i in (0..size).step_by(2) {
            let p = blake3_hash(&cat(&[&level[i], &level[i + 1]])).into();
            next.push(p);
        }
        level = next;
        size = level.len();
    }

    Ok(level[0])
}

/// Generate the full 2GB dataset and compute its Merkle root
/// This function creates all `N_LEAVES` (67,108,864) leaves in memory
/// as specified in the Obex Engine I documentation
/// 
/// # Arguments
/// * `k` - The 32-byte key for deterministic leaf generation
/// 
/// # Returns
/// A tuple containing the vector of all leaves and the computed Merkle root
/// 
/// # Errors
/// Returns `Step1Error::IndexOutOfRange` if any internal calculations fail
/// 
/// # Panics
/// Panics if `N_LEAVES` doesn't fit in `usize`
pub fn generate_full_dataset(k: &[u8; 32]) -> Result<(Vec<Leaf>, Root), Step1Error> {
    let cap = usize::try_from(N_LEAVES).expect("N_LEAVES should fit in usize");
    
    // Use chunked allocation to avoid 2GB allocation failure
    // Allocate in smaller chunks and build incrementally
    let chunk_size = 1024 * 1024; // 1M leaves per chunk (32MB each)
    // Avoid a single up-front 2 GiB allocation which may fail on some Windows setups
    // Grow the vector incrementally instead (dataset size remains exactly the same)
    let mut leaves: Vec<Leaf> = Vec::new();

    // Generate leaves in chunks to avoid memory allocation issues
    let mut i = 0u64;
    while i < N_LEAVES {
        let chunk_end = std::cmp::min(i + chunk_size as u64, N_LEAVES);
        for leaf_idx in i..chunk_end {
            leaves.push(compute_leaf(k, leaf_idx));
        }
        i = chunk_end;
    }

    // Compute Merkle root without duplicating the entire leaf level in memory.
    // Build parents directly from the leaves, then iteratively reduce level-by-level.
    let level_len = cap; // number of elements at the current level

    // Edge-case guard (not expected for this project where N_LEAVES = 2^26 > 1)
    if level_len == 1 {
        let first = leaves[0];
        return Ok((leaves, first));
    }

    // First reduction: from leaves to first parent level
    let mut parents: Vec<Node> = Vec::with_capacity(level_len / 2);
    for i in (0..level_len).step_by(2) {
        let p: Node = blake3_hash(&cat(&[&leaves[i], &leaves[i + 1]])).into();
        parents.push(p);
    }

    // Reduce level by level until root
    let mut size = parents.len();
    while size > 1 {
        assert!(size % 2 == 0, "Level size must remain even (perfect tree)");
        let mut next: Vec<Node> = Vec::with_capacity(size / 2);
        for i in (0..size).step_by(2) {
            let p: Node = blake3_hash(&cat(&[&parents[i], &parents[i + 1]])).into();
            next.push(p);
        }
        parents = next;
        size = parents.len();
    }

    let root = parents[0];

    Ok((leaves, root))
}

/// Generate Merkle path for a specific leaf index from the full dataset
/// This function computes the authentication path for succinct verification
/// 
/// # Arguments
/// * `leaves` - Array of leaf values (must be exactly `N_LEAVES` in length)
/// * `index` - Index of the leaf to generate path for
/// 
/// # Returns
/// Merkle path from leaf to root
/// 
/// # Errors
/// Returns `Step1Error::IndexOutOfRange` if index is invalid or leaves length doesn't match `N_LEAVES`
/// 
/// # Panics
/// Panics if `N_LEAVES` or calculated indices don't fit in `usize`
pub fn generate_merkle_path(leaves: &[Leaf], index: u64) -> Result<MerklePath, Step1Error> {
    if index >= N_LEAVES {
        return Err(Step1Error::IndexOutOfRange);
    }
    
    if leaves.len() != usize::try_from(N_LEAVES).expect("N_LEAVES should fit in usize") {
        return Err(Step1Error::IndexOutOfRange);
    }
    
    let mut path = Vec::with_capacity(MERKLE_DEPTH);
    let mut was_right = Vec::with_capacity(MERKLE_DEPTH);
    
    // Memory-efficient approach: build tree level by level without copying entire dataset
    let mut current_index = index;
    let mut level_size = N_LEAVES;
    
    for level in 0..MERKLE_DEPTH {
        // Determine if current index is right child
        let is_right = (current_index & 1) == 1;
        was_right.push(is_right);
        
        // Get sibling index
        let sibling_index = if is_right {
            current_index.saturating_sub(1)
        } else {
            current_index.saturating_add(1)
        };
        
        // Calculate sibling node efficiently without storing entire level
        let sibling_node = if level == 0 {
            // At leaf level, directly access from leaves array
            let sib_usize = usize::try_from(sibling_index).map_err(|_| Step1Error::IndexOutOfRange)?;
            *leaves.get(sib_usize).ok_or(Step1Error::IndexOutOfRange)?
        } else {
            // For higher levels, compute sibling by building minimal subtree
            compute_node_at_level(leaves, sibling_index, level)?
        };
        
        path.push(sibling_node);
        
        // Move to parent level
        current_index >>= 1u32;
        level_size >>= 1u32;
        
        if level_size == 1 {
            break;
        }
    }
    
    Ok(MerklePath { path, was_right })
}

// Helper function to compute a specific node at a given level without storing entire level
fn compute_node_at_level(leaves: &[Leaf], node_index: u64, level: usize) -> Result<Node, Step1Error> {
    if level == 0 {
        let leaf_idx = usize::try_from(node_index).map_err(|_| Step1Error::IndexOutOfRange)?;
        return Ok(*leaves.get(leaf_idx).ok_or(Step1Error::IndexOutOfRange)?);
    }
    
    // Recursively compute left and right children
    let left_child_index = node_index << 1;
    let right_child_index = left_child_index + 1;
    
    let left_child = compute_node_at_level(leaves, left_child_index, level - 1)?;
    let right_child = compute_node_at_level(leaves, right_child_index, level - 1)?;
    
    Ok(blake3_hash(&cat(&[&left_child, &right_child])).into())
}

/// Merkle authentication path: 26 siblings, from leaf level (level 0) up to level 25
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct MerklePath {
    /// Exactly `MERKLE_DEPTH` siblings, each 32 bytes.
    /// At level `l`, path[l] is the sibling of the running hash before hashing upward.
    pub path: Vec<Node>,
    /// At each level, indicate whether the running hash was a left child (false) or right child (true).
    /// Length == `MERKLE_DEPTH`.
    pub was_right: Vec<bool>,
}

impl MerklePath {
    /// Verify a Merkle proof.
    /// 
    /// # Arguments
    /// * `leaf` - The leaf value to verify
    /// * `root` - The expected Merkle root
    /// * `index` - The leaf index in the tree
    /// 
    /// # Returns
    /// Ok(()) if the proof is valid
    /// 
    /// # Errors
    /// Returns `Step1Error::BadMerkleProof` if verification fails
    fn verify(&self, leaf: &Leaf, root: &Root, index: u64) -> Result<(), Step1Error> {
        if self.path.len() != MERKLE_DEPTH || self.was_right.len() != MERKLE_DEPTH {
            return Err(Step1Error::BadMerklePathLength);
        }
        // Recompute upward
        let mut h: Node = *leaf;
        let mut _idx = index;
        for lvl in 0..MERKLE_DEPTH {
            let sib = match self.path.get(lvl) {
                Some(s) => *s,
                None => return Err(Step1Error::BadMerklePathLength),
            };
            let right = match self.was_right.get(lvl) {
                Some(r) => *r,
                None => return Err(Step1Error::BadMerklePathLength),
            };
            h = if right {
                // parent = H(left || right) where left = sibling, right = h
                blake3_hash(&cat(&[&sib, &h])).into()
            } else {
                // parent = H(left || right) where left = h, right = sibling
                blake3_hash(&cat(&[&h, &sib])).into()
            };
            _idx >>= 1u32;
        }
        if &h == root { Ok(()) } else { Err(Step1Error::BadLeafOpen) }
    }
}

// ---------- Challenges & succinct openings ----------

/// Build challenge seed for proof-of-work verification.
/// 
/// C = BLAKE3( `DOMAIN_TAG` || "CHAL" || E || `epoch_nonce` || pk || root )
/// 
/// # Arguments
/// * `epoch_hash` - The epoch hash E (32 bytes)
/// * `epoch_nonce` - The epoch nonce (32 bytes)
/// * `pk` - The Ed25519 public key (32 bytes)
/// * `root` - The Merkle root (32 bytes)
/// 
/// # Returns
/// The challenge seed C (32 bytes)
#[must_use]
pub fn build_challenge_seed(
    epoch_hash: &EpochHash,
    epoch_nonce: &EpochNonce,
    pk: &VerifyingKey,
    root: &Root,
) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(DOMAIN_TAG);
    h.update(b"CHAL");
    h.update(epoch_hash);
    h.update(epoch_nonce);
    h.update(pk.as_bytes());
    h.update(root);
    h.finalize().into()
}

/// Expand challenge seed into distinct leaf indices.
/// 
/// Expands `C` deterministically into `k` distinct indices in [0, N_LEAVES-1],
/// by hashing C || LE64(counter), taking the first 8 bytes LE as u64, and reducing mod N.
/// Rejection sampling avoids duplicates.
/// 
/// # Arguments
/// * `c_seed` - The challenge seed C (32 bytes)
/// * `k` - Number of distinct indices to generate
/// 
/// # Returns
/// Vector of k distinct indices in range [0, N_LEAVES-1]
#[must_use]
#[inline]
#[expect(
    clippy::integer_division_remainder_used,
    clippy::little_endian_bytes,
    reason = "Integer operations and byte conversion are safe within controlled bounds for cryptographic index derivation"
)]
pub fn derive_indices(c_seed: &[u8; 32], k: usize) -> Vec<u64> {
    let mut out = Vec::with_capacity(k);
    let mut seen: HashSet<u64> = HashSet::with_capacity(k.saturating_mul(2));
    let mut ctr: u64 = 0;
    while out.len() < k {
        let block = cat(&[c_seed, &le64(ctr)]);
        let v = blake3_hash(&block);
        let mut eight = [0_u8; 8];
        eight.copy_from_slice(&v.as_bytes()[0..8]);
        let idx = u64::from_le_bytes(eight) % N_LEAVES;
        if seen.insert(idx) {
            out.push(idx);
        }
        ctr = ctr.wrapping_add(1);
    }
    out
}

// ---------- Registration object ----------

/// The registration payload the participant submits after building the dataset and merkle root.
/// 
/// Contains all necessary data for verifying a participant's registration including
/// VRF proof, identity signature, and Merkle root.
pub struct Registration<'registration_data> {
    pub chain_id: &'registration_data ChainId,
    pub epoch_hash: &'registration_data EpochHash,   // E (recomputable)
    pub epoch_nonce: &'registration_data EpochNonce,
    pub epoch_number: u64,
    pub pk: &'registration_data VerifyingKey,        // 32 B
    pub root: &'registration_data Root,              // 32 B
    pub sig: &'registration_data Signature,          // 64 B (over M)
    pub vrf_output: &'registration_data VrfOutput,   // y
    pub vrf_proof: &'registration_data VrfProof,     // π
}

/// A challenge opening containing the leaf and its Merkle path.
/// 
/// Used to prove that a specific leaf exists in the dataset at the given index.
pub struct ChallengeOpen<'leaf_data> {
    /// The index of the leaf in the dataset
    pub index: u64,
    /// The leaf value (32 bytes)
    pub leaf: &'leaf_data Leaf,
    /// The Merkle path from leaf to root
    pub path: &'leaf_data MerklePath,
}

/// Verify a registration + succinct openings (k indices).
/// 
/// This performs exactly the agreed checks including VRF verification,
/// epoch hash validation, signature verification, and Merkle proof validation.
/// 
/// # Arguments
/// * `vrf` - The VRF implementation to use for verification
/// * `reg` - The registration data to verify
/// * `openings` - The challenge openings to verify
/// 
/// # Returns
/// Ok(()) if all verifications pass, otherwise appropriate `Step1Error`
/// 
/// # Errors
/// Returns various `Step1Error` variants for different validation failures
pub fn verify_registration_succinct<V: Vrf>(
    vrf: &V,
     reg: &Registration,
     openings: &[ChallengeOpen],
 ) -> Result<(), Step1Error> {
    // 1) Rebuild alpha and verify VRF, recover y'
    let alpha = build_alpha(reg.chain_id, reg.epoch_number, reg.epoch_nonce);
    let y_prime = vrf.verify(&alpha, reg.vrf_proof)?;

    // Ensure provided y matches verified y (exact bytes)
    if &y_prime != reg.vrf_output {
        return Err(Step1Error::BadVrf);
    }

    // 2) Recompute E from transcript and check matches provided epoch_hash
    let e_prime = compute_epoch_hash(
        reg.chain_id,
        reg.epoch_number,
        reg.epoch_nonce,
        reg.vrf_output,
        reg.vrf_proof,
    );
    if &e_prime != reg.epoch_hash {
        return Err(Step1Error::BadEpochHash);
    }

    // 3) Verify Ed25519 signature σ over M
    let message_bytes = build_M(reg.epoch_hash, reg.epoch_nonce, reg.pk);
    verify_identity_sig(reg.pk, &message_bytes, reg.sig)?;

    // 4) Derive SEED, K
    let (_seed, derived_key) = derive_seed_and_key(&message_bytes, reg.sig);

    // 5) Verify each opening:
    for op in openings {
        if op.index >= N_LEAVES {
            return Err(Step1Error::IndexOutOfRange);
        }
        // Recompute Leaf[index]
        let leaf_prime = compute_leaf(&derived_key, op.index);
        if &leaf_prime != op.leaf {
            return Err(Step1Error::BadLeafOpen);
        }
        // Verify Merkle path to root
        op.path.verify(op.leaf, reg.root, op.index)?;
    }

    Ok(())
}

// ---------- Ticket issuance & verification ----------

/// Ticket structure for epoch participation.
/// 
/// Contains all necessary information for validating epoch participation
/// including validity period and cryptographic commitments.
/// 
/// Serialization layout (in this exact order):
///  `DOMAIN_TAG` (14)
///  `CHAIN_ID` (32)
///  `LE64(epoch_number)` (8)
///  `epoch_hash` E (32)
///  `epoch_nonce` (32)
///  `pk` (32)
///  `root` (32)
///  `LE64(valid_from)` (8)
///  `LE64(valid_to)` (8)
#[derive(Clone, Debug)]
pub struct Ticket {
    pub chain_id: ChainId,
    pub epoch_hash: EpochHash,
    pub epoch_nonce: EpochNonce,
    pub epoch_number: u64,
    pub pk: [u8; 32],
    pub root: Root,
    pub valid_from: u64, // slot index start (inclusive)
    pub valid_to: u64,   // slot index end (inclusive)
 }
 
 impl Ticket {
     /// Serialize ticket to bytes in the exact order specified.
     /// 
     /// # Returns
     /// Serialized ticket bytes (198 bytes total)
     #[must_use]
    #[inline]
    #[expect(clippy::implicit_return, reason = "Explicit returns reduce readability in simple serialization methods")]
     pub fn serialize(&self) -> Vec<u8> {
         cat(&[
             DOMAIN_TAG,
             &self.chain_id,
             &le64(self.epoch_number),
             &self.epoch_hash,
             &self.epoch_nonce,
             &self.pk,
             &self.root,
             &le64(self.valid_from),
             &le64(self.valid_to),
         ])
     }
 }
 
 /// Sign a ticket with the issuer's private key.
 /// 
 /// `ticket_sig` = `Ed25519_Sign(issuer_sk, BLAKE3("TICKET" || Serialize(TICKET)))`
 /// 
 /// # Arguments
 /// * `issuer_sk` - The issuer's Ed25519 signing key
 /// * `ticket` - The ticket to sign
 /// 
 /// # Returns
 /// The Ed25519 signature over the ticket
 #[must_use]
#[inline]
#[expect(clippy::implicit_return, reason = "Explicit returns reduce readability in simple signing functions")]
pub fn sign_ticket(issuer_sk: &SigningKey, ticket: &Ticket) -> Signature {
     let ser = ticket.serialize();
     let tmsg = cat(&[b"TICKET", &ser]);
     let digest = blake3_hash(&tmsg);
     issuer_sk.sign(digest.as_bytes())
 }
 
 /// Verify a ticket signature and validity period.
 /// 
 /// Performs the following checks:
 /// 1. Verify Ed25519 signature over BLAKE3("TICKET" || serialize(TICKET))
 /// 2. Check slot validity: `current_slot` ∈ [`valid_from`, `valid_to`]
 /// 
 /// # Arguments
 /// * `issuer_vk` - The issuer's Ed25519 public key
 /// * `ticket` - The ticket to verify
 /// * `ticket_sig` - The signature to verify
 /// * `current_slot` - The current slot index for validity check
 /// 
 /// # Returns
 /// Ok(()) if ticket is valid, otherwise appropriate `Step1Error`
 /// 
 /// # Errors
 /// * `Step1Error::TicketBadSig` - Invalid signature
 /// * `Step1Error::TicketExpired` - Ticket is outside validity period
#[inline]
#[expect(clippy::implicit_return, reason = "Implicit returns are appropriate for verification logic")]
 pub fn verify_ticket(
     issuer_vk: &VerifyingKey,
     ticket: &Ticket,
     ticket_sig: &Signature,
     current_slot: u64,
 ) -> Result<(), Step1Error> {
    // Sig check
    let ser = ticket.serialize();
    let tmsg = cat(&[b"TICKET", &ser]);
    let digest = blake3_hash(&tmsg);
    let verify_result = issuer_vk.verify(digest.as_bytes(), ticket_sig);
    if verify_result.is_err() {
        return Err(Step1Error::TicketBadSig);
    }

    // Slot validity
    if current_slot < ticket.valid_from || current_slot > ticket.valid_to {
        return Err(Step1Error::TicketExpired);
    }

    Ok(())
}

// ---------- End of library ----------

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    // Helper struct for testing that includes prove functionality
    struct TestVrf {
        signing_key: SigningKey,
    }

    impl TestVrf {
        fn new() -> Self {
            let signing_key = SigningKey::generate(&mut OsRng);
            Self { signing_key }
        }

        fn prove(&self, alpha: &[u8]) -> (VrfOutput, VrfProof) {
            // Simple deterministic proof generation for testing
            let mut output = [0u8; 64];
            let mut proof = [0u8; 80];
            
            // Generate deterministic output using BLAKE3
            let mut hasher = blake3::Hasher::new();
            hasher.update(b"ECVRF-TEST-OUTPUT");
            hasher.update(self.signing_key.verifying_key().as_bytes());
            hasher.update(alpha);
            let hash1 = hasher.finalize();
            output[..32].copy_from_slice(hash1.as_bytes());
            
            // Second part of output
            let mut hasher2 = blake3::Hasher::new();
            hasher2.update(b"ECVRF-TEST-OUTPUT-2");
            hasher2.update(hash1.as_bytes());
            let hash2 = hasher2.finalize();
            output[32..64].copy_from_slice(hash2.as_bytes());
            
            // Generate proof
            let mut hasher3 = blake3::Hasher::new();
            hasher3.update(b"ECVRF-TEST-PROOF");
            hasher3.update(hash1.as_bytes());
            let hash3 = hasher3.finalize();
            proof[..32].copy_from_slice(hash3.as_bytes());
            
            let mut hasher4 = blake3::Hasher::new();
            hasher4.update(b"ECVRF-TEST-PROOF-2");
            hasher4.update(hash3.as_bytes());
            let hash4 = hasher4.finalize();
            proof[32..64].copy_from_slice(hash4.as_bytes());
            
            let mut hasher5 = blake3::Hasher::new();
            hasher5.update(b"ECVRF-TEST-PROOF-3");
            hasher5.update(hash4.as_bytes());
            let hash5 = hasher5.finalize();
            proof[64..80].copy_from_slice(&hash5.as_bytes()[..16]);
            
            (output, proof)
        }
    }

    impl Vrf for TestVrf {
        fn verify(&self, alpha: &[u8], proof: &VrfProof) -> Result<VrfOutput, Step1Error> {
            // For testing purposes, regenerate the expected proof and compare
            let (expected_output, expected_proof) = self.prove(alpha);
            if proof == &expected_proof {
                Ok(expected_output)
            } else {
                Err(Step1Error::BadVrf)
            }
        }
    }

    // VRF implementation for testing
    struct MockVrf {
        output: Vec<u8>,
    }

    impl MockVrf {
        #[expect(dead_code, reason = "Test utility function for mock VRF implementation")]
        fn new(output: Vec<u8>) -> Self {
            Self { output }
        }
    }

    impl Vrf for MockVrf {
        fn verify(&self, _alpha: &[u8], _proof: &VrfProof) -> Result<VrfOutput, Step1Error> {
            let mut output = [0u8; 64];
            let len = self.output.len().min(64);
            output[..len].copy_from_slice(&self.output[..len]);
            Ok(output)
        }
    }

    #[test]
    fn test_vrf_output_size() {
        let test_vrf = TestVrf::new();
        let alpha = b"test input";
        let (output, _proof) = test_vrf.prove(alpha);
        
        assert_eq!(output.len(), 64, "VRF output must be exactly 64 bytes");
    }

    #[test]
    fn test_vrf_proof_size() {
        let test_vrf = TestVrf::new();
        let alpha = b"test input";
        let (_output, proof) = test_vrf.prove(alpha);
        
        assert_eq!(proof.len(), 80, "VRF proof must be exactly 80 bytes");
    }

    #[test]
    fn test_vrf_verification() {
        let test_vrf = TestVrf::new();
        let alpha = b"test input";
        let (expected_output, proof) = test_vrf.prove(alpha);
        
        // Verification should succeed and return the same output
        let verify_result = test_vrf.verify(alpha, &proof);
        match verify_result {
            Ok(output) => {
                assert_eq!(output, expected_output, "VRF verification should return the same output");
            }
            Err(e) => panic!("VRF verification should succeed with correct parameters, got: {e:?}"),
        }
    }

    #[test]
    fn test_vrf_verification_fails_with_wrong_input() {
        let test_vrf = TestVrf::new();
        let alpha = b"test input";
        let (_output, proof) = test_vrf.prove(alpha);
        
        // Verification should fail with different input
        let wrong_alpha = b"wrong input";
        match test_vrf.verify(wrong_alpha, &proof) {
           Ok(_ok) => panic!("VRF verification should fail with wrong input"),
             Err(Step1Error::BadVrf) => {}, // Expected error
             Err(e) => panic!("VRF verification should fail with BadVrf error, got: {e:?}"),
        }
    }

    #[test]
    fn test_vrf_deterministic() {
        let test_vrf = TestVrf::new();
        let alpha = b"test input";
        let (output1, proof1) = test_vrf.prove(alpha);
        let (output2, proof2) = test_vrf.prove(alpha);
        
        // Same input should produce same output and proof
        assert_eq!(output1, output2, "VRF should be deterministic for same input");
        assert_eq!(proof1, proof2, "VRF proof should be deterministic for same input");
    }

    #[test]
    fn test_vrf_different_inputs_different_outputs() {
        let test_vrf = TestVrf::new();
        let alpha1 = b"input 1";
        let alpha2 = b"input 2";
        let (output1, _) = test_vrf.prove(alpha1);
        let (output2, _) = test_vrf.prove(alpha2);
        
        // Different inputs should produce different outputs
        assert_ne!(output1, output2, "Different inputs should produce different VRF outputs");
    }

    #[test]
    fn test_domain_tag_length() {
        assert_eq!(DOMAIN_TAG.len(), 14);
        assert_eq!(DOMAIN_TAG, b"[Iota]_|::\"v1\"");
    }

    #[test]
    fn test_constants() {
        assert_eq!(DATASET_BYTES, 0x8000_0000);
        assert_eq!(LEAF_BYTES, 32);
        assert_eq!(N_LEAVES, 0x0400_0000);
        assert_eq!(MERKLE_DEPTH, 26);
    }

    #[test]
    fn test_le64_encoding() {
        assert_eq!(le64(0), [0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(le64(1), [1, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(le64(256), [0, 1, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn test_build_alpha() {
        let chain_id = [1u8; 32];
        let epoch_number = 42u64;
        let epoch_nonce = [2u8; 32];
        
        let alpha = build_alpha(&chain_id, epoch_number, &epoch_nonce);
        
        // Should be DOMAIN_TAG (14) + CHAIN_ID (32) + LE64(epoch_number) (8) + epoch_nonce (32) = 86 bytes
        assert_eq!(alpha.len(), 86);
        
        // Check that it starts with DOMAIN_TAG
        assert_eq!(&alpha[0..14], DOMAIN_TAG);
        
        // Check that chain_id follows
        assert_eq!(&alpha[14..46], &chain_id);
        
        // Check that epoch_number follows (little-endian)
        assert_eq!(&alpha[46..54], &le64(epoch_number));
        
        // Check that epoch_nonce follows
        assert_eq!(&alpha[54..86], &epoch_nonce);
    }

    #[test]
    fn test_compute_epoch_hash() {
        let chain_id = [1u8; 32];
        let epoch_number = 42u64;
        let epoch_nonce = [2u8; 32];
        let y = vec![3u8; 16];
        let pi = vec![4u8; 32];
        
        let epoch_hash = compute_epoch_hash(&chain_id, epoch_number, &epoch_nonce, &y, &pi);
        
        // Should be exactly 32 bytes
        assert_eq!(epoch_hash.len(), 32);
        
        // Should be deterministic
        let epoch_hash2 = compute_epoch_hash(&chain_id, epoch_number, &epoch_nonce, &y, &pi);
        assert_eq!(epoch_hash, epoch_hash2);
    }

    #[test]
    fn test_build_m() {
        let epoch_hash: EpochHash = [1u8; 32];
        let epoch_nonce: EpochNonce = [2u8; 32];
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        
        let m = build_M(&epoch_hash, &epoch_nonce, &verifying_key);
        let _signature = signing_key.sign(&m);
        
        // Should be DOMAIN_TAG (14) + "EPOCH" (5) + epoch_hash (32) + epoch_nonce (32) + pk (32) = 115 bytes
        assert_eq!(m.len(), 115);
        
        // Check that it starts with DOMAIN_TAG
        assert_eq!(&m[0..14], DOMAIN_TAG);
        
        // Check that "EPOCH" follows
        assert_eq!(&m[14..19], b"EPOCH");
        
        // Check that epoch_hash follows
        assert_eq!(&m[19..51], &epoch_hash);
        
        // Check that epoch_nonce follows
        assert_eq!(&m[51..83], &epoch_nonce);
        
        // Check that pk follows
        assert_eq!(&m[83..115], verifying_key.as_bytes());
    }

    #[test]
    fn test_identity_signature() {
        let epoch_hash = [1u8; 32];
        let epoch_nonce = [2u8; 32];
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        
        let m = build_M(&epoch_hash, &epoch_nonce, &verifying_key);
        let signature = signing_key.sign(&m);
        
        // Verify the signature
        assert!(verify_identity_sig(&verifying_key, &m, &signature).is_ok());
        
        // Test with wrong message should fail
        let wrong_message = build_M(&[0u8; 32], &epoch_nonce, &verifying_key);
        assert!(verify_identity_sig(&verifying_key, &wrong_message, &signature).is_err());
    }

    #[test]
    fn test_derive_seed_and_key() {
        let epoch_hash = [1u8; 32];
        let epoch_nonce = [2u8; 32];
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        
        let m = build_M(&epoch_hash, &epoch_nonce, &verifying_key);
        let signature = signing_key.sign(&m);
        
       let (seed, derived_key) = derive_seed_and_key(&m, &signature);
        
        // Both should be 32 bytes
        assert_eq!(seed.len(), 32);
       assert_eq!(derived_key.len(), 32);
        
        // Should be deterministic
       let (seed2, k2) = derive_seed_and_key(&m, &signature);
        assert_eq!(seed, seed2);
       assert_eq!(derived_key, k2);
    }

    #[test]
    fn test_compute_leaf() {
       let test_key: [u8; 32] = [1u8; 32];
       let leaf0 = compute_leaf(&test_key, 0);
       let leaf1 = compute_leaf(&test_key, 1);
         
         // Should be 32 bytes each
         assert_eq!(leaf0.len(), 32);
         assert_eq!(leaf1.len(), 32);
         
         // Should be different for different indices
       assert_ne!(leaf0, leaf1);
         
         // Deterministic: same key and index should produce same leaf
       let leaf0_again = compute_leaf(&test_key, 0);
         assert_eq!(leaf0, leaf0_again);
     }

     #[test]
     fn test_parent_function() {
         let left = [1u8; 32];
         let right = [2u8; 32];
         
         let parent_node = parent(&left, &right);
         
         // Should be 32 bytes
         assert_eq!(parent_node.len(), 32);
         
         // Should be deterministic
         let parent_node2 = parent(&left, &right);
         assert_eq!(parent_node, parent_node2);
         
         // Order should matter
         let parent_node_swapped = parent(&right, &left);
         assert_ne!(parent_node, parent_node_swapped);
     }

     #[test]
     fn test_build_challenge_seed() {
         let epoch_hash = [1u8; 32];
         let epoch_nonce = [2u8; 32];
         let signing_key = SigningKey::generate(&mut OsRng);
         let verifying_key = signing_key.verifying_key();
         let root = [3u8; 32];
         
         let challenge_seed = build_challenge_seed(&epoch_hash, &epoch_nonce, &verifying_key, &root);
         
         // Should be exactly 32 bytes
         assert_eq!(challenge_seed.len(), 32);
         
         // Should be deterministic
         let challenge_seed2 = build_challenge_seed(&epoch_hash, &epoch_nonce, &verifying_key, &root);
         assert_eq!(challenge_seed, challenge_seed2);
     }

     #[test]
     fn test_derive_indices() {
         let c_seed = [0u8; 32];
       let count = 10;
         
       let indices = derive_indices(&c_seed, count);
         
         // Should have exactly k indices
       assert_eq!(indices.len(), count);
         
         // All indices should be in range [0, N_LEAVES)
         for &idx in &indices {
             assert!(idx < N_LEAVES);
         }
         
         // Should be deterministic
       let indices2 = derive_indices(&c_seed, count);
         assert_eq!(indices, indices2);
         
         // Should have no duplicates
         let mut sorted_indices = indices;
         sorted_indices.sort_unstable();
         sorted_indices.dedup();
       assert_eq!(sorted_indices.len(), count);
     }

     #[test]
     fn test_ticket_signing_and_verification() {
         let issuer_key = SigningKey::generate(&mut OsRng);
         let issuer_vk = issuer_key.verifying_key();
         
         let ticket = Ticket {
             chain_id: [1u8; 32],
             epoch_number: 42,
             epoch_hash: [2u8; 32],
             epoch_nonce: [3u8; 32],
             pk: [4u8; 32],
             root: [5u8; 32],
             valid_from: 100,
             valid_to: 200,
         };
         
         let ticket_sig = sign_ticket(&issuer_key, &ticket);
         
         // Should verify successfully with current slot in range
       assert!(verify_ticket(&issuer_vk, &ticket, &ticket_sig, 150).is_ok(), "ticket must verify for in-range slot");
         
         // Should fail with slot before valid_from
       let res_before = verify_ticket(&issuer_vk, &ticket, &ticket_sig, 50);
       assert!(matches!(res_before, Err(Step1Error::TicketExpired)));
         
         // Should fail with slot after valid_to
       let res_after = verify_ticket(&issuer_vk, &ticket, &ticket_sig, 250);
       assert!(matches!(res_after, Err(Step1Error::TicketExpired)));
     }
     
     #[test]
     fn test_full_dataset_generation() {
         let test_key = [42u8; 32]; // Test key
             
             // This test uses a smaller dataset for performance
            // In practice, the full 2GB dataset would be generated
            for i in 0..1000 {
                let leaf = compute_leaf(&test_key, i);
                // Verify leaf generation is deterministic
                assert_eq!(leaf, compute_leaf(&test_key, i));
            }
             
             // Verify leaves are deterministic
           let leaf_0_first = compute_leaf(&test_key, 0);
           let leaf_0_second = compute_leaf(&test_key, 0);
             assert_eq!(leaf_0_first, leaf_0_second);
             
             // Verify different indices produce different leaves
           let leaf_1 = compute_leaf(&test_key, 1);
             assert_ne!(leaf_0_first, leaf_1);
             
             // Test that the constants are correct for 2 GiB
             assert_eq!(DATASET_BYTES, 0x8000_0000); // 2 GiB
             assert_eq!(DATASET_BYTES, N_LEAVES * LEAF_BYTES_U64);
             assert_eq!(N_LEAVES, 0x0400_0000); // 2^26
             assert_eq!(MERKLE_DEPTH, 26);
         }
         
         #[test]
         fn test_merkle_path_generation_small() {
 
           let test_key = [123u8; 32];
             
             // The generate_merkle_path function expects exactly N_LEAVES (67M+ leaves)
             // For testing, we'll verify the function validates input size correctly
           let mut small_leaves: Vec<Leaf> = Vec::with_capacity(8);
            for i in 0..8 {
                small_leaves.push(compute_leaf(&test_key, i));
            }
             
             // This should fail because we don't have N_LEAVES
            let path_result = generate_merkle_path(&small_leaves, 0);
            assert!(matches!(path_result, Err(Step1Error::IndexOutOfRange))); // Expected to fail with wrong dataset size
            
            // Test the constants are correct for the full dataset
 
            assert_eq!(N_LEAVES, 0x0400_0000);
             
            // Test that compute_leaf works deterministically
            let leaf_0 = compute_leaf(&test_key, 0);
            let leaf_0_again = compute_leaf(&test_key, 0);
            assert_eq!(leaf_0, leaf_0_again);
            
            // Test small Merkle tree with merkle_root_from_leaves
            let root = merkle_root_from_leaves(small_leaves.iter().copied());
            assert!(matches!(root, Err(Step1Error::IndexOutOfRange))); // Should fail because we need exactly N_LEAVES
        }
    }
