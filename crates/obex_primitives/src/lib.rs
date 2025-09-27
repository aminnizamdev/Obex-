#![forbid(unsafe_code)]
#![deny(
    warnings,
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    clippy::cargo
)]
#![allow(
    clippy::module_name_repetitions,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::result_large_err
)]

//! Obex alpha primitives: hashing, fixed-width little-endian encodings, binary Merkle trees.
#![cfg_attr(not(feature = "std"), no_std)]
#[cfg(all(not(feature = "std"), feature = "alloc"))]
extern crate alloc;
//
// This crate implements the normative utilities shared across obex.α I/II/III/T:
//
// - Domain-tagged SHA3-256 with length framing
// - Fixed-width little-endian integer encodings
// - Binary Merkle (duplicate last when odd) and leaf verification
// - Constant-time equality helpers for 32-byte digests

#[cfg(all(not(feature = "std"), feature = "alloc"))]
use alloc::vec::Vec;
use sha3::{Digest, Sha3_256};
#[cfg(feature = "std")]
use std::vec::Vec;
use subtle::ConstantTimeEq;

/// 32-byte hash (SHA3-256 output).
pub type Hash256 = [u8; 32];

/// 32-byte public key (Ed25519).
pub type Pk32 = [u8; 32];

/// 64-byte signature (Ed25519 canonical encoding).
pub type Sig64 = [u8; 64];

pub mod constants;
pub mod consensus;

/// Convert an unsigned integer to fixed-width little-endian bytes.
///
/// The output is exactly `W` bytes (no overlong encodings).
#[must_use]
pub fn le_bytes<const W: usize>(mut x: u128) -> [u8; W] {
    let mut out = [0u8; W];
    let mut i = 0usize;
    while i < W {
        out[i] = (x & 0xFF) as u8;
        x >>= 8;
        i += 1;
    }
    out
}

/// Read a `u64` from the first 8 bytes of a little-endian byte slice.
#[must_use]
pub fn u64_from_le(b: &[u8]) -> u64 {
    let mut x: u64 = 0;
    let mut i = 0usize;
    while i < 8 && i < b.len() {
        x |= u64::from(b[i]) << (8 * i as u64);
        i += 1;
    }
    x
}

/// Domain-tagged SHA3-256 with length framing as specified:
/// `H(tag_ascii, parts[])` = `SHA3_256`( UTF8(tag) || Σ ( LE(|p|,8) || p ) )
#[must_use]
pub fn h_tag(tag: &str, parts: &[&[u8]]) -> Hash256 {
    // Assert that consensus tags are all within the `obex.` namespace in debug builds.
    debug_assert!(
        tag.starts_with("obex."),
        "non-obex.* tag used in consensus hashing: {tag}"
    );
    let mut hasher = Sha3_256::new();
    hasher.update(tag.as_bytes());
    for p in parts {
        let len_le = le_bytes::<8>(p.len() as u128);
        hasher.update(len_le);
        hasher.update(p);
    }
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

#[cfg(test)]
mod tag_asserts {
    use super::*;

    #[test]
    fn all_public_tag_constants_are_obex_namespaced() {
        let tags = [
            constants::TAG_MERKLE_LEAF,
            constants::TAG_MERKLE_NODE,
            constants::TAG_MERKLE_EMPTY,
            constants::TAG_ALPHA,
            constants::TAG_SEED,
            constants::TAG_L0,
            constants::TAG_LBL,
            constants::TAG_IDX,
            constants::TAG_CHAL,
            constants::TAG_PART_LEAF,
            constants::TAG_PARTREC,
            constants::TAG_VRFY,
            constants::TAG_HEADER_ID,
            constants::TAG_SLOT_SEED,
            constants::TAG_VDF_YCORE,
            constants::TAG_VDF_EDGE,
            constants::TAG_TX_ACCESS,
            constants::TAG_TX_BODY_V1,
            constants::TAG_TX_ID,
            constants::TAG_TX_COMMIT,
            constants::TAG_TX_SIG,
            constants::TAG_TXID_LEAF,
            constants::TAG_TICKET_ID,
            constants::TAG_TICKET_LEAF,
            constants::TAG_SYS_TX,
            constants::TAG_REWARD_DRAW,
            constants::TAG_REWARD_RANK,
        ];
        for t in tags {
            assert!(t.starts_with("obex."), "tag not obex.*: {t}");
        }
    }

    #[test]
    fn tag_constants_match_expected_ascii() {
        let checks: &[(&str, &[u8])] = &[
            (constants::TAG_MERKLE_LEAF, b"obex.merkle.leaf"),
            (constants::TAG_MERKLE_NODE, b"obex.merkle.node"),
            (constants::TAG_MERKLE_EMPTY, b"obex.merkle.empty"),
            (constants::TAG_ALPHA, b"obex.alpha"),
            (constants::TAG_SEED, b"obex.seed"),
            (constants::TAG_L0, b"obex.l0"),
            (constants::TAG_LBL, b"obex.lbl"),
            (constants::TAG_IDX, b"obex.idx"),
            (constants::TAG_CHAL, b"obex.chal"),
            (constants::TAG_PART_LEAF, b"obex.part.leaf"),
            (constants::TAG_PARTREC, b"obex.partrec"),
            (constants::TAG_VRFY, b"obex.vrfy"),
            (constants::TAG_HEADER_ID, b"obex.header.id"),
            (constants::TAG_SLOT_SEED, b"obex.slot.seed"),
            (constants::TAG_VDF_YCORE, b"obex.vdf.ycore"),
            (constants::TAG_VDF_EDGE, b"obex.vdf.edge"),
            (constants::TAG_TX_ACCESS, b"obex.tx.access"),
            (constants::TAG_TX_BODY_V1, b"obex.tx.body.v1"),
            (constants::TAG_TX_ID, b"obex.tx.id"),
            (constants::TAG_TX_COMMIT, b"obex.tx.commit"),
            (constants::TAG_TX_SIG, b"obex.tx.sig"),
            (constants::TAG_TXID_LEAF, b"obex.txid.leaf"),
            (constants::TAG_TICKET_ID, b"obex.ticket.id"),
            (constants::TAG_TICKET_LEAF, b"obex.ticket.leaf"),
            (constants::TAG_SYS_TX, b"obex.sys.tx"),
            (constants::TAG_REWARD_DRAW, b"obex.reward.draw"),
            (constants::TAG_REWARD_RANK, b"obex.reward.rank"),
        ];
        for (actual, expected) in checks {
            assert_eq!(
                (*actual).as_bytes(),
                *expected,
                "tag ASCII mismatch: {actual}"
            );
        }
    }
}

/// Compute the Merkle leaf hash of a payload using the shared leaf domain tag.
#[must_use]
pub fn merkle_leaf(payload: &[u8]) -> Hash256 {
    h_tag(constants::TAG_MERKLE_LEAF, &[payload])
}

/// Compute the Merkle node hash from two child node hashes using the shared node domain tag.
#[must_use]
pub fn merkle_node(left: &Hash256, right: &Hash256) -> Hash256 {
    let mut cat = [0u8; 64];
    cat[..32].copy_from_slice(left);
    cat[32..].copy_from_slice(right);
    h_tag(constants::TAG_MERKLE_NODE, &[&cat])
}

/// Compute the binary Merkle root. When the number of nodes at a level is odd,
/// the last node is duplicated. The empty tree root is `H("obex.merkle.empty", [])`.
#[must_use]
pub fn merkle_root(leaves_payload: &[Vec<u8>]) -> Hash256 {
    if leaves_payload.is_empty() {
        return h_tag(constants::TAG_MERKLE_EMPTY, &[]);
    }
    let mut level: Vec<Hash256> = leaves_payload.iter().map(|p| merkle_leaf(p)).collect();
    while level.len() > 1 {
        if level.len() % 2 == 1 {
            if let Some(last) = level.last().copied() {
                level.push(last);
            }
        }
        let mut next: Vec<Hash256> = Vec::with_capacity(level.len() / 2);
        let mut i = 0usize;
        while i < level.len() {
            next.push(merkle_node(&level[i], &level[i + 1]));
            i += 2;
        }
        level = next;
    }
    // length >= 1
    level[0]
}

/// A Merkle authentication path for a leaf at `index`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MerklePath {
    /// Sibling hashes from leaf to root.
    pub siblings: Vec<Hash256>,
    /// Leaf index in the tree (0-based).
    pub index: u64,
}

/// Verify a Merkle leaf payload against the supplied root with the given path.
#[must_use]
pub fn merkle_verify_leaf(root: &Hash256, leaf_payload: &[u8], path: &MerklePath) -> bool {
    let mut h = merkle_leaf(leaf_payload);
    let mut idx = path.index;
    for sib in &path.siblings {
        h = if idx & 1 == 0 {
            merkle_node(&h, sib)
        } else {
            merkle_node(sib, &h)
        };
        idx >>= 1;
    }
    ct_eq_hash(root, &h)
}

/// Constant-time equality for two 32-byte hashes.
#[must_use]
pub fn ct_eq_hash(a: &Hash256, b: &Hash256) -> bool {
    a.ct_eq(b).into()
}

#[cfg(test)]
#[allow(
    clippy::too_many_lines,
    clippy::needless_pass_by_value,
    clippy::missing_panics_doc,
    clippy::missing_assert_message
)]
mod tests {
    use super::*;

    #[test]
    fn merkle_empty_matches_tag() {
        let empty = h_tag(constants::TAG_MERKLE_EMPTY, &[]);
        let root = merkle_root(&[]);
        assert!(ct_eq_hash(&empty, &root));
    }

    #[test]
    fn merkle_two_leaves_stable() {
        let leaves = vec![vec![0xAAu8; 3], vec![0xBBu8; 5]];
        let root = merkle_root(&leaves);
        // Determinism: second run yields the same root
        let root2 = merkle_root(&[vec![0xAAu8; 3], vec![0xBBu8; 5]]);
        assert!(ct_eq_hash(&root, &root2));
        // Sanity: root differs if leaf order changes
        let root_swapped = merkle_root(&[vec![0xBBu8; 5], vec![0xAAu8; 3]]);
        assert!(!ct_eq_hash(&root, &root_swapped));
    }
}
