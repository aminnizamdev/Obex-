// ========== consensus.rs (single source of truth) ==========
#![allow(non_upper_case_globals)]

use sha3::{Digest, Sha3_256};

#[cfg(all(not(feature = "std"), feature = "alloc"))]
use alloc::vec::Vec;
#[cfg(feature = "std")]
use std::vec::Vec;

pub type Hash256 = [u8; 32];

pub const OBEX_SHA3_TAGS: &[&str] = &[
    // shared Merkle / part
    "merkle.leaf",
    "merkle.node",
    "merkle.empty",
    "part.leaf",
    // α-I (Obex)
    "obex.alpha",
    "obex.partrec",
    "obex.seed",
    "obex.l0",
    "obex.lbl",
    "obex.idx",
    "obex.chal",
    "obex.vrfy",
    // α-II (header)
    "obex.header.id",
    "slot.seed",
    // α-III (admission/tx)
    "tx.access",
    "tx.body.v1",
    "tx.id",
    "tx.commit",
    "tx.sig",
    "ticket.id",
    "ticket.leaf",
    // α-T (tokenomics/system tx/rewards)
    "sys.tx",
    "reward.draw",
    "reward.rank",
    // VDF canonical (if your adapter uses them)
    "vdf.ycore.canon",
    "vdf.edge",
];

pub const MAX_PARTREC_SIZE: usize = 600_000;
pub const LEN_U32: usize = 4;
pub const LEN_U64: usize = 8;
pub const LEN_U128: usize = 16;

// Length-framed, domain-tagged SHA3-256
#[inline]
#[must_use]
pub fn h_tag(tag: &str, parts: &[&[u8]]) -> Hash256 {
    debug_assert!(OBEX_SHA3_TAGS.contains(&tag));
    let mut buf = Vec::with_capacity(64);
    buf.extend_from_slice(tag.as_bytes());
    for p in parts {
        let len = (p.len() as u64).to_le_bytes();
        buf.extend_from_slice(&len);
        buf.extend_from_slice(p);
    }
    sha3_256(&buf)
}

// Plug in your real SHA3-256 here:
#[must_use]
pub fn sha3_256(input: &[u8]) -> Hash256 {
    let mut hasher = Sha3_256::new();
    hasher.update(input);
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

// Binary Merkle with duplicate-last
#[inline]
#[must_use]
pub fn merkle_leaf(payload: &[u8]) -> Hash256 {
    h_tag("merkle.leaf", &[payload])
}

#[inline]
#[must_use]
pub fn merkle_node(l: &Hash256, r: &Hash256) -> Hash256 {
    let mut cat = [0u8; 64];
    cat[..32].copy_from_slice(l);
    cat[32..].copy_from_slice(r);
    h_tag("merkle.node", &[&cat])
}

#[must_use]
pub fn merkle_root(leaves_payload: &[Vec<u8>]) -> Hash256 {
    if leaves_payload.is_empty() {
        return h_tag("merkle.empty", &[]);
    }
    let mut lvl: Vec<Hash256> = leaves_payload.iter().map(|p| merkle_leaf(p)).collect();
    while lvl.len() > 1 {
        if lvl.len() & 1 == 1 {
            lvl.push(*lvl.last().unwrap());
        }
        let mut nxt = Vec::with_capacity(lvl.len() / 2);
        for i in (0..lvl.len()).step_by(2) {
            nxt.push(merkle_node(&lvl[i], &lvl[i + 1]));
        }
        lvl = nxt;
    }
    lvl[0]
}
