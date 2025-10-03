use crate::types::N_LEAVES;
use sha3::{Digest, Sha3_256};

/// Streaming builder yields leaves without holding 2 GB in RAM.
pub struct DatasetBuilder<'a> {
    k: &'a [u8; 32],
    i: u32,
    end: u32,
}

impl<'a> DatasetBuilder<'a> {
    #[must_use]
    pub const fn new(k: &'a [u8;32]) -> Self { Self { k, i: 0, end: N_LEAVES } }
}

impl Iterator for DatasetBuilder<'_> {
    type Item = [u8; 32];
    fn next(&mut self) -> Option<Self::Item> {
        if self.i >= self.end { return None; }
        let leaf = compute_leaf(self.k, self.i);
        self.i += 1;
        Some(leaf)
    }
}

/// Leaf[i] = SHA3_256( K || LE64(i) )
#[must_use]
pub fn compute_leaf(k: &[u8;32], index: u32) -> [u8; 32] {
    let msg = index.to_le_bytes();
    let mut hasher = Sha3_256::new();
    hasher.update(k);
    hasher.update(&msg);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}