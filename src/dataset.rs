use crate::types::N_LEAVES;
use blake3;

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

/// Leaf[i] = BLAKE3(key=K, input=LE64(i))
#[must_use]
pub fn compute_leaf(k: &[u8;32], index: u32) -> [u8; 32] {
    let msg = index.to_le_bytes();
    let keyed = blake3::keyed_hash(k, &msg);
    let mut out = [0u8;32];
    out.copy_from_slice(keyed.as_bytes());
    out
}