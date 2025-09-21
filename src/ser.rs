use crate::{
    errors::Step1Error,
    types::{
        ALPHA_LEN, ChainId, DOMAIN_TAG, EpochNonce, MerklePath, MerkleRoot, EpochHash,
        Registration, VRF_OUTPUT_LEN, VRF_PROOF_LEN, VrfOutput, VrfProof
    }
};

#[inline]
#[must_use]
pub const fn le64(x: u64) -> [u8; 8] {
    x.to_le_bytes()
}

#[inline]
#[must_use]
pub const fn le32(x: u32) -> [u8; 4] {
    x.to_le_bytes()
}

/// α = `DOMAIN_TAG` || `CHAIN_ID` || `LE64(epoch_number)` || `epoch_nonce` (86 bytes)
#[must_use]
pub fn build_alpha(chain_id: &ChainId, epoch_number: u64, epoch_nonce: &EpochNonce) -> [u8; ALPHA_LEN] {
    let mut out = [0u8; ALPHA_LEN];
    let mut off = 0usize;
    out[off..off+14].copy_from_slice(DOMAIN_TAG); off+=14;
    out[off..off+32].copy_from_slice(&chain_id.0); off+=32;
    out[off..off+8].copy_from_slice(&le64(epoch_number)); off+=8;
    out[off..off+32].copy_from_slice(&epoch_nonce.0); // off+=32;
    out
}

/// Canonical Registration encoding for signatures and transport.
/// Order is fixed; lengths are exact; no trailing bytes.
///
/// # Errors
///
/// This function currently does not return errors, but the Result type is maintained for future extensibility.
pub fn encode_registration(reg: &Registration) -> Result<Vec<u8>, Step1Error> {
    let mut v = Vec::with_capacity(14+32+8+32 + VRF_OUTPUT_LEN + VRF_PROOF_LEN + 32 + 32);
    v.extend_from_slice(DOMAIN_TAG);                          // 14
    v.extend_from_slice(&reg.chain_id.0);                     // 32
    v.extend_from_slice(&le64(reg.epoch_number));             // 8
    v.extend_from_slice(&reg.epoch_nonce.0);                  // 32
    v.extend_from_slice(&reg.vrf_output.0);                   // 64
    v.extend_from_slice(&reg.vrf_proof.0);                    // 80
    v.extend_from_slice(&reg.epoch_hash.0);                   // 32
    v.extend_from_slice(&reg.root.0);                         // 32
    // Public key is encoded in its raw 32-byte Ed25519 form.
    v.extend_from_slice(reg.pk.as_bytes());                   // 32
    // Signature (64 bytes) appended at the end for full blob transport (optional).
    v.extend_from_slice(&reg.sig.to_bytes());                 // 64
    Ok(v)
}

/// Canonical `MerklePath`: `LE32(count)` || count * 32-byte nodes
#[must_use]
pub fn encode_merkle_path(path: &MerklePath) -> Vec<u8> {
    let mut v = Vec::with_capacity(4 + path.path.len()*32);
    v.extend_from_slice(&le32(u32::try_from(path.path.len()).unwrap_or(0)));
    for n in &path.path { v.extend_from_slice(n); }
    v
}

/// Decode a Merkle path from bytes.
///
/// # Errors
///
/// Returns `Step1Error` if the data is too short, has invalid length, or decoding fails.
pub fn decode_merkle_path(b: &[u8]) -> Result<MerklePath, Step1Error> {
    if b.len() < 4 { return Err(Step1Error::DecodeError("short path")); }
    let mut len_bytes = [0u8;4];
    len_bytes.copy_from_slice(&b[..4]);
    let count = u32::from_le_bytes(len_bytes) as usize;
    if b.len() != 4 + 32*count { return Err(Step1Error::InvalidLength { expected: 4+32*count, got: b.len() }); }
    let mut path = Vec::with_capacity(count);
    for i in 0..count {
        let mut n = [0u8;32];
        n.copy_from_slice(&b[4 + i*32 .. 4 + (i+1)*32]);
        path.push(n);
    }
    Ok(MerklePath { path })
}

/// Type alias for the complex registration decode result
type RegistrationDecodeResult = (ChainId, u64, EpochNonce, VrfOutput, VrfProof, EpochHash, MerkleRoot, [u8; 32], [u8; 64]);

/// Decode a registration from bytes. Returns owned data that can be referenced.
///
/// # Errors
///
/// Returns `Step1Error` if the data length is invalid, domain tag is incorrect, or decoding fails.
pub fn decode_registration(data: &[u8]) -> Result<RegistrationDecodeResult, Step1Error> {
    let expected_len = 14 + 32 + 8 + 32 + VRF_OUTPUT_LEN + VRF_PROOF_LEN + 32 + 32 + 32 + 64;
    if data.len() != expected_len {
        return Err(Step1Error::InvalidLength { expected: expected_len, got: data.len() });
    }
    
    let mut offset = 0;
    
    // Skip DOMAIN_TAG (14 bytes)
    if &data[offset..offset+14] != DOMAIN_TAG {
        return Err(Step1Error::DecodeError("invalid domain tag"));
    }
    offset += 14;
    
    // Chain ID (32 bytes)
    let mut chain_id_bytes = [0u8; 32];
    chain_id_bytes.copy_from_slice(&data[offset..offset+32]);
    let chain_id = ChainId(chain_id_bytes);
    offset += 32;
    
    // Epoch number (8 bytes, little endian)
    let mut epoch_bytes = [0u8; 8];
    epoch_bytes.copy_from_slice(&data[offset..offset+8]);
    let epoch_number = u64::from_le_bytes(epoch_bytes);
    offset += 8;
    
    // Epoch nonce (32 bytes)
    let mut epoch_nonce_bytes = [0u8; 32];
    epoch_nonce_bytes.copy_from_slice(&data[offset..offset+32]);
    let epoch_nonce = EpochNonce(epoch_nonce_bytes);
    offset += 32;
    
    // VRF output (64 bytes)
    let mut vrf_output_bytes = [0u8; VRF_OUTPUT_LEN];
    vrf_output_bytes.copy_from_slice(&data[offset..offset+VRF_OUTPUT_LEN]);
    let vrf_output = VrfOutput(vrf_output_bytes);
    offset += VRF_OUTPUT_LEN;
    
    // VRF proof (80 bytes)
    let mut vrf_proof_bytes = [0u8; VRF_PROOF_LEN];
    vrf_proof_bytes.copy_from_slice(&data[offset..offset+VRF_PROOF_LEN]);
    let vrf_proof = VrfProof(vrf_proof_bytes);
    offset += VRF_PROOF_LEN;
    
    // Epoch hash (32 bytes)
    let mut epoch_hash_bytes = [0u8; 32];
    epoch_hash_bytes.copy_from_slice(&data[offset..offset+32]);
    let epoch_hash = EpochHash(epoch_hash_bytes);
    offset += 32;
    
    // Root (32 bytes)
    let mut root_bytes = [0u8; 32];
    root_bytes.copy_from_slice(&data[offset..offset+32]);
    let root = MerkleRoot(root_bytes);
    offset += 32;
    
    // Public key (32 bytes)
    let mut pk_bytes = [0u8; 32];
    pk_bytes.copy_from_slice(&data[offset..offset+32]);
    offset += 32;
    
    // Signature (64 bytes)
    let mut sig_bytes = [0u8; 64];
    sig_bytes.copy_from_slice(&data[offset..offset+64]);
    
    Ok((chain_id, epoch_number, epoch_nonce, vrf_output, vrf_proof, epoch_hash, root, pk_bytes, sig_bytes))
}