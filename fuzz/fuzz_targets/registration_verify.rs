#![no_main]

use libfuzzer_sys::fuzz_target;
use obex_engine_i::{
    types::*,
    registration::verify_registration,
    vrf::mk_chain_vrf
};
// Removed unused ed25519_dalek imports

fuzz_target!(|data: &[u8]| {
    // Need enough data for all Registration fields
    if data.len() < 32 + 8 + 32 + 64 + 80 + 32 + 32 + 32 + 64 { return; }
    
    // Extract components from fuzz input
    let mut offset = 0;
    
    // Create Registration with proper fields
    let chain_id = ChainId(data[offset..offset+32].try_into().unwrap_or([0u8; 32]));
    offset += 32;
    
    let epoch_number = u64::from_le_bytes(data[offset..offset+8].try_into().unwrap_or([0u8; 8]));
    offset += 8;
    
    let epoch_nonce = EpochNonce(data[offset..offset+32].try_into().unwrap_or([0u8; 32]));
    offset += 32;
    
    let vrf_output = VrfOutput(data[offset..offset+64].try_into().unwrap_or([0u8; 64]));
    offset += 64;
    
    let vrf_proof = VrfProof(data[offset..offset+80].try_into().unwrap_or([0u8; 80]));
    offset += 80;
    
    let epoch_hash = EpochHash(data[offset..offset+32].try_into().unwrap_or([0u8; 32]));
    offset += 32;
    
    let root = MerkleRoot(data[offset..offset+32].try_into().unwrap_or([0u8; 32]));
    offset += 32;
    
    let pk_bytes: [u8; 32] = data[offset..offset+32].try_into().unwrap_or([0u8; 32]);
    let pk = ed25519_dalek::VerifyingKey::from_bytes(&pk_bytes).unwrap_or_else(|_| {
        ed25519_dalek::VerifyingKey::from_bytes(&[0u8; 32]).unwrap()
    });
    offset += 32;
    
    let sig_bytes: [u8; 64] = data[offset..offset+64].try_into().unwrap_or([0u8; 64]);
    let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
    
    let reg = Registration {
        chain_id: &chain_id,
        epoch_number,
        epoch_nonce: &epoch_nonce,
        vrf_proof: &vrf_proof,
        vrf_output: &vrf_output,
        epoch_hash: &epoch_hash,
        pk: &pk,
        sig: &sig,
        root: &root,
    };
    
    let epoch = 1u32;
    let vrf = mk_chain_vrf([0u8; 32]);
    let merkle_root = MerkleRoot([0u8; 32]);
    let challenge_opens = vec![];
    
    // Fuzz the registration verification
    let _ = verify_registration(&reg, epoch, &vrf, &merkle_root, &challenge_opens);
});