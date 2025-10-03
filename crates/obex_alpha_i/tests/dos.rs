#![allow(clippy::unwrap_used)]

use obex_alpha_i::{obex_verify_partrec_bytes, EcVrfVerifier, MAX_PARTREC_SIZE};
use obex_primitives::Hash256;

struct NeverVrf;
impl EcVrfVerifier for NeverVrf {
    fn verify(&self, _vrf_pubkey: &[u8; 32], _alpha: &Hash256, _vrf_proof: &[u8]) -> Option<Vec<u8>> {
        None
    }
}

#[test]
fn partrec_oversize_rejected_early() {
    // Any bytes longer than MAX_PARTREC_SIZE must be rejected without decoding/VRF.
    let bytes = vec![0u8; MAX_PARTREC_SIZE + 1];
    let slot = 1u64;
    let parent_id = [0u8; 32];
    let vrf = NeverVrf;
    let ok = obex_verify_partrec_bytes(&bytes, slot, &parent_id, &vrf);
    assert!(!ok, "oversize partrec must be rejected");
}

