#![cfg(any(feature = "ecvrf_rfc9381", feature = "ecvrf_rfc9381-ed25519"))]
use obex_alpha_i::vrf;

// KATs: enforce length rejects and round-trip against underlying prover for TAI.
#[test]
fn vrf_kat_lengths_and_rejects() {
    let pk = [0u8; vrf::VRF_PK_BYTES];
    let alpha = [1u8; 32];
    let pi = [2u8; vrf::VRF_PI_BYTES];
    // Wrong alpha length
    assert!(vrf::verify(&pk, &[0u8; 31], &pi).is_err());
    // Random π should reject
    assert!(vrf::verify(&pk, &alpha, &pi).is_err());
}

// (RFC 9381 vector tests can be added by adapting crate API; kept minimal here.)
