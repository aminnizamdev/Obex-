#![cfg(any(feature = "ecvrf_rfc9381", feature = "ecvrf_rfc9381-ed25519"))]
use obex_alpha_i::vrf;

#[test]
fn vrf_suite_constant() {
    assert_eq!(vrf::VRF_SUITE_NAME, "ECVRF-EDWARDS25519-SHA512-TAI");
}

#[test]
fn vrf_rejects_wrong_alpha_len() {
    let pk = [3u8; vrf::VRF_PK_BYTES];
    let pi = [4u8; vrf::VRF_PI_BYTES];
    // alpha must be exactly 32 bytes
    assert!(vrf::verify(&pk, &[1u8; 31], &pi).is_err());
}

#[test]
fn vrf_rejects_random_pi() {
    let pk = [7u8; vrf::VRF_PK_BYTES];
    let pi = [9u8; vrf::VRF_PI_BYTES];
    let alpha = [5u8; 32];
    // Random proof should fail verification under TAI
    assert!(vrf::verify(&pk, &alpha, &pi).is_err());
}

