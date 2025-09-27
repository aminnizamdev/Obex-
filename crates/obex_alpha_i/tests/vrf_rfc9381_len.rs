use obex_alpha_i::vrf::{ecvrf_verify_beta_tai_opt, VRF_PI_BYTES};

#[test]
fn rfc9381_tai_len() {
    let vk = [2u8; 32];
    let alpha = [3u8; 32];

    // Too long
    let pi_long = vec![0u8; VRF_PI_BYTES + 1];
    assert!(ecvrf_verify_beta_tai_opt(vk, alpha, &pi_long).is_none());

    // Too short
    let pi_short = vec![0u8; VRF_PI_BYTES - 1];
    assert!(ecvrf_verify_beta_tai_opt(vk, alpha, &pi_short).is_none());

    // Correct length (should still fail due to invalid proof, but not due to length)
    let pi_correct = vec![0u8; VRF_PI_BYTES];
    assert!(ecvrf_verify_beta_tai_opt(vk, alpha, &pi_correct).is_none());
}
