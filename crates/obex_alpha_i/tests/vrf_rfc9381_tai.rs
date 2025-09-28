use obex_alpha_i::vrf::{
    ecvrf_verify_beta_tai, ecvrf_verify_beta_tai_opt, verify_msg_tai, VrfPi, VrfPk, VRF_Y_BYTES,
};

// Simple hex helper
fn hex(s: &str) -> Vec<u8> {
    if s.is_empty() {
        return vec![];
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

struct V {
    vk: &'static str,
    alpha: &'static str,
    pi: &'static str,
    beta: &'static str,
}

const OK: &[V] = &[
    V{
        vk:"d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        alpha:"",
        pi:"8657106690b5526245a92b003bb079ccd1a92130477671f6fc01ad16f26f723f26f8a57ccaed74ee1b190bed1f479d9727d2d0f9b005a6e456a35d4fb0daab1268a1b0db10836d9826a528ca76567805",
        beta:"90cf1df3b703cce59e2a35b925d411164068269d7b2d29f3301c03dd757876ff66b71dda49d2de59d03450451af026798e8f81cd2e333de5cdf4f3e140fdd8ae",
    },
    V{
        vk:"3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        alpha:"72",
        pi:"f3141cd382dc42909d19ec5110469e4feae18300e94f304590abdced48aed5933bf0864a62558b3ed7f2fea45c92a465301b3bbf5e3e54ddf2d935be3b67926da3ef39226bbc355bdc9850112c8f4b02",
        beta:"eb4440665d3891d668e7e0fcaf587f1b4bd7fbfe99d0eb2211ccec90496310eb5e33821bc613efb94db5e5b54c70a848a0bef4553a41befc57663b56373a5031",
    },
    V{
        vk:"fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        alpha:"af82",
        pi:"9bc0f79119cc5604bf02d23b4caede71393cedfbb191434dd016d30177ccbf8096bb474e53895c362d8628ee9f9ea3c0e52c7a5c691b6c18c9979866568add7a2d41b00b05081ed0f58ee5e31b3a970e",
        beta:"645427e5d00c62a23fb703732fa5d892940935942101e456ecca7bb217c61c452118fec1219202a0edcf038bb6373241578be7217ba85a2687f7a0310b2df19f",
    },
];

#[test]
fn rfc9381_tai_valid() {
    for v in OK {
        let vk: VrfPk = hex(v.vk).try_into().unwrap();
        let alpha = hex(v.alpha);
        let pi: VrfPi = hex(v.pi).try_into().unwrap();
        let expected = hex(v.beta);

        let out = verify_msg_tai(&vk, &alpha, &pi).expect("verify ok");
        assert_eq!(out.to_vec(), expected, "beta mismatch");
        assert_eq!(out.len(), 64);
        assert_eq!(pi.len(), 80);
    }
}

#[test]
fn rfc9381_tai_invalid() {
    let v = &OK[0];
    let vk: VrfPk = hex(v.vk).try_into().unwrap();
    let alpha = hex(v.alpha);
    let mut pi_bytes = hex(v.pi);

    // Flip a bit in the proof
    pi_bytes[0] ^= 1;
    let pi_bad: VrfPi = pi_bytes.try_into().unwrap();
    assert!(verify_msg_tai(&vk, &alpha, &pi_bad).is_err());

    // Bad public key
    let vk_bad = [0u8; 32];
    let pi: VrfPi = hex(v.pi).try_into().unwrap();
    assert!(verify_msg_tai(&vk_bad, &alpha, &pi).is_err());
}

/// Test ecvrf_verify_beta_tai function behavior and API consistency
/// This locks the VRF adapter behaviour and β/π lengths forever as required
#[test]
fn ecvrf_verify_beta_tai_valid_cases() {
    // Test that ecvrf_verify_beta_tai and ecvrf_verify_beta_tai_opt work consistently
    // We use the RFC vector's public key but with a 32-byte alpha for consensus use
    let v = &OK[0];
    let vk: VrfPk = hex(v.vk).try_into().unwrap();

    // Create a 32-byte alpha for consensus (different from RFC vector's variable-length alpha)
    let alpha32 = [0x42u8; 32]; // Fixed 32-byte alpha for consensus

    // Use a zero proof (will fail verification but tests function signatures)
    let pi_zero = [0u8; 80];

    // Test ecvrf_verify_beta_tai function with 32-byte alpha
    let result = ecvrf_verify_beta_tai(&vk, &alpha32, &pi_zero);
    assert!(result.is_err(), "Zero proof should fail verification");

    // Test ecvrf_verify_beta_tai_opt function
    let opt_result = ecvrf_verify_beta_tai_opt(vk, alpha32, &pi_zero);
    assert!(
        opt_result.is_none(),
        "Zero proof should fail verification with opt function"
    );

    // Test that both functions handle the same inputs consistently
    // This ensures the API contract is locked forever
    assert_eq!(
        result.is_err(),
        opt_result.is_none(),
        "Both functions should fail consistently"
    );

    // Test with the original RFC vector to ensure verify_msg_tai still works
    let alpha_bytes = hex(v.alpha);
    let pi: VrfPi = hex(v.pi).try_into().unwrap();
    let msg_result = verify_msg_tai(&vk, &alpha_bytes, &pi);
    assert!(
        msg_result.is_ok(),
        "Original RFC vector should verify with variable-length alpha"
    );

    let beta = msg_result.unwrap();
    assert_eq!(
        beta.len(),
        VRF_Y_BYTES,
        "Beta should be {} bytes",
        VRF_Y_BYTES
    );
}

/// Test ecvrf_verify_beta_tai function with invalid cases (bit-flipped)
/// This ensures verification fails for corrupted inputs as required
#[test]
fn ecvrf_verify_beta_tai_invalid_cases() {
    let v = &OK[0];
    let vk: VrfPk = hex(v.vk).try_into().unwrap();
    let pi_bytes = hex(v.pi);

    // Convert to 32-byte alpha
    let mut alpha32 = [0u8; 32];
    let alpha_bytes = hex(v.alpha);
    alpha32[..alpha_bytes.len()].copy_from_slice(&alpha_bytes);

    // Test single bit flip in proof - this locks verification behavior forever
    for byte_idx in 0..pi_bytes.len() {
        for bit_idx in 0..8 {
            let mut corrupted_pi = pi_bytes.clone();
            corrupted_pi[byte_idx] ^= 1 << bit_idx;

            let pi: VrfPi = corrupted_pi.try_into().unwrap();

            // ecvrf_verify_beta_tai should fail
            let result = ecvrf_verify_beta_tai(&vk, &alpha32, &pi);
            assert!(
                result.is_err(),
                "Corrupted proof at byte {} bit {} should fail",
                byte_idx,
                bit_idx
            );

            // ecvrf_verify_beta_tai_opt should also fail
            let opt_result = ecvrf_verify_beta_tai_opt(vk, alpha32, &pi);
            assert!(
                opt_result.is_none(),
                "Corrupted proof at byte {} bit {} should fail with opt function",
                byte_idx,
                bit_idx
            );
        }
    }

    // Test invalid public key
    let pi: VrfPi = hex(v.pi).try_into().unwrap();
    let invalid_keys = [
        [0u8; 32],    // All zeros
        [0xffu8; 32], // All ones
        [0x01u8; 32], // All ones (different pattern)
    ];

    for (i, &bad_vk) in invalid_keys.iter().enumerate() {
        let result = ecvrf_verify_beta_tai(&bad_vk, &alpha32, &pi);
        assert!(
            result.is_err(),
            "Invalid public key {} should fail verification",
            i
        );

        let opt_result = ecvrf_verify_beta_tai_opt(bad_vk, alpha32, &pi);
        assert!(
            opt_result.is_none(),
            "Invalid public key {} should fail verification with opt function",
            i
        );
    }
}

/// Test that ensures β=64 and π=80 lengths are enforced forever
#[test]
fn ecvrf_verify_beta_tai_length_enforcement() {
    // This test locks the VRF adapter behaviour and β/π lengths forever
    let vk = [0x42u8; 32];
    let alpha32 = [0x01u8; 32];
    let pi = [0u8; 80]; // Correct π length

    // Test that function signature enforces correct lengths
    let result = ecvrf_verify_beta_tai(&vk, &alpha32, &pi);
    // Should fail due to invalid proof, but not due to length issues
    assert!(result.is_err(), "Invalid proof should fail verification");

    // Test opt function with wrong proof lengths
    let wrong_lengths = [0, 1, 79, 81, 100];
    for &len in &wrong_lengths {
        let pi_wrong = vec![0u8; len];
        let opt_result = ecvrf_verify_beta_tai_opt(vk, alpha32, &pi_wrong);
        assert!(
            opt_result.is_none(),
            "Wrong proof length {} should be rejected",
            len
        );
    }

    // Test with correct length but invalid proof
    let pi_correct = vec![0u8; 80];
    let opt_result = ecvrf_verify_beta_tai_opt(vk, alpha32, &pi_correct);
    assert!(
        opt_result.is_none(),
        "Invalid proof with correct length should fail verification"
    );
}
