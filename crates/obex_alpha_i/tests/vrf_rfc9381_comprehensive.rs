#![cfg(any(feature = "ecvrf_rfc9381", feature = "ecvrf_rfc9381-ed25519"))]
use obex_alpha_i::vrf::{
    ecvrf_verify_beta_tai, ecvrf_verify_beta_tai_opt, verify_msg_tai, VrfPi, VrfPk, VRF_PI_BYTES,
    VRF_PK_BYTES, VRF_Y_BYTES,
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

struct TestVector {
    vk: &'static str,
    alpha: &'static str,
    pi: &'static str,
    beta: &'static str,
}

// RFC-9381 test vectors for ECVRF-EDWARDS25519-SHA512-TAI
const VALID_VECTORS: &[TestVector] = &[
    TestVector {
        vk: "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        alpha: "",
        pi: "8657106690b5526245a92b003bb079ccd1a92130477671f6fc01ad16f26f723f26f8a57ccaed74ee1b190bed1f479d9727d2d0f9b005a6e456a35d4fb0daab1268a1b0db10836d9826a528ca76567805",
        beta: "90cf1df3b703cce59e2a35b925d411164068269d7b2d29f3301c03dd757876ff66b71dda49d2de59d03450451af026798e8f81cd2e333de5cdf4f3e140fdd8ae",
    },
    TestVector {
        vk: "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        alpha: "72",
        pi: "f3141cd382dc42909d19ec5110469e4feae18300e94f304590abdced48aed5933bf0864a62558b3ed7f2fea45c92a465301b3bbf5e3e54ddf2d935be3b67926da3ef39226bbc355bdc9850112c8f4b02",
        beta: "eb4440665d3891d668e7e0fcaf587f1b4bd7fbfe99d0eb2211ccec90496310eb5e33821bc613efb94db5e5b54c70a848a0bef4553a41befc57663b56373a5031",
    },
    TestVector {
        vk: "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        alpha: "af82",
        pi: "9bc0f79119cc5604bf02d23b4caede71393cedfbb191434dd016d30177ccbf8096bb474e53895c362d8628ee9f9ea3c0e52c7a5c691b6c18c9979866568add7a2d41b00b05081ed0f58ee5e31b3a970e",
        beta: "645427e5d00c62a23fb703732fa5d892940935942101e456ecca7bb217c61c452118fec1219202a0edcf038bb6373241578be7217ba85a2687f7a0310b2df19f",
    },
];

#[test]
fn rfc9381_tai_valid_vectors() {
    for (i, vector) in VALID_VECTORS.iter().enumerate() {
        let vk: VrfPk = hex(vector.vk)
            .try_into()
            .unwrap_or_else(|_| panic!("Invalid VK in vector {}", i));
        let alpha_bytes = hex(vector.alpha);
        let pi: VrfPi = hex(vector.pi)
            .try_into()
            .unwrap_or_else(|_| panic!("Invalid PI in vector {}", i));
        let expected_beta = hex(vector.beta);

        // Test verify_msg_tai function (for variable-length alpha)
        let result = verify_msg_tai(&vk, &alpha_bytes, &pi);
        assert!(result.is_ok(), "Vector {} should verify successfully", i);

        let beta = result.unwrap();
        assert_eq!(
            beta.len(),
            VRF_Y_BYTES,
            "Beta should be {} bytes",
            VRF_Y_BYTES
        );
        assert_eq!(
            beta.to_vec(),
            expected_beta,
            "Beta mismatch in vector {}",
            i
        );
    }
}

#[test]
fn rfc9381_tai_ecvrf_functions() {
    // Test ecvrf_verify_beta_tai and ecvrf_verify_beta_tai_opt with random 32-byte alpha
    // These functions are for consensus use with 32-byte alpha, not RFC test vectors
    let alpha32 = [0x42u8; 32]; // Random 32-byte alpha

    // Generate a simple test case - we'll just verify the functions work consistently
    // We can't use RFC vectors since they use variable-length alpha
    let vk = [1u8; 32]; // Simple test key
    let pi = [0u8; 80]; // Zero proof (will fail verification but tests function signature)

    // Test that both functions handle the same inputs consistently
    let tai_result = ecvrf_verify_beta_tai(&vk, &alpha32, &pi);
    let opt_result = ecvrf_verify_beta_tai_opt(vk, alpha32, &pi);

    // Both should fail with the same error (zero proof)
    assert!(tai_result.is_err(), "Zero proof should fail verification");
    assert!(
        opt_result.is_none(),
        "Zero proof should fail verification in opt function"
    );
}

#[test]
fn rfc9381_tai_invalid_proof_single_bit_flip() {
    let vector = &VALID_VECTORS[0];
    let vk: VrfPk = hex(vector.vk).try_into().unwrap();
    let alpha_bytes = hex(vector.alpha);
    let mut alpha32 = [0u8; 32];
    alpha32[..alpha_bytes.len()].copy_from_slice(&alpha_bytes);

    let pi_bytes = hex(vector.pi);

    // Test single bit flips in proof
    for byte_idx in 0..pi_bytes.len() {
        for bit_idx in 0..8 {
            let mut corrupted_pi = pi_bytes.clone();
            corrupted_pi[byte_idx] ^= 1 << bit_idx;

            let pi: VrfPi = corrupted_pi.try_into().unwrap();

            // Should fail verification
            let result = ecvrf_verify_beta_tai(&vk, &alpha32, &pi);
            assert!(
                result.is_err(),
                "Corrupted proof at byte {} bit {} should fail",
                byte_idx,
                bit_idx
            );

            let opt_result = ecvrf_verify_beta_tai_opt(vk, alpha32, &pi);
            assert!(
                opt_result.is_none(),
                "Corrupted proof at byte {} bit {} should fail with opt function",
                byte_idx,
                bit_idx
            );
        }
    }
}

#[test]
fn rfc9381_tai_invalid_public_key() {
    let vector = &VALID_VECTORS[0];
    let alpha_bytes = hex(vector.alpha);
    let mut alpha32 = [0u8; 32];
    alpha32[..alpha_bytes.len()].copy_from_slice(&alpha_bytes);
    let pi: VrfPi = hex(vector.pi).try_into().unwrap();

    // Test various invalid public keys
    let invalid_keys = [
        [0u8; VRF_PK_BYTES],    // All zeros
        [0xffu8; VRF_PK_BYTES], // All ones
        [0x01u8; VRF_PK_BYTES], // All ones (different pattern)
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

#[test]
fn rfc9381_tai_wrong_proof_lengths() {
    let vk = [0x42u8; VRF_PK_BYTES];
    let alpha = [0x01u8; 32];

    // Test various wrong proof lengths
    let wrong_lengths = [0, 1, 79, 81, 100, 200];

    for &len in &wrong_lengths {
        let pi_wrong_len = vec![0u8; len];

        // opt function should reject wrong lengths immediately
        let opt_result = ecvrf_verify_beta_tai_opt(vk, alpha, &pi_wrong_len);
        assert!(
            opt_result.is_none(),
            "Wrong proof length {} should be rejected",
            len
        );
    }

    // Test correct length but invalid proof
    let pi_correct_len = vec![0u8; VRF_PI_BYTES];
    let opt_result = ecvrf_verify_beta_tai_opt(vk, alpha, &pi_correct_len);
    assert!(
        opt_result.is_none(),
        "Invalid proof with correct length should fail verification"
    );
}

#[test]
fn rfc9381_tai_constants_validation() {
    // Validate the constants match RFC-9381 requirements
    assert_eq!(VRF_PK_BYTES, 32, "VRF public key should be 32 bytes");
    assert_eq!(VRF_PI_BYTES, 80, "VRF proof should be 80 bytes");
    assert_eq!(VRF_Y_BYTES, 64, "VRF output should be 64 bytes");
}

#[test]
fn rfc9381_tai_deterministic_output() {
    // Test that the same inputs always produce the same output
    let vector = &VALID_VECTORS[0];
    let vk: VrfPk = hex(vector.vk).try_into().unwrap();
    let alpha_bytes = hex(vector.alpha);
    let pi: VrfPi = hex(vector.pi).try_into().unwrap();

    // Run the same verification multiple times with verify_msg_tai
    let result1 = verify_msg_tai(&vk, &alpha_bytes, &pi).unwrap();
    let result2 = verify_msg_tai(&vk, &alpha_bytes, &pi).unwrap();
    let result3 = verify_msg_tai(&vk, &alpha_bytes, &pi).unwrap();

    assert_eq!(
        result1.to_vec(),
        result2.to_vec(),
        "Results should be deterministic"
    );
    assert_eq!(
        result2.to_vec(),
        result3.to_vec(),
        "Results should be deterministic"
    );
    assert_eq!(
        result1.len(),
        VRF_Y_BYTES,
        "Beta should be {} bytes",
        VRF_Y_BYTES
    );
}
