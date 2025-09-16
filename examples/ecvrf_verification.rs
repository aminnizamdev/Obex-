//! Verification-only implementation for the Obex Engine I (OE1).
//!
//! This implementation shows how to verify VRF proofs using the RFC 9381 ECVRF
//! implementation with pure Rust vrf-r255 backend, following the Obex Engine I specifications.
//!
//! This implementation focuses purely on verification and does not include proving
//! functionality, as per the Obex Engine I specification.

use obex_engine_i::{LegacyVrfAdapter, NewVrf, Vrf, VrfProof, VrfProofNew, build_alpha, mk_chain_vrf};

fn main() {
    println!("=== Obex Engine I - VRF Verification Example ===");
    println!("Using RFC 9381 ECVRF-RISTRETTO255-SHA512 with pure Rust vrf-r255 backend\n");

    // Ed25519 public key (32 bytes)
    let pk_bytes = [
        0x3d, 0x40, 0x17, 0xc3, 0xe8, 0x43, 0x89, 0x5a,
        0x92, 0xb7, 0x0a, 0xa7, 0x4d, 0x1b, 0x7e, 0xbc,
        0x9c, 0x98, 0x2c, 0xcf, 0x2e, 0xc4, 0x96, 0x8c,
        0xc0, 0xcd, 0x55, 0xf1, 0x2a, 0xf4, 0x66, 0x0c,
    ];

    // Create VRF instance using the factory function
    let vrf = mk_chain_vrf(pk_bytes);
    println!("Created VRF instance with Ed25519 public key");

    // VRF input (alpha)
    let alpha = b"test_input_for_vrf_verification";
    println!("VRF input (alpha): {:?}", std::str::from_utf8(alpha).unwrap());

    // VRF proof (80 bytes: gamma(32) || c(16) || s(32))
    // Note: This is a zero proof for testing
    // In practice, this would come from a VRF prover
    let proof: VrfProofNew = [
        // Gamma point (32 bytes)
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
        // c scalar (16 bytes)
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
        0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
        // s scalar (32 bytes)
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
        0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40,
        0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
        0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50,
    ];

    println!("VRF proof length: {} bytes (gamma(32) || c(16) || s(32))", proof.len());

    // Attempt VRF verification
    match vrf.verify(alpha, &proof) {
        Ok(output) => {
            println!("VRF verification succeeded!");
            println!("  VRF output length: {} bytes", output.0.len());
            println!("  VRF output (first 16 bytes): {:02x?}", &output.0[..16]);
        }
        Err(e) => {
            println!("VRF verification failed: {e:?}");
            println!("  This is expected with the zero proof data");
        }
    }

    println!("\n=== Legacy VRF Adapter Example ===");
    
    // Demonstrate the legacy VRF adapter for backward compatibility
    let legacy_vrf = LegacyVrfAdapter::new(vrf);
    let legacy_proof: VrfProof = proof; // Same proof format
    
    match legacy_vrf.verify(alpha, &legacy_proof) {
        Ok(output) => {
            println!("Legacy VRF verification succeeded!");
            println!("  Legacy VRF output length: {} bytes", output.len());
        }
        Err(e) => {
            println!("Legacy VRF verification failed: {e:?}");
            println!("  This is expected with the zero proof data");
        }
    }

    println!("\n=== VRF Integration with OE1 ===");
    
    // Demonstrate integration with OE1 epoch computation
    let chain_id = [0u8; 32];
    let epoch_number = 1u64;
    let epoch_nonce = [1u8; 32];
    
    // Build alpha for epoch computation
    let epoch_alpha = build_alpha(&chain_id, epoch_number, &epoch_nonce);
    println!("Built epoch alpha: {} bytes", epoch_alpha.len());
    
    // This would be used in actual VRF verification for epoch hash computation
    // Create a new VRF instance for direct verification
    let vrf2 = mk_chain_vrf(pk_bytes);
    match vrf2.verify(&epoch_alpha, &proof) {
        Ok(vrf_output) => println!("Epoch VRF verified: {vrf_output:?}"),
        Err(_) => println!("Epoch VRF verification failed"),
    }

    println!("\n=== Summary ===");
    println!("This implementation shows:");
    println!("• RFC 9381 ECVRF-RISTRETTO255-SHA512 verification using vrf-r255");
    println!("• Proper VRF proof format: gamma(32) || c(16) || s(32)");
    println!("• Integration with OE1 epoch hash computation");
    println!("• Legacy VRF adapter for backward compatibility");
    println!("• Verification-only approach as per blueprint specification");
    

}
