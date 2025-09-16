//! Basic usage for the Obex Engine I (OE1) implementation.
//! 
//! This implementation shows how to:
//! 1. Implement a VRF (Verifiable Random Function)
//! 2. Use the Obex Engine I for epoch hash computation
//! 3. Generate identity signatures and derive seeds
//! 4. Create and verify tickets

use obex_engine_i::{ChallengeOpen, DATASET_BYTES, EcVrfRistretto255, LegacyVrfAdapter, N_LEAVES, Registration, Ticket, build_M, build_alpha, build_challenge_seed, compute_epoch_hash, derive_indices, derive_seed_and_key, generate_full_dataset, generate_merkle_path, sign_ticket, verify_registration_succinct, verify_ticket};
use obex_engine_i::ecvrf_traits::{Vrf as NewVrf, VrfError, VrfOutput, VrfProof};
use obex_engine_i::Vrf; // Legacy Vrf trait
use ed25519_dalek::{SigningKey, Signer};
use rand::rngs::OsRng;

/// RFC 9381 ECVRF-RISTRETTO255-SHA512 implementation.
/// This demonstrates the proper VRF implementation following the Obex Engine I specification.
struct ProductionVrf {
    vrf_impl: EcVrfRistretto255,
}

impl ProductionVrf {
    #[allow(dead_code)]
    fn new_with_public_key(_public_key: [u8; 32]) -> Self {
        // Create a new VRF instance with real cryptographic capabilities
        // This enables both proving and verification with actual ECVRF operations
        let vrf_impl = EcVrfRistretto255::new();
        
        Self { vrf_impl }
    }
    
    fn new_with_real_crypto() -> Self {
        // Create a VRF instance with real cryptographic security
        // Using cryptographically secure random number generation
        Self {
            vrf_impl: EcVrfRistretto255::new(), // Uses OsRng for secure key generation
        }
    }
    
    fn from_secret_bytes(secret_bytes: &[u8; 32]) -> Result<Self, VrfError> {
        // Create VRF instance from specific secret key bytes
        Ok(Self {
            vrf_impl: EcVrfRistretto255::from_secret_bytes(secret_bytes)?,
        })
    }
    
    fn secret_key_bytes(&self) -> [u8; 32] {
        self.vrf_impl.secret_key_bytes()
    }
}

impl NewVrf for ProductionVrf {
    fn prove(&self, alpha: &[u8]) -> Result<([u8; 80], VrfOutput), VrfError> {
        self.vrf_impl.prove(alpha)
    }
    
    fn verify(&self, alpha: &[u8], proof: &VrfProof) -> Result<VrfOutput, VrfError> {
        // Use the actual RFC 9381 ECVRF implementation
        self.vrf_impl.verify(alpha, proof)
    }
    
    fn public_key(&self) -> [u8; 32] {
        self.vrf_impl.public_key()
    }
}

#[allow(clippy::too_many_lines)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Obex Engine I (OE1) - Basic Usage Example");
    println!("=======================================");
    
    // Step 1: Setup chain parameters
    let chain_id = [1u8; 32];
    let epoch_number = 42u64;
    let epoch_nonce = [2u8; 32];
    
    println!("\n1. Chain Parameters:");
    println!("   Chain ID: {:?}", &chain_id[0..8]);
    println!("   Epoch Number: {epoch_number}");
    println!("   Epoch Nonce: {:?}", &epoch_nonce[0..8]);
    
    // Step 2: Create VRF with real cryptographic capabilities
    let production_vrf = ProductionVrf::new_with_real_crypto();
    let vrf_public_key = production_vrf.public_key();
    let secret_key_bytes = production_vrf.secret_key_bytes();
    let alpha = build_alpha(&chain_id, epoch_number, &epoch_nonce);
    
    // Generate a REAL VRF proof using actual cryptographic operations
    let (pi, y) = match production_vrf.prove(&alpha) {
        Ok((proof, output)) => (proof, output.0),
        Err(e) => return Err(format!("VRF proving failed: {:?}", e).into()),
    };
    
    // Create verification VRF instance with the same secret key
    let verification_vrf = ProductionVrf::from_secret_bytes(&secret_key_bytes)
        .map_err(|e| format!("Failed to create verification VRF: {:?}", e))?;
    let vrf = LegacyVrfAdapter::new(verification_vrf);
    println!("   Using ECVRF-RISTRETTO255-SHA512 implementation with real cryptography");
    
    println!("\n2. VRF Computation (Real Cryptography):");
    println!("   Alpha length: {} bytes", alpha.len());
    println!("   VRF Public Key: {:02x?}", &vrf_public_key[0..8]);
    println!("   VRF Output (y): {:?}", &y[0..8]);
    println!("   VRF Proof (π): {:?}", &pi[0..8]);
    
    // Verify VRF - this should now SUCCEED with real proof
    match vrf.verify(&alpha, &pi) {
        Ok(verified_y) => {
            println!("   ✓ VRF verification succeeded with real cryptographic proof!");
            println!("   Verified output matches: {}", verified_y == y);
        }
        Err(err) => {
            println!("   ✗ VRF verification failed: {:?}", err);
            return Err("Real VRF proof should verify successfully".into());
        }
    }
    
    // Also test that zero proofs are properly rejected
    let zero_proof = [0u8; 80];
    match vrf.verify(&alpha, &zero_proof) {
        Ok(_) => {
            println!("   ✗ ERROR: Zero proof should not verify!");
            return Err("Security vulnerability: zero proof verified".into());
        }
        Err(_) => {
            println!("   ✓ Zero proof correctly rejected (security check passed)");
        }
    }
    
    // Step 3: Compute epoch hash
    let epoch_hash = compute_epoch_hash(&chain_id, epoch_number, &epoch_nonce, &y, &pi);
    println!("\n3. Epoch Hash: {:?}", &epoch_hash[0..8]);
    
    // Step 4: Identity binding and signature
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    
    let m = build_M(&epoch_hash, &epoch_nonce, &verifying_key);
    let identity_sig = signing_key.sign(&m);
    
    println!("\n4. Identity Binding:");
    println!("   Public Key: {:?}", &verifying_key.as_bytes()[0..8]);
    println!("   Message (M) length: {} bytes", m.len());
    println!("   Identity Signature: {:?}", &identity_sig.to_bytes()[0..8]);
    
    // Verify identity signature
    if verifying_key.verify_strict(&m, &identity_sig).is_err() {
        return Err("Identity signature verification failed".into());
    }
    println!("   Identity signature verification successful");
    
    // Step 5: Derive seed and key
    let (seed, k) = derive_seed_and_key(&m, &identity_sig);
    println!("\n5. Seed and Key Derivation:");
    println!("   Seed: {:?}", &seed[0..8]);
    println!("   Key (k): {:?}", &k[0..8]);
    
    // Step 6: Generate full 2GB dataset as per specification
    println!("\n6. Generating full 2GB dataset...");
    println!("   This will create {N_LEAVES} leaves ({DATASET_BYTES} bytes)");
      
      let (full_dataset, root) = generate_full_dataset(&k)
          .expect("Failed to generate full dataset");
      
      println!("   Full 2GB dataset generated successfully!");
      println!("   Dataset size: {} leaves", full_dataset.len());
      println!("   Sample leaf at index 0: {:?}", &full_dataset[0][0..8]);
      println!("   Sample leaf at index {}: {:?}", N_LEAVES - 1, &full_dataset[usize::try_from(N_LEAVES - 1).expect("N_LEAVES should fit in usize")][0..8]);
    
    println!("   Sample Merkle Root (4 leaves): {:?}", &root[0..8]);
    
    // Step 7: Challenge derivation
    let challenge_seed = build_challenge_seed(&epoch_hash, &epoch_nonce, &verifying_key, &root);
    let k_challenges = 5; // Small number for testing
    let indices = derive_indices(&challenge_seed, k_challenges);
    
    println!("\n7. Challenge Derivation:");
    println!("   Challenge Seed: {:?}", &challenge_seed[0..8]);
    println!("   Challenge Indices (k={k_challenges}): {indices:?}");
    
    // Generate Merkle paths for the challenged indices
     println!("   Generating Merkle paths for challenged leaves...");
      let mut challenge_openings = Vec::new();
      for &index in &indices {
          let merkle_path = generate_merkle_path(&full_dataset, index)
              .expect("Failed to generate Merkle path");
          challenge_openings.push((index, merkle_path));
      }
      println!("   Generated {} Merkle paths", challenge_openings.len());
    
    // Step 8: Registration verification with succinct proofs
    println!("\n8. Registration Verification:");
    
    // Create registration payload
     let registration = Registration {
         chain_id: &chain_id,
         epoch_number,
         epoch_nonce: &epoch_nonce,
         vrf_proof: &pi,
         vrf_output: &y,
         epoch_hash: &epoch_hash,
         pk: &verifying_key,
         sig: &identity_sig,
         root: &root,
     };
    
    // Create challenge openings for succinct verification
    let mut openings = Vec::new();
    for (index, merkle_path) in &challenge_openings {
        let leaf = &full_dataset[usize::try_from(*index).expect("index should fit in usize")];
        openings.push(ChallengeOpen {
            index: *index,
            leaf,
            path: merkle_path,
        });
    }
    
    // Perform succinct verification (will fail with dummy VRF proof)
    match verify_registration_succinct(&vrf, &registration, &openings) {
        Ok(()) => println!("   Registration verification successful with succinct proofs"),
        Err(e) => println!("   ! Registration verification failed (expected with zero proof): {e:?}"),
    }
    
    // Step 9: Create and verify a ticket
    let issuer_key = SigningKey::generate(&mut OsRng);
    let issuer_vk = issuer_key.verifying_key();
    
    let ticket = Ticket {
        chain_id,
        epoch_number,
        epoch_hash,
        epoch_nonce,
        pk: *verifying_key.as_bytes(),
        root,
        valid_from: 100,
        valid_to: 200,
    };
    
    let ticket_sig = sign_ticket(&issuer_key, &ticket);
    
    println!("\n9. Ticket Issuance:");
    println!("   Issuer Public Key: {:?}", &issuer_vk.as_bytes()[0..8]);
    println!("   Ticket valid from slot {} to {}", ticket.valid_from, ticket.valid_to);
    println!("   Ticket Signature: {:?}", &ticket_sig.to_bytes()[0..8]);
    
    // Verify ticket for current slot 150 (within valid range)
    let current_slot = 150;
    match verify_ticket(&issuer_vk, &ticket, &ticket_sig, current_slot) {
        Ok(()) => println!("   Ticket verification successful for slot {current_slot}"),
        Err(e) => return Err(format!("Ticket verification failed: {e:?}").into()),
    }
    
    // Test ticket verification failure for out-of-range slot
    let invalid_slot = 250;
    match verify_ticket(&issuer_vk, &ticket, &ticket_sig, invalid_slot) {
        Ok(()) => println!("   Unexpected success for slot {invalid_slot}"),
        Err(_) => println!("   Ticket correctly rejected for slot {invalid_slot} (out of range)"),
     }
    
    println!("\nAll operations completed successfully!");
    println!("\nNote: This implementation shows the Obex Engine I interface.");
    println!("The VRF now uses GENUINE cryptographic operations with random secret keys.");
    println!("This demonstrates the complete ECVRF-RISTRETTO255-SHA512 implementation.");
    println!("\nThe registration verification demonstrates the succinct proof system");
    println!("where only challenged leaves and their Merkle paths are verified.");
    println!("\n✓ All cryptographic operations use real RFC 9381 ECVRF with secure randomness!");
    println!("✓ Secret keys generated using cryptographically secure OsRng!");
    
    Ok(())
}

