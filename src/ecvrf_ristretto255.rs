//! RFC 9381 ECVRF implementation using vrf-r255 (pure Rust)
//! This provides ECVRF-RISTRETTO255-SHA512 ciphersuite

use crate::ecvrf_traits::{Vrf, VrfError, VrfOutput, VrfProof};

#[cfg(feature = "vrf-r255")]
use vrf_r255::{PublicKey, SecretKey};

#[cfg(feature = "vrf-r255")]
use rand_core::OsRng;

#[cfg(not(feature = "vrf-r255"))]
compile_error!("EcVrfRistretto255 requires the 'vrf-r255' feature to be enabled. This prevents accidental use of fallback implementations.");

/// RFC 9381 ECVRF implementation using ristretto255
/// This implementation requires the 'vrf-r255' feature to be enabled.
#[cfg(feature = "vrf-r255")]
pub struct EcVrfRistretto255 {
    /// The VRF secret key for proving
    secret_key: SecretKey,
    /// The VRF public key for verification
    public_key: PublicKey,
}

#[cfg(feature = "vrf-r255")]
impl EcVrfRistretto255 {
    /// Generate a new VRF keypair
    #[must_use]
    pub fn new() -> Self {
        let secret_key = SecretKey::generate(OsRng);
        let public_key = PublicKey::from(secret_key);
        Self {
            secret_key,
            public_key,
        }
    }
    
    /// Create a new VRF instance from a secret key
    #[must_use]
    pub fn from_secret_key(secret_key: SecretKey) -> Self {
        let public_key = PublicKey::from(secret_key);
        Self {
            secret_key,
            public_key,
        }
    }
    
    /// Create a new VRF instance from secret key bytes
    /// 
    /// # Errors
    /// Returns `VrfError::InvalidPublicKey` if the secret key bytes are invalid
    pub fn from_secret_bytes(secret_bytes: &[u8; 32]) -> Result<Self, VrfError> {
        let secret_key = SecretKey::from_bytes(*secret_bytes)
            .into_option()
            .ok_or(VrfError::InvalidPublicKey)?;
        Ok(Self::from_secret_key(secret_key))
    }
    
    /// Get the secret key bytes
    #[must_use]
    pub fn secret_key_bytes(&self) -> [u8; 32] {
        self.secret_key.to_bytes()
    }
}

#[cfg(feature = "vrf-r255")]
impl Default for EcVrfRistretto255 {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "vrf-r255")]
impl Vrf for EcVrfRistretto255 {
    /// Generate a VRF proof for the given input message
    /// Returns both the VRF proof and the VRF output
    fn prove(&self, alpha: &[u8]) -> Result<(VrfProof, VrfOutput), VrfError> {
        // Generate the proof using vrf-r255
        let proof = self.secret_key.prove(alpha);
        
        // Convert the proof to our VrfProof format (80 bytes)
        let proof_bytes = proof.to_bytes();
        let vrf_proof = VrfProof::try_from(proof_bytes.as_slice())
            .map_err(|_| VrfError::InvalidProof)?;
        
        // Verify the proof to get the output hash
        let hash_output = self.public_key.verify(alpha, &proof)
            .into_option()
            .ok_or(VrfError::VerificationFailed)?;
        
        // Convert to VrfOutput (64 bytes)
        let vrf_output = VrfOutput(hash_output);
        
        Ok((vrf_proof, vrf_output))
    }
    
    /// Verify VRF proof π on input message `alpha` according to RFC 9381
    ///
    /// This implementation uses the vrf-r255 crate for ECVRF-RISTRETTO255-SHA512 verification.
    /// Returns the 64-byte VRF output y if verification succeeds.
    fn verify(
        &self,
        alpha: &[u8],
        proof: &VrfProof,
    ) -> Result<VrfOutput, VrfError> {
        // Reject zero proofs immediately
        if proof.iter().all(|&b| b == 0) {
            return Err(VrfError::InvalidProof);
        }
        
        // Convert proof bytes to vrf-r255 Proof
        if proof.len() != 80 {
            return Err(VrfError::InvalidProof);
        }
        let mut proof_array = [0_u8; 80];
        proof_array.copy_from_slice(proof);
        let vrf_proof = vrf_r255::Proof::from_bytes(proof_array)
            .ok_or(VrfError::InvalidProof)?;
        
        // Verify the proof and get the hash output
        let hash_output = self.public_key.verify(alpha, &vrf_proof)
            .into_option()
            .ok_or(VrfError::VerificationFailed)?;
        
        // Convert to VrfOutput (64 bytes)
        let vrf_output = VrfOutput(hash_output);
        
        Ok(vrf_output)
    }
    
    /// Get the public key associated with this VRF instance
    fn public_key(&self) -> [u8; 32] {
        self.public_key.to_bytes()
    }
}

#[cfg(all(test, feature = "vrf-r255"))]
mod tests {
    use super::*;

    #[test]
    fn test_vrf_prove_and_verify() {
        let vrf = EcVrfRistretto255::new();
        let input = b"test message";
        
        // Generate a proof
        let (proof, output1) = vrf.prove(input).expect("Proving should succeed");
        
        // Verify the proof
        let output2 = vrf.verify(input, &proof).expect("Verification should succeed");
        
        // Outputs should match
        assert_eq!(output1.0, output2.0);
    }

    #[test]
    fn test_vrf_deterministic() {
        // Create a VRF instance and get its secret key bytes
        let vrf_original = EcVrfRistretto255::new();
        let secret_bytes = vrf_original.secret_key_bytes();
        
        // Create two VRF instances from the same secret key
        let vrf1 = EcVrfRistretto255::from_secret_bytes(&secret_bytes).unwrap();
        let vrf2 = EcVrfRistretto255::from_secret_bytes(&secret_bytes).unwrap();
        
        let input = b"deterministic test";
        
        let (proof1, output1) = vrf1.prove(input).unwrap();
        let (proof2, output2) = vrf2.prove(input).unwrap();
        
        // Same secret key should produce same proof and output
        assert_eq!(proof1, proof2);
        assert_eq!(output1.0, output2.0);
    }

    #[test]
    fn test_vrf_different_inputs() {
        let vrf = EcVrfRistretto255::new();
        let input1 = b"message 1";
        let input2 = b"message 2";
        
        let (proof1, output1) = vrf.prove(input1).unwrap();
        let (proof2, output2) = vrf.prove(input2).unwrap();
        
        // Different inputs should produce different outputs
        assert_ne!(proof1, proof2);
        assert_ne!(output1.0, output2.0);
    }
    
    #[test]
    fn test_vrf_verification() {
        let vrf = EcVrfRistretto255::new();
        
        // Test with zero data
        let dummy_proof = [0u8; 80];
        let input = b"test input";
        
        // This should fail with the real implementation due to zero proof
        let result = vrf.verify(input, &dummy_proof);
        assert!(result.is_err());
    }
    
    #[test]
    fn test_proof_size_validation() {
        // Note: VrfProof is a fixed-size array [u8; 80], so size validation
        // is enforced at compile time by the type system. This test documents
        // that the type system prevents invalid proof sizes.
        let vrf = EcVrfRistretto255::new();
        let input = b"test input";
        
        // Valid size proof (80 bytes) - should fail due to invalid content
        let valid_size_proof = [1u8; 80];
        assert!(vrf.verify(input, &valid_size_proof).is_err());
    }
    
    #[test]
    fn test_proof_bit_flip_rejection() {
        let vrf = EcVrfRistretto255::new();
        let input = b"test input";
        
        // Create a proof with some pattern, then flip bits
        let mut proof = [0u8; 80];
        for (i, item) in proof.iter_mut().enumerate() {
            *item = u8::try_from(i % 256).expect("i % 256 should always fit in u8");
        }
        
        // Test original pattern (should fail due to invalid proof)
        assert!(vrf.verify(input, &proof).is_err());
        
        // Flip various bits and ensure they still fail
        for bit_pos in [0, 1, 7, 8, 15, 31, 32, 63, 64, 79] {
            let mut flipped_proof = proof;
            flipped_proof[bit_pos / 8] ^= 1 << (bit_pos % 8);
            assert!(vrf.verify(input, &flipped_proof).is_err());
        }
    }
    
    #[test]
    fn test_edge_case_proofs() {
        let vrf = EcVrfRistretto255::new();
        let input = b"test input";
        
        // Test edge case patterns
        let all_zeros = [0u8; 80];
        let all_ones = [0xFFu8; 80];
        let alternating = {
            let mut proof = [0u8; 80];
            for (i, item) in proof.iter_mut().enumerate() {
                *item = if i % 2 == 0 { 0xAA } else { 0x55 };
            }
            proof
        };
        
        assert!(vrf.verify(input, &all_zeros).is_err());
        assert!(vrf.verify(input, &all_ones).is_err());
        assert!(vrf.verify(input, &alternating).is_err());
    }
}
