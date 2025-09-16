// src/vrf.rs
#[derive(Debug, Clone)]
pub struct VrfOutput(pub [u8; 64]);  // RFC 9381 IETF ECVRF output length

pub type VrfProof = [u8; 80];  // ECVRF proof: gamma(32) || c(16) || s(32)

#[derive(Debug)]
pub enum VrfError {
    BadLength,
    VerifyFailed,
    InternalError,
    InvalidPublicKey,
    InvalidProof,
    VerificationFailed,
}

pub trait Vrf {
    /// Generate a VRF proof for the given input message
    /// Returns both the proof and the VRF output hash
    /// 
    /// # Errors
    /// Returns `VrfError` if proof generation fails or inputs are invalid
    fn prove(&self, alpha: &[u8]) -> Result<(VrfProof, VrfOutput), VrfError>;
    
    /// Verify VRF proof π on input message `alpha` under the VRF public key.
    /// Returns the 64-byte VRF output y if (and only if) verification succeeds.
    /// 
    /// # Errors
    /// Returns `VrfError` if verification fails or inputs are invalid
    fn verify(&self, alpha: &[u8], proof: &VrfProof) -> Result<VrfOutput, VrfError>;
    
    /// Get the public key associated with this VRF instance
    fn public_key(&self) -> [u8; 32];
}
