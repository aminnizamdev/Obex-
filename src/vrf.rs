use crate::{errors::Step1Error, types::{ALPHA_LEN, VrfOutput, VrfProof}};

/// Public VRF trait used by the registration verifier.
pub trait Vrf {
    /// Verify a VRF proof π on input α under the VRF public key.
    /// Returns the 64-byte VRF output y on success.
    ///
    /// # Errors
    /// Returns `Step1Error` if the input sizes are invalid or verification fails.
    fn verify(&self, alpha: &[u8], proof: &VrfProof) -> Result<VrfOutput, Step1Error>;
}

/// Chain VRF adapter backed by the vrf-r255 RFC 9381 implementation.
///
/// Note: `pk_bytes` are the VRF public key bytes (Ristretto255), not Ed25519.
pub struct ChainVrf {
    pk_bytes: [u8; 32],
}

/// Construct a VRF verifier instance from a 32-byte VRF public key.
#[must_use]
pub const fn mk_chain_vrf(pk_bytes: [u8; 32]) -> ChainVrf {
    ChainVrf { pk_bytes }
}

impl Vrf for ChainVrf {
    fn verify(&self, alpha: &[u8], proof: &VrfProof) -> Result<VrfOutput, Step1Error> {
        if alpha.len() != ALPHA_LEN {
            return Err(Step1Error::InvalidLength { expected: ALPHA_LEN, got: alpha.len() });
        }

        #[cfg(not(feature = "vrf-r255"))]
        {
            compile_error!("ChainVrf requires the 'vrf-r255' feature to be enabled");
        }

        #[cfg(feature = "vrf-r255")]
        {
            let Some(pk) = vrf_r255::PublicKey::from_bytes(self.pk_bytes) else {
                return Err(Step1Error::InvalidProof);
            };

            let mut proof_arr = [0u8; 80];
            proof_arr.copy_from_slice(&proof.0);
            let Some(proof) = vrf_r255::Proof::from_bytes(proof_arr) else {
                return Err(Step1Error::InvalidProof);
            };

            let verified = pk.verify(alpha, &proof);
            let Some(output) = verified.into_option() else {
                return Err(Step1Error::InvalidProof);
            };
            return Ok(VrfOutput(output));
        }

        #[allow(unreachable_code)]
        Err(Step1Error::InvalidProof)
    }
}