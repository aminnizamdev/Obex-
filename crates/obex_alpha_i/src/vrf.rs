#![allow(clippy::missing_inline_in_public_items)]

// obex_alpha_i::vrf — RFC 9381 ECVRF adapter (ED25519 + SHA-512 + TAI)
// Consensus-normative: lengths and suite are hard-coded.

#[cfg(any(feature = "ecvrf_rfc9381", feature = "ecvrf_rfc9381-ed25519"))]
mod rfc9381 {
    use core::fmt;
    use sha2::Sha512;
    use vrf_rfc9381::ec::edwards25519::{tai::EdVrfEdwards25519TaiPublicKey, EdVrfProof};
    use vrf_rfc9381::Verifier as _;

    pub const VRF_SUITE_NAME: &str = "ECVRF-EDWARDS25519-SHA512-TAI";
    pub const VRF_PK_BYTES: usize = 32; // public key
    pub const VRF_PI_BYTES: usize = 80; // proof π
    pub const VRF_Y_BYTES: usize = 64; // output β

    pub type VrfPk = [u8; VRF_PK_BYTES];
    pub type VrfPi = [u8; VRF_PI_BYTES];
    pub type VrfY = [u8; VRF_Y_BYTES];

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub enum VrfError {
        BadPublicKey,
        BadProofEncoding,
        VerificationFailed,
    }
    impl fmt::Display for VrfError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::BadPublicKey => f.write_str("malformed or non-canonical VRF public key"),
                Self::BadProofEncoding => f.write_str("malformed VRF proof encoding"),
                Self::VerificationFailed => f.write_str("VRF verification failed"),
            }
        }
    }

    #[inline]
    pub fn verify(vrf_pk: &VrfPk, alpha: &[u8], pi: &VrfPi) -> Result<VrfY, VrfError> {
        if alpha.len() != 32 {
            return Err(VrfError::VerificationFailed);
        }
        let vk = EdVrfEdwards25519TaiPublicKey::from_slice(vrf_pk)
            .map_err(|_| VrfError::BadPublicKey)?;
        let proof = <EdVrfProof as vrf_rfc9381::Proof<Sha512>>::decode_pi(pi)
            .map_err(|_| VrfError::BadProofEncoding)?;
        let out = vk
            .verify(alpha, proof)
            .map_err(|_| VrfError::VerificationFailed)?;
        let mut y = [0u8; VRF_Y_BYTES];
        y.copy_from_slice(out.as_slice());
        Ok(y)
    }

    /// Verify for arbitrary-length alpha message (RFC vectors). Not used in consensus.
    #[inline]
    pub fn verify_msg_tai(vrf_pk: &VrfPk, alpha_msg: &[u8], pi: &VrfPi) -> Result<VrfY, VrfError> {
        let vk = EdVrfEdwards25519TaiPublicKey::from_slice(vrf_pk)
            .map_err(|_| VrfError::BadPublicKey)?;
        let proof = <EdVrfProof as vrf_rfc9381::Proof<Sha512>>::decode_pi(pi)
            .map_err(|_| VrfError::BadProofEncoding)?;
        let out = vk
            .verify(alpha_msg, proof)
            .map_err(|_| VrfError::VerificationFailed)?;
        let mut y = [0u8; VRF_Y_BYTES];
        y.copy_from_slice(out.as_slice());
        Ok(y)
    }
}

#[cfg(any(feature = "ecvrf_rfc9381", feature = "ecvrf_rfc9381-ed25519"))]
pub use rfc9381::{
    verify, verify_msg_tai, VrfError, VrfPi, VrfPk, VrfY, VRF_PI_BYTES, VRF_PK_BYTES,
    VRF_SUITE_NAME, VRF_Y_BYTES,
};

/// Convenience wrapper with explicit TAI naming used by tests/vectors.
#[inline]
pub fn ecvrf_verify_beta_tai(
    vrf_pk: &VrfPk,
    alpha: &[u8; 32],
    pi: &VrfPi,
) -> Result<VrfY, VrfError> {
    verify(vrf_pk, alpha, pi)
}

/// Variant used for RFC vectors with arbitrary-length alpha messages.
#[inline]
pub fn ecvrf_verify_beta_tai_msg(
    vrf_pk: &VrfPk,
    alpha_msg: &[u8],
    pi: &VrfPi,
) -> Result<VrfY, VrfError> {
    verify_msg_tai(vrf_pk, alpha_msg, pi)
}

/// Consensus-facing adapter: exactly 32-byte alpha and 80-byte proof → 64-byte beta.
/// Returns None on any failure.
#[inline]
#[must_use]
pub fn ecvrf_verify_beta_tai_consensus(
    vrf_pk: &VrfPk,
    alpha32: &[u8; 32],
    pi80: &VrfPi,
) -> Option<VrfY> {
    verify(vrf_pk, alpha32, pi80).ok()
}

/// Adapter requested by the protocol checklist: take raw slices, enforce lengths, return Option.
/// This does not replace the existing API to avoid breaking changes.
#[inline]
#[must_use]
pub fn ecvrf_verify_beta_tai_opt(vk: [u8; 32], alpha: [u8; 32], pi: &[u8]) -> Option<[u8; 64]> {
    if pi.len() != VRF_PI_BYTES {
        return None;
    }
    let mut pi80 = [0u8; VRF_PI_BYTES];
    pi80.copy_from_slice(pi);
    let pk: VrfPk = vk;
    verify(&pk, &alpha, &pi80).ok()
}
