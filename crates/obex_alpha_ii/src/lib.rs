#![forbid(unsafe_code)]
#![deny(
    warnings,
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    clippy::cargo
)]
#![allow(
    clippy::module_name_repetitions,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::result_large_err
)]

//! obex.α II — Deterministic Header Engine (forkless by equalities)
//!
//! Implements the canonical header structure, identity hash, builder, and validator
//! per `obex.alpha II.txt`. Providers for beacon, participation, admission, and tx roots
//! are passed via traits.

use obex_primitives::{constants, ct_eq_hash, h_tag, le_bytes, Hash256};
use thiserror::Error;

/// Network version (consensus-sealed)
pub const OBEX_ALPHA_II_VERSION: u32 = 2;
/// Consensus size caps for beacon fields (deployment-defined; enforced before verification).
pub const MAX_PI_LEN: usize = 1_048_576;  // example: 1 MiB
pub const MAX_ELL_LEN: usize = 65_536;    // example: 64 KiB

/// Providers (adapters) for equality checks
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BeaconInputs<'a> {
    pub parent_id: &'a Hash256,
    pub slot: u64,
    pub seed_commit: &'a Hash256,
    pub vdf_y_core: &'a Hash256,
    pub vdf_y_edge: &'a Hash256,
    pub vdf_pi: &'a [u8],
    pub vdf_ell: &'a [u8],
}

pub trait BeaconVerifier { fn verify(&self, inputs: &BeaconInputs<'_>) -> bool; }

pub trait TicketRootProvider { fn compute_ticket_root(&self, slot: u64) -> Hash256; }
pub trait PartRootProvider   { fn compute_part_root(&self, slot: u64) -> Hash256; }
pub trait TxRootProvider     { fn compute_txroot(&self, slot: u64) -> Hash256; }

/// Canonical header object
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Header {
    pub parent_id: Hash256,
    pub slot: u64,
    pub obex_version: u32,

    // Beacon (VDF)
    pub seed_commit: Hash256,
    pub vdf_y_core: Hash256,
    pub vdf_y_edge: Hash256,
    pub vdf_pi: Vec<u8>,
    pub vdf_ell: Vec<u8>,

    // Deterministic commitments
    pub ticket_root: Hash256,
    pub part_root: Hash256,
    pub txroot_prev: Hash256,
}

/// Canonical header ID over field values (not transport bytes)
#[must_use]
pub fn obex_header_id(h: &Header) -> Hash256 {
    h_tag(constants::TAG_HEADER_ID, &[
        &h.parent_id,
        &le_bytes::<8>(u128::from(h.slot)),
        &le_bytes::<4>(u128::from(h.obex_version)),

        &h.seed_commit,
        &h.vdf_y_core,
        &h.vdf_y_edge,
        &le_bytes::<4>(h.vdf_pi.len() as u128),
        &h.vdf_pi,
        &le_bytes::<4>(h.vdf_ell.len() as u128),
        &h.vdf_ell,

        &h.ticket_root,
        &h.part_root,
        &h.txroot_prev,
    ])
}

// ——— Canonical header serializer/deserializer (wire layout §4.1) ————

#[derive(Debug, Error)]
pub enum CodecError { #[error("short input")] Short, #[error("trailing")] Trailing }

const fn read_exact<'a>(src: &mut &'a [u8], n: usize) -> Result<&'a [u8], CodecError> {
    if src.len() < n { return Err(CodecError::Short); }
    let (a,b) = src.split_at(n); *src = b; Ok(a)
}

#[must_use]
pub fn serialize_header(h: &Header) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&h.parent_id);
    out.extend_from_slice(&le_bytes::<8>(u128::from(h.slot)));
    out.extend_from_slice(&le_bytes::<4>(u128::from(h.obex_version)));

    out.extend_from_slice(&h.seed_commit);
    out.extend_from_slice(&h.vdf_y_core);
    out.extend_from_slice(&h.vdf_y_edge);
    out.extend_from_slice(&le_bytes::<4>(h.vdf_pi.len() as u128));
    out.extend_from_slice(&h.vdf_pi);
    out.extend_from_slice(&le_bytes::<4>(h.vdf_ell.len() as u128));
    out.extend_from_slice(&h.vdf_ell);

    out.extend_from_slice(&h.ticket_root);
    out.extend_from_slice(&h.part_root);
    out.extend_from_slice(&h.txroot_prev);
    out
}

pub fn deserialize_header(mut src: &[u8]) -> Result<Header, CodecError> {
    let parent_id = { let b = read_exact(&mut src, 32)?; let mut a = [0u8;32]; a.copy_from_slice(b); a };
    let slot      = u64::from_le_bytes(read_exact(&mut src, 8)?.try_into().unwrap());
    let obex_version = u32::from_le_bytes(read_exact(&mut src, 4)?.try_into().unwrap());
    let seed_commit = { let b = read_exact(&mut src, 32)?; let mut a = [0u8;32]; a.copy_from_slice(b); a };
    let vdf_y_core  = { let b = read_exact(&mut src, 32)?; let mut a = [0u8;32]; a.copy_from_slice(b); a };
    let vdf_y_edge  = { let b = read_exact(&mut src, 32)?; let mut a = [0u8;32]; a.copy_from_slice(b); a };
    let pi_len = u32::from_le_bytes(read_exact(&mut src, 4)?.try_into().unwrap()) as usize;
    let vdf_pi = read_exact(&mut src, pi_len)?.to_vec();
    let ell_len = u32::from_le_bytes(read_exact(&mut src, 4)?.try_into().unwrap()) as usize;
    let vdf_ell = read_exact(&mut src, ell_len)?.to_vec();
    let ticket_root = { let b = read_exact(&mut src, 32)?; let mut a = [0u8;32]; a.copy_from_slice(b); a };
    let part_root   = { let b = read_exact(&mut src, 32)?; let mut a = [0u8;32]; a.copy_from_slice(b); a };
    let txroot_prev = { let b = read_exact(&mut src, 32)?; let mut a = [0u8;32]; a.copy_from_slice(b); a };
    if !src.is_empty() { return Err(CodecError::Trailing); }
    Ok(Header { parent_id, slot, obex_version, seed_commit, vdf_y_core, vdf_y_edge, vdf_pi, vdf_ell, ticket_root, part_root, txroot_prev })
}

/// Build the canonical header for slot s = parent.slot + 1.
#[must_use]
pub fn build_header(
    parent: &Header,
    beacon_fields: (Hash256, Hash256, Hash256, Vec<u8>, Vec<u8>),
    ticket_roots: &impl TicketRootProvider,
    part_roots: &impl PartRootProvider,
    tx_roots: &impl TxRootProvider,
    obex_version: u32,
) -> Header {
    let s = parent.slot + 1;
    let (seed_commit, y_core, y_edge, pi, ell) = beacon_fields;

    let ticket_root = ticket_roots.compute_ticket_root(s);
    let part_root = part_roots.compute_part_root(s);
    let txroot_prev = tx_roots.compute_txroot(parent.slot);

    Header {
        parent_id: obex_header_id(parent),
        slot: s,
        obex_version,
        seed_commit,
        vdf_y_core: y_core,
        vdf_y_edge: y_edge,
        vdf_pi: pi,
        vdf_ell: ell,
        ticket_root,
        part_root,
        txroot_prev,
    }
}

/// Validation errors
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidateErr {
    BadParentLink,
    BadSlotProgression,
    BeaconInvalid,
    TicketRootMismatch,
    PartRootMismatch,
    TxRootPrevMismatch,
    VersionMismatch,
}

/// Validate a candidate header against deterministic equalities.
pub fn validate_header(
    h: &Header,
    parent: &Header,
    beacon: &impl BeaconVerifier,
    ticket_roots: &impl TicketRootProvider,
    part_roots: &impl PartRootProvider,
    tx_roots: &impl TxRootProvider,
    expected_version: u32,
) -> Result<(), ValidateErr> {
    // 1) Parent linkage & slot progression
    let parent_id_expected = obex_header_id(parent);
    if !ct_eq_hash(&h.parent_id, &parent_id_expected) { return Err(ValidateErr::BadParentLink); }
    if h.slot != parent.slot + 1 { return Err(ValidateErr::BadSlotProgression); }

    // 2) Beacon equality & caps (size first)
    if h.vdf_pi.len() > MAX_PI_LEN || h.vdf_ell.len() > MAX_ELL_LEN {
    return Err(ValidateErr::BeaconInvalid);
    }
    if !beacon.verify(&BeaconInputs {
        parent_id: &h.parent_id,
        slot: h.slot,
        seed_commit: &h.seed_commit,
        vdf_y_core: &h.vdf_y_core,
        vdf_y_edge: &h.vdf_y_edge,
        vdf_pi: &h.vdf_pi,
        vdf_ell: &h.vdf_ell,
    }) {
        return Err(ValidateErr::BeaconInvalid);
    }

    // 3) Admission equality (slot s)
    let ticket_root_local = ticket_roots.compute_ticket_root(h.slot);
    if !ct_eq_hash(&h.ticket_root, &ticket_root_local) { return Err(ValidateErr::TicketRootMismatch); }

    // 4) Participation equality (slot s)
    let part_root_local = part_roots.compute_part_root(h.slot);
    if !ct_eq_hash(&h.part_root, &part_root_local) { return Err(ValidateErr::PartRootMismatch); }

    // 5) Execution equality (slot s-1)
    let txroot_prev_local = tx_roots.compute_txroot(parent.slot);
    if !ct_eq_hash(&h.txroot_prev, &txroot_prev_local) { return Err(ValidateErr::TxRootPrevMismatch); }

    // 6) Version equality
    if h.obex_version != expected_version { return Err(ValidateErr::VersionMismatch); }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    struct BeaconOk;
    impl BeaconVerifier for BeaconOk { fn verify(&self, _inputs: &BeaconInputs<'_>) -> bool { true } }
    struct ZeroRoot;
    impl TicketRootProvider for ZeroRoot { fn compute_ticket_root(&self, _slot: u64) -> Hash256 { [0u8; 32] } }
    impl PartRootProvider   for ZeroRoot { fn compute_part_root(&self, _slot: u64) -> Hash256 { [0u8; 32] } }
    impl TxRootProvider     for ZeroRoot { fn compute_txroot(&self, _slot: u64) -> Hash256 { [0u8; 32] } }

    #[test]
    fn header_build_and_validate_roundtrip() {
        let parent = Header {
            parent_id: [9u8; 32],
            slot: 7,
            obex_version: OBEX_ALPHA_II_VERSION,
            seed_commit: [1u8; 32],
            vdf_y_core: [2u8; 32],
            vdf_y_edge: [3u8; 32],
            vdf_pi: vec![],
            vdf_ell: vec![],
            ticket_root: [0u8; 32],
            part_root: [0u8; 32],
            txroot_prev: [0u8; 32],
        };
        let providers = ZeroRoot;
        let h = build_header(
            &parent,
            ([4u8; 32], [5u8; 32], [6u8; 32], vec![], vec![]),
            &providers,
            &providers,
            &providers,
            OBEX_ALPHA_II_VERSION,
        );
        let beacon = BeaconOk;
        assert!(validate_header(&h, &parent, &beacon, &providers, &providers, &providers, OBEX_ALPHA_II_VERSION).is_ok());
    }
}


