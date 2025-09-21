#![forbid(unsafe_code)]
#![deny(warnings)]
#![deny(clippy::all, clippy::pedantic, clippy::nursery)]

//! Obex Engine I - Step 1 Implementation
//!
//! This crate implements the cryptographic core for Obex Engine I's Step 1 protocol.
//! It provides secure, efficient implementations of VRF verification, Merkle path
//! validation, challenge derivation, and registration verification.

// Step 1: Sybil-deterrence (byte-precise, exact to agreed spec)
//
// Fixed cryptographic choices agreed:
// - Hash: BLAKE3 (32-byte output)
// - Signature: Ed25519
// - VRF: ECVRF-RISTRETTO255-SHA512 (RFC 9381)
// - Merkle tree: Binary, BLAKE3-based, 2^26 leaves
// - Domain separation: 14-byte ASCII tag "[Iota]_|::"v1"
//
// This implementation prioritizes:
// 1. Correctness: Exact adherence to the agreed specification
// 2. Security: Constant-time operations where applicable
// 3. Performance: Optimized for batch operations
// 4. Maintainability: Clear, well-documented code structure

// Core modules
pub mod types;
pub mod errors;
pub mod ser;
pub mod domain;
pub mod vrf;
pub mod merkle;
pub mod challenge;
pub mod dataset;
pub mod registration;
pub mod hashers;
pub mod ticket;
pub mod ecvrf_traits;
pub mod ecvrf_ristretto255;

// Re-export commonly used types and functions
pub use types::*;
pub use errors::Step1Error;
pub use vrf::{Vrf, ChainVrf, mk_chain_vrf};
pub use merkle::verify_merkle_path;
pub use challenge::{derive_challenge_indices, verify_challenge_indices};
pub use dataset::compute_leaf;
pub use registration::{verify_registration_succinct, verify_registration, verify_challenge_open, verify_registrations_batch};
pub use hashers::{compute_epoch_hash, build_m, derive_seed_and_key, build_challenge_seed};
pub use ticket::{verify_ticket_time, create_ticket, verify_tickets_batch, is_ticket_valid_time};

// Version and protocol constants
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const PROTOCOL_VERSION: u32 = 1;
