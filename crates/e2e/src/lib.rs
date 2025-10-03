//! End-to-end integration tests for OBEX.ALPHA protocol
//!
//! This crate provides comprehensive integration tests that exercise
//! the full protocol pipeline across α-I, α-II, α-III, and α-T.

#![forbid(unsafe_code)]
#![deny(warnings)]

// Anchor to ensure SHA3-256 presence without underscore-binding side effects.
pub use obex_primitives::OBEX_SHA3_256_ANCHOR as _obex_sha3_anchor_e2e;
