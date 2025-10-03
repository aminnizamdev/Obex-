# OBEX Alpha v1.0.0

[![License: MIT OR Apache-2.0](https://img.shields.io/badge/License-MIT%20OR%20Apache--2.0-blue.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/rust-stable-orange.svg)](https://www.rust-lang.org/)

> **A next-generation blockchain protocol implementing verifiable random functions (VRF), deterministic consensus, and modular tokenomics with comprehensive testing infrastructure.**

OBEX Alpha is a production-ready blockchain implementation featuring RFC 9381 ECVRF consensus, deterministic header validation, transaction admission control, and sophisticated tokenomics. Built with Rust for maximum safety, performance, and cryptographic security.

## Features

### Core Protocol Components

- **VRF-Based Consensus**: RFC 9381 ECVRF-EDWARDS25519-SHA512-TAI implementation with pluggable verification
- **Participation Engine**: Memory-intensive proofs with 96 challenges (2^-96 security) and 512 MiB RAM target
- **Deterministic Headers**: Forkless consensus through equality-based header validation
- **Transaction Admission**: Fee-based admission with flat/percentage fee structures and access list encoding
- **Tokenomics Engine**: Emission control with halving periods, escrow, and DRP (Distributed Reward Protocol)
- **Cryptographic Security**: Ed25519 signatures with domain-tagged SHA3-256 hashing

### Architecture Highlights

- **Modular Design**: Five specialized engines (α-I, α-II, α-III, α-T) plus E2E integration layer
- **Type Safety**: Comprehensive Rust type system with zero unsafe code and strict error handling
- **Comprehensive Testing**: 47+ tests including golden byte verification, VRF compliance, and E2E pipeline tests
- **Production Ready**: Frozen consensus rules, deterministic behavior, and comprehensive fuzzing infrastructure

## Table of Contents

- [Quick Start](#quick-start)
- [Architecture](#architecture)
- [Installation](#installation)
- [Usage](#usage)
- [Testing](#testing)
- [API Documentation](#api-documentation)
- [Contributing](#contributing)
- [Security](#security)
- [License](#license)

## Quick Start

```bash
# Clone the repository
git clone https://github.com/aminnizamdev/Obex-.git
cd Obex-

# Build the project
cargo build --release

# Run comprehensive tests
cargo test --workspace --all-features

# Run VRF-specific tests
cargo test --package obex_alpha_i --features ecvrf_rfc9381

# Run end-to-end pipeline tests
cargo test --package e2e
```

## Architecture

OBEX Alpha implements a sophisticated multi-engine architecture:

```
┌─────────────────────────────────────────────────────────────┐
│                    OBEX Alpha Protocol                      │
├─────────────────────────────────────────────────────────────┤
│  α-I: Participation Engine (VRF + RAM-hard proofs)         │
│  α-II: Header Engine (Block validation & chain linking)    │
│  α-III: Admission Engine (Transaction processing)          │
│  α-T: Tokenomics Engine (Rewards & system transactions)    │
│  E2E: Integration Layer (End-to-end pipeline)              │
├─────────────────────────────────────────────────────────────┤
│           Primitives: Consensus, Crypto, Merkle            │
└─────────────────────────────────────────────────────────────┘
```

### Engine Responsibilities

| Engine | Purpose | Key Features |
|--------|---------|--------------|
| **α-I** | Participation Engine | RFC 9381 VRF verification, 96-challenge proofs, Merkle path validation, 512 MiB RAM target |
| **α-II** | Header Engine | Deterministic header validation, forkless consensus, VDF integration, beacon verification |
| **α-III** | Admission Engine | Transaction fee calculation, access list encoding, bind value validation, memo support |
| **α-T** | Tokenomics Engine | Emission scheduling, halving periods, reward distribution, 21M total supply |
| **E2E** | Integration Layer | 3-slot pipeline testing, settlement/finality/emission, mock provider implementations |

## Installation

### Prerequisites

- **Rust 1.70+**: Install from [rustup.rs](https://rustup.rs/)
- **Git**: For version control and dependency management

### Build from Source

```bash
# Clone repository
git clone https://github.com/aminnizamdev/Obex-.git
cd Obex-

# Install dependencies and build
cargo build --release

# Verify installation
cargo test --workspace
```

### Feature Flags

```toml
# obex_primitives features
[features]
default = ["std"]
std = []                                  # Standard library support
alloc = []                               # Allocation support for no_std

# obex_alpha_i features  
[features]
default = ["ecvrf_rfc9381"]
ecvrf_rfc9381 = ["vrf-rfc9381", "sha2"]  # RFC 9381 VRF implementation
```

## Usage

### Basic VRF Operations

```rust
use obex_alpha_i::vrf;

// Verify VRF proof using RFC 9381 ECVRF
let pk_bytes: [u8; 32] = [/* Ed25519 public key */];
let alpha = b"input_message";
let proof: [u8; 80] = [/* VRF proof: gamma(32) || c(16) || s(32) */];

match vrf::verify(&pk_bytes, alpha, &proof) {
    Ok(output) => println!("VRF output: {:02x?}", &output[..16]),
    Err(e) => eprintln!("VRF verification failed: {:?}", e),
}
```

### Participation Record Verification

```rust
use obex_alpha_i::{ObexPartRec, ChallengeOpen, MerklePathLite};

// Create participation record
let partrec = ObexPartRec {
    vrf_pk: [/* 32-byte Ed25519 public key */],
    vrf_proof: [/* 80-byte VRF proof */],
    challenges: vec![
        ChallengeOpen {
            index: 12345,
            value: [/* 32-byte challenge value */],
            path: MerklePathLite { path: vec![[0u8; 32]; 20] },
        },
        // ... up to 96 challenges
    ],
};

// Verification would be done through the participation engine
println!("Participation record with {} challenges", partrec.challenges.len());
```

### Header Operations

```rust
use obex_alpha_ii::{Header, obex_header_id};
use obex_primitives::Hash256;

// Create header
let header = Header {
    parent_id: Hash256([/* parent block hash */]),
    slot: 12345,
    version: 2,
    vdf_input: [/* VDF input */],
    vdf_proof: vec![/* VDF proof */],
    vdf_output: [/* VDF output */],
    ticket_root: Hash256([/* ticket Merkle root */]),
    part_root: Hash256([/* participation root */]),
    tx_root: Hash256([/* transaction root */]),
};

// Compute canonical header ID
let header_id = obex_header_id(&header);
println!("Header ID: {:02x?}", &header_id[..8]);
```

### Transaction Fee Calculation

```rust
use obex_alpha_iii::{fee_int_uobx, TxBodyV1, AccessList};

// Calculate transaction fee
let amount_uobx = 1_000_000; // 1 OBX in micro-OBX
let fee = fee_int_uobx(amount_uobx);
println!("Transaction fee: {} μOBX", fee);

// Create transaction body
let tx_body = TxBodyV1 {
    sender: [/* 32-byte sender address */],
    recipient: [/* 32-byte recipient address */],
    nonce: 42,
    amount_uobx,
    fee_uobx: fee,
    bind_1: [0u8; 32],
    bind_2: [0u8; 32],
    access_list: AccessList {
        read_accounts: vec![[/* account addresses */]],
        write_accounts: vec![[/* account addresses */]],
    },
    memo: b"payment memo".to_vec(),
};
```

### Tokenomics Operations

```rust
use obex_alpha_t::{EmissionState, on_slot_emission, period_index};

// Calculate emission for a slot
let slot = 1_000_000;
let period = period_index(slot);
let mut emission_state = EmissionState { total_emitted_uobx: 0 };

let emission = on_slot_emission(slot, &mut emission_state);
println!("Slot {} (period {}): {} μOBX emitted", slot, period, emission);
println!("Total emitted: {} μOBX", emission_state.total_emitted_uobx);
```

## Examples and Benchmarks

OBEX Alpha includes comprehensive examples and performance testing infrastructure:

### Examples

- **`ecvrf_implementation.rs`**: Complete VRF implementation with real cryptography
- **`ecvrf_verification.rs`**: Verification-only VRF implementation for validators
- **`vrf_r255_api.rs`**: Pure Rust vrf-r255 backend integration

### Benchmarks

Performance benchmarks using Criterion.rs:

```bash
# Run all benchmarks
cargo bench

# Benchmark specific operations
cargo bench merkle_verify
cargo bench vrf_verify
cargo bench challenge_derivation
```

### Fuzzing Infrastructure

Comprehensive fuzzing with libfuzzer-sys:

```bash
# Install cargo-fuzz
cargo install cargo-fuzz

# Run registration decoding fuzz tests
cargo fuzz run registration_decode

# Run registration verification fuzz tests  
cargo fuzz run registration_verify
```

## Testing

OBEX Alpha includes comprehensive test coverage across all components:

### Test Categories

```bash
# Unit tests for all components
cargo test --workspace

# VRF-specific tests with RFC 9381 vectors
cargo test --package obex_alpha_i --features ecvrf_rfc9381

# Golden byte tests (consensus-critical)
cargo test golden

# End-to-end pipeline tests
cargo test --package e2e

# Performance benchmarks
cargo bench
```

### Test Results Summary

- **Total Tests**: 47+ comprehensive test cases
- **Coverage**: All critical paths and edge cases
- **Golden Tests**: Byte-precise consensus validation
- **VRF Vectors**: RFC 9381 compliance verification
- **E2E Tests**: 3-slot pipeline determinism

### Key Test Suites

| Test Suite | Purpose | Coverage |
|------------|---------|----------|
| `vrf_rfc9381_*` | VRF compliance | RFC 9381 test vectors |
| `golden_*` | Consensus validation | Byte-precise serialization |
| `e2e_*` | Integration testing | Multi-slot pipelines |
| `header_*` | Block validation | Header format compliance |
| `ticket_*` | Transaction processing | Fee and admission rules |

## API Documentation

### Core Types

```rust
// Cryptographic primitives (obex_primitives)
pub type Hash256 = [u8; 32];           // SHA3-256 output
pub type Pk32 = [u8; 32];              // Ed25519 public key
pub type Sig64 = [u8; 64];             // Ed25519 signature

// Participation engine constants (obex_alpha_i)
pub const CHALLENGES_Q: usize = 96;     // Challenge count (2^-96 security)
pub const MEM_MIB: usize = 512;         // RAM target per prover (512 MiB)
pub const N_LABELS: usize = 134_217_728; // 2^27 labels in dataset
pub const PASSES: usize = 3;            // Argon2 passes

// Header engine constants (obex_alpha_ii)
pub const MAX_PI_LEN: usize = 1024;     // Max VDF proof length
pub const MAX_ELL_LEN: usize = 64;      // Max VDF output length

// Admission engine constants (obex_alpha_iii)
pub const MIN_TX_UOBX: u64 = 1;         // Minimum transaction amount
pub const FLAT_SWITCH_UOBX: u64 = 1_000_000; // Fee structure switch point
pub const FLAT_FEE_UOBX: u64 = 1000;    // Flat fee for small transactions

// Tokenomics constants (obex_alpha_t)
pub const TOTAL_SUPPLY_UOBX: u64 = 21_000_000_000_000; // 21M OBX total
pub const SLOTS_PER_PROTOCOL_YEAR: u64 = 31_557_600;   // ~1 year in slots
pub const LAST_EMISSION_SLOT: u64 = 1_325_419_200;     // Final emission slot
```

### Key Functions

```rust
// VRF operations (obex_alpha_i::vrf)
pub fn verify(pk: &[u8; 32], alpha: &[u8], proof: &[u8; 80]) -> Result<[u8; 64], VrfError>;
pub fn verify_msg_tai(pk: &[u8; 32], alpha: &[u8], proof: &[u8; 80]) -> Result<[u8; 64], VrfError>;

// Header operations (obex_alpha_ii)
pub fn obex_header_id(header: &Header) -> Hash256;

// Transaction operations (obex_alpha_iii)
pub fn fee_int_uobx(amount_uobx: u64) -> u64;
pub fn encode_access(access_list: &AccessList) -> Vec<u8>;
pub fn canonical_tx_bytes(tx_body: &TxBodyV1) -> Vec<u8>;

// Tokenomics operations (obex_alpha_t)
pub fn period_index(slot: u64) -> u32;
pub fn reward_den_for_period(period: u32) -> u64;
pub fn on_slot_emission(slot: u64, state: &mut EmissionState) -> u64;

// Cryptographic primitives (obex_primitives)
pub fn h_tag(tag: &[u8], data: &[u8]) -> Hash256;
pub fn sha3_256(data: &[u8]) -> Hash256;
pub fn merkle_leaf(data: &[u8]) -> Hash256;
pub fn merkle_node(left: &Hash256, right: &Hash256) -> Hash256;
pub fn merkle_root(leaves: &[Hash256]) -> Hash256;
```

## Contributing

We welcome contributions to OBEX Alpha! Please follow these guidelines:

### Development Setup

```bash
# Fork and clone the repository
git clone https://github.com/yourusername/Obex-.git
cd Obex-

# Make your changes and test
cargo test --workspace --all-features
cargo fmt --all
cargo clippy --all-targets --all-features
```

### Code Standards

- **Safety First**: No `unsafe` code without exceptional justification
- **Comprehensive Testing**: All new features must include tests
- **Documentation**: Public APIs require documentation
- **Performance**: Benchmark performance-critical changes
- **Consensus Safety**: Changes to consensus rules require careful review

<!-- Pull request workflow omitted for solo development setup -->

## Security

OBEX Alpha prioritizes security through multiple layers:

### Cryptographic Security

- **VRF Implementation**: RFC 9381 ECVRF-EDWARDS25519-SHA512-TAI
- **Digital Signatures**: Ed25519 with domain separation
- **Hash Functions**: SHA3-256 with length framing
- **Memory Safety**: Rust's ownership system prevents common vulnerabilities

### Consensus Security

- **Deterministic Execution**: Reproducible state transitions
- **Byzantine Fault Tolerance**: Robust under adversarial conditions
- **DoS Protection**: Size limits and resource constraints
- **Cryptographic Proofs**: Verifiable random functions and Merkle proofs

### Reporting Security Issues

Please report security vulnerabilities to: **security@obex.example**

- Use encrypted communication when possible
- Provide detailed reproduction steps
- Allow reasonable time for response and fixes
- Follow responsible disclosure practices

## License

OBEX Alpha is dual-licensed under:

- **MIT License** ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)
- **Apache License 2.0** ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)

You may choose either license for your use.

### Third-Party Licenses

This project includes dependencies with their own licenses:

- `ed25519-dalek`: BSD-3-Clause
- `sha3`: MIT OR Apache-2.0
- `vrf-rfc9381`: MIT OR Apache-2.0
- `serde`: MIT OR Apache-2.0

## Acknowledgments

- **RFC 9381**: IETF VRF specification authors
- **Rust Community**: For exceptional tooling and libraries
- **Cryptography Researchers**: For foundational security research
- **Open Source Contributors**: For reviews, testing, and improvements


*OBEX Alpha v1.0.0 - Production-ready blockchain protocol with VRF consensus*
