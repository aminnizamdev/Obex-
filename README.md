# OBEX Alpha v1.0.0

[![CI](https://github.com/aminnizamdev/Obex-/actions/workflows/ci.yml/badge.svg)](https://github.com/aminnizamdev/Obex-/actions/workflows/ci.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/License-MIT%20OR%20Apache--2.0-blue.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange.svg)](https://www.rust-lang.org/)

> **A next-generation blockchain protocol implementing verifiable random functions (VRF), RAM-hard proof-of-work, and deterministic consensus mechanisms.**

OBEX Alpha is a cutting-edge blockchain implementation featuring cryptographically secure consensus, VRF-based randomness, and a modular architecture designed for high-performance distributed systems. Built with Rust for maximum safety and performance.

## Features

### Core Protocol Components

- **VRF-Based Consensus**: RFC 9381 ECVRF-EDWARDS25519-SHA512-TAI implementation
- **RAM-Hard Proof System**: Memory-intensive participation proofs (512 MiB target)
- **Cryptographic Security**: Ed25519 signatures with SHA3-256 domain separation
- **High Performance**: Zero-copy serialization and optimized data structures
- **Deterministic Consensus**: Reproducible state transitions and ticket ordering
- **Byzantine Fault Tolerance**: Robust consensus under adversarial conditions

### Architecture Highlights

- **Modular Design**: Five specialized engines (α-I through α-T + E2E)
- **Type Safety**: Comprehensive Rust type system with zero unsafe code
- **Comprehensive Testing**: 47+ tests with golden byte verification
- **CI/CD Pipeline**: Automated testing with feature matrix validation
- **Production Ready**: Frozen consensus rules and deterministic behavior

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
| **α-I** | Participation proofs | VRF verification, RAM-hard challenges, Merkle proofs |
| **α-II** | Block headers | Parent-child linking, slot validation, header v2 format |
| **α-III** | Transaction admission | Fee validation, ticket processing, state updates |
| **α-T** | Tokenomics | Reward distribution, system transactions, emission control |
| **E2E** | Integration | 3-slot pipeline, deterministic ordering, golden tests |

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
[features]
default = []
ecvrf_rfc9381 = ["vrf-rfc9381", "sha2"]  # RFC 9381 VRF implementation
std = []                                  # Standard library support
alloc = []                               # Allocation support for no_std
```

## Usage

### Basic VRF Operations

```rust
use obex_alpha_i::{vrf, VrfPk32};

// Verify VRF proof using RFC 9381 ECVRF
let vrf_pk: VrfPk32 = [/* 32-byte Ed25519 public key */];
let alpha = [/* 32-byte input */];
let proof = [/* 80-byte VRF proof */];

match vrf::verify(&vrf_pk, &alpha, &proof) {
    Ok(output) => println!("VRF output: {:?}", output),
    Err(e) => eprintln!("VRF verification failed: {}", e),
}
```

### Participation Record Verification

```rust
use obex_alpha_i::{verify_partrec, PartRec};

// Verify participation record
let parent_id = [/* parent block hash */];
let slot = 12345u64;
let y_prev = [/* previous VRF output */];
let partrec = PartRec { /* participation record */ };

match verify_partrec(&parent_id, slot, &y_prev, &partrec) {
    Ok(()) => println!("Participation record valid"),
    Err(e) => eprintln!("Verification failed: {:?}", e),
}
```

### Header Validation

```rust
use obex_alpha_ii::{verify_header, HeaderV2};

// Validate block header
let header = HeaderV2 { /* header data */ };
let parent_header = HeaderV2 { /* parent header */ };

match verify_header(&header, Some(&parent_header)) {
    Ok(()) => println!("Header valid"),
    Err(e) => eprintln!("Header validation failed: {:?}", e),
}
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
// Cryptographic primitives
pub type Hash256 = [u8; 32];           // SHA3-256 output
pub type VrfPk32 = [u8; 32];           // Ed25519 VRF public key
pub type Sig64 = [u8; 64];             // Ed25519 signature

// Consensus constants
pub const CHALLENGES_Q: usize = 96;     // Challenge count (2^-96 security)
pub const MEM_MIB: usize = 512;         // RAM target per prover
pub const MAX_PARTREC_SIZE: usize = 600_000; // DoS protection limit
```

### Key Functions

```rust
// VRF operations
pub fn verify(pk: &VrfPk32, alpha: &[u8; 32], proof: &[u8; 80]) -> Result<[u8; 64], VrfError>;

// Participation verification
pub fn verify_partrec(parent_id: &Hash256, slot: u64, y_prev: &Hash256, rec: &PartRec) -> Result<(), VerifyErr>;

// Header validation
pub fn verify_header(header: &HeaderV2, parent: Option<&HeaderV2>) -> Result<(), HeaderErr>;

// Merkle operations
pub fn merkle_root(leaves: &[Hash256]) -> Hash256;
pub fn merkle_verify_leaf(root: &Hash256, index: usize, leaf: &Hash256, path: &[Hash256]) -> bool;
```

## Contributing

We welcome contributions to OBEX Alpha! Please follow these guidelines:

### Development Setup

```bash
# Fork and clone the repository
git clone https://github.com/yourusername/Obex-.git
cd Obex-

# Create a feature branch
git checkout -b feature/your-feature-name

# Make your changes and test
cargo test --workspace --all-features
cargo fmt --all
cargo clippy --all-targets --all-features

# Submit a pull request
```

### Code Standards

- **Safety First**: No `unsafe` code without exceptional justification
- **Comprehensive Testing**: All new features must include tests
- **Documentation**: Public APIs require documentation
- **Performance**: Benchmark performance-critical changes
- **Consensus Safety**: Changes to consensus rules require careful review

### Pull Request Process

1. **Fork** the repository and create a feature branch
2. **Implement** your changes with comprehensive tests
3. **Validate** all tests pass: `cargo test --workspace --all-features`
4. **Format** code: `cargo fmt --all`
5. **Lint** code: `cargo clippy --all-targets --all-features`
6. **Submit** pull request with detailed description

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

## Support

- **Documentation**: [API Docs](https://docs.rs/obex-alpha)
- **Issues**: [GitHub Issues](https://github.com/aminnizamdev/Obex-/issues)
- **Discussions**: [GitHub Discussions](https://github.com/aminnizamdev/Obex-/discussions)
- **Email**: engineering@obex.example

---

**Built by the OBEX Labs team**

*OBEX Alpha v1.0.0 - Production-ready blockchain protocol with VRF consensus*