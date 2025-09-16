# Obex Engine I - Standardized Terminology Glossary

## Core Project Identity
- **Project Name**: Obex Engine I (OE1)
- **Package Name**: `obex_engine_i`
- **Version**: 0.2.0

## VRF (Verifiable Random Function) Terminology

### Standard Terms (RFC 9381 Compliant)
- **VRF**: Verifiable Random Function
- **ECVRF**: Elliptic Curve Verifiable Random Function
- **Ciphersuite**: ECVRF-RISTRETTO255-SHA512 (RFC 9381)
- **VRF Input**: `alpha` (input message to VRF)
- **VRF Output**: `y` (64-byte hash output)
- **VRF Proof**: `π` (pi) (80-byte proof: gamma(32) || c(16) || s(32))
- **VRF Public Key**: `pk` (32 bytes)
- **VRF Secret Key**: `sk` (32 bytes for R255, 64 bytes for libsodium)

### VRF Implementation Types
- **EcVrfRistretto255**: Pure Rust RFC 9381 implementation using vrf-r255
- **EcVrfEd25519Libsodium**: Libsodium-based RFC 9381 implementation

## Cryptographic Primitives

### Hash Functions
- **BLAKE3**: Primary hash function (32-byte output)
- **SHA-512**: Used in ECVRF ciphersuite

### Digital Signatures
- **Ed25519**: Digital signature scheme
- **Signature**: `σ` (sigma) (64 bytes)
- **Signing Key**: Ed25519 private key (32 bytes)
- **Verifying Key**: Ed25519 public key (32 bytes)

## Blockchain/Protocol Terminology

### Chain Parameters
- **Chain ID**: 32-byte chain identifier
- **Epoch Number**: u64 epoch counter
- **Epoch Nonce**: 32-byte random value per epoch
- **Epoch Hash**: `E` (32-byte epoch identifier)

### Domain Separation
- **Domain Tag**: `[Iota]_|::"v1"` (14 ASCII bytes)
- **Protocol Version**: v1

### Dataset and Merkle Tree
- **Dataset Size**: 2 GiB (2,147,483,648 bytes)
- **Leaf Size**: 32 bytes
- **Number of Leaves**: N = 67,108,864 (2^26)
- **Merkle Depth**: 26 levels
- **Leaf**: 32-byte data element
- **Node**: 32-byte Merkle tree internal node
- **Root**: 32-byte Merkle tree root
- **Merkle Path**: Authentication path with siblings

### Registration and Tickets
- **Registration**: Participant submission with dataset proof
- **Challenge**: Indices to prove dataset possession
- **Challenge Seed**: `C` (32 bytes)
- **Ticket**: Issuer-signed authorization
- **Identity Binding**: Message `M` linking epoch to participant

## Encoding Standards
- **LE64**: Little-endian 64-bit encoding
- **Byte Concatenation**: `||` operator
- **Array Notation**: `[start, end)` for ranges

## Error Handling
- **Step1Error**: Primary error type for protocol violations
- **VrfError**: VRF-specific error type

## Implementation Patterns
- **NewVrf**: Modern VRF trait from ecvrf_traits module
- **Vrf**: Legacy VRF trait for backward compatibility
- **Factory Function**: `mk_chain_vrf()`
- **Adapter Pattern**: `LegacyVrfAdapter<T>`

## Type Aliases
- **VrfProofNew**: Type alias for `VrfProof` from ecvrf_traits module
- **VrfOutputNew**: Type alias for `VrfOutput` from ecvrf_traits module
- **NewVrf**: Type alias for the new `Vrf` trait from ecvrf_traits module

## Constants Naming Convention
- Use SCREAMING_SNAKE_CASE for constants
- Prefix with component: `ECVRF_`, `DATASET_`, `MERKLE_`
- Suffix with unit: `_LEN`, `_BYTES`, `_DEPTH`

## Function Naming Convention
- Use snake_case for functions
- Prefix with action: `compute_`, `build_`, `derive_`, `verify_`, `generate_`
- Mathematical variables: Use single letters (`E`, `M`, `C`) when matching spec

## Documentation Standards
- Use `///` for public API documentation
- Use `//!` for module-level documentation
- Reference RFC 9381 for VRF-related functionality
- Include byte lengths in parentheses: "(32 bytes)"
- Use mathematical notation for formulas: `E = BLAKE3(...)`