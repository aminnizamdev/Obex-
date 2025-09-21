# Obex Engine I - Standardized Terminology Glossary

## Core Project Identity
- **Project Name**: Obex Engine I (OE1)
- **Package Name**: `obex_engine_i`
- **Version**: see `src/lib.rs::VERSION`

## VRF (Verifiable Random Function) Terminology

### Standard Terms (RFC 9381 Compliant)
- **VRF**: Verifiable Random Function
- **ECVRF**: Elliptic Curve Verifiable Random Function
- **Ciphersuite**: ECVRF-RISTRETTO255-SHA512 (RFC 9381)
- **VRF Input**: `alpha` (α) (86 bytes) = `DOMAIN_TAG || CHAIN_ID(32) || LE64(epoch_number) || EPOCH_NONCE(32)`
- **VRF Output**: `y` (64 bytes)
- **VRF Proof**: `π` (80 bytes) = `gamma(32) || c(16) || s(32)`
- **VRF Public Key**: 32-byte Ristretto VRF key (distinct from Ed25519)
- **VRF Secret Key**: not exposed in the public adapter; proving is used in examples

### VRF Implementation Types
- **ChainVrf**: Verify-only adapter backed by `vrf-r255` (public API)
- **EcVrfRistretto255**: Feature-gated proving/verification used in examples

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
- **Epoch Hash**: `E` (32-byte BLAKE3 digest; `EpochHash` newtype)

### Domain Separation
- **Domain Tag**: `[Iota]_|::"v1"` (14 ASCII bytes)
- **Protocol Version**: v1
- **Tags**: `VRFOUT`, `EPOCH`, `SEED`, `KDF`, `CHAL`

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
 - **Challenge Count**: `CHALLENGE_COUNT = 32` indices per registration

## Encoding Standards
- **LE64**: Little-endian 64-bit encoding
- **Byte Concatenation**: `||` operator
- **Array Notation**: `[start, end)` for ranges
- **VRF Input α**: fixed 86-byte array built only via `build_alpha`
- **Registration (wire)**: strict order, fixed lengths, includes domain tag; rejects trailing bytes:
  `DOMAIN_TAG(14) || CHAIN_ID(32) || LE64(epoch)(8) || EPOCH_NONCE(32) || y(64) || π(80) || E(32) || root(32) || pk(32) || σ(64)`
- **MerklePath**: `LE32(count)` followed by `count × 32`-byte nodes

## Error Handling
- **Step1Error**: Primary error type with variants including:
  - `InvalidLength`, `OutOfRangeIndex`, `InvalidProof`, `InvalidSignature`
  - `MerklePathMismatch`, `ChallengeDerivationError`, `ChallengeDerivationFailed`, `ChallengeIndicesMismatch`
  - `DecodeError`, `EncodeError`, `TicketExpired`
- **VrfError**: VRF-specific error (internal/examples), not used by the public adapter

## Implementation Patterns
- **Verify-only adapter**: `mk_chain_vrf([u8;32]) -> impl Vrf` using a Ristretto VRF public key
- **Strict lints**: `forbid(unsafe_code)`, deny warnings, Clippy all/pedantic/nursery
- **Determinism**: byte-precise construction; no trailing bytes accepted by decoders
- **Uniformity**: challenge indices via rejection sampling; bounded retries; uniqueness enforced

## Type System
- **Newtypes**: `ChainId([u8;32])`, `EpochNonce([u8;32])`, `EpochHash([u8;32])`, `VrfOutput([u8;64])`, `VrfProof([u8;80])`, `MerkleRoot([u8;32])`
- **MerklePath**: `path: Vec<[u8;32]>`
- **Registration<'a>**: references chain parameters, VRF items, `E`, identity `(pk, σ)`, and `root`

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