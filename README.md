Obex α — Deterministic, Byte‑Precise Engines (I, II, III, T)

## Overview

Obex α is a Rust workspace implementing the consensus‑critical components of the OBEX protocol as four engines, plus shared primitives:

- obex_primitives: cryptographic primitives (SHA3‑256 domain‑tagged hashing, fixed‑width LE encodings, binary Merkle, constant‑time digest equality) and shared constants
- obex_alpha_i: Participation Engine (VRF‑salted, RAM‑hard labeling, canonical participation record codecs)
- obex_alpha_ii: Deterministic Header Engine (forkless via equality checks and canonical header codecs)
- obex_alpha_iii: Deterministic Admission (fee rule, ticket records, per‑slot ticket Merkle)
- obex_alpha_t: Tokenomics (emission schedule, escrow with epoch‑stable NLB splits, DRP distribution, system transactions)

The codebase is byte‑precise and strongly typed. All crates forbid unsafe code and deny all Clippy lints including pedantic, nursery, and cargo. Consensus hashing is SHA3‑256 only with OBEX domain tags and length framing.

## Linting, Toolchain, and MSRV

- Toolchain: stable (pinned via `rust-toolchain.toml`)
- Lints: `#![forbid(unsafe_code)]` and `#![deny(warnings, clippy::all, clippy::pedantic, clippy::nursery, clippy::cargo)]` across crates
- Formatting: standard rustfmt
- Minimum Supported Rust Version: stable toolchain specified above

## Workspace Layout

```text
crates/
  obex_primitives/
  obex_alpha_i/      # α I — Participation
  obex_alpha_ii/     # α II — Headers
  obex_alpha_iii/    # α III — Admission
  obex_alpha_t/      # α T — Tokenomics
```

## obex_primitives

Core utilities and consensus constants. `no_std` ready with feature‑gated `alloc`.

- Features:
  - default: `std`
  - optional: `alloc` (with `no_std`)
- Types:
  - `Hash256 = [u8; 32]`, `Pk32 = [u8; 32]`, `Sig64 = [u8; 64]`
- Hashing and encodings:
  - `h_tag(tag, parts) -> Hash256`: domain‑tagged SHA3‑256 with length framing
  - `le_bytes<const W: usize>(x: u128) -> [u8; W]`: fixed‑width little‑endian
  - `u64_from_le(b: &[u8]) -> u64`
- Merkle:
  - `merkle_leaf(payload)`, `merkle_node(l, r)`, `merkle_root(leaves)` (duplicate‑last rule for odd counts)
  - `MerklePath { siblings, index }`, `merkle_verify_leaf(root, leaf_payload, path)`
- Constant‑time digest equality:
  - `ct_eq_hash(a, b) -> bool` (via `subtle::ConstantTimeEq`)
- Consensus constants: `obex_primitives::constants`
  - Genesis: `GENESIS_PARENT_ID`, `TXROOT_GENESIS`, `GENESIS_SLOT`
  - Tags (selection; see source for complete set):
    - Merkle: `obex.merkle.leaf`, `obex.merkle.node`, `obex.merkle.empty`
    - Participation/VRF: `obex.alpha`, `obex.seed`, `obex.lbl`, `obex.idx`, `obex.chal`, `obex.part.leaf`, `obex.partrec`, `obex.vrfy`
    - Headers/Beacon: `obex.header.id`, `obex.slot.seed`, `obex.vdf.ycore`, `obex.vdf.edge`
- Transactions: `obex.tx.access`, `obex.tx.body.v1`, `obex.tx.id`, `obex.tx.commit`, `obex.tx.sig`, `obex.txid.leaf`
    - Tickets/Rewards: `obex.ticket.id`, `obex.ticket.leaf`, `obex.reward.draw`, `obex.reward.rank`

## obex_alpha_i — Participation Engine (α I)

Implements the RAM‑hard labeling process and verification of canonical participation records (`ObexPartRec`).

- Key constants: `CHALLENGES_Q = 96`, `LABEL_BYTES = 32`, `MAX_PARTREC_SIZE = 600_000`
- Canonical hashing:
  - `alpha = H("obex.alpha", [ parent_id, LE(slot,8), y_edge_{s-1}, vrf_pk ])`
  - `seed  = H("obex.seed",  [ y_edge_{s-1}, pk_ed25519, vrf_y ])`
- Verification entry points:
  - `obex_verify_partrec(rec, slot, parent_id, vrf_provider) -> bool`
  - `obex_verify_partrec_bytes(bytes, slot, parent_id, vrf_provider) -> bool` (enforces `MAX_PARTREC_SIZE` pre‑decode)
- Canonical codecs:
  - `encode_partrec(&ObexPartRec) -> Vec<u8>`
  - `decode_partrec(&[u8]) -> Result<ObexPartRec, CodecError>` (enforces VRF lengths and challenge count)
- Participation set commitment:
  - `build_participation_set(slot, parent_id, submissions, vrf_provider) -> (Vec<Pk32>, Hash256)`; leaves are `H("obex.part.leaf",[]) || pk`, and keys are sorted for determinism
- VRF integration (RFC 9381 ECVRF):
  - Feature flags: `obex_alpha_i/ecvrf_rfc9381-ed25519` (legacy), alias `obex_alpha_i/ecvrf_rfc9381`
  - Consensus suite/lengths: `ECVRF-EDWARDS25519-SHA512-TAI`, `vrf_pk=32`, `vrf_pi=80`, `vrf_y=64`
  - Adapter: `obex_alpha_i::vrf` (vrf-rfc9381 0.0.3, TAI); β/π lengths enforced
  - Official RFC 9381 TAI vectors included: `crates/obex_alpha_i/tests/vrf_rfc9381_tai.rs`

## obex_alpha_ii — Deterministic Header Engine (α II)

Defines the canonical `Header`, its identity hash, codecs, and deterministic validation via equalities.

- Providers (traits): `BeaconVerifier`, `TicketRootProvider`, `PartRootProvider`, `TxRootProvider`
- Size caps (DoS protection): `MAX_PI_LEN`, `MAX_ELL_LEN`
- Canonical ID: `obex_header_id(&Header) -> Hash256` (hash over field values with explicit length framing for variable‑length fields)
- Codecs: `serialize_header(&Header) -> Vec<u8>`, `deserialize_header(&[u8]) -> Result<Header, _>`
- Validation: `validate_header(h, parent, beacon, ticket_roots, part_roots, tx_roots, expected_version) -> Result<(), ValidateErr>`
  - Header ID field order (frozen): `parent_id, slot, obex_version, seed_commit, vdf_y_core, vdf_y_edge, len(vdf_pi), vdf_pi, len(vdf_ell), vdf_ell, ticket_root, part_root, txroot_prev`
  - Version: `OBEX_ALPHA_II_VERSION = 2`; `Header` includes `part_root` and validation enforces `part_root == compute_part_root(slot)`

## obex_alpha_iii — Deterministic Admission (α III)

Implements the fee rule, canonical transaction bytes, signatures, ticket records, and per‑slot ticket root.

- Fee rule (integer‑exact): flat for small transfers, percent for larger; `fee_int_uobx`
- Canonical transaction bytes: `canonical_tx_bytes(&TxBodyV1)`; `txid`, `tx_commit`
- Ticket records: `TicketRecord`, `enc_ticket_leaf`; per‑slot root via `build_ticket_root_for_slot`
- Admission: `admit_single`, `admit_slot_canonical`
  - Determinism: sorts inputs canonically; empty set yields `obex.merkle.empty`

## obex_alpha_t — Tokenomics (α T)

Implements the emission schedule (U256 accumulator), escrow with epoch‑stable NLB splits, Deterministic Reward Pool (DRP) distribution, and a canonical system transaction codec.

- Emission: `on_slot_emission(st, slot_1based, credit_emission)`; halving schedule with `U256` accumulators
- NLB fee routing: `route_fee_with_nlb` with epoch state managed by `nlb_roll_epoch_if_needed`
- DRP distribution: `distribute_drp_for_slot`
  - System transactions: `enc_sys_tx`, `dec_sys_tx`; kinds include Escrow/Treasury/Verifier credits, Burn, RewardPayout, EmissionCredit; REWARD_PAYOUT items ordered by lottery rank (deterministic)

## Golden Fixtures and E2E Harness

- Golden artifacts are checked in under `tests/golden/` with deterministic generators:
  - α I PartRec bytes: generator `crates/obex_alpha_i/examples/gen_golden_partrec.rs`
    - Writes `crates/obex_alpha_i/tests/golden/partrec_v1.bin`
    - Tests: `crates/obex_alpha_i/tests/golden_partrec.rs` (accept + flip‑bit behavior)
  - α II Header bytes: generator `crates/obex_alpha_ii/examples/gen_golden_header.rs`
    - Writes `crates/obex_alpha_ii/tests/golden/header_v2_parent.bin`, `header_v2_slot1.bin`, `header_v2_slot1.id.hex`
    - Tests: `crates/obex_alpha_ii/tests/golden_header_bytes.rs` (roundtrip, ID hex match, flip‑bit changes)
- E2E harness: `crates/obex_alpha_ii/tests/e2e_three_slots.rs`
  - Builds a 3‑slot chain (slots 1..3), validates equalities, and asserts header ID uniqueness
  - Additional α II e2e: `crates/obex_alpha_ii/tests/e2e.rs` validates `part_root` binding

To regenerate fixtures deterministically:

```bash
cargo run --release -p obex_alpha_i  --example gen_golden_partrec
cargo run --release -p obex_alpha_ii --example gen_golden_header
```

## Security and Correctness Properties

- Byte‑precise canonical codecs for consensus objects (I: `ObexPartRec`; II: `Header`; T: `SysTx`)
- Domain‑separated hashing everywhere (tags centralized in `obex_primitives::constants`)
- Constant‑time equality for all digest comparisons (32‑byte hashes)
- Deterministic sorting and duplicate‑last rule in Merkle computations
 - Hashing discipline: SHA3‑256 only for consensus; domain‑tag strings are frozen with KATs in `crates/obex_primitives/tests/kats.rs`

## Building, Testing, and Linting

```bash
# Build all crates (release)
cargo build --release --all-targets

# Run tests (dev or release)
cargo test --all-targets
cargo test --release --all-targets

# Optional: run with ECVRF adapter feature (TAI suite)
cargo test --features obex_alpha_i/ecvrf_rfc9381-ed25519 --release
cargo test --features obex_alpha_i/ecvrf_rfc9381 --release

# Clippy — strictest settings (pedantic, nursery, cargo) and deny warnings
cargo clippy --workspace --all-targets --all-features -- \
  -D warnings -W clippy::all -W clippy::pedantic -W clippy::nursery -W clippy::cargo
```

## no_std Readiness

`obex_primitives` supports `no_std` with `alloc`. Enable by disabling default features and opting into `alloc`:

```toml
[dependencies]
obex_primitives = { version = "0.1", default-features = false, features = ["alloc"] }
```

## CI

Recommended CI gates to enforce formatting, lints, determinism, and `no_std` readiness:

- Formatting: `cargo fmt --check`
- Clippy: `cargo clippy --all-targets --all-features -- -D warnings -W clippy::all -W clippy::pedantic -W clippy::nursery -W clippy::cargo`
- Tests: `cargo test --release --all-targets` and with feature `obex_alpha_i/ecvrf_rfc9381-ed25519`
- Determinism: run tests twice and diff outputs to assert byte-for-byte determinism
- no_std: build `obex_primitives` with `--no-default-features --features alloc` for an embedded target

## License

Dual licensed under MIT or Apache‑2.0, at your option.

## Status and Known Notes

- The ECVRF adapter (`obex_alpha_i::vrf`) is wired to `vrf-rfc9381` 0.0.3 using the `ECVRF-EDWARDS25519-SHA512-TAI` suite and enforces 32/80/64 byte lengths end‑to‑end. Consensus hashing uses SHA3‑256 only (domain‑tagged) throughout α ι/ϑ/κ/τ. The VRF RFC 9381 TAI test vectors are integrated and passing.
  - The workspace does not expose binaries; it is a library suite with comprehensive unit and golden tests (including fixed‑hex KATs for tags and header IDs).

### Gating tests present
- α I: VRF suite constant, wrong‑length α rejection, random π rejection; oversize `ObexPartRec` rejected pre‑decode; participation‑set dedup determinism
- α II: `part_root` flip‑bit mismatch → `ValidateErr::PartRootMismatch`; 3‑slot E2E header ID uniqueness
- α III: fee rule branches and admission state updates; empty‑slot ticket root equals empty tag
- α T: emission accumulator monotonicity; fee split cap respected; system tx codec roundtrip

