OBEX Alpha — Spec Freeze (Consensus-Critical Snapshot)

Scope
- This document freezes consensus tag strings, hashing rules, pinned cryptographic dependencies, and protocol version constants for α‑I/α‑II/α‑III/α‑T.
- Any change here is a consensus change and must be treated as a hard fork.

Hashing Discipline
- Hash: SHA3‑256 (32‑byte output), length‑framed, domain‑tagged.
- H(tag, parts[]) = SHA3_256( UTF8(tag) || Σ ( LE(|p|,8) || p ) ).
- No alternative hash functions in consensus code.

Consensus Tag Strings (non‑exhaustive, normative)
- merkle.leaf
- merkle.node
- merkle.empty
- obex.alpha
- obex.partrec
- obex.seed
- obex.l0
- obex.lbl
- obex.idx
- obex.chal
- obex.vrfy
- obex.header.id
- obex.slot.seed
- tx.access
- tx.body.v1
- tx.id
- tx.commit
- tx.sig
- ticket.id
- ticket.leaf
- sys.tx
- reward.draw
- reward.rank

Pinned Crypto/Backends (crate, version)
- sha3 = 0.10.8
- subtle = 2.6.1
- thiserror = 2.0.16
- ed25519-dalek = 2.2.0
- vrf-rfc9381 = 0.0.3 (suite ECVRF‑EDWARDS25519‑SHA512‑TAI)
- primitive-types = 0.12.2 (α‑T)

Protocol Version Constants
- OBEX_ALPHA_I_VERSION = 1
- OBEX_ALPHA_II_VERSION = 2
- OBEX_ALPHA_III_VERSION = 1
- OBEX_ALPHA_T_VERSION = 1

Beacon/VDF Adapter Contract (α‑II)
- seed_commit == H("obex.slot.seed", [ parent_id, LE(slot,8) ]).
- MAX_PI_LEN and MAX_ELL_LEN enforced before verification.
- Backend (e.g., class‑group Wesolowski) to be frozen with vectors: (seed_commit, vdf_y_core, vdf_y_edge, vdf_pi, vdf_ell).

Ed25519 and VRF Encodings
- Ed25519 signatures: 64‑byte canonical; verification via verify_strict.
- ECVRF (RFC 9381, edwards25519, SHA‑512, TAI): pk 32, pi 80, y 64.

Deterministic Merkle
- Binary tree, duplicate‑last for odd level size; empty root is H("merkle.empty", []).

Change Control
- Any change to the above requires bumping the corresponding OBEX_ALPHA_*_VERSION and coordinated rollout.


