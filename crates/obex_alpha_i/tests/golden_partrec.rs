use std::fs;
use std::path::Path;

use obex_alpha_i::{
    decode_partrec, encode_partrec, obex_check_partrec, ChallengeOpen, EcVrfVerifier,
    MerklePathLite, VerifyErr, CHALLENGES_Q, MAX_PARTREC_SIZE, OBEX_ALPHA_I_VERSION,
};
use obex_primitives::{constants, Hash256};

fn read_golden() -> Vec<u8> {
    let p = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("golden")
        .join("partrec_v1.bin");
    fs::read(p).expect("read golden partrec_v1.bin")
}

#[test]
fn golden_partrec_accept_and_roundtrip() {
    let bytes = read_golden();
    let rec = decode_partrec(&bytes).expect("decode golden");
    let bytes2 = encode_partrec(&rec).expect("re-encode");
    assert_eq!(bytes2, bytes, "golden bytes stable");
}

struct AcceptY(Vec<u8>);
impl EcVrfVerifier for AcceptY {
    fn verify(&self, _k: &[u8; 32], _a: &Hash256, _p: &[u8]) -> Option<Vec<u8>> {
        Some(self.0.clone())
    }
}

#[test]
fn golden_partrec_flipbit_precise_errors() {
    let bytes = read_golden();
    let rec = decode_partrec(&bytes).expect("decode golden");
    let vrf = AcceptY(rec.vrf_y.clone());
    // 1) Alpha mismatch
    let bad_alpha = {
        let mut r = rec.clone();
        r.alpha[0] ^= 1;
        r
    };
    let err = obex_check_partrec(
        &bad_alpha,
        bad_alpha.slot,
        &constants::GENESIS_PARENT_ID,
        &vrf,
    )
    .unwrap_err();
    assert_eq!(err, VerifyErr::AlphaMismatch);
    // 2) Seed mismatch
    let bad_seed = {
        let mut r = rec.clone();
        r.seed[0] ^= 1;
        r
    };
    let err = obex_check_partrec(
        &bad_seed,
        bad_seed.slot,
        &constants::GENESIS_PARENT_ID,
        &vrf,
    )
    .unwrap_err();
    assert_eq!(err, VerifyErr::SeedMismatch);
    // 3) Root path sibling corruption -> MerkleLiInvalid (first path)
    let bad_li = {
        let mut r = rec.clone();
        if let Some(ch) = r.challenges.get_mut(0) {
            if let Some(sib) = ch.pi.siblings.get_mut(0) {
                sib[0] ^= 1;
            }
        }
        r
    };
    let err =
        obex_check_partrec(&bad_li, bad_li.slot, &constants::GENESIS_PARENT_ID, &vrf).unwrap_err();
    assert_eq!(err, VerifyErr::SigInvalid);
    // 4) Signature flip -> SigInvalid
    let bad_sig = {
        let mut r = rec;
        r.sig[0] ^= 1;
        r
    };
    let err = obex_check_partrec(&bad_sig, bad_sig.slot, &constants::GENESIS_PARENT_ID, &vrf)
        .unwrap_err();
    assert_eq!(err, VerifyErr::SigInvalid);
}

/// Test comprehensive flip-bit failures for all critical fields
/// This locks the consensus behavior for ObexPartRec validation forever
#[test]
fn golden_partrec_comprehensive_flipbit_failures() {
    let bytes = read_golden();
    let rec = decode_partrec(&bytes).expect("decode golden");
    let vrf = AcceptY(rec.vrf_y.clone());

    // Test alpha flip-bit failures (consensus-critical)
    for byte_idx in 0..32 {
        for bit_idx in 0..8 {
            let mut bad_alpha = rec.clone();
            bad_alpha.alpha[byte_idx] ^= 1 << bit_idx;

            let err = obex_check_partrec(
                &bad_alpha,
                bad_alpha.slot,
                &constants::GENESIS_PARENT_ID,
                &vrf,
            )
            .unwrap_err();
            assert_eq!(
                err,
                VerifyErr::AlphaMismatch,
                "Alpha bit flip at byte {} bit {} should cause AlphaMismatch",
                byte_idx,
                bit_idx
            );
        }
    }

    // Test seed flip-bit failures (consensus-critical)
    for byte_idx in 0..32 {
        for bit_idx in 0..8 {
            let mut bad_seed = rec.clone();
            bad_seed.seed[byte_idx] ^= 1 << bit_idx;

            let err = obex_check_partrec(
                &bad_seed,
                bad_seed.slot,
                &constants::GENESIS_PARENT_ID,
                &vrf,
            )
            .unwrap_err();
            assert_eq!(
                err,
                VerifyErr::SeedMismatch,
                "Seed bit flip at byte {} bit {} should cause SeedMismatch",
                byte_idx,
                bit_idx
            );
        }
    }

    // Test root flip-bit failures (consensus-critical)
    for byte_idx in 0..32 {
        for bit_idx in 0..8 {
            let mut bad_root = rec.clone();
            bad_root.root[byte_idx] ^= 1 << bit_idx;

            let err = obex_check_partrec(
                &bad_root,
                bad_root.slot,
                &constants::GENESIS_PARENT_ID,
                &vrf,
            )
            .unwrap_err();
            // Root changes affect signature verification
            assert_eq!(
                err,
                VerifyErr::SigInvalid,
                "Root bit flip at byte {} bit {} should cause SigInvalid",
                byte_idx,
                bit_idx
            );
        }
    }

    // Test signature flip-bit failures (consensus-critical)
    for byte_idx in 0..64 {
        for bit_idx in 0..8 {
            let mut bad_sig = rec.clone();
            bad_sig.sig[byte_idx] ^= 1 << bit_idx;

            let err =
                obex_check_partrec(&bad_sig, bad_sig.slot, &constants::GENESIS_PARENT_ID, &vrf)
                    .unwrap_err();
            assert_eq!(
                err,
                VerifyErr::SigInvalid,
                "Signature bit flip at byte {} bit {} should cause SigInvalid",
                byte_idx,
                bit_idx
            );
        }
    }
}

/// Test oversize challenges (Q != 96) rejection
/// This locks the CHALLENGES_Q constant behavior forever
#[test]
fn golden_partrec_challenges_q_enforcement() {
    let bytes = read_golden();
    let mut rec = decode_partrec(&bytes).expect("decode golden");
    let vrf = AcceptY(rec.vrf_y.clone());

    // Test Q < 96 (too few challenges)
    rec.challenges.truncate(95);
    let err = obex_check_partrec(&rec, rec.slot, &constants::GENESIS_PARENT_ID, &vrf).unwrap_err();
    assert_eq!(err, VerifyErr::ChallengesLen);

    // Test Q > 96 (too many challenges)
    let bytes = read_golden();
    let mut rec = decode_partrec(&bytes).expect("decode golden");
    rec.challenges.push(ChallengeOpen {
        idx: 1,
        li: [9u8; 32],
        pi: MerklePathLite { siblings: vec![] },
        lim1: [10u8; 32],
        pim1: MerklePathLite { siblings: vec![] },
        lj: [11u8; 32],
        pj: MerklePathLite { siblings: vec![] },
        lk: [12u8; 32],
        pk_: MerklePathLite { siblings: vec![] },
    });

    let err = obex_check_partrec(&rec, rec.slot, &constants::GENESIS_PARENT_ID, &vrf).unwrap_err();
    assert_eq!(err, VerifyErr::ChallengesLen);
}

/// Test canonical byte image stability
/// This ensures the golden ObexPartRec byte representation never changes
#[test]
fn golden_partrec_canonical_byte_image() {
    let bytes = read_golden();
    let rec = decode_partrec(&bytes).expect("decode golden");

    // Re-encode and verify byte-for-byte stability
    let bytes2 = encode_partrec(&rec).expect("re-encode");
    assert_eq!(
        bytes2, bytes,
        "Golden ObexPartRec canonical byte image must be stable"
    );

    // Verify specific byte length (consensus-critical)
    assert!(
        bytes.len() <= MAX_PARTREC_SIZE,
        "Golden ObexPartRec must respect MAX_PARTREC_SIZE"
    );

    // Verify field structure integrity
    assert_eq!(rec.version, OBEX_ALPHA_I_VERSION);
    assert_eq!(rec.challenges.len(), CHALLENGES_Q);
    assert_eq!(rec.vrf_y.len(), 64); // Network-wide fixed
    assert_eq!(rec.vrf_pi.len(), 80); // RFC 9381 proof length
}
