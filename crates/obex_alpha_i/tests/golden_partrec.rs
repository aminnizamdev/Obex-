use std::fs;
use std::path::Path;

use obex_alpha_i::{decode_partrec, encode_partrec, obex_check_partrec, EcVrfVerifier, VerifyErr};
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
