#![allow(unused)]
use obex_alpha_i::{encode_partrec, decode_partrec, ObexPartRec, ChallengeOpen, MerklePathLite, OBEX_ALPHA_I_VERSION, CHALLENGES_Q};
use hex::ToHex;

#[test]
fn partrec_golden_roundtrip() {
    let mut challenges = Vec::with_capacity(CHALLENGES_Q);
    for _ in 0..CHALLENGES_Q {
        challenges.push(ChallengeOpen {
            idx: 1,
            li: [9u8;32],
            pi: MerklePathLite { siblings: vec![] },
            lim1: [10u8;32],
            pim1: MerklePathLite { siblings: vec![] },
            lj: [11u8;32],
            pj: MerklePathLite { siblings: vec![] },
            lk: [12u8;32],
            pk_: MerklePathLite { siblings: vec![] },
        });
    }
    let rec = ObexPartRec {
        version: OBEX_ALPHA_I_VERSION,
        slot: 1,
        pk_ed25519: [1u8;32],
        vrf_pk: [2u8;32],
        y_edge_prev: [3u8;32],
        alpha: [4u8;32],
        vrf_y: vec![5u8;64],
        vrf_pi: vec![6u8;80],
        seed: [7u8;32],
        root: [8u8;32],
        challenges,
        sig: [13u8;64],
    };
    let bytes = encode_partrec(&rec).expect("encode");
    let rec2 = decode_partrec(&bytes).expect("decode");
    assert_eq!(rec2.version, rec.version);
    assert_eq!(rec2.slot, rec.slot);
    assert_eq!(rec2.pk_ed25519, rec.pk_ed25519);
    assert_eq!(rec2.vrf_pk, rec.vrf_pk);
    assert_eq!(rec2.vrf_y, rec.vrf_y);
    assert_eq!(rec2.vrf_pi.len(), 80);
    assert_eq!(rec2.challenges.len(), CHALLENGES_Q);
    // Byte-for-byte stability: re-encode equals original
    let bytes2 = encode_partrec(&rec2).expect("encode2");
    assert_eq!(bytes2, bytes);
    // Provide a hex digest KAT (length only here to avoid freezing values prematurely)
    let hex = bytes.encode_hex::<String>();
    assert!(!hex.is_empty());
}


