#![allow(unused)]
use hex::ToHex;
use obex_alpha_ii::{
    deserialize_header, obex_header_id, serialize_header, Header, OBEX_ALPHA_II_VERSION,
};

#[test]
fn header_golden_roundtrip() {
    let h = Header {
        parent_id: [1u8; 32],
        slot: 42,
        obex_version: OBEX_ALPHA_II_VERSION,
        seed_commit: [2u8; 32],
        vdf_y_core: [3u8; 32],
        vdf_y_edge: [4u8; 32],
        vdf_pi: vec![0xAA, 0xBB],
        vdf_ell: vec![0xCC],
        ticket_root: [5u8; 32],
        part_root: [6u8; 32],
        txroot_prev: [7u8; 32],
    };
    let bytes = serialize_header(&h);
    let h2 = deserialize_header(&bytes).expect("decode");
    assert_eq!(h2.slot, h.slot);
    assert_eq!(obex_header_id(&h2), obex_header_id(&h));
    // KAT: header id hex is stable given deterministic fields
    let id_hex = obex_header_id(&h).encode_hex::<String>();
    assert_eq!(
        id_hex,
        "ddb4398849e1938cdadae933065712f7548f1827779792fd2356b77390922098"
    );
}
