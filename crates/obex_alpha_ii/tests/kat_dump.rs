use obex_alpha_ii::*;
use hex::ToHex;

#[test]
fn dump_header_id_hex() {
    let h = Header {
        parent_id: [1u8;32],
        slot: 42,
        obex_version: OBEX_ALPHA_II_VERSION,
        seed_commit: [2u8;32],
        vdf_y_core: [3u8;32],
        vdf_y_edge: [4u8;32],
        vdf_pi: vec![0xAA,0xBB],
        vdf_ell: vec![0xCC],
        ticket_root: [5u8;32],
        part_root: [6u8;32],
        txroot_prev: [7u8;32],
    };
    let id_hex = obex_header_id(&h).encode_hex::<String>();
    println!("HEADER_ID_HEX:{id_hex}");
}


