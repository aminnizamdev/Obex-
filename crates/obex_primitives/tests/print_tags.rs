use obex_primitives::{constants, h_tag};
use hex::ToHex;

#[test]
fn print_tag_hex() {
    let tags = [
        constants::TAG_MERKLE_EMPTY,
        constants::TAG_MERKLE_LEAF,
        constants::TAG_MERKLE_NODE,
        constants::TAG_ALPHA,
        constants::TAG_SEED,
        constants::TAG_L0,
        constants::TAG_LBL,
        constants::TAG_IDX,
        constants::TAG_CHAL,
        constants::TAG_PART_LEAF,
        constants::TAG_PARTREC,
        constants::TAG_HEADER_ID,
        constants::TAG_SLOT_SEED,
        constants::TAG_VDF_YCORE,
        constants::TAG_VDF_EDGE,
        constants::TAG_TX_ACCESS,
        constants::TAG_TX_BODY_V1,
        constants::TAG_TX_ID,
        constants::TAG_TX_COMMIT,
        constants::TAG_TX_SIG,
        constants::TAG_TXID_LEAF,
        constants::TAG_TICKET_ID,
        constants::TAG_TICKET_LEAF,
        constants::TAG_SYS_TX,
        constants::TAG_REWARD_DRAW,
        constants::TAG_REWARD_RANK,
    ];
    for t in tags { println!("{}:{}", t, h_tag(t, &[]).encode_hex::<String>()); }
}


