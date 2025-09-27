use std::fs;
use std::path::Path;

use hex::ToHex;
use obex_alpha_ii::{
    build_header, obex_header_id, serialize_header, Header, PartRootProvider, TicketRootProvider,
    TxRootProvider, OBEX_ALPHA_II_VERSION,
};
use obex_primitives::{constants, h_tag, le_bytes, Hash256};

fn empty_root() -> Hash256 {
    h_tag(constants::TAG_MERKLE_EMPTY, &[])
}

struct EmptyPartRoot;
impl PartRootProvider for EmptyPartRoot {
    fn compute_part_root(&self, _slot: u64) -> Hash256 {
        empty_root()
    }
}
struct EmptyTicketRoot;
impl TicketRootProvider for EmptyTicketRoot {
    fn compute_ticket_root(&self, _slot: u64) -> Hash256 {
        empty_root()
    }
}
struct EmptyTxRoot;
impl TxRootProvider for EmptyTxRoot {
    fn compute_txroot(&self, _slot: u64) -> Hash256 {
        empty_root()
    }
}

fn mk_parent() -> Header {
    let parent_id = [0u8; 32];
    let slot = 0u64;
    let seed_commit = h_tag(
        constants::TAG_SLOT_SEED,
        &[&parent_id, &le_bytes::<8>(u128::from(slot))],
    );
    let vdf_y_core = h_tag(constants::TAG_VDF_YCORE, &[&[1u8; 32]]);
    let vdf_y_edge = h_tag(constants::TAG_VDF_EDGE, &[&vdf_y_core]);
    Header {
        parent_id,
        slot,
        obex_version: OBEX_ALPHA_II_VERSION,
        seed_commit,
        vdf_y_core,
        vdf_y_edge,
        vdf_pi: vec![],
        vdf_ell: vec![],
        ticket_root: empty_root(),
        part_root: empty_root(),
        txroot_prev: empty_root(),
    }
}

fn main() {
    let parent = mk_parent();
    let s = parent.slot + 1;
    let seed_commit = h_tag(
        constants::TAG_SLOT_SEED,
        &[&obex_header_id(&parent), &le_bytes::<8>(u128::from(s))],
    );
    let y_core = h_tag(constants::TAG_VDF_YCORE, &[&[2u8; 32]]);
    let y_edge = h_tag(constants::TAG_VDF_EDGE, &[&y_core]);

    let ticket_roots = EmptyTicketRoot;
    let part_roots = EmptyPartRoot;
    let tx_roots = EmptyTxRoot;

    let child = build_header(
        &parent,
        (seed_commit, y_core, y_edge, vec![], vec![]),
        &ticket_roots,
        &part_roots,
        &tx_roots,
        OBEX_ALPHA_II_VERSION,
    );

    let out_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("golden");
    fs::create_dir_all(&out_dir).expect("mkdir -p tests/golden");

    let parent_path = out_dir.join("header_v2_parent.bin");
    let child_path = out_dir.join("header_v2_slot1.bin");
    fs::write(&parent_path, serialize_header(&parent)).expect("write parent header bin");
    fs::write(&child_path, serialize_header(&child)).expect("write child header bin");

    let id_hex = obex_header_id(&child).encode_hex::<String>();
    fs::write(out_dir.join("header_v2_slot1.id.hex"), id_hex.as_bytes()).expect("write id hex");

    println!("WROTE:{},{}", parent_path.display(), child_path.display());
}
