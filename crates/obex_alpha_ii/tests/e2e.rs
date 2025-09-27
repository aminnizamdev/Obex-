use obex_alpha_ii::{
    build_header, obex_header_id, validate_header, BeaconInputs, BeaconVerifier, Header,
    PartRootProvider, TicketRootProvider, TxRootProvider, ValidateErr, OBEX_ALPHA_II_VERSION,
};
use obex_primitives::{constants, h_tag, le_bytes, Hash256};

fn empty_root() -> Hash256 {
    h_tag(constants::TAG_MERKLE_EMPTY, &[])
}

struct BeaconOk;
impl BeaconVerifier for BeaconOk {
    fn verify(&self, i: &BeaconInputs<'_>) -> bool {
        let seed_expected = h_tag(
            constants::TAG_SLOT_SEED,
            &[i.parent_id, &le_bytes::<8>(u128::from(i.slot))],
        );
        seed_expected == *i.seed_commit
            && h_tag(constants::TAG_VDF_EDGE, &[i.vdf_y_core]) == *i.vdf_y_edge
    }
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

#[test]
fn e2e_empty_slot_header_roundtrip_and_mismatch() {
    let parent = mk_parent();
    let s = parent.slot + 1;
    let parent_id_hdr = obex_header_id(&parent);
    let seed_commit = h_tag(
        constants::TAG_SLOT_SEED,
        &[&parent_id_hdr, &le_bytes::<8>(u128::from(s))],
    );
    let y_core = h_tag(constants::TAG_VDF_YCORE, &[&[2u8; 32]]);
    let y_edge = h_tag(constants::TAG_VDF_EDGE, &[&y_core]);

    let ticket_roots = EmptyTicketRoot;
    let part_roots = EmptyPartRoot;
    let tx_roots = EmptyTxRoot;
    let h = build_header(
        &parent,
        (seed_commit, y_core, y_edge, vec![], vec![]),
        &ticket_roots,
        &part_roots,
        &tx_roots,
        OBEX_ALPHA_II_VERSION,
    );

    let id = obex_header_id(&h);
    assert_eq!(id, obex_header_id(&h), "id stable");

    let beacon = BeaconOk;
    assert!(validate_header(
        &h,
        &parent,
        &beacon,
        &ticket_roots,
        &part_roots,
        &tx_roots,
        OBEX_ALPHA_II_VERSION
    )
    .is_ok());

    // Flip part_root → PartRootMismatch
    let mut bad = h;
    bad.part_root[0] ^= 1;
    let err = validate_header(
        &bad,
        &parent,
        &beacon,
        &ticket_roots,
        &part_roots,
        &tx_roots,
        OBEX_ALPHA_II_VERSION,
    )
    .unwrap_err();
    assert!(matches!(err, ValidateErr::PartRootMismatch));
}
