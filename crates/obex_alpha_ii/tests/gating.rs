use obex_alpha_ii::*;
use obex_primitives::Hash256;

#[test]
fn header_validate_err_parent_link() {
    struct BeaconOk;
    impl BeaconVerifier for BeaconOk {
        fn verify(&self, _i: &BeaconInputs<'_>) -> bool {
            true
        }
    }
    struct Zero;
    impl TicketRootProvider for Zero {
        fn compute_ticket_root(&self, _s: u64) -> Hash256 {
            [0; 32]
        }
    }
    impl PartRootProvider for Zero {
        fn compute_part_root(&self, _: u64) -> Hash256 {
            [0; 32]
        }
    }
    impl TxRootProvider for Zero {
        fn compute_txroot(&self, _: u64) -> Hash256 {
            [0; 32]
        }
    }

    let parent = Header {
        parent_id: [9; 32],
        slot: 7,
        obex_version: OBEX_ALPHA_II_VERSION,
        seed_commit: [1; 32],
        vdf_y_core: [2; 32],
        vdf_y_edge: [3; 32],
        vdf_pi: vec![],
        vdf_ell: vec![],
        ticket_root: [0; 32],
        part_root: [0; 32],
        txroot_prev: [0; 32],
    };
    let providers = Zero;
    let beacon = BeaconOk;
    let mut h = build_header(
        &parent,
        ([4; 32], [5; 32], [6; 32], vec![], vec![]),
        &providers,
        &providers,
        &providers,
        OBEX_ALPHA_II_VERSION,
    );
    h.parent_id = [8; 32];
    assert!(matches!(
        validate_header(
            &h,
            &parent,
            &beacon,
            &providers,
            &providers,
            &providers,
            OBEX_ALPHA_II_VERSION
        ),
        Err(ValidateErr::BadParentLink)
    ));

    // Seed commit mismatch should surface as BadSeedCommit
    let mut h2 = build_header(
        &parent,
        ([9; 32], [5; 32], [6; 32], vec![], vec![]),
        &providers,
        &providers,
        &providers,
        OBEX_ALPHA_II_VERSION,
    );
    // Keep parent linkage correct
    h2.parent_id = obex_header_id(&parent);
    assert!(matches!(
        validate_header(
            &h2,
            &parent,
            &beacon,
            &providers,
            &providers,
            &providers,
            OBEX_ALPHA_II_VERSION
        ),
        Err(ValidateErr::BadSeedCommit)
    ));
}
