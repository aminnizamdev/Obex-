use obex_alpha_ii::{
    build_header, obex_header_id, validate_header, BeaconInputs, BeaconVerifier, Header,
    PartRootProvider, TicketRootProvider, TxRootProvider, OBEX_ALPHA_II_VERSION,
};
use obex_primitives::{constants, h_tag, le_bytes, Hash256, Pk32};

fn empty_root() -> Hash256 {
    h_tag(constants::TAG_MERKLE_EMPTY, &[])
}

struct BeaconOk;
impl BeaconVerifier for BeaconOk {
    fn verify(&self, _i: &BeaconInputs<'_>) -> bool {
        true
    }
}

struct Providers<'a> {
    part_pks: &'a [Pk32],
    txids_by_slot: &'a [(u64, Vec<Hash256>)],
}
impl PartRootProvider for Providers<'_> {
    fn compute_part_root(&self, _slot: u64) -> Hash256 {
        let leaves: Vec<Vec<u8>> = self
            .part_pks
            .iter()
            .map(|pk| {
                let mut b = Vec::new();
                b.extend_from_slice(&h_tag(constants::TAG_PART_LEAF, &[]));
                b.extend_from_slice(pk);
                b
            })
            .collect();
        obex_primitives::merkle_root(&leaves)
    }
}
impl TicketRootProvider for Providers<'_> {
    fn compute_ticket_root(&self, slot: u64) -> Hash256 {
        let mut list = self
            .txids_by_slot
            .iter()
            .find(|(s, _v)| *s == slot)
            .map(|(_, v)| v.clone())
            .unwrap_or_default();
        list.sort_unstable();
        let leaves: Vec<Vec<u8>> = list
            .iter()
            .map(|txid| {
                let mut p = Vec::new();
                p.extend_from_slice(&h_tag(constants::TAG_TXID_LEAF, &[]));
                p.extend_from_slice(txid);
                p
            })
            .collect();
        obex_primitives::merkle_root(&leaves)
    }
}
impl TxRootProvider for Providers<'_> {
    fn compute_txroot(&self, slot: u64) -> Hash256 {
        self.compute_ticket_root(slot)
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
fn e2e_three_slots_pipeline_determinism() {
    let part_pks: Vec<Pk32> = vec![[1u8; 32], [2u8; 32], [3u8; 32]];
    let txids: Vec<(u64, Vec<Hash256>)> = vec![
        (1, vec![[9u8; 32], [8u8; 32]]),
        (2, vec![[7u8; 32]]),
        (3, vec![]),
    ];
    let providers = Providers {
        part_pks: &part_pks,
        txids_by_slot: &txids,
    };
    let beacon = BeaconOk;

    let parent = mk_parent();
    let mut h_prev = parent;
    for s1 in 1..=3u64 {
        let seed_commit = h_tag(
            constants::TAG_SLOT_SEED,
            &[&obex_header_id(&h_prev), &le_bytes::<8>(u128::from(s1))],
        );
        #[allow(clippy::cast_possible_truncation)]
        let y_core = h_tag(constants::TAG_VDF_YCORE, &[&[s1 as u8; 32]]);
        let y_edge = h_tag(constants::TAG_VDF_EDGE, &[&y_core]);
        let h = build_header(
            &h_prev,
            (seed_commit, y_core, y_edge, vec![], vec![]),
            &providers,
            &providers,
            &providers,
            OBEX_ALPHA_II_VERSION,
        );
        assert!(validate_header(
            &h,
            &h_prev,
            &beacon,
            &providers,
            &providers,
            &providers,
            OBEX_ALPHA_II_VERSION
        )
        .is_ok());
        h_prev = h;
    }
}
