use obex_alpha_ii::{build_header, obex_header_id, validate_header, BeaconInputs, BeaconVerifier, Header, PartRootProvider, TicketRootProvider, TxRootProvider, OBEX_ALPHA_II_VERSION};
use obex_primitives::{constants, h_tag, le_bytes, Hash256, Pk32};

fn empty_root() -> Hash256 { h_tag(constants::TAG_MERKLE_EMPTY, &[]) }

struct BeaconOk;
impl BeaconVerifier for BeaconOk {
    fn verify(&self, i: &BeaconInputs<'_>) -> bool {
        let seed_expected = h_tag(constants::TAG_SLOT_SEED, &[i.parent_id, &le_bytes::<8>(i.slot as u128)]);
        seed_expected == *i.seed_commit && h_tag(constants::TAG_VDF_EDGE, &[i.vdf_y_core]) == *i.vdf_y_edge
    }
}

struct Providers<'a> { part_pks: &'a [Pk32], txids_by_slot: &'a [(u64, Vec<Hash256>)] }

impl PartRootProvider for Providers<'_> {
    fn compute_part_root(&self, _slot: u64) -> Hash256 {
        let leaves: Vec<Vec<u8>> = self.part_pks.iter().map(|pk| {
            let mut b = Vec::with_capacity(64);
            b.extend_from_slice(&h_tag(constants::TAG_PART_LEAF, &[]));
            b.extend_from_slice(pk);
            b
        }).collect();
        obex_primitives::merkle_root(&leaves)
    }
}
impl TicketRootProvider for Providers<'_> {
    fn compute_ticket_root(&self, slot: u64) -> Hash256 {
        // Create synthetic tickets from txids_by_slot
        let mut list = self.txids_by_slot.iter().find(|(s,_v)| *s == slot).map(|(_,v)| v.clone()).unwrap_or_default();
        list.sort();
        let leaves: Vec<Vec<u8>> = list.iter().map(|txid| {
            let mut payload = Vec::new();
            payload.extend_from_slice(&h_tag(constants::TAG_TXID_LEAF, &[]));
            payload.extend_from_slice(txid);
            payload
        }).collect();
        obex_primitives::merkle_root(&leaves)
    }
}
impl TxRootProvider for Providers<'_> {
    fn compute_txroot(&self, slot: u64) -> Hash256 {
        let mut list = self.txids_by_slot.iter().find(|(s,_v)| *s == slot).map(|(_,v)| v.clone()).unwrap_or_default();
        list.sort();
        let leaves: Vec<Vec<u8>> = list.iter().map(|txid| {
            let mut payload = Vec::new();
            payload.extend_from_slice(&h_tag(constants::TAG_TXID_LEAF, &[]));
            payload.extend_from_slice(txid);
            payload
        }).collect();
        obex_primitives::merkle_root(&leaves)
    }
}

fn mk_parent() -> Header {
    let parent_id = [0u8;32];
    let slot = 0u64;
    let seed_commit = h_tag(constants::TAG_SLOT_SEED, &[&parent_id, &le_bytes::<8>(slot as u128)]);
    let vdf_y_core = h_tag(constants::TAG_VDF_YCORE, &[&[1u8;32]]);
    let vdf_y_edge = h_tag(constants::TAG_VDF_EDGE, &[&vdf_y_core]);
    Header { parent_id, slot, obex_version: OBEX_ALPHA_II_VERSION, seed_commit, vdf_y_core, vdf_y_edge, vdf_pi: vec![], vdf_ell: vec![], ticket_root: empty_root(), part_root: empty_root(), txroot_prev: empty_root() }
}

#[test]
fn e2e_three_slots_freeze() {
    // Participation set for slots 1..=3 (static mock pks)
    let part_pks: Vec<Pk32> = vec![[1u8;32],[2u8;32],[3u8;32]];
    let providers = Providers { part_pks: &part_pks, txids_by_slot: &[] };
    let beacon = BeaconOk;

    let parent = mk_parent();
    // Build headers for slots 1..=3 with empty tx roots
    let mut headers = Vec::new();
    let mut h_prev = parent.clone();
    for s1 in 1..=3u64 {
        let seed_commit = h_tag(constants::TAG_SLOT_SEED, &[&obex_header_id(&h_prev), &le_bytes::<8>(s1 as u128)]);
        let y_core = h_tag(constants::TAG_VDF_YCORE, &[&[s1 as u8; 32]]);
        let y_edge = h_tag(constants::TAG_VDF_EDGE, &[&y_core]);
        let h = build_header(&h_prev, (seed_commit, y_core, y_edge, vec![], vec![]), &providers, &providers, &providers, OBEX_ALPHA_II_VERSION);
        assert!(validate_header(&h, &h_prev, &beacon, &providers, &providers, &providers, OBEX_ALPHA_II_VERSION).is_ok());
        headers.push(h.clone());
        h_prev = h;
    }

    // Freeze header IDs uniqueness across 3 slots
    let ids: Vec<Hash256> = headers.iter().map(obex_header_id).collect();
    assert!(ids[0] != ids[1] && ids[1] != ids[2] && ids[0] != ids[2]);
}


