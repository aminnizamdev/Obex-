//! Conformance checks: recompute and compare golden artifacts.

use obex_alpha_ii::{deserialize_header, obex_header_id};
use obex_alpha_iii::{build_ticket_root_for_slot, AlphaIIIState, TicketRecord};
use obex_alpha_i::{build_participation_set, EcVrfVerifier, ObexPartRec};
use obex_primitives::Hash256;

struct NeverVrf;
impl EcVrfVerifier for NeverVrf {
    fn verify(&self, _vrf_pubkey: &[u8; 32], _alpha: &Hash256, _vrf_proof: &[u8]) -> Option<Vec<u8>> {
        None
    }
}

#[test]
fn header_id_matches_golden_child_if_present() {
    // Optional: skip if files not present
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests").join("golden");
    let child = dir.join("header_v2_slot1.bin");
    if let Ok(bytes) = std::fs::read(child) {
        let h = deserialize_header(&bytes).expect("decode child");
        let id = obex_header_id(&h);
        let hex = hex::encode(id);
        let exp_hex = std::fs::read_to_string(dir.join("header_v2_slot1.id.hex")).expect("id hex");
        assert_eq!(hex, exp_hex);
    }
}

#[test]
fn ticket_root_recomputes() {
    let mut st = AlphaIIIState::default();
    // Empty slot root equals empty merkle root
    let (_leaves, root) = build_ticket_root_for_slot(1, &st);
    assert_eq!(root, obex_primitives::merkle_root(&[]));

    // With a record present, recomputation should succeed deterministically
    let rec = TicketRecord {
        ticket_id: [0u8; 32],
        txid: [1u8; 32],
        sender: [2u8; 32],
        nonce: 0,
        amount_u: 1000,
        fee_u: 10,
        s_admit: 1,
        s_exec: 1,
        commit_hash: [3u8; 32],
    };
    st.admitted_by_slot.entry(2).or_default().push(rec);
    let (_leaves2, _root2) = build_ticket_root_for_slot(2, &st);
}

#[test]
fn participation_root_recomputes_empty() {
    // With no submissions, the participation set is empty and root is H("merkle.empty",[])
    let vrf = NeverVrf;
    let slot = 1u64;
    let parent_id = [0u8; 32];
    let it = std::iter::empty::<&ObexPartRec>();
    let (_pks, root) = build_participation_set(slot, &parent_id, it, &vrf);
    assert_eq!(root, obex_primitives::merkle_root(&[]));
}


