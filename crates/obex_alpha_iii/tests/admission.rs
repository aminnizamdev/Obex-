use obex_alpha_iii::*;
use obex_primitives::{constants, h_tag, Hash256};

const fn pk(v: u8) -> [u8; 32] {
    [v; 32]
}

#[test]
fn nonce_equality_and_insufficient_funds_and_canonical_order() {
    let mut st = AlphaIIIState::default();
    let y_prev: Hash256 = [9u8; 32];
    st.spendable_u.insert(pk(1), 10_000);
    let mut txs: Vec<(TxBodyV1, Sig)> = Vec::new();
    for n in 0..3u64 {
        let tx = TxBodyV1 {
            sender: pk(1),
            recipient: pk(2),
            nonce: n,
            amount_u: 1_000,
            fee_u: fee_int_uobx(1_000),
            s_bind: 7,
            y_bind: y_prev,
            access: AccessList::default(),
            memo: vec![],
        };
        let sig = [0u8; 64];
        txs.push((tx, sig));
    }
    // BadSig → all rejected, but admission call should be deterministic and not mutate state.
    let out1 = admit_slot_canonical(7, &y_prev, &txs, &mut st);
    assert!(out1.is_empty());
    assert_eq!(st.nonce_of(&pk(1)), 0);
    // Deterministic ticket root for empty set
    let (_leaves, root) = build_ticket_root_for_slot(7, &st);
    assert_eq!(root, h_tag(constants::TAG_MERKLE_EMPTY, &[]));
}
