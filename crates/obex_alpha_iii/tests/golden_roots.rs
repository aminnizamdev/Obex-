use hex::ToHex;
use obex_alpha_iii::*;
use obex_primitives::{constants, h_tag, merkle_root, Pk32};

const fn pk(val: u8) -> Pk32 {
    [val; 32]
}

#[test]
fn ticket_and_tx_roots_fixed_hex() {
    let y_prev = [7u8; 32];
    let s_now = 5u64;
    let tx1 = TxBodyV1 {
        sender: pk(1),
        recipient: pk(2),
        nonce: 0,
        amount_u: 2_000,
        fee_u: fee_int_uobx(2_000),
        s_bind: s_now,
        y_bind: y_prev,
        access: AccessList::default(),
        memo: vec![],
    };
    let tx2 = TxBodyV1 {
        sender: pk(3),
        recipient: pk(4),
        nonce: 0,
        amount_u: 1_234,
        fee_u: fee_int_uobx(1_234),
        s_bind: s_now,
        y_bind: y_prev,
        access: AccessList::default(),
        memo: vec![0xAA, 0xBB],
    };

    let rec1 = TicketRecord {
        ticket_id: h_tag(
            constants::TAG_TICKET_ID,
            &[
                &txid(&tx1),
                &obex_primitives::le_bytes::<8>(u128::from(s_now)),
            ],
        ),
        txid: txid(&tx1),
        sender: tx1.sender,
        nonce: tx1.nonce,
        amount_u: tx1.amount_u,
        fee_u: tx1.fee_u,
        s_admit: s_now,
        s_exec: s_now,
        commit_hash: tx_commit(&tx1),
    };
    let rec2 = TicketRecord {
        ticket_id: h_tag(
            constants::TAG_TICKET_ID,
            &[
                &txid(&tx2),
                &obex_primitives::le_bytes::<8>(u128::from(s_now)),
            ],
        ),
        txid: txid(&tx2),
        sender: tx2.sender,
        nonce: tx2.nonce,
        amount_u: tx2.amount_u,
        fee_u: tx2.fee_u,
        s_admit: s_now,
        s_exec: s_now,
        commit_hash: tx_commit(&tx2),
    };

    let mut list = vec![rec1.clone(), rec2.clone()];
    list.sort_by(|a, b| a.txid.cmp(&b.txid));
    let leaves: Vec<Vec<u8>> = list.iter().map(enc_ticket_leaf).collect();
    let ticket_root = merkle_root(&leaves).encode_hex::<String>();
    assert_eq!(
        ticket_root,
        "d3869a56f8eab1b055a9adf2835e2c164292c51e53fcb9168b8c20b7473ece9d"
    );

    let txids = [rec1.txid, rec2.txid];
    let leaves_tx: Vec<Vec<u8>> = txids
        .iter()
        .map(|xid| {
            let mut v = Vec::with_capacity(64);
            v.extend_from_slice(&h_tag(constants::TAG_TXID_LEAF, &[]));
            v.extend_from_slice(xid);
            v
        })
        .collect();
    let txroot = merkle_root(&leaves_tx).encode_hex::<String>();
    assert_eq!(
        txroot,
        "24974d37ad6c4da1b1ee8d655b6d8cf05db37ae9e5b3b75d41e5351708f86800"
    );
}

#[test]
fn ticket_root_determinism_and_order() {
    let mut st = AlphaIIIState::default();
    // Empty slot -> empty root
    let (_leaves0, root0) = build_ticket_root_for_slot(5, &st);
    assert_eq!(root0, h_tag(constants::TAG_MERKLE_EMPTY, &[]));

    // Admit some tickets and ensure determinism
    st.spendable_u.insert(pk(1), 10_000);
    let y_prev = [7u8; 32];
    let sig = [0u8; 64];
    for (i, amt) in [2_000u128, 1_234u128, 3_000u128].into_iter().enumerate() {
        let tx = TxBodyV1 {
            sender: pk(1),
            #[allow(clippy::cast_possible_truncation)]
            recipient: pk((i + 2) as u8),
            nonce: i as u64,
            amount_u: amt,
            fee_u: fee_int_uobx(amt),
            s_bind: 9,
            y_bind: y_prev,
            access: AccessList::default(),
            memo: vec![],
        };
        let _ = admit_single(&tx, &sig, 9, &y_prev, &mut st);
    }
    let (leaves1, root1) = build_ticket_root_for_slot(9, &st);
    let (leaves2, root2) = build_ticket_root_for_slot(9, &st);
    assert_eq!(leaves1.len(), leaves2.len());
    assert_eq!(root1, root2);
}
