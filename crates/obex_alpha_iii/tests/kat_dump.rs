use hex::ToHex;
use obex_alpha_iii::*;
use obex_primitives::{constants, h_tag, merkle_root, Pk32};

const fn pk(val: u8) -> Pk32 {
    [val; 32]
}

#[test]
fn dump_ticket_and_tx_roots_hex() {
    // Two simple txs for the same slot/bind
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

    // Build TicketRecords deterministically as admit_single would for Finalized cases
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

    // ticket_root: sort by txid ascending
    let mut list = vec![rec1.clone(), rec2.clone()];
    list.sort_by(|a, b| a.txid.cmp(&b.txid));
    let leaves: Vec<Vec<u8>> = list.iter().map(enc_ticket_leaf).collect();
    let ticket_root = merkle_root(&leaves);
    println!("TICKET_ROOT:{}", ticket_root.encode_hex::<String>());

    // txroot: leaves = tag || txid for executed (previous slot); here we just use tx ids
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
    let txroot = merkle_root(&leaves_tx);
    println!("TXROOT:{}", txroot.encode_hex::<String>());
}
