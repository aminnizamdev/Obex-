use obex_alpha_iii::*;
use obex_primitives::{constants, h_tag, Pk32};
use ed25519_dalek::{SigningKey, Signer, VerifyingKey};

const fn pk(val: u8) -> Pk32 { [val; 32] }

#[test]
fn reject_fee_mismatch() {
    // Generate a valid signature for the transaction to reach the fee check
    let sk = SigningKey::from_bytes(&[1u8; 32]);
    let vk: VerifyingKey = (&sk).into();
    let sender_pk: Pk32 = vk.to_bytes();
    let tx = TxBodyV1{ sender: sender_pk, recipient: pk(2), nonce:0, amount_u: 2_000, fee_u: 1, s_bind: 5, y_bind: [7u8;32], access: AccessList::default(), memo: vec![]};
    let msg = h_tag(constants::TAG_TX_SIG, &[&canonical_tx_bytes(&tx)]);
    let sig = sk.sign(&msg).to_bytes();
    let mut st=AlphaIIIState::default();
    match admit_single(&tx, &sig, 5, &tx.y_bind, &mut st) { AdmitResult::Rejected(AdmitErr::FeeMismatch)=>{}, _=> panic!("expected fee mismatch") }
}

#[test]
fn empty_slot_ticket_root_matches_empty_tag() {
    let st=AlphaIIIState::default(); let (_leaves,root)=build_ticket_root_for_slot(1,&st);
    assert_eq!(root, obex_primitives::h_tag(obex_primitives::constants::TAG_MERKLE_EMPTY, &[]));
}

