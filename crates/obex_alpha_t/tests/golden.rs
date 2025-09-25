#![allow(unused)]
use obex_alpha_t::{SysTx, SysTxKind, enc_sys_tx, dec_sys_tx};
use hex::ToHex;

#[test]
fn sys_tx_golden_roundtrip() {
    let tx = SysTx { kind: SysTxKind::RewardPayout, slot: 99, pk: [9u8;32], amt: 12345 };
    let b = enc_sys_tx(&tx);
    let tx2 = dec_sys_tx(&b).expect("decode");
    assert_eq!(tx2.slot, tx.slot);
    assert_eq!(tx2.kind as u8, tx.kind as u8);
    assert_eq!(tx2.amt, tx.amt);
    // Byte-for-byte re-encode equality
    let b2 = enc_sys_tx(&tx2);
    assert_eq!(b2, b);
    // Hex output exists for KAT dumps
    let _hex = b.encode_hex::<String>();
}

