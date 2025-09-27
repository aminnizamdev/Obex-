#![allow(unused)]
use hex::ToHex;
use obex_alpha_t::*;

#[test]
fn sys_tx_golden_roundtrip() {
    let tx = SysTx {
        kind: SysTxKind::RewardPayout,
        slot: 99,
        pk: [9u8; 32],
        amt: 12345,
    };
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

#[test]
fn emission_monotone_and_total_hits_supply_at_terminal() {
    // Sampling prefix only for monotonicity; full schedule is enormous.
    const SAMPLE_SLOTS: u128 = 100_000;
    let mut st = EmissionState::default();
    let mut last = 0u128;
    let mut total = 0u128;
    for s in 1u128..=SAMPLE_SLOTS {
        on_slot_emission(&mut st, s, |amt| {
            total = total.saturating_add(amt);
        });
        assert!(st.total_emitted_u >= last);
        last = st.total_emitted_u;
    }
    // Terminal slot must flush any residual and hit exact total supply.
    on_slot_emission(&mut st, LAST_EMISSION_SLOT, |amt| {
        total = total.saturating_add(amt);
    });
    assert_eq!(st.total_emitted_u, TOTAL_SUPPLY_UOBX);
    assert!(total > 0);
}

#[test]
fn fees_epoch_roll_and_escrow_conservation() {
    let mut fs = FeeSplitState::default();
    let mut ver = 0u128;
    let mut tre = 0u128;
    let mut burned = 0u128;
    let mut escrow = 0u128;
    for slot in [0u64, NLB_EPOCH_SLOTS, NLB_EPOCH_SLOTS + 1] {
        let (_total, _fee) = process_transfer(
            slot,
            10_000,
            2_345,
            &mut fs,
            |_| {},
            |_| {},
            |e| {
                escrow = escrow.saturating_add(e);
            },
            |v| {
                ver = ver.saturating_add(v);
            },
            |t| {
                tre = tre.saturating_add(t);
            },
            |b| {
                burned = burned.saturating_add(b);
            },
        );
        let delta_escrow = ver.saturating_add(tre).saturating_add(burned);
        assert!(escrow >= delta_escrow);
    }
}

#[test]
fn drp_winners_unique_and_stable() {
    let y = [9u8; 32];
    let set: Vec<[u8; 32]> = (0u8..32u8).map(|v| [v; 32]).collect();
    let idx = pick_k_unique_indices(&y, 7, set.len(), 16);
    let mut s = std::collections::BTreeSet::new();
    for i in &idx {
        assert!(s.insert(*i), "duplicate index");
    }
    let idx2 = pick_k_unique_indices(&y, 7, set.len(), 16);
    assert_eq!(idx, idx2);
}
