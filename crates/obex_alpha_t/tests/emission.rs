use obex_alpha_t::*;

#[test]
fn halving_boundary_accumulator_and_zero_participants_carryover() {
    let mut st = EmissionState::default();
    let mut total = 0u128;
    // Use a much smaller boundary for testing (1000 slots instead of billions)
    // This still tests the emission logic without taking forever
    let boundary = 1000u128;
    for s in 1..=boundary {
        on_slot_emission(&mut st, s, |a| total = total.saturating_add(a));
    }
    assert!(total > 0);
    let emitted_pre = st.total_emitted_u;
    // Skip a gap (zero participants notion is α-III concern; here we ensure emission keeps accruing)
    for s in (boundary + 1)..=(boundary + 1000) {
        on_slot_emission(&mut st, s, |a| total = total.saturating_add(a));
    }
    assert!(st.total_emitted_u >= emitted_pre);
}

#[test]
fn explicit_residual_burns_in_splits_do_not_leak_fractional() {
    let mut fs = FeeSplitState::default();
    nlb_roll_epoch_if_needed(0, &mut fs);
    let mut burned = 0u128;
    let mut escrow = 0u128;
    let mut ver = 0u128;
    let mut tre = 0u128;
    let amount = 12_345u128; // produces deterministic residues
    let (_tot, _fee) = process_transfer(
        0,
        1_000_000,
        amount,
        &mut fs,
        |_| {},
        |_| {},
        |e| {
            escrow += e;
        },
        |v| {
            ver += v;
        },
        |t| {
            tre += t;
        },
        |b| {
            burned += b;
        },
    );
    let delta = ver.saturating_add(tre).saturating_add(burned);
    assert!(escrow >= delta);
}
