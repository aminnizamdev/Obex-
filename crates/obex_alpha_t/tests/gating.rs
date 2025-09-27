use obex_alpha_t::*;
use std::cell::RefCell;

#[test]
fn emission_runs_and_credits_total() {
    let mut st = EmissionState::default();
    let mut sum = 0u128;
    for s in 1u128..=1000 {
        on_slot_emission(&mut st, s, |amt| {
            sum = sum.saturating_add(amt);
        });
    }
    assert!(sum > 0);
}

#[test]
fn escrow_conservation_basic() {
    let mut fs = FeeSplitState::default();
    let mut sent = 0u128;
    nlb_roll_epoch_if_needed(0, &mut fs);
    let (_, fee) = process_transfer(
        0,
        10_000,
        2_000,
        &mut fs,
        |_| {},
        |_| {},
        |f| {
            sent = sent.saturating_add(f);
        },
        |_| {},
        |_| {},
        |_| {},
    );
    assert!(fs.fee_escrow_u >= fee);
}

#[test]
fn route_fee_calls_in_order_and_not_overdraw() {
    let mut fs = FeeSplitState::default();
    nlb_roll_epoch_if_needed(0, &mut fs);
    fs.fee_escrow_u = 0; // start at zero
                         // First accrue fee into escrow
    let mut escrow_credit_total = 0u128;
    let (_total, fee) = process_transfer(
        0,
        10_000,
        2_000,
        &mut fs,
        |_| {},
        |_| {},
        |f| {
            escrow_credit_total = escrow_credit_total.saturating_add(f);
        },
        |_| {},
        |_| {},
        |_| {},
    );
    assert!(fee > 0);
    assert_eq!(fs.fee_escrow_u, escrow_credit_total);

    // Now route releases and capture call order
    let calls: RefCell<Vec<&'static str>> = RefCell::new(Vec::new());
    let start_escrow = fs.fee_escrow_u;
    route_fee_with_nlb(
        &mut fs,
        10, // numerator
        1,  // denominator (flat)
        |v| {
            if v > 0 {
                calls.borrow_mut().push("verifier");
            }
        },
        |t| {
            if t > 0 {
                calls.borrow_mut().push("treasury");
            }
        },
        |b| {
            if b > 0 {
                calls.borrow_mut().push("burn");
            }
        },
    );
    // Order must be verifier -> treasury -> burn when releases occur
    let calls_vec = calls.borrow().clone();
    if calls_vec.len() == 3 {
        assert_eq!(calls_vec, vec!["verifier", "treasury", "burn"]);
    }
    assert!(fs.fee_escrow_u <= start_escrow);
}
