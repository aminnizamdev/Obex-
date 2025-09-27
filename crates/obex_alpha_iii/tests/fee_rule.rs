use obex_alpha_iii::*;

#[test]
fn fee_rule_flat_and_percent_and_reject_on_mismatch() {
    assert_eq!(fee_int_uobx(10), FLAT_FEE_UOBX);
    assert_eq!(fee_int_uobx(1_000), FLAT_FEE_UOBX);
    assert_eq!(fee_int_uobx(1_001), 11);
    // Mismatch scenario covered in admission tests (FeeMismatch).
}
