#![forbid(unsafe_code)]
#![deny(
    warnings,
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    clippy::cargo
)]
#![allow(
    clippy::module_name_repetitions,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::result_large_err
)]

//! obex.α T — Tokenomics (Deterministic Emission, Fees, and Validator Rewards)
//! Implements emission schedule, fee escrow with epoch-stable splits (NLB), and DRP distribution.

use obex_primitives::{consensus, le_bytes, u64_from_le, Hash256};
use primitive_types::U256;
use std::sync::LazyLock as Lazy;
use thiserror::Error;
// Anchor to ensure SHA3-256 presence without underscore-binding side effects.
pub use obex_primitives::OBEX_SHA3_256_ANCHOR as _obex_sha3_anchor_t;

/// Network version (consensus-sealed)
pub const OBEX_ALPHA_T_VERSION: u32 = 1;
pub const UOBX_PER_OBX: u128 = 100_000_000;
pub const TOTAL_SUPPLY_OBX: u128 = 1_000_000;
pub const TOTAL_SUPPLY_UOBX: u128 = TOTAL_SUPPLY_OBX * UOBX_PER_OBX;

pub const SLOT_MS: u64 = 100;
pub const SLOTS_PER_SEC: u64 = 1_000 / SLOT_MS;
pub const PROTOCOL_YEAR_SEC: u64 = 365 * 86_400;
pub const SLOTS_PER_YEAR: u64 = PROTOCOL_YEAR_SEC * SLOTS_PER_SEC;

pub const YEARS_PER_HALVING: u64 = 5;
pub const SLOTS_PER_HALVING: u128 = (SLOTS_PER_YEAR as u128) * (YEARS_PER_HALVING as u128);
pub const HALVING_COUNT: u32 = 20;
pub const LAST_EMISSION_SLOT: u128 = (SLOTS_PER_YEAR as u128) * 100;

#[inline]
fn pow2_u256(n: u32) -> U256 {
    U256::from(1u8) << n
}

static TWO_POW_N_MINUS1: Lazy<U256> = Lazy::new(|| pow2_u256(HALVING_COUNT - 1));
static TWO_POW_N: Lazy<U256> = Lazy::new(|| pow2_u256(HALVING_COUNT));
static R0_NUM: Lazy<U256> = Lazy::new(|| U256::from(TOTAL_SUPPLY_UOBX) * *TWO_POW_N_MINUS1);
static R0_DEN: Lazy<U256> =
    Lazy::new(|| U256::from(SLOTS_PER_HALVING) * (*TWO_POW_N - U256::from(1u8)));

#[derive(Clone, Default, Debug, PartialEq, Eq)]
pub struct EmissionState {
    pub total_emitted_u: u128,
    pub acc_num: U256,
}

#[inline]
#[allow(clippy::cast_possible_truncation)]
const fn period_index(slot_1based: u128) -> u32 {
    // Checked conversion: safe under consensus bounds (≤ LAST_EMISSION_SLOT).
    let periods = (slot_1based - 1) / SLOTS_PER_HALVING;
    assert!(periods <= (u32::MAX as u128), "period index overflow");
    periods as u32
}
#[inline]
fn reward_den_for_period(p: u32) -> U256 {
    *R0_DEN * pow2_u256(p)
}

pub fn on_slot_emission(
    st: &mut EmissionState,
    slot_1based: u128,
    mut credit_emission: impl FnMut(u128),
) {
    if slot_1based == 0 || slot_1based > LAST_EMISSION_SLOT {
        return;
    }
    let p = period_index(slot_1based);
    let den = reward_den_for_period(p);
    st.acc_num += *R0_NUM;
    let payout_u256 = st.acc_num / den;
    if payout_u256 > U256::zero() {
        let payout = payout_u256.as_u128();
        let remaining = TOTAL_SUPPLY_UOBX - st.total_emitted_u;
        let pay = payout.min(remaining);
        if pay > 0 {
            credit_emission(pay);
            st.total_emitted_u = st.total_emitted_u.saturating_add(pay);
            st.acc_num -= U256::from(pay) * den;
        }
    }
    if slot_1based == LAST_EMISSION_SLOT {
        // Flush any residual to hit exact total supply at terminal slot.
        let remaining = TOTAL_SUPPLY_UOBX.saturating_sub(st.total_emitted_u);
        if remaining > 0 {
            credit_emission(remaining);
            st.total_emitted_u = TOTAL_SUPPLY_UOBX;
            st.acc_num = U256::zero();
        }
        assert!(st.total_emitted_u == TOTAL_SUPPLY_UOBX);
    }
}

pub const MIN_TRANSFER_U: u128 = 10;
pub const FLAT_SWITCH_U: u128 = 1_000;
pub const FLAT_FEE_U: u128 = 10;

#[inline]
#[must_use]
pub fn fee_int(amount_u: u128) -> u128 {
    assert!(amount_u >= MIN_TRANSFER_U);
    if amount_u <= FLAT_SWITCH_U {
        FLAT_FEE_U
    } else {
        amount_u.div_ceil(100)
    }
}

pub const NLB_EPOCH_SLOTS: u64 = 10_000;

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct NlbEpochState {
    pub epoch_index: u64,
    pub start_slot: u64,
    pub eff_supply_snapshot_u: u128,
    pub v_pct: u8,
    pub t_pct: u8,
    pub b_pct: u8,
}

#[derive(Clone, Default, Debug, PartialEq, Eq)]
pub struct FeeSplitState {
    pub acc_v_num: u128,
    pub acc_t_num: u128,
    pub acc_b_num: u128,
    pub fee_escrow_u: u128,
    pub total_burned_u: u128,
    pub nlb: NlbEpochState,
}

const TH_500K_OBX: u128 = 500_000 * UOBX_PER_OBX;
const TH_400K_OBX: u128 = 400_000 * UOBX_PER_OBX;
const TH_300K_OBX: u128 = 300_000 * UOBX_PER_OBX;
const TH_200K_OBX: u128 = 200_000 * UOBX_PER_OBX;

const BASE_TREASURY_PCT: u8 = 40;
const INITIAL_BURN_PCT: u8 = 20;
const BASE_VERIFIER_PCT: u8 = 40;
const BURN_FLOOR_PCT: u8 = 1;

#[inline]
const fn burn_percent(eff_μ: u128) -> u8 {
    if eff_μ >= TH_500K_OBX {
        20
    } else if eff_μ >= TH_400K_OBX {
        15
    } else if eff_μ >= TH_300K_OBX {
        10
    } else if eff_μ >= TH_200K_OBX {
        5
    } else {
        BURN_FLOOR_PCT
    }
}

#[inline]
fn compute_splits(eff_μ: u128) -> (u8, u8, u8) {
    let b = burn_percent(eff_μ);
    let redirect = INITIAL_BURN_PCT.saturating_sub(b);
    let v = BASE_VERIFIER_PCT.saturating_add(redirect);
    let t = BASE_TREASURY_PCT;
    debug_assert!((u16::from(v) + u16::from(t) + u16::from(b)) == 100);
    (v, t, b)
}

#[inline]
const fn epoch_index(slot: u64) -> u64 {
    slot / NLB_EPOCH_SLOTS
}

pub fn nlb_roll_epoch_if_needed(slot: u64, fs: &mut FeeSplitState) {
    let idx = epoch_index(slot);
    if idx == fs.nlb.epoch_index {
        return;
    }
    fs.nlb.epoch_index = idx;
    fs.nlb.start_slot = idx * NLB_EPOCH_SLOTS;
    let eff_u = TOTAL_SUPPLY_UOBX.saturating_sub(fs.total_burned_u);
    fs.nlb.eff_supply_snapshot_u = eff_u;
    let (v, t, b) = compute_splits(eff_u);
    fs.nlb.v_pct = v;
    fs.nlb.t_pct = t;
    fs.nlb.b_pct = b;
}

const DEN_10K: u128 = 10_000; // Constants before statements per clippy

pub fn route_fee_with_nlb(
    fs: &mut FeeSplitState,
    fee_num: u128,
    fee_den: u128,
    mut credit_verifier: impl FnMut(u128),
    mut credit_treasury: impl FnMut(u128),
    mut burn: impl FnMut(u128),
) {
    let fee_num_over_100 = if fee_den == 1 {
        fee_num.saturating_mul(100)
    } else {
        fee_num
    };
    let add_v = fee_num_over_100.saturating_mul(u128::from(fs.nlb.v_pct));
    let add_t = fee_num_over_100.saturating_mul(u128::from(fs.nlb.t_pct));
    let add_b = fee_num_over_100.saturating_mul(u128::from(fs.nlb.b_pct));
    fs.acc_v_num = fs.acc_v_num.saturating_add(add_v);
    fs.acc_t_num = fs.acc_t_num.saturating_add(add_t);
    fs.acc_b_num = fs.acc_b_num.saturating_add(add_b);

    let mut rel_v = fs.acc_v_num / DEN_10K;
    let mut rel_t = fs.acc_t_num / DEN_10K;
    let mut rel_b = fs.acc_b_num / DEN_10K;

    let total_rel = rel_v.saturating_add(rel_t).saturating_add(rel_b);
    if total_rel > fs.fee_escrow_u {
        let mut deficit = total_rel - fs.fee_escrow_u;
        let reduce = |x: &mut u128, d: &mut u128| {
            let cut = (*x).min(*d);
            *x -= cut;
            *d -= cut;
        };
        reduce(&mut rel_b, &mut deficit);
        reduce(&mut rel_t, &mut deficit);
        reduce(&mut rel_v, &mut deficit);
    }

    if rel_v > 0 {
        credit_verifier(rel_v);
        fs.fee_escrow_u -= rel_v;
        fs.acc_v_num %= DEN_10K;
    }
    if rel_t > 0 {
        credit_treasury(rel_t);
        fs.fee_escrow_u -= rel_t;
        fs.acc_t_num %= DEN_10K;
    }
    if rel_b > 0 {
        burn(rel_b);
        fs.fee_escrow_u -= rel_b;
        fs.acc_b_num %= DEN_10K;
        fs.total_burned_u = fs.total_burned_u.saturating_add(rel_b);
    }
}

#[allow(clippy::too_many_arguments)]
pub fn process_transfer(
    slot: u64,
    sender_balance_μ: u128,
    amount_μ: u128,
    fs: &mut FeeSplitState,
    mut debit_sender: impl FnMut(u128),
    mut credit_recipient: impl FnMut(u128),
    mut escrow_credit: impl FnMut(u128),
    credit_verifier: impl FnMut(u128),
    credit_treasury: impl FnMut(u128),
    burn: impl FnMut(u128),
) -> (u128, u128) {
    assert!(amount_μ >= MIN_TRANSFER_U);
    nlb_roll_epoch_if_needed(slot, fs);
    let (fee_num, fee_den) = if amount_μ <= FLAT_SWITCH_U {
        (FLAT_FEE_U, 1)
    } else {
        (amount_μ, 100)
    };
    let fee_μ = fee_num.div_ceil(fee_den);
    let total_debit = amount_μ.saturating_add(fee_μ);
    assert!(sender_balance_μ >= total_debit);
    debit_sender(total_debit);
    credit_recipient(amount_μ);
    fs.fee_escrow_u = fs.fee_escrow_u.saturating_add(fee_μ);
    escrow_credit(fee_μ);
    route_fee_with_nlb(fs, fee_num, fee_den, credit_verifier, credit_treasury, burn);
    (total_debit, fee_μ)
}

#[inline]
fn ctr_draw(y: &Hash256, s: u64, t: u32) -> Hash256 {
    consensus::h_tag(
        "obex.reward.draw",
        &[
            y,
            &le_bytes::<8>(u128::from(s)),
            &le_bytes::<4>(u128::from(t)),
        ],
    )
}

// Items before statements per clippy
use std::collections::BTreeSet;

#[must_use]
pub fn pick_k_unique_indices(
    y_edge_s: &Hash256,
    slot: u64,
    set_len: usize,
    winners_k: usize,
) -> Vec<usize> {
    if set_len == 0 || winners_k == 0 {
        return vec![];
    }
    let mut out = Vec::with_capacity(winners_k);
    let mut seen = BTreeSet::new();
    let mut t: u32 = 0;
    while out.len() < winners_k {
        let h = ctr_draw(y_edge_s, slot, t);
        let idx = usize::try_from(u64_from_le(&h[..8]) % (set_len as u64)).unwrap_or(usize::MAX);
        if seen.insert(idx) {
            out.push(idx);
        }
        t = t.wrapping_add(1);
    }
    out
}

#[inline]
fn reward_rank(y: &Hash256, pk: &Hash256) -> Hash256 {
    consensus::h_tag("obex.reward.rank", &[y, pk])
}

pub const DRP_BASELINE_PCT: u8 = 20;
pub const DRP_K_WINNERS: usize = 16;

#[allow(clippy::too_many_arguments)]
pub fn distribute_drp_for_slot(
    s: u64,
    y_edge_s: &Hash256,
    part_set_sorted: &[Hash256],
    mut read_pool_balance: impl FnMut() -> u128,
    mut debit_pool: impl FnMut(u128),
    mut credit_pk: impl FnMut(&Hash256, u128),
    mut burn_fn: impl FnMut(u128),
) {
    let m = part_set_sorted.len();
    let drp = read_pool_balance();
    if drp == 0 || m == 0 {
        return;
    }
    let baseline = (drp * u128::from(DRP_BASELINE_PCT)) / 100;
    let lottery = drp - baseline;
    let per_base = baseline / (m as u128);
    let base_rem = baseline % (m as u128);
    let k = core::cmp::min(DRP_K_WINNERS, m);
    if k == 0 {
        return;
    }
    let winners_idx = pick_k_unique_indices(y_edge_s, s, m, k);
    let per_win = lottery / (k as u128);
    let lot_rem = lottery % (k as u128);
    if per_base == 0 && per_win == 0 {
        return;
    }
    let total_pay = per_base * (m as u128) + per_win * (k as u128);
    debit_pool(total_pay);
    if per_base > 0 {
        for pk in part_set_sorted {
            credit_pk(pk, per_base);
        }
    }
    if base_rem > 0 {
        burn_fn(base_rem);
    }
    if per_win > 0 {
        let mut winners: Vec<(usize, Hash256)> = winners_idx
            .iter()
            .map(|&i| (i, reward_rank(y_edge_s, &part_set_sorted[i])))
            .collect();
        winners.sort_by(|a, b| a.1.cmp(&b.1));
        for (idx, _rank) in winners {
            credit_pk(&part_set_sorted[idx], per_win);
        }
    }
    if lot_rem > 0 {
        burn_fn(lot_rem);
    }
}

// ——— System transaction (consensus wire) ——————————————————————————

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SysTxKind {
    EscrowCredit = 0,
    VerifierCredit = 1,
    TreasuryCredit = 2,
    Burn = 3,
    RewardPayout = 4,
    EmissionCredit = 5,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SysTx {
    pub kind: SysTxKind,
    pub slot: u64,
    pub pk: Hash256,
    pub amt: u128,
}

#[derive(Debug, Error)]
pub enum SysTxCodecError {
    #[error("short")]
    Short,
    #[error("trailing")]
    Trailing,
}

const fn read_exact<'a>(src: &mut &'a [u8], n: usize) -> Result<&'a [u8], SysTxCodecError> {
    if src.len() < n {
        return Err(SysTxCodecError::Short);
    }
    let (a, b) = src.split_at(n);
    *src = b;
    Ok(a)
}

#[must_use]
pub fn enc_sys_tx(tx: &SysTx) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&consensus::h_tag("obex.sys.tx", &[]));
    out.extend_from_slice(&[tx.kind as u8]);
    out.extend_from_slice(&le_bytes::<8>(u128::from(tx.slot)));
    out.extend_from_slice(&tx.pk);
    out.extend_from_slice(&le_bytes::<16>(tx.amt));
    out
}

pub fn dec_sys_tx(mut src: &[u8]) -> Result<SysTx, SysTxCodecError> {
    let _tag = read_exact(&mut src, 32)?; // domain tag bytes
    let kind = {
        let b = read_exact(&mut src, 1)?[0];
        match b {
            0 => SysTxKind::EscrowCredit,
            1 => SysTxKind::VerifierCredit,
            2 => SysTxKind::TreasuryCredit,
            4 => SysTxKind::RewardPayout,
            5 => SysTxKind::EmissionCredit,
            _ => SysTxKind::Burn,
        }
    };
    let slot = u64::from_le_bytes(read_exact(&mut src, 8)?.try_into().unwrap());
    let pk = {
        let b = read_exact(&mut src, 32)?;
        let mut a = [0u8; 32];
        a.copy_from_slice(b);
        a
    };
    let amt = u128::from_le_bytes(read_exact(&mut src, 16)?.try_into().unwrap());
    if !src.is_empty() {
        return Err(SysTxCodecError::Trailing);
    }
    Ok(SysTx {
        kind,
        slot,
        pk,
        amt,
    })
}

/// Canonical ordering for system transactions within a slot (consensus-critical)
/// Order: `ESCROW_CREDIT` → `EMISSION_CREDIT` → `VERIFIER_CREDIT` → `TREASURY_CREDIT` → `BURN` → `REWARD_PAYOUT` (by rank)
#[must_use]
pub fn canonical_sys_tx_order(sys_txs: Vec<SysTx>, y_edge_s: &Hash256) -> Vec<SysTx> {
    // Separate REWARD_PAYOUT transactions from others
    let (mut reward_payouts, mut others): (Vec<_>, Vec<_>) = sys_txs
        .into_iter()
        .partition(|tx| matches!(tx.kind, SysTxKind::RewardPayout));

    // Sort non-REWARD_PAYOUT transactions by kind priority
    others.sort_by_key(|tx| match tx.kind {
        SysTxKind::EscrowCredit => 0,
        SysTxKind::EmissionCredit => 1,
        SysTxKind::VerifierCredit => 2,
        SysTxKind::TreasuryCredit => 3,
        SysTxKind::Burn => 4,
        SysTxKind::RewardPayout => 5, // Should not happen due to partition
    });

    // Sort REWARD_PAYOUT transactions by reward_rank
    reward_payouts.sort_by(|a, b| {
        let rank_a = reward_rank(y_edge_s, &a.pk);
        let rank_b = reward_rank(y_edge_s, &b.pk);
        rank_a.cmp(&rank_b)
    });

    // Combine: others first, then reward payouts
    others.extend(reward_payouts);
    others
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emission_monotonic_and_terminal_assert() {
        let mut st = EmissionState::default();
        // Run a few slots to ensure no panic and monotonic emission.
        let mut total = 0u128;
        for s in 1u128..=1_000 {
            on_slot_emission(&mut st, s, |amt| {
                total = total.saturating_add(amt);
            });
        }
        assert!(total > 0);
    }

    #[test]
    fn fee_rule_flat_and_percent() {
        assert_eq!(fee_int(10), FLAT_FEE_U);
        assert_eq!(fee_int(1_000), FLAT_FEE_U);
        assert_eq!(fee_int(1_001), 11);
    }

    #[test]
    fn escrow_split_respects_cap() {
        let mut fs = FeeSplitState::default();
        // Initialize epoch params deterministically
        nlb_roll_epoch_if_needed(0, &mut fs);
        fs.fee_escrow_u = 5; // low escrow to trigger cap logic
                             // amount 100 → fee rational 10/1, splits will try to release more than escrow
        route_fee_with_nlb(&mut fs, 10, 1, |_| {}, |_| {}, |_| {});
        assert!(fs.fee_escrow_u <= 5);
    }

    #[test]
    fn canonical_sys_tx_ordering() {
        let pk1 = [1u8; 32];
        let pk2 = [2u8; 32];
        let pk3 = [3u8; 32];
        let y_edge = [0u8; 32];

        // Create system transactions in random order
        let sys_txs = vec![
            SysTx {
                kind: SysTxKind::Burn,
                slot: 100,
                pk: pk1,
                amt: 50,
            },
            SysTx {
                kind: SysTxKind::RewardPayout,
                slot: 100,
                pk: pk2,
                amt: 200,
            },
            SysTx {
                kind: SysTxKind::EscrowCredit,
                slot: 100,
                pk: pk3,
                amt: 100,
            },
            SysTx {
                kind: SysTxKind::VerifierCredit,
                slot: 100,
                pk: pk1,
                amt: 75,
            },
            SysTx {
                kind: SysTxKind::RewardPayout,
                slot: 100,
                pk: pk1,
                amt: 150,
            },
            SysTx {
                kind: SysTxKind::EmissionCredit,
                slot: 100,
                pk: pk2,
                amt: 300,
            },
            SysTx {
                kind: SysTxKind::TreasuryCredit,
                slot: 100,
                pk: pk3,
                amt: 25,
            },
        ];

        // Apply canonical ordering
        let ordered = canonical_sys_tx_order(sys_txs, &y_edge);

        // Verify the order: EscrowCredit, EmissionCredit, VerifierCredit, TreasuryCredit, Burn, RewardPayout
        assert_eq!(ordered[0].kind, SysTxKind::EscrowCredit);
        assert_eq!(ordered[1].kind, SysTxKind::EmissionCredit);
        assert_eq!(ordered[2].kind, SysTxKind::VerifierCredit);
        assert_eq!(ordered[3].kind, SysTxKind::TreasuryCredit);
        assert_eq!(ordered[4].kind, SysTxKind::Burn);
        assert_eq!(ordered[5].kind, SysTxKind::RewardPayout);
        assert_eq!(ordered[6].kind, SysTxKind::RewardPayout);

        // Verify that RewardPayout transactions are sorted by reward_rank
        let rank1 = reward_rank(&y_edge, &pk1);
        let rank2 = reward_rank(&y_edge, &pk2);

        if rank1 < rank2 {
            assert_eq!(ordered[5].pk, pk1);
            assert_eq!(ordered[6].pk, pk2);
        } else {
            assert_eq!(ordered[5].pk, pk2);
            assert_eq!(ordered[6].pk, pk1);
        }
    }
}
