use std::fs;
use std::path::Path;

use hex::ToHex;
use obex_alpha_ii::{
    deserialize_header, obex_header_id, validate_header, ValidateErr, OBEX_ALPHA_II_VERSION,
};
use obex_alpha_ii::{
    BeaconInputs, BeaconVerifier, PartRootProvider, TicketRootProvider, TxRootProvider,
};
use obex_primitives::{constants, h_tag, le_bytes, Hash256};

fn golden_dir() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("golden")
}

#[test]
fn golden_header_parent_and_child_roundtrip() {
    let dir = golden_dir();
    for name in ["header_v2_parent.bin", "header_v2_slot1.bin"] {
        let path = dir.join(name);
        let bytes = fs::read(&path).expect("read golden header");
        let h = deserialize_header(&bytes).expect("decode header");
        let enc = obex_alpha_ii::serialize_header(&h);
        assert_eq!(enc, bytes, "wire bytes stable for {name}");
    }
}

#[test]
fn golden_header_child_id_matches_hex() {
    let dir = golden_dir();
    let bytes = fs::read(dir.join("header_v2_slot1.bin")).expect("read child");
    let h = deserialize_header(&bytes).expect("decode child");
    let id_hex = obex_header_id(&h).encode_hex::<String>();
    let exp_hex = fs::read_to_string(dir.join("header_v2_slot1.id.hex")).expect("read id hex");
    assert_eq!(id_hex, exp_hex);
}

#[test]
fn golden_header_flipbit_changes_id_or_decode() {
    let dir = golden_dir();
    let bytes = fs::read(dir.join("header_v2_slot1.bin")).expect("read child");
    for i in [0usize, 8, 12, 32, 64, bytes.len() - 1] {
        let mut b = bytes.clone();
        b[i] ^= 1;
        if let Ok(h2) = obex_alpha_ii::deserialize_header(&b) {
            let id1 = obex_header_id(&obex_alpha_ii::deserialize_header(&bytes).unwrap());
            let id2 = obex_header_id(&h2);
            assert_ne!(id1, id2, "flip bit should alter header id");
        }
    }
}

struct BeaconOk;
impl BeaconVerifier for BeaconOk {
    fn verify(&self, i: &BeaconInputs<'_>) -> bool {
        let seed_expected = h_tag(
            constants::TAG_SLOT_SEED,
            &[i.parent_id, &le_bytes::<8>(u128::from(i.slot))],
        );
        seed_expected == *i.seed_commit
            && h_tag(constants::TAG_VDF_EDGE, &[i.vdf_y_core]) == *i.vdf_y_edge
    }
}
#[derive(Clone, Copy)]
struct ConstRoots {
    t: Hash256,
    p: Hash256,
    xprev: Hash256,
}
impl TicketRootProvider for ConstRoots {
    fn compute_ticket_root(&self, _: u64) -> Hash256 {
        self.t
    }
}
impl PartRootProvider for ConstRoots {
    fn compute_part_root(&self, _: u64) -> Hash256 {
        self.p
    }
}
impl TxRootProvider for ConstRoots {
    fn compute_txroot(&self, _: u64) -> Hash256 {
        self.xprev
    }
}

#[test]
fn golden_header_field_flip_specific_errors() {
    let dir = golden_dir();
    let bytes_p = fs::read(dir.join("header_v2_parent.bin")).unwrap();
    let bytes_c = fs::read(dir.join("header_v2_slot1.bin")).unwrap();
    let parent = deserialize_header(&bytes_p).unwrap();
    let h = deserialize_header(&bytes_c).unwrap();
    let providers = ConstRoots {
        t: h.ticket_root,
        p: h.part_root,
        xprev: h.txroot_prev,
    };
    let beacon = BeaconOk;

    #[allow(clippy::type_complexity)]
    #[allow(clippy::type_complexity)]
    let cases: Vec<(Box<dyn Fn(&mut obex_alpha_ii::Header)>, ValidateErr)> = vec![
        (
            Box::new(|hh| {
                hh.parent_id[0] ^= 1;
            }),
            ValidateErr::BadParentLink,
        ),
        (
            Box::new(|hh| {
                hh.slot = parent.slot;
            }),
            ValidateErr::BadSlot,
        ),
        (
            Box::new(|hh| {
                hh.ticket_root[0] ^= 1;
            }),
            ValidateErr::TicketRootMismatch,
        ),
        (
            Box::new(|hh| {
                hh.part_root[0] ^= 1;
            }),
            ValidateErr::PartRootMismatch,
        ),
        (
            Box::new(|hh| {
                hh.txroot_prev[0] ^= 1;
            }),
            ValidateErr::TxRootPrevMismatch,
        ),
        (
            Box::new(|hh| {
                hh.obex_version ^= 1;
            }),
            ValidateErr::VersionMismatch,
        ),
    ];
    for (m, exp) in cases {
        let mut hh = h.clone();
        m(&mut hh);
        let got = validate_header(
            &hh,
            &parent,
            &beacon,
            &providers,
            &providers,
            &providers,
            OBEX_ALPHA_II_VERSION,
        )
        .unwrap_err();
        assert_eq!(got, exp);
    }
}

/// Test comprehensive flip-bit failures for all Header v2 fields
/// This locks the consensus behavior for Header validation forever
#[test]
fn golden_header_comprehensive_flipbit_failures() {
    let dir = golden_dir();
    let parent_bytes = fs::read(dir.join("header_v2_parent.bin")).expect("read parent");
    let child_bytes = fs::read(dir.join("header_v2_slot1.bin")).expect("read child");

    let parent = deserialize_header(&parent_bytes).expect("decode parent");
    let child = deserialize_header(&child_bytes).expect("decode child");

    let beacon = BeaconOk;
    let providers = ConstRoots {
        t: child.ticket_root,
        p: child.part_root,
        xprev: child.txroot_prev,
    };

    // Test parent_id flip-bit failures (consensus-critical)
    for byte_idx in 0..32 {
        for bit_idx in 0..8 {
            let mut bad_child = child.clone();
            bad_child.parent_id[byte_idx] ^= 1 << bit_idx;

            let err = validate_header(
                &bad_child,
                &parent,
                &beacon,
                &providers,
                &providers,
                &providers,
                OBEX_ALPHA_II_VERSION,
            )
            .unwrap_err();
            assert_eq!(
                err,
                ValidateErr::BadParentLink,
                "Parent ID bit flip at byte {} bit {} should cause BadParentLink",
                byte_idx,
                bit_idx
            );
        }
    }

    // Test seed_commit flip-bit failures (consensus-critical)
    for byte_idx in 0..32 {
        for bit_idx in 0..8 {
            let mut bad_child = child.clone();
            bad_child.seed_commit[byte_idx] ^= 1 << bit_idx;

            let err = validate_header(
                &bad_child,
                &parent,
                &beacon,
                &providers,
                &providers,
                &providers,
                OBEX_ALPHA_II_VERSION,
            )
            .unwrap_err();
            assert_eq!(
                err,
                ValidateErr::BeaconInvalid,
                "Seed commit bit flip at byte {} bit {} should cause BeaconInvalid",
                byte_idx,
                bit_idx
            );
        }
    }

    // Test vdf_y_core flip-bit failures (consensus-critical)
    for byte_idx in 0..32 {
        for bit_idx in 0..8 {
            let mut bad_child = child.clone();
            bad_child.vdf_y_core[byte_idx] ^= 1 << bit_idx;

            let err = validate_header(
                &bad_child,
                &parent,
                &beacon,
                &providers,
                &providers,
                &providers,
                OBEX_ALPHA_II_VERSION,
            )
            .unwrap_err();
            assert_eq!(
                err,
                ValidateErr::BeaconInvalid,
                "VDF Y core bit flip at byte {} bit {} should cause BeaconInvalid",
                byte_idx,
                bit_idx
            );
        }
    }

    // Test vdf_y_edge flip-bit failures (consensus-critical)
    for byte_idx in 0..32 {
        for bit_idx in 0..8 {
            let mut bad_child = child.clone();
            bad_child.vdf_y_edge[byte_idx] ^= 1 << bit_idx;

            let err = validate_header(
                &bad_child,
                &parent,
                &beacon,
                &providers,
                &providers,
                &providers,
                OBEX_ALPHA_II_VERSION,
            )
            .unwrap_err();
            assert_eq!(
                err,
                ValidateErr::BeaconInvalid,
                "VDF Y edge bit flip at byte {} bit {} should cause BeaconInvalid",
                byte_idx,
                bit_idx
            );
        }
    }

    // Test ticket_root flip-bit failures (consensus-critical)
    for byte_idx in 0..32 {
        for bit_idx in 0..8 {
            let mut bad_child = child.clone();
            bad_child.ticket_root[byte_idx] ^= 1 << bit_idx;

            let err = validate_header(
                &bad_child,
                &parent,
                &beacon,
                &providers,
                &providers,
                &providers,
                OBEX_ALPHA_II_VERSION,
            )
            .unwrap_err();
            assert_eq!(
                err,
                ValidateErr::TicketRootMismatch,
                "Ticket root bit flip at byte {} bit {} should cause TicketRootMismatch",
                byte_idx,
                bit_idx
            );
        }
    }

    // Test part_root flip-bit failures (consensus-critical for Header v2)
    for byte_idx in 0..32 {
        for bit_idx in 0..8 {
            let mut bad_child = child.clone();
            bad_child.part_root[byte_idx] ^= 1 << bit_idx;

            let err = validate_header(
                &bad_child,
                &parent,
                &beacon,
                &providers,
                &providers,
                &providers,
                OBEX_ALPHA_II_VERSION,
            )
            .unwrap_err();
            assert_eq!(
                err,
                ValidateErr::PartRootMismatch,
                "Part root bit flip at byte {} bit {} should cause PartRootMismatch",
                byte_idx,
                bit_idx
            );
        }
    }

    // Test txroot_prev flip-bit failures (consensus-critical)
    for byte_idx in 0..32 {
        for bit_idx in 0..8 {
            let mut bad_child = child.clone();
            bad_child.txroot_prev[byte_idx] ^= 1 << bit_idx;

            let err = validate_header(
                &bad_child,
                &parent,
                &beacon,
                &providers,
                &providers,
                &providers,
                OBEX_ALPHA_II_VERSION,
            )
            .unwrap_err();
            assert_eq!(
                err,
                ValidateErr::TxRootPrevMismatch,
                "TX root prev bit flip at byte {} bit {} should cause TxRootPrevMismatch",
                byte_idx,
                bit_idx
            );
        }
    }
}

/// Test VDF proof field flip-bit failures
/// This locks the beacon verification behavior forever
#[test]
fn golden_header_vdf_proof_flipbit_failures() {
    let dir = golden_dir();
    let parent_bytes = fs::read(dir.join("header_v2_parent.bin")).expect("read parent");
    let child_bytes = fs::read(dir.join("header_v2_slot1.bin")).expect("read child");

    let parent = deserialize_header(&parent_bytes).expect("decode parent");
    let child = deserialize_header(&child_bytes).expect("decode child");

    let beacon = BeaconOk;
    let providers = ConstRoots {
        t: child.ticket_root,
        p: child.part_root,
        xprev: child.txroot_prev,
    };

    // Test vdf_pi flip-bit failures (variable length field)
    for byte_idx in 0..child.vdf_pi.len() {
        for bit_idx in 0..8 {
            let mut bad_child = child.clone();
            bad_child.vdf_pi[byte_idx] ^= 1 << bit_idx;

            let err = validate_header(
                &bad_child,
                &parent,
                &beacon,
                &providers,
                &providers,
                &providers,
                OBEX_ALPHA_II_VERSION,
            )
            .unwrap_err();
            assert_eq!(
                err,
                ValidateErr::BeaconInvalid,
                "VDF pi bit flip at byte {} bit {} should cause BeaconInvalid",
                byte_idx,
                bit_idx
            );
        }
    }

    // Test vdf_ell flip-bit failures (variable length field)
    for byte_idx in 0..child.vdf_ell.len() {
        for bit_idx in 0..8 {
            let mut bad_child = child.clone();
            bad_child.vdf_ell[byte_idx] ^= 1 << bit_idx;

            let err = validate_header(
                &bad_child,
                &parent,
                &beacon,
                &providers,
                &providers,
                &providers,
                OBEX_ALPHA_II_VERSION,
            )
            .unwrap_err();
            assert_eq!(
                err,
                ValidateErr::BeaconInvalid,
                "VDF ell bit flip at byte {} bit {} should cause BeaconInvalid",
                byte_idx,
                bit_idx
            );
        }
    }
}

/// Test canonical Header v2 byte image stability
/// This ensures the golden Header v2 byte representation never changes
#[test]
fn golden_header_canonical_byte_image_stability() {
    let dir = golden_dir();

    // Test parent header canonical stability
    let parent_bytes = fs::read(dir.join("header_v2_parent.bin")).expect("read parent");
    let parent = deserialize_header(&parent_bytes).expect("decode parent");
    let parent_bytes2 = obex_alpha_ii::serialize_header(&parent);
    assert_eq!(
        parent_bytes2, parent_bytes,
        "Golden parent Header v2 canonical byte image must be stable"
    );

    // Test child header canonical stability
    let child_bytes = fs::read(dir.join("header_v2_slot1.bin")).expect("read child");
    let child = deserialize_header(&child_bytes).expect("decode child");
    let child_bytes2 = obex_alpha_ii::serialize_header(&child);
    assert_eq!(
        child_bytes2, child_bytes,
        "Golden child Header v2 canonical byte image must be stable"
    );

    // Verify Header v2 structure integrity
    assert_eq!(parent.obex_version, OBEX_ALPHA_II_VERSION);
    assert_eq!(child.obex_version, OBEX_ALPHA_II_VERSION);
    assert_eq!(
        child.slot,
        parent.slot + 1,
        "Child slot must be parent slot + 1"
    );

    // Verify header ID stability
    let child_id_hex = obex_header_id(&child).encode_hex::<String>();
    let exp_hex = fs::read_to_string(dir.join("header_v2_slot1.id.hex")).expect("read id hex");
    assert_eq!(child_id_hex, exp_hex, "Header ID must be stable");
}
