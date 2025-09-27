use std::fs;
use std::path::Path;

use hex::ToHex;
use obex_alpha_ii::{
    deserialize_header, obex_header_id, validate_header, ValidateErr, OBEX_ALPHA_II_VERSION,
};
use obex_alpha_ii::{
    BeaconInputs, BeaconVerifier, PartRootProvider, TicketRootProvider, TxRootProvider,
};
use obex_primitives::Hash256;

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
    fn verify(&self, _i: &BeaconInputs<'_>) -> bool {
        true
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
