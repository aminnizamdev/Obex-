use std::fs;
use std::path::Path;

use hex::ToHex;
use obex_alpha_ii::{deserialize_header, obex_header_id};

fn golden_dir() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests").join("golden")
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


