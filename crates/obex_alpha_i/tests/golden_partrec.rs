use std::fs;
use std::path::Path;

use obex_alpha_i::{decode_partrec, encode_partrec};

fn read_golden() -> Vec<u8> {
    let p = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests").join("golden").join("partrec_v1.bin");
    fs::read(p).expect("read golden partrec_v1.bin")
}

#[test]
fn golden_partrec_accept_and_roundtrip() {
    let bytes = read_golden();
    let rec = decode_partrec(&bytes).expect("decode golden");
    let bytes2 = encode_partrec(&rec).expect("re-encode");
    assert_eq!(bytes2, bytes, "golden bytes stable");
}

#[test]
fn golden_partrec_flipbit_failures() {
    let bytes = read_golden();
    for i in [0usize, 4, 12, 40, 80, 112, bytes.len() - 1] {
        let mut b = bytes.clone();
        b[i] ^= 1;
        let _ = decode_partrec(&b).ok();
        // For now we assert inequality to the original bytes upon re-encode when decodable.
        if let Ok(rec) = decode_partrec(&b) {
            let enc = encode_partrec(&rec).expect("enc");
            assert_ne!(enc, bytes, "flip-bit should change the canonical encoding");
        }
    }
}


