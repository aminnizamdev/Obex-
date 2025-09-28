#![no_main]

use libfuzzer_sys::fuzz_target;
use obex_alpha_i::decode_partrec;

fuzz_target!(|data: &[u8]| {
    let _ = decode_partrec(data);
});