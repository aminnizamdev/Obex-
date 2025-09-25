#![no_main]

use libfuzzer_sys::fuzz_target;
use obex_engine_i::ser::decode_registration;

fuzz_target!(|data: &[u8]| {
    // Fuzz the registration decoder with arbitrary input
    let _ = decode_registration(data);
});