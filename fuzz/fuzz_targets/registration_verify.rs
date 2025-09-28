#![no_main]

use libfuzzer_sys::fuzz_target;
use obex_alpha_i::{obex_verify_partrec_bytes, vrf::VrfPk};

fuzz_target!(|data: &[u8]| {
    // Require minimum plausible size: header + one challenge + sig
    if data.len() < 416 { return; }
    // Use fixed slot/parent for fuzz
    let slot: u64 = 1;
    let parent_id = [0u8; 32];
    // Dummy VRF provider: not needed since we call the bytes helper which needs a real provider;
    // here we short-circuit by using a zero-sized struct that won't be used because most inputs fail decode.
    struct NoVrf;
    impl obex_alpha_i::EcVrfVerifier for NoVrf {
        fn verify(&self, _k: &VrfPk, _a: &[u8;32], _p: &[u8]) -> Option<Vec<u8>> { None }
    }
    let vrf = NoVrf;
    let _ = obex_verify_partrec_bytes(data, slot, &parent_id, &vrf);
});