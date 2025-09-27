use std::fs;
use std::path::Path;

use obex_alpha_i::{
    encode_partrec, ChallengeOpen, MerklePathLite, ObexPartRec, CHALLENGES_Q, OBEX_ALPHA_I_VERSION,
};
use obex_primitives::{constants, h_tag, le_bytes, Hash256, Pk32};

fn main() {
    // Deterministic fixture: small, validly-shaped record with empty Merkle paths.
    let pk: Pk32 = [1u8; 32];
    let vrf_pk: [u8; 32] = [2u8; 32];
    let y_prev: Hash256 = [3u8; 32];
    let vrf_y: Vec<u8> = vec![5u8; 64];
    let parent_id = constants::GENESIS_PARENT_ID;
    let slot = 1u64;
    let alpha: Hash256 = h_tag(
        constants::TAG_ALPHA,
        &[
            &parent_id,
            &le_bytes::<8>(u128::from(slot)),
            &y_prev,
            &vrf_pk,
        ],
    );
    let seed: Hash256 = h_tag(constants::TAG_SEED, &[&y_prev, &pk, &vrf_y]);
    let root: Hash256 = h_tag(constants::TAG_MERKLE_EMPTY, &[]);

    let mut challenges = Vec::with_capacity(CHALLENGES_Q);
    for _ in 0..CHALLENGES_Q {
        challenges.push(ChallengeOpen {
            idx: 1,
            li: [9u8; 32],
            pi: MerklePathLite { siblings: vec![] },
            lim1: [10u8; 32],
            pim1: MerklePathLite { siblings: vec![] },
            lj: [11u8; 32],
            pj: MerklePathLite { siblings: vec![] },
            lk: [12u8; 32],
            pk_: MerklePathLite { siblings: vec![] },
        });
    }

    let rec = ObexPartRec {
        version: OBEX_ALPHA_I_VERSION,
        slot,
        pk_ed25519: pk,
        vrf_pk,
        y_edge_prev: y_prev,
        alpha,
        vrf_y,
        vrf_pi: vec![6u8; 80],
        seed,
        root,
        challenges,
        sig: [13u8; 64],
    };

    let bytes = encode_partrec(&rec).expect("encode");

    let out_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("golden");
    fs::create_dir_all(&out_dir).expect("mkdir -p tests/golden");
    let out_path = out_dir.join("partrec_v1.bin");
    fs::write(&out_path, &bytes).expect("write golden partrec");
    println!("WROTE:{}", out_path.display());
}
