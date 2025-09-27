use obex_alpha_i::{obex_verify_partrec_bytes, EcVrfVerifier};
use obex_primitives::Hash256;

struct RejectAllVrf;
impl EcVrfVerifier for RejectAllVrf {
    fn verify(
        &self,
        _vrf_pubkey: &[u8; 32],
        _alpha: &Hash256,
        _vrf_proof: &[u8],
    ) -> Option<Vec<u8>> {
        None
    }
}

#[test]
fn oversize_partrec_rejected_predecode() {
    // Construct a too-large buffer (over MAX_PARTREC_SIZE)
    let bytes = vec![0u8; 600_001];
    let slot = 1u64;
    let parent_id = [0u8; 32];
    let vrf = RejectAllVrf;
    assert!(!obex_verify_partrec_bytes(&bytes, slot, &parent_id, &vrf));
}

#[test]
fn build_participation_set_dedups_by_pk() {
    use obex_alpha_i::{build_participation_set, ObexPartRec, CHALLENGES_Q, OBEX_ALPHA_I_VERSION};
    use obex_primitives::Pk32;
    struct AcceptAllVrf;
    impl EcVrfVerifier for AcceptAllVrf {
        fn verify(
            &self,
            _vrf_pubkey: &Pk32,
            _alpha: &Hash256,
            _vrf_proof: &[u8],
        ) -> Option<Vec<u8>> {
            Some(vec![1u8; 64])
        }
    }

    // Minimal well-formed records with same sender pk, should dedup
    let mk = |pk: Pk32| ObexPartRec {
        version: OBEX_ALPHA_I_VERSION,
        slot: 1,
        pk_ed25519: pk,
        vrf_pk: [2u8; 32],
        y_edge_prev: [3u8; 32],
        alpha: [4u8; 32],
        vrf_y: vec![5u8; 64],
        vrf_pi: vec![6u8; 80],
        seed: [7u8; 32],
        root: [8u8; 32],
        challenges: (0..CHALLENGES_Q)
            .map(|_| obex_alpha_i::ChallengeOpen {
                idx: 1,
                li: [9; 32],
                pi: obex_alpha_i::MerklePathLite { siblings: vec![] },
                lim1: [10; 32],
                pim1: obex_alpha_i::MerklePathLite { siblings: vec![] },
                lj: [11; 32],
                pj: obex_alpha_i::MerklePathLite { siblings: vec![] },
                lk: [12; 32],
                pk_: obex_alpha_i::MerklePathLite { siblings: vec![] },
            })
            .collect(),
        sig: [13u8; 64],
    };
    let a = mk([1u8; 32]);
    let b = mk([1u8; 32]); // same pk
    let (_pks, root1) =
        build_participation_set(1, &[0u8; 32], [a.clone(), b].iter(), &AcceptAllVrf);
    let (_pks2, root2) = build_participation_set(1, &[0u8; 32], std::iter::once(&a), &AcceptAllVrf);
    assert_eq!(root1, root2);
}
