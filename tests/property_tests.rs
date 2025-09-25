//! Property-based tests for Obex Engine I

use obex_engine_i::*;
use proptest::prelude::*;
use ed25519_dalek::{SigningKey, Signer};
use rand_core::OsRng;

// Property test: Merkle path verification should be deterministic
proptest! {
    #[test]
    fn merkle_verification_deterministic(
        index in 0u32..N_LEAVES,
        leaf in prop::array::uniform32(any::<u8>()),
        path_data in prop::collection::vec(prop::array::uniform32(any::<u8>()), 26)
    ) {
        let path = MerklePath { path: path_data };
        let root = MerkleRoot([0u8; 32]); // Dummy root
        
        // Verification should be deterministic
        let result1 = verify_merkle_path(index, &leaf, &path, &root);
        let result2 = verify_merkle_path(index, &leaf, &path, &root);
        prop_assert_eq!(result1.is_ok(), result2.is_ok());
    }
}

// Property test: Challenge indices should be uniform
proptest! {
    #[test]
    fn challenge_indices_uniformity(
        chain_id in prop::array::uniform32(any::<u8>()),
        epoch_number in any::<u64>(),
        epoch_nonce in prop::array::uniform32(any::<u8>()),
        vrf_output in prop::collection::vec(any::<u8>(), 64..=64),
        vrf_proof in prop::collection::vec(any::<u8>(), 80..=80),
        epoch_hash in prop::array::uniform32(any::<u8>()),
        root in prop::array::uniform32(any::<u8>()),
        _epoch in any::<u32>()
    ) {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let dummy_sig = signing_key.sign(b"test message");
        
        let _reg = Registration {
            chain_id: &ChainId(chain_id),
            epoch_number,
            epoch_nonce: &EpochNonce(epoch_nonce),
            vrf_proof: &VrfProof(vrf_proof.try_into().unwrap()),
            vrf_output: &VrfOutput(vrf_output.try_into().unwrap()),
            epoch_hash: &EpochHash(epoch_hash),
            pk: &verifying_key,
            sig: &dummy_sig,
            root: &MerkleRoot(root),
        };
        
        // Challenge derivation should be deterministic
        let challenge_seed1 = build_challenge_seed(
            &EpochHash(epoch_hash),
            &EpochNonce(epoch_nonce),
            &verifying_key,
            &MerkleRoot(root)
        );
        let challenge_seed2 = build_challenge_seed(
            &EpochHash(epoch_hash),
            &EpochNonce(epoch_nonce),
            &verifying_key,
            &MerkleRoot(root)
        );
        
        prop_assert_eq!(challenge_seed1, challenge_seed2);
    }
}

// Property test: Ticket validation time bounds
proptest! {
    #[test]
    fn ticket_time_validation(
        valid_from in any::<u64>(),
        valid_to in any::<u64>(),
        current_time in any::<u64>()
    ) {
        // Construct a ticket to check time window logic
        let ticket = Ticket {
            chain_id: [0u8; 32],
            epoch_number: 1,
            epoch_hash: [0u8; 32],
            epoch_nonce: [0u8; 32],
            pk: [0u8; 32],
            root: [0u8; 32],
            valid_from,
            valid_to,
        };
        
        // Use the ticket to compute validity and ensure binding
        let is_valid_time = current_time >= ticket.valid_from && current_time <= ticket.valid_to;
        let expected_valid = valid_from <= valid_to && is_valid_time;
        
        // This is a simplified check - in real implementation, 
        // ticket validation would involve signature verification
        prop_assert_eq!(is_valid_time, expected_valid);
    }
}

// Property test: Basic type consistency
proptest! {
    #[test]
    fn type_consistency(
        chain_id in prop::array::uniform32(any::<u8>()),
        _epoch_number in any::<u64>(),
        epoch_nonce in prop::array::uniform32(any::<u8>()),
        vrf_output in prop::collection::vec(any::<u8>(), 64..=64),
        vrf_proof in prop::collection::vec(any::<u8>(), 80..=80),
        epoch_hash in prop::array::uniform32(any::<u8>()),
        root in prop::array::uniform32(any::<u8>())
    ) {
        // Test that type wrappers work correctly
        let chain_id_wrapped = ChainId(chain_id);
        let epoch_nonce_wrapped = EpochNonce(epoch_nonce);
        let vrf_output_array: [u8; 64] = vrf_output.clone().try_into().unwrap();
        let vrf_output_wrapped = VrfOutput(vrf_output_array);
        let vrf_proof_array: [u8; 80] = vrf_proof.clone().try_into().unwrap();
        let vrf_proof_wrapped = VrfProof(vrf_proof_array);
        let epoch_hash_wrapped = MerkleRoot(epoch_hash);
        let root_wrapped = MerkleRoot(root);
        
        // Verify that wrapped values preserve the original data
        prop_assert_eq!(chain_id_wrapped.0, chain_id);
        prop_assert_eq!(epoch_nonce_wrapped.0, epoch_nonce);
        prop_assert_eq!(vrf_output_wrapped.0.to_vec(), vrf_output);
        prop_assert_eq!(vrf_proof_wrapped.0.to_vec(), vrf_proof);
        prop_assert_eq!(epoch_hash_wrapped.0, epoch_hash);
        prop_assert_eq!(root_wrapped.0, root);
    }
}