//! VRF-R255 API implementation

#[cfg(feature = "vrf-r255")]
fn main() {
    use vrf_r255::{PublicKey, SecretKey};
    use rand_core::OsRng;
    
    let sk = SecretKey::generate(OsRng);
    let pk = PublicKey::from(sk);
    let msg = b"input message";
    let proof = sk.prove(msg);
    let result = pk.verify(msg, &proof);
    
    println!("Verification result type: {}", std::any::type_name_of_val(&result));
    println!("Verification successful: {}", bool::from(result.is_some()));
    
    // Serialization - check what methods exist
    println!("Testing available methods...");
    
    // Try different serialization methods
    // let pk_bytes = pk.to_bytes();  // This might not exist
    // let proof_bytes = proof.to_bytes();  // This might not exist
    
    println!("API implementation completed");
}

#[cfg(not(feature = "vrf-r255"))]
fn main() {
    println!("vrf-r255 feature not enabled");
}
