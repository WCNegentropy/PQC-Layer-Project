//! Fuzz target for ML-DSA-65 signature verification.
//!
//! Feeds arbitrary signatures and public key bytes to the verifier.
//! Must never panic; should return Err on invalid inputs.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Split fuzz input: first half as "signature", second half as "public key"
    if data.len() < 2 {
        return;
    }
    let mid = data.len() / 2;
    let sig_bytes = &data[..mid];
    let pk_bytes = &data[mid..];

    // Try to parse public key — must not panic
    if let Ok(pk) = aegis_crypto::SigningPublicKey::from_bytes(pk_bytes) {
        // Try to verify with arbitrary signature — must not panic
        let _ = pk.verify(b"fuzz message", sig_bytes);
    }
});
