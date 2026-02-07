//! Fuzz target for hybrid KEM public key and ciphertext deserialization.
//!
//! Ensures that arbitrary byte inputs to `from_bytes` never panic.
//! Expected behavior: returns Ok or Err, never crashes.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Fuzz public key deserialization — must not panic
    let _ = aegis_crypto::HybridPublicKey::from_bytes(data);

    // Fuzz ciphertext deserialization — must not panic
    let _ = aegis_crypto::HybridCiphertext::from_bytes(data);
});
