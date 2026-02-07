//! Fuzz target for ChaCha20-Poly1305 AEAD decrypt.
//!
//! Feeds arbitrary ciphertext to the decryptor. Must never panic;
//! should return Err(AeadError) on invalid/tampered input.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Use a fixed key and nonce for consistent fuzz state
    let key = [0x42u8; aegis_crypto::AEAD_KEY_SIZE];
    let nonce = [0x01u8; aegis_crypto::AEAD_NONCE_SIZE];

    let cipher = aegis_crypto::AeadCipher::new(&key);

    // Try decrypting arbitrary data — must not panic
    let _ = cipher.decrypt(&nonce, data, b"fuzz-aad");
});
