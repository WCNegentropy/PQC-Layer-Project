//! ChaCha20-Poly1305 AEAD wrapper for Aegis transport encryption.
//!
//! Provides authenticated encryption with associated data (AEAD) using
//! ChaCha20-Poly1305 (RFC 8439). This is used for encrypting tunnel transport
//! packets after key exchange.
//!
//! # Security Properties
//!
//! - 256-bit key, 96-bit nonce, 128-bit authentication tag.
//! - Encrypt-then-MAC construction (inherent to AEAD).
//! - Nonces must never be reused with the same key.

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use zeroize::Zeroizing;

use crate::CryptoError;

/// Size of a ChaCha20-Poly1305 key in bytes (256 bits).
pub const AEAD_KEY_SIZE: usize = 32;
/// Size of a ChaCha20-Poly1305 nonce in bytes (96 bits).
pub const AEAD_NONCE_SIZE: usize = 12;
/// Size of the Poly1305 authentication tag in bytes (128 bits).
pub const AEAD_TAG_SIZE: usize = 16;

/// AEAD cipher wrapper providing encrypt/decrypt with zeroizing key management.
pub struct AeadCipher {
    cipher: ChaCha20Poly1305,
}

impl AeadCipher {
    /// Create a new AEAD cipher from a 32-byte key.
    pub fn new(key: &[u8; AEAD_KEY_SIZE]) -> Self {
        let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
        Self { cipher }
    }

    /// Encrypt plaintext with the given nonce and optional associated data.
    ///
    /// Returns ciphertext with the 16-byte authentication tag appended.
    /// The nonce MUST be unique for every encryption under the same key.
    pub fn encrypt(
        &self,
        nonce: &[u8; AEAD_NONCE_SIZE],
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        use chacha20poly1305::aead::Payload;
        let payload = Payload {
            msg: plaintext,
            aad,
        };
        self.cipher
            .encrypt(Nonce::from_slice(nonce), payload)
            .map_err(|_| CryptoError::AeadError)
    }

    /// Decrypt ciphertext (with appended tag) using the given nonce and AAD.
    ///
    /// Returns the decrypted plaintext, or an error if authentication fails.
    pub fn decrypt(
        &self,
        nonce: &[u8; AEAD_NONCE_SIZE],
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        use chacha20poly1305::aead::Payload;
        let payload = Payload {
            msg: ciphertext,
            aad,
        };
        self.cipher
            .decrypt(Nonce::from_slice(nonce), payload)
            .map(Zeroizing::new)
            .map_err(|_| CryptoError::AeadError)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = [0x42u8; AEAD_KEY_SIZE];
        let nonce = [0x01u8; AEAD_NONCE_SIZE];
        let plaintext = b"Hello, post-quantum world!";
        let aad = b"aegis-transport-v1";

        let cipher = AeadCipher::new(&key);
        let ciphertext = cipher.encrypt(&nonce, plaintext, aad).unwrap();

        // Ciphertext should be plaintext + 16-byte tag
        assert_eq!(ciphertext.len(), plaintext.len() + AEAD_TAG_SIZE);

        let decrypted = cipher.decrypt(&nonce, &ciphertext, aad).unwrap();
        assert_eq!(decrypted.as_slice(), plaintext);
    }

    #[test]
    fn wrong_key_fails() {
        let key1 = [0x42u8; AEAD_KEY_SIZE];
        let key2 = [0x43u8; AEAD_KEY_SIZE];
        let nonce = [0x01u8; AEAD_NONCE_SIZE];
        let plaintext = b"secret data";

        let cipher1 = AeadCipher::new(&key1);
        let cipher2 = AeadCipher::new(&key2);

        let ciphertext = cipher1.encrypt(&nonce, plaintext, b"").unwrap();
        assert!(cipher2.decrypt(&nonce, &ciphertext, b"").is_err());
    }

    #[test]
    fn wrong_nonce_fails() {
        let key = [0x42u8; AEAD_KEY_SIZE];
        let nonce1 = [0x01u8; AEAD_NONCE_SIZE];
        let nonce2 = [0x02u8; AEAD_NONCE_SIZE];
        let plaintext = b"secret data";

        let cipher = AeadCipher::new(&key);
        let ciphertext = cipher.encrypt(&nonce1, plaintext, b"").unwrap();
        assert!(cipher.decrypt(&nonce2, &ciphertext, b"").is_err());
    }

    #[test]
    fn wrong_aad_fails() {
        let key = [0x42u8; AEAD_KEY_SIZE];
        let nonce = [0x01u8; AEAD_NONCE_SIZE];
        let plaintext = b"secret data";

        let cipher = AeadCipher::new(&key);
        let ciphertext = cipher.encrypt(&nonce, plaintext, b"correct-aad").unwrap();
        assert!(cipher.decrypt(&nonce, &ciphertext, b"wrong-aad").is_err());
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let key = [0x42u8; AEAD_KEY_SIZE];
        let nonce = [0x01u8; AEAD_NONCE_SIZE];
        let plaintext = b"secret data";

        let cipher = AeadCipher::new(&key);
        let mut ciphertext = cipher.encrypt(&nonce, plaintext, b"").unwrap();

        // Flip a bit in the ciphertext
        ciphertext[0] ^= 0x01;
        assert!(cipher.decrypt(&nonce, &ciphertext, b"").is_err());
    }

    #[test]
    fn empty_plaintext() {
        let key = [0x42u8; AEAD_KEY_SIZE];
        let nonce = [0x01u8; AEAD_NONCE_SIZE];

        let cipher = AeadCipher::new(&key);
        let ciphertext = cipher.encrypt(&nonce, b"", b"header").unwrap();
        assert_eq!(ciphertext.len(), AEAD_TAG_SIZE); // tag only

        let decrypted = cipher.decrypt(&nonce, &ciphertext, b"header").unwrap();
        assert!(decrypted.is_empty());
    }
}
