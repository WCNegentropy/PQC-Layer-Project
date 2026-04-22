//! ML-DSA-65 (FIPS 204) post-quantum digital signature wrapper.
//!
//! Provides key generation, signing, and verification using ML-DSA-65
//! (formerly Dilithium3), the NIST-standardized post-quantum signature scheme.
//!
//! # Security Properties
//!
//! - NIST Security Level 3 (equivalent to AES-192).
//! - Signing key is stored as `Zeroizing<Vec<u8>>` for automatic memory scrubbing.
//! - Uses `pqcrypto-mldsa` (successor to deprecated `pqcrypto-dilithium`).

use pqcrypto_mldsa::mldsa65;
use pqcrypto_traits::sign::{
    DetachedSignature as SignDetachedSignature, PublicKey as SignPublicKey,
    SecretKey as SignSecretKey,
};
use zeroize::Zeroizing;

use crate::CryptoError;

/// A ML-DSA-65 signing keypair.
pub struct SigningKeypair {
    public_key: mldsa65::PublicKey,
    secret_key_bytes: Zeroizing<Vec<u8>>,
}

impl SigningKeypair {
    /// Generate a new ML-DSA-65 signing keypair.
    pub fn generate() -> Self {
        let (pk, sk) = mldsa65::keypair();
        Self {
            public_key: pk,
            secret_key_bytes: Zeroizing::new(sk.as_bytes().to_vec()),
        }
    }

    /// Reconstruct a signing keypair from serialized public and secret key bytes.
    pub fn from_bytes(public_key_bytes: &[u8], secret_key_bytes: &[u8]) -> Result<Self, CryptoError> {
        let public_key =
            mldsa65::PublicKey::from_bytes(public_key_bytes).map_err(|_| CryptoError::SignatureError)?;
        let secret_key =
            mldsa65::SecretKey::from_bytes(secret_key_bytes).map_err(|_| CryptoError::SignatureError)?;
        Ok(Self {
            public_key,
            secret_key_bytes: Zeroizing::new(secret_key.as_bytes().to_vec()),
        })
    }

    /// Get the public key bytes.
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.public_key.as_bytes().to_vec()
    }

    /// Get a zeroizing copy of the secret key bytes.
    pub fn secret_key_bytes(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(self.secret_key_bytes.to_vec())
    }

    /// Sign a message, returning the detached signature bytes.
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let sk = mldsa65::SecretKey::from_bytes(&self.secret_key_bytes)
            .map_err(|_| CryptoError::SignatureError)?;
        let sig = mldsa65::detached_sign(message, &sk);
        Ok(sig.as_bytes().to_vec())
    }
}

/// A ML-DSA-65 public verification key.
pub struct SigningPublicKey {
    inner: mldsa65::PublicKey,
}

impl SigningPublicKey {
    /// Deserialize a public key from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        let inner =
            mldsa65::PublicKey::from_bytes(bytes).map_err(|_| CryptoError::SignatureError)?;
        Ok(Self { inner })
    }

    /// Serialize the public key to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.as_bytes().to_vec()
    }

    /// Verify a detached signature on a message.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), CryptoError> {
        let sig = mldsa65::DetachedSignature::from_bytes(signature)
            .map_err(|_| CryptoError::SignatureError)?;
        mldsa65::verify_detached_signature(&sig, message, &self.inner)
            .map_err(|_| CryptoError::SignatureError)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify_roundtrip() {
        let keypair = SigningKeypair::generate();
        let message = b"Authenticate this handshake";

        let signature = keypair.sign(message).unwrap();

        let pk = SigningPublicKey::from_bytes(&keypair.public_key_bytes()).unwrap();
        pk.verify(message, &signature).unwrap();
    }

    #[test]
    fn wrong_message_fails() {
        let keypair = SigningKeypair::generate();
        let signature = keypair.sign(b"correct message").unwrap();

        let pk = SigningPublicKey::from_bytes(&keypair.public_key_bytes()).unwrap();
        assert!(pk.verify(b"wrong message", &signature).is_err());
    }

    #[test]
    fn wrong_key_fails() {
        let keypair1 = SigningKeypair::generate();
        let keypair2 = SigningKeypair::generate();

        let signature = keypair1.sign(b"test message").unwrap();

        let pk2 = SigningPublicKey::from_bytes(&keypair2.public_key_bytes()).unwrap();
        assert!(pk2.verify(b"test message", &signature).is_err());
    }

    #[test]
    fn tampered_signature_fails() {
        let keypair = SigningKeypair::generate();
        let message = b"test message";
        let mut signature = keypair.sign(message).unwrap();

        // Flip a bit
        signature[0] ^= 0x01;

        let pk = SigningPublicKey::from_bytes(&keypair.public_key_bytes()).unwrap();
        assert!(pk.verify(message, &signature).is_err());
    }

    #[test]
    fn public_key_serialization() {
        let keypair = SigningKeypair::generate();
        let pk_bytes = keypair.public_key_bytes();
        let pk = SigningPublicKey::from_bytes(&pk_bytes).unwrap();
        assert_eq!(pk.to_bytes(), pk_bytes);
    }

    #[test]
    fn keypair_reconstruction_from_bytes() {
        let keypair = SigningKeypair::generate();
        let restored = SigningKeypair::from_bytes(
            &keypair.public_key_bytes(),
            &keypair.secret_key_bytes(),
        )
        .unwrap();

        let message = b"restored signing keypair";
        let signature = restored.sign(message).unwrap();
        let public_key = SigningPublicKey::from_bytes(&restored.public_key_bytes()).unwrap();
        public_key.verify(message, &signature).unwrap();
    }
}
