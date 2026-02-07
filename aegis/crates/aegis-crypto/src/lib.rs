//! Aegis Crypto Engine (Layer 2)
//!
//! Post-quantum cryptographic primitives for Project Aegis:
//!
//! - **KEM** (`kem`): Hybrid X25519 + ML-KEM-768 key encapsulation.
//! - **AEAD** (`aead`): ChaCha20-Poly1305 authenticated encryption.
//! - **Signatures** (`sign`): ML-DSA-65 post-quantum digital signatures.
//!
//! # Security Properties
//!
//! - If EITHER X25519 OR ML-KEM is secure, the combined KEM secret is secure.
//! - Transcript binding (salt) prevents cross-protocol replay attacks.
//! - All intermediate key material is zeroized after use via `Zeroizing<Vec<u8>>`.
//! - ML-KEM uses implicit rejection (no error on bad ciphertext — AEAD catches mismatch).

use thiserror::Error;

pub mod aead;
pub mod kem;
pub mod sign;

// Re-export primary types for convenience
pub use aead::{AeadCipher, AEAD_KEY_SIZE, AEAD_NONCE_SIZE, AEAD_TAG_SIZE};
pub use kem::{
    AegisCrypto, EncapsulationResult, HybridCiphertext, HybridPublicKey, HybridSecretKey,
    HYBRID_CT_SIZE, HYBRID_PK_SIZE,
};
pub use sign::{SigningKeypair, SigningPublicKey};

/// Errors that can occur during cryptographic operations.
#[derive(Debug, Error)]
pub enum CryptoError {
    /// Input data has an invalid length for the expected type.
    #[error("invalid length: expected {expected}, got {got}")]
    InvalidLength { expected: usize, got: usize },

    /// HKDF expansion failed (should not happen with valid parameters).
    #[error("key derivation failed")]
    KdfError,

    /// AEAD encryption or decryption failed (authentication failure).
    #[error("AEAD encryption/decryption failed")]
    AeadError,

    /// Signature operation failed (invalid signature or key).
    #[error("signature operation failed")]
    SignatureError,
}
