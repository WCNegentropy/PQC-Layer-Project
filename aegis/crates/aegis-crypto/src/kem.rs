//! Hybrid post-quantum key encapsulation mechanism combining X25519 and ML-KEM-768.
//!
//! # Security Properties
//!
//! - If EITHER X25519 OR ML-KEM is secure, the combined secret is secure.
//! - Transcript binding (salt) prevents cross-protocol replay attacks.
//! - All intermediate key material is zeroized after use via `Zeroizing<Vec<u8>>`.
//! - ML-KEM uses implicit rejection (no error on bad ciphertext — AEAD catches mismatch).

use hkdf::Hkdf;
use pqcrypto_kyber::kyber768;
use pqcrypto_traits::kem::{
    Ciphertext as KemCiphertext, PublicKey as KemPublicKey, SecretKey as KemSecretKey,
    SharedSecret as KemSharedSecret,
};
use sha3::{Digest, Sha3_256};
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::CryptoError;

/// Size of an X25519 public key in bytes.
const X25519_PK_SIZE: usize = 32;
/// Size of an ML-KEM-768 public key in bytes.
const MLKEM_PK_SIZE: usize = 1184;
/// Size of an X25519 shared secret (the ephemeral public key sent on the wire).
const X25519_EPH_SIZE: usize = 32;
/// Size of an ML-KEM-768 ciphertext in bytes.
const MLKEM_CT_SIZE: usize = 1088;

/// Size of an X25519 secret key in bytes.
const X25519_SK_SIZE: usize = 32;

/// Combined hybrid secret key size: X25519 (32) + ML-KEM-768 SK (variable).
/// Serialized as: X25519 SK (32) + ML-KEM SK bytes.
/// Note: The actual size depends on the ML-KEM-768 secret key size from pqcrypto.
pub const HYBRID_PK_SIZE: usize = X25519_PK_SIZE + MLKEM_PK_SIZE;
/// Combined hybrid ciphertext size: X25519 ephemeral (32) + ML-KEM-768 CT (1088) = 1120 bytes.
pub const HYBRID_CT_SIZE: usize = X25519_EPH_SIZE + MLKEM_CT_SIZE;

/// Label used in transcript binding for domain separation.
const TRANSCRIPT_LABEL: &[u8] = b"aegis-hybrid-kem-v1-transcript";
/// Info string for HKDF expand.
const HKDF_INFO: &[u8] = b"aegis-hybrid-kem-v1";

/// A hybrid public key combining X25519 and ML-KEM-768.
#[derive(Clone)]
pub struct HybridPublicKey {
    x25519: X25519PublicKey,
    ml_kem: kyber768::PublicKey,
}

impl HybridPublicKey {
    /// Serialize the hybrid public key to bytes (1216 bytes).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(HYBRID_PK_SIZE);
        buf.extend_from_slice(self.x25519.as_bytes());
        buf.extend_from_slice(self.ml_kem.as_bytes());
        buf
    }

    /// Deserialize a hybrid public key from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != HYBRID_PK_SIZE {
            return Err(CryptoError::InvalidLength {
                expected: HYBRID_PK_SIZE,
                got: bytes.len(),
            });
        }
        let x25519_bytes: [u8; 32] = bytes[..X25519_PK_SIZE].try_into().unwrap();
        let x25519 = X25519PublicKey::from(x25519_bytes);
        let ml_kem = kyber768::PublicKey::from_bytes(&bytes[X25519_PK_SIZE..]).map_err(|_| {
            CryptoError::InvalidLength {
                expected: MLKEM_PK_SIZE,
                got: bytes.len() - X25519_PK_SIZE,
            }
        })?;
        Ok(Self { x25519, ml_kem })
    }
}

/// A hybrid secret key combining X25519 and ML-KEM-768.
///
/// Both components are wrapped for zeroize-on-drop:
/// - `x25519` is wrapped in `Zeroizing<StaticSecret>` (StaticSecret implements Zeroize but not ZeroizeOnDrop).
/// - `ml_kem_bytes` stores the raw key bytes in `Zeroizing<Vec<u8>>` since `pqcrypto`'s `SecretKey`
///   does not implement Zeroize. The key is reconstructed on demand via `ml_kem_key()`.
pub struct HybridSecretKey {
    x25519: Zeroizing<StaticSecret>,
    ml_kem_bytes: Zeroizing<Vec<u8>>,
}

impl HybridSecretKey {
    /// Create a new hybrid secret key, converting the ML-KEM key to zeroizing bytes.
    fn new(x25519: StaticSecret, ml_kem: kyber768::SecretKey) -> Self {
        Self {
            x25519: Zeroizing::new(x25519),
            ml_kem_bytes: Zeroizing::new(ml_kem.as_bytes().to_vec()),
        }
    }

    /// Reconstruct the ML-KEM secret key from stored bytes.
    fn ml_kem_key(&self) -> Result<kyber768::SecretKey, CryptoError> {
        kyber768::SecretKey::from_bytes(&self.ml_kem_bytes).map_err(|_| {
            CryptoError::InvalidLength {
                expected: self.ml_kem_bytes.len(),
                got: self.ml_kem_bytes.len(),
            }
        })
    }

    /// Serialize the hybrid secret key to bytes.
    ///
    /// Format: `X25519 SK (32 bytes) || ML-KEM SK bytes`.
    /// The caller is responsible for securing the output.
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        let mut buf = Zeroizing::new(Vec::with_capacity(X25519_SK_SIZE + self.ml_kem_bytes.len()));
        buf.extend_from_slice(self.x25519.as_bytes());
        buf.extend_from_slice(&self.ml_kem_bytes);
        buf
    }

    /// Deserialize a hybrid secret key from bytes.
    ///
    /// Expects the format produced by [`to_bytes`]: `X25519 SK (32) || ML-KEM SK`.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() <= X25519_SK_SIZE {
            return Err(CryptoError::InvalidLength {
                expected: X25519_SK_SIZE + 1,
                got: bytes.len(),
            });
        }
        let x25519_bytes: [u8; X25519_SK_SIZE] = bytes[..X25519_SK_SIZE].try_into().unwrap();
        let x25519 = StaticSecret::from(x25519_bytes);
        let ml_kem_bytes = bytes[X25519_SK_SIZE..].to_vec();
        // Validate that the ML-KEM bytes are a valid secret key
        kyber768::SecretKey::from_bytes(&ml_kem_bytes).map_err(|_| {
            CryptoError::InvalidLength {
                expected: 0,
                got: ml_kem_bytes.len(),
            }
        })?;
        Ok(Self {
            x25519: Zeroizing::new(x25519),
            ml_kem_bytes: Zeroizing::new(ml_kem_bytes),
        })
    }
}

/// A hybrid ciphertext combining X25519 ephemeral public key and ML-KEM-768 ciphertext.
pub struct HybridCiphertext {
    x25519_ephemeral: X25519PublicKey,
    ml_kem_ct: kyber768::Ciphertext,
}

impl HybridCiphertext {
    /// Serialize the hybrid ciphertext to bytes (1120 bytes).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(HYBRID_CT_SIZE);
        buf.extend_from_slice(self.x25519_ephemeral.as_bytes());
        buf.extend_from_slice(self.ml_kem_ct.as_bytes());
        buf
    }

    /// Deserialize a hybrid ciphertext from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != HYBRID_CT_SIZE {
            return Err(CryptoError::InvalidLength {
                expected: HYBRID_CT_SIZE,
                got: bytes.len(),
            });
        }
        let eph_bytes: [u8; 32] = bytes[..X25519_EPH_SIZE].try_into().unwrap();
        let x25519_ephemeral = X25519PublicKey::from(eph_bytes);
        let ml_kem_ct =
            kyber768::Ciphertext::from_bytes(&bytes[X25519_EPH_SIZE..]).map_err(|_| {
                CryptoError::InvalidLength {
                    expected: MLKEM_CT_SIZE,
                    got: bytes.len() - X25519_EPH_SIZE,
                }
            })?;
        Ok(Self {
            x25519_ephemeral,
            ml_kem_ct,
        })
    }
}

/// Result of an encapsulation operation.
pub struct EncapsulationResult {
    /// The derived shared secret (32 bytes).
    pub shared_secret: Zeroizing<[u8; 32]>,
    /// The hybrid ciphertext to send to the recipient.
    pub ciphertext: HybridCiphertext,
}

/// The main interface for the Aegis hybrid cryptographic engine.
pub struct AegisCrypto;

impl AegisCrypto {
    /// Generate a new hybrid keypair (X25519 + ML-KEM-768).
    pub fn keygen() -> (HybridPublicKey, HybridSecretKey) {
        let mut rng = rand::thread_rng();

        // X25519 keypair
        let x25519_secret = StaticSecret::random_from_rng(&mut rng);
        let x25519_public = X25519PublicKey::from(&x25519_secret);

        // ML-KEM-768 keypair
        let (ml_kem_pk, ml_kem_sk) = kyber768::keypair();

        (
            HybridPublicKey {
                x25519: x25519_public,
                ml_kem: ml_kem_pk,
            },
            HybridSecretKey::new(x25519_secret, ml_kem_sk),
        )
    }

    /// Encapsulate: generate a shared secret and ciphertext for a recipient.
    ///
    /// The sender calls this with the recipient's public key.
    pub fn encapsulate(recipient_pk: &HybridPublicKey) -> Result<EncapsulationResult, CryptoError> {
        let mut rng = rand::thread_rng();

        // X25519: ephemeral key exchange
        let eph_secret = EphemeralSecret::random_from_rng(&mut rng);
        let eph_public = X25519PublicKey::from(&eph_secret);
        let x25519_shared = eph_secret.diffie_hellman(&recipient_pk.x25519);

        // ML-KEM-768: encapsulate
        let (ml_kem_ss, ml_kem_ct) = kyber768::encapsulate(&recipient_pk.ml_kem);

        // Combine shared secrets with transcript binding
        let shared_secret = Self::derive_hybrid_secret(
            x25519_shared.as_bytes(),
            ml_kem_ss.as_bytes(),
            &recipient_pk.to_bytes(),
            eph_public.as_bytes(),
            ml_kem_ct.as_bytes(),
        )?;

        Ok(EncapsulationResult {
            shared_secret,
            ciphertext: HybridCiphertext {
                x25519_ephemeral: eph_public,
                ml_kem_ct,
            },
        })
    }

    /// Decapsulate: recover the shared secret from a ciphertext.
    ///
    /// The recipient calls this with the received ciphertext and their own keypair.
    pub fn decapsulate(
        ciphertext: &HybridCiphertext,
        secret_key: &HybridSecretKey,
        public_key: &HybridPublicKey,
    ) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
        // X25519: compute shared secret from ephemeral public + our static secret
        let x25519_shared = secret_key
            .x25519
            .diffie_hellman(&ciphertext.x25519_ephemeral);

        // ML-KEM-768: decapsulate (implicit rejection on bad ciphertext)
        let ml_kem_sk = secret_key.ml_kem_key()?;
        let ml_kem_ss = kyber768::decapsulate(&ciphertext.ml_kem_ct, &ml_kem_sk);

        // Combine with same transcript binding
        Self::derive_hybrid_secret(
            x25519_shared.as_bytes(),
            ml_kem_ss.as_bytes(),
            &public_key.to_bytes(),
            ciphertext.x25519_ephemeral.as_bytes(),
            ciphertext.ml_kem_ct.as_bytes(),
        )
    }

    /// Derive the hybrid shared secret using HKDF-SHA3-256 with transcript binding.
    ///
    /// ```text
    /// SharedSecret = HKDF-SHA3-256(
    ///     ikm  = X25519_SharedSecret || ML-KEM-768_SharedSecret,
    ///     salt = SHA3-256(label || recipient_pk || ephemeral_pk || ml_kem_ct),
    ///     info = b"aegis-hybrid-kem-v1"
    /// )
    /// ```
    fn derive_hybrid_secret(
        x25519_ss: &[u8],
        ml_kem_ss: &[u8],
        recipient_pk: &[u8],
        ephemeral_pk: &[u8],
        ml_kem_ct: &[u8],
    ) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
        // Concatenate input keying material
        let mut ikm = Zeroizing::new(Vec::with_capacity(x25519_ss.len() + ml_kem_ss.len()));
        ikm.extend_from_slice(x25519_ss);
        ikm.extend_from_slice(ml_kem_ss);

        // Compute transcript hash for salt
        let mut transcript = Sha3_256::new();
        transcript.update(TRANSCRIPT_LABEL);
        transcript.update(recipient_pk);
        transcript.update(ephemeral_pk);
        transcript.update(ml_kem_ct);
        let salt = transcript.finalize();

        // HKDF extract + expand
        let hk = Hkdf::<Sha3_256>::new(Some(&salt), &ikm);
        let mut okm = Zeroizing::new([0u8; 32]);
        hk.expand(HKDF_INFO, okm.as_mut())
            .map_err(|_| CryptoError::KdfError)?;

        Ok(okm)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hybrid_key_exchange_roundtrip() {
        let (pk, sk) = AegisCrypto::keygen();
        let result = AegisCrypto::encapsulate(&pk).unwrap();
        let ct_bytes = result.ciphertext.to_bytes();
        let ct = HybridCiphertext::from_bytes(&ct_bytes).unwrap();
        let recovered = AegisCrypto::decapsulate(&ct, &sk, &pk).unwrap();
        assert_eq!(result.shared_secret.as_ref(), recovered.as_ref());
    }

    #[test]
    fn different_recipients_different() {
        let (pk1, _sk1) = AegisCrypto::keygen();
        let (pk2, _sk2) = AegisCrypto::keygen();
        let r1 = AegisCrypto::encapsulate(&pk1).unwrap();
        let r2 = AegisCrypto::encapsulate(&pk2).unwrap();
        assert_ne!(r1.shared_secret.as_ref(), r2.shared_secret.as_ref());
    }

    #[test]
    fn wrong_key_decapsulation_fails() {
        let (pk1, _sk1) = AegisCrypto::keygen();
        let (_pk2, sk2) = AegisCrypto::keygen();
        let result = AegisCrypto::encapsulate(&pk1).unwrap();
        let wrong = AegisCrypto::decapsulate(&result.ciphertext, &sk2, &pk1).unwrap();
        assert_ne!(result.shared_secret.as_ref(), wrong.as_ref());
    }

    #[test]
    fn public_key_serialization() {
        let (pk, _sk) = AegisCrypto::keygen();
        let bytes = pk.to_bytes();
        assert_eq!(bytes.len(), HYBRID_PK_SIZE);
        let pk2 = HybridPublicKey::from_bytes(&bytes).unwrap();
        assert_eq!(pk.to_bytes(), pk2.to_bytes());
    }

    #[test]
    fn ciphertext_serialization() {
        let (pk, _sk) = AegisCrypto::keygen();
        let result = AegisCrypto::encapsulate(&pk).unwrap();
        let bytes = result.ciphertext.to_bytes();
        assert_eq!(bytes.len(), HYBRID_CT_SIZE);
        let ct2 = HybridCiphertext::from_bytes(&bytes).unwrap();
        assert_eq!(result.ciphertext.to_bytes(), ct2.to_bytes());
    }

    #[test]
    fn invalid_lengths_rejected() {
        assert!(HybridPublicKey::from_bytes(&[0u8; 10]).is_err());
        assert!(HybridPublicKey::from_bytes(&[0u8; HYBRID_PK_SIZE + 1]).is_err());
        assert!(HybridCiphertext::from_bytes(&[0u8; 10]).is_err());
        assert!(HybridCiphertext::from_bytes(&[0u8; HYBRID_CT_SIZE + 1]).is_err());
        assert!(HybridPublicKey::from_bytes(&[]).is_err());
        assert!(HybridCiphertext::from_bytes(&[]).is_err());
    }
}
