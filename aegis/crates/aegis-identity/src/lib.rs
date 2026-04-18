//! Aegis Identity Anchor (Layer 4)
//!
//! Manages cryptographic identity for users and devices:
//!
//! - **Key Hierarchy** (`keys`): Root → Device → Session key derivation.
//! - **DID** (`did`): Decentralized Identifiers for self-sovereign identity.
//! - **Credentials** (`credentials`): Verifiable Credentials issuance and verification.
//! - **Auth** (`auth`): Authentication challenges and responses.
//!
//! # Design
//!
//! Identity is anchored to a root keypair (ML-DSA-65 + Ed25519 hybrid).
//! Device keys are derived via HKDF. Session keys are ephemeral.
//! DIDs are self-issued and can be published to a distributed ledger.

pub mod auth;
pub mod credentials;
pub mod did;
pub mod keys;

/// Errors from identity operations.
#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    /// The provided key material is invalid.
    #[error("invalid key material: {0}")]
    InvalidKey(String),

    /// Authentication challenge failed.
    #[error("authentication failed: {0}")]
    AuthFailed(String),

    /// Credential verification failed.
    #[error("credential verification failed: {0}")]
    CredentialInvalid(String),

    /// Cryptographic operation error (delegated from aegis-crypto).
    #[error("crypto error: {0}")]
    CryptoError(String),

    /// Serialization or deserialization error.
    #[error("serialization error: {0}")]
    Serialization(String),
}

impl From<aegis_crypto::CryptoError> for IdentityError {
    fn from(value: aegis_crypto::CryptoError) -> Self {
        Self::CryptoError(value.to_string())
    }
}

pub(crate) fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[allow(clippy::manual_is_multiple_of)]
pub(crate) fn decode_hex(input: &str) -> Result<Vec<u8>, IdentityError> {
    if input.len() % 2 != 0 {
        return Err(IdentityError::InvalidKey(
            "hex input must have even length".into(),
        ));
    }

    input
        .as_bytes()
        .chunks(2)
        .map(|chunk| {
            let value = std::str::from_utf8(chunk)
                .map_err(|_| IdentityError::InvalidKey("invalid UTF-8 in hex data".into()))?;
            u8::from_str_radix(value, 16)
                .map_err(|_| IdentityError::InvalidKey("invalid hex character".into()))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_display() {
        let err = IdentityError::InvalidKey("bad format".into());
        assert!(err.to_string().contains("invalid key material"));
    }
}
