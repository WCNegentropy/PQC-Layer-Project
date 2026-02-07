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
