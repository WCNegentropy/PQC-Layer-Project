//! Aegis Social Fabric (Layer 7)
//!
//! Decentralized, quantum-resistant social communication:
//!
//! - **Messaging** (`messaging`): PQ Double Ratchet for 1:1 encrypted messaging.
//! - **Groups** (`groups`): MLS-inspired group key management with PQ KEM.
//! - **Federation** (`federation`): ActivityPub-compatible federation protocol.
//!
//! # Design
//!
//! Messages are end-to-end encrypted using a post-quantum Double Ratchet
//! protocol. Group messaging uses an MLS-like tree structure with hybrid
//! KEM for key updates. Federation enables interoperability with existing
//! ActivityPub networks while adding PQ encryption.

pub mod federation;
pub mod groups;
pub mod messaging;

/// Errors from social operations.
#[derive(Debug, thiserror::Error)]
pub enum SocialError {
    /// The recipient is unknown or unreachable.
    #[error("recipient not found: {0}")]
    RecipientNotFound(String),

    /// Message decryption failed (ratchet state mismatch, etc.).
    #[error("message decryption failed: {0}")]
    DecryptionFailed(String),

    /// Group operation error (member not authorized, etc.).
    #[error("group error: {0}")]
    GroupError(String),

    /// Federation protocol error.
    #[error("federation error: {0}")]
    FederationError(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_display() {
        let err = SocialError::RecipientNotFound("user@example.com".into());
        assert!(err.to_string().contains("recipient not found"));
    }
}
