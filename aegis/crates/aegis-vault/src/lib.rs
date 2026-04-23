//! Aegis Data Sovereignty Vault (Layer 5)
//!
//! Provides encrypted data storage with these capabilities:
//!
//! - **Store** (`store`): Encrypted object storage with per-file keys.
//! - **Sync** (`sync`): CRDT-based conflict-free multi-device synchronization.
//! - **Mount** (`mount`): FUSE filesystem for transparent encryption.
//!
//! # Design
//!
//! Each file is encrypted with a unique key derived from a vault master key
//! via HKDF. File metadata is stored in an encrypted SQLite database.
//! Sync uses CRDTs to merge changes without conflicts across devices.

pub mod mount;
pub mod store;
pub mod sync;

/// Errors from vault operations.
#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    /// The vault is locked (master key not available).
    #[error("vault is locked")]
    Locked,

    /// File not found in the vault.
    #[error("file not found: {0}")]
    NotFound(String),

    /// I/O error during vault operation.
    #[error("vault I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Cryptographic error (AEAD decryption failure, etc.).
    #[error("vault crypto error: {0}")]
    CryptoError(String),

    /// Serialization or deserialization error.
    #[error("vault serialization error: {0}")]
    Serialization(String),

    /// Sync conflict that could not be automatically resolved.
    #[error("sync conflict: {0}")]
    SyncConflict(String),

    /// Mount or virtual filesystem error.
    #[error("vault mount error: {0}")]
    Mount(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_display() {
        let err = VaultError::Locked;
        assert_eq!(err.to_string(), "vault is locked");
    }
}
