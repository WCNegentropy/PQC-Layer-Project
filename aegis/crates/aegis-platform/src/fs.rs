//! Encrypted filesystem abstraction.
//!
//! Defines the [`EncryptedFs`] trait for implementing FUSE-based encrypted
//! filesystems. The vault crate will use this to provide per-file encryption
//! with AEAD and key hierarchy management.
//!
//! # Planned Features
//!
//! - Per-file encryption keys derived from a master key via HKDF.
//! - FUSE mount for transparent encryption/decryption.
//! - CRDT-based sync metadata for conflict-free multi-device sync.

use crate::PlatformError;

/// Metadata for an encrypted file entry.
#[derive(Debug, Clone)]
pub struct FileEntry {
    /// Relative path within the vault.
    pub path: String,
    /// File size in bytes (plaintext).
    pub size: u64,
    /// Whether this entry is a directory.
    pub is_dir: bool,
    /// Last modification timestamp (Unix epoch seconds).
    pub modified: u64,
}

/// Trait for an encrypted filesystem backend.
///
/// Implementations provide encrypted storage with per-file keys.
/// The FUSE layer will delegate to this trait for all file operations.
pub trait EncryptedFs: Send + Sync {
    /// Read an encrypted file, returning decrypted plaintext.
    fn read_file(&self, path: &str) -> Result<Vec<u8>, PlatformError>;

    /// Write plaintext data, encrypting it in storage.
    fn write_file(&self, path: &str, data: &[u8]) -> Result<(), PlatformError>;

    /// Delete a file from encrypted storage.
    fn delete_file(&self, path: &str) -> Result<(), PlatformError>;

    /// List entries in a directory.
    fn list_dir(&self, path: &str) -> Result<Vec<FileEntry>, PlatformError>;

    /// Check if a path exists.
    fn exists(&self, path: &str) -> Result<bool, PlatformError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_entry_creation() {
        let entry = FileEntry {
            path: "documents/secret.txt".to_string(),
            size: 1024,
            is_dir: false,
            modified: 1700000000,
        };
        assert_eq!(entry.path, "documents/secret.txt");
        assert!(!entry.is_dir);
    }
}
