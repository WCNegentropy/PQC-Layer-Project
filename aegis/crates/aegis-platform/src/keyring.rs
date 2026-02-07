//! Secure credential and key storage abstraction.
//!
//! Defines the [`Keyring`] trait for storing and retrieving secrets
//! using the OS-native credential manager or hardware security modules.
//!
//! # Planned Backends
//!
//! | Platform | Backend           | Status  |
//! |----------|-------------------|---------|
//! | Linux    | libsecret / DBUS  | Planned |
//! | macOS    | Keychain Services | Planned |
//! | Windows  | Credential Manager| Planned |
//! | Hardware | TPM 2.0 / HSM     | Planned |

use crate::PlatformError;

/// Trait for secure credential storage.
///
/// Implementations store secrets in platform-native keyrings or
/// hardware security modules, never in plaintext files.
pub trait Keyring: Send + Sync {
    /// Store a secret under the given service/account identifiers.
    fn store(&self, service: &str, account: &str, secret: &[u8]) -> Result<(), PlatformError>;

    /// Retrieve a previously stored secret.
    fn retrieve(&self, service: &str, account: &str) -> Result<Vec<u8>, PlatformError>;

    /// Delete a stored secret.
    fn delete(&self, service: &str, account: &str) -> Result<(), PlatformError>;

    /// Check if a secret exists for the given service/account.
    fn exists(&self, service: &str, account: &str) -> Result<bool, PlatformError>;
}

/// In-memory keyring for testing. Secrets are NOT persisted.
#[cfg(test)]
pub struct MemoryKeyring {
    store: std::sync::Mutex<std::collections::HashMap<(String, String), Vec<u8>>>,
}

#[cfg(test)]
impl MemoryKeyring {
    pub fn new() -> Self {
        Self {
            store: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }
}

#[cfg(test)]
impl Keyring for MemoryKeyring {
    fn store(&self, service: &str, account: &str, secret: &[u8]) -> Result<(), PlatformError> {
        self.store
            .lock()
            .unwrap()
            .insert((service.to_string(), account.to_string()), secret.to_vec());
        Ok(())
    }

    fn retrieve(&self, service: &str, account: &str) -> Result<Vec<u8>, PlatformError> {
        self.store
            .lock()
            .unwrap()
            .get(&(service.to_string(), account.to_string()))
            .cloned()
            .ok_or_else(|| PlatformError::KeyringError("not found".into()))
    }

    fn delete(&self, service: &str, account: &str) -> Result<(), PlatformError> {
        self.store
            .lock()
            .unwrap()
            .remove(&(service.to_string(), account.to_string()));
        Ok(())
    }

    fn exists(&self, service: &str, account: &str) -> Result<bool, PlatformError> {
        Ok(self
            .store
            .lock()
            .unwrap()
            .contains_key(&(service.to_string(), account.to_string())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_keyring_store_retrieve() {
        let kr = MemoryKeyring::new();
        kr.store("aegis", "master-key", b"secret123").unwrap();
        let secret = kr.retrieve("aegis", "master-key").unwrap();
        assert_eq!(secret, b"secret123");
    }

    #[test]
    fn memory_keyring_not_found() {
        let kr = MemoryKeyring::new();
        assert!(kr.retrieve("aegis", "nonexistent").is_err());
    }

    #[test]
    fn memory_keyring_delete() {
        let kr = MemoryKeyring::new();
        kr.store("aegis", "key", b"val").unwrap();
        assert!(kr.exists("aegis", "key").unwrap());
        kr.delete("aegis", "key").unwrap();
        assert!(!kr.exists("aegis", "key").unwrap());
    }
}
