//! Aegis Platform Abstraction Layer (Layer 1)
//!
//! Provides OS-level abstractions for the Aegis stack:
//!
//! - **TUN/TAP** (`tun`): Virtual network interface management.
//! - **Keyring** (`keyring`): Secure credential storage (OS keychain, TPM, HSM).
//! - **Entropy** (`entropy`): Cryptographic random number generation with health checks.
//! - **Filesystem** (`fs`): FUSE filesystem trait for encrypted storage.
//!
//! # Design
//!
//! Each subsystem is defined as a trait, allowing platform-specific implementations
//! to be swapped at compile time via `cfg` attributes or at runtime via trait objects.

pub mod entropy;
pub mod fs;
pub mod keyring;
pub mod tun;

/// Errors from platform operations.
#[derive(Debug, thiserror::Error)]
pub enum PlatformError {
    /// The requested operation is not supported on this platform.
    #[error("unsupported on this platform: {0}")]
    Unsupported(String),

    /// An I/O error from the underlying OS.
    #[error("platform I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Insufficient privileges (e.g., TUN creation requires root).
    #[error("insufficient privileges: {0}")]
    PermissionDenied(String),

    /// Keyring or credential storage error.
    #[error("keyring error: {0}")]
    KeyringError(String),
}

/// Initialize platform-level subsystems.
///
/// Call this once at application startup. Currently a no-op placeholder;
/// future versions will probe hardware capabilities (TPM, HSM) and
/// configure entropy sources.
pub fn init() -> Result<(), PlatformError> {
    // Future: probe TPM/HSM, configure entropy health monitoring
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_succeeds() {
        assert!(init().is_ok());
    }
}
