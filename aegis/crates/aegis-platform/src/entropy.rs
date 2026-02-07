//! Cryptographic entropy source abstraction.
//!
//! Provides a trait for obtaining cryptographically secure random bytes,
//! with optional health monitoring (e.g., detecting entropy starvation).
//!
//! The default implementation delegates to the OS CSPRNG via `getrandom`.
//! Future implementations may blend hardware RNG (RDRAND, TPM) with
//! OS entropy for defense-in-depth.

use crate::PlatformError;

/// Trait for a cryptographic entropy source.
pub trait EntropySource: Send + Sync {
    /// Fill `buf` with cryptographically secure random bytes.
    fn fill_bytes(&self, buf: &mut [u8]) -> Result<(), PlatformError>;

    /// Generate `n` random bytes.
    fn random_bytes(&self, n: usize) -> Result<Vec<u8>, PlatformError> {
        let mut buf = vec![0u8; n];
        self.fill_bytes(&mut buf)?;
        Ok(buf)
    }
}

/// OS-native entropy source (delegates to `getrandom`).
pub struct OsEntropy;

impl EntropySource for OsEntropy {
    fn fill_bytes(&self, buf: &mut [u8]) -> Result<(), PlatformError> {
        getrandom::getrandom(buf).map_err(|e| {
            PlatformError::Io(std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn os_entropy_fills_buffer() {
        let entropy = OsEntropy;
        let bytes = entropy.random_bytes(32).unwrap();
        assert_eq!(bytes.len(), 32);
        // Extremely unlikely to be all zeros
        assert_ne!(bytes, vec![0u8; 32]);
    }

    #[test]
    fn os_entropy_different_each_time() {
        let entropy = OsEntropy;
        let a = entropy.random_bytes(32).unwrap();
        let b = entropy.random_bytes(32).unwrap();
        assert_ne!(a, b);
    }
}
