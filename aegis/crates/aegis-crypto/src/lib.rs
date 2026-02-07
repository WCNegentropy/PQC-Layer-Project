//! Aegis Crypto Library
//!
//! This crate provides cryptographic primitives and utilities for the Aegis platform.
//! It includes post-quantum cryptography implementations for secure data protection.

/// Main library entry point
pub fn init() {
    println!("Aegis Crypto initialized");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_init() {
        init();
    }
}
