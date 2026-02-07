//! Encrypted object storage backend.
//!
//! Provides per-file encryption using ChaCha20-Poly1305 with keys
//! derived from the vault master key via HKDF.
//!
//! # Planned API
//!
//! ```rust,ignore
//! let vault = VaultStore::open("/path/to/vault", &master_key)?;
//! vault.write("documents/secret.txt", plaintext)?;
//! let data = vault.read("documents/secret.txt")?;
//! ```
