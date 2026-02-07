//! Key hierarchy management.
//!
//! Implements the Aegis key derivation tree:
//!
//! ```text
//! Root Key (ML-DSA-65 + Ed25519)
//! ├── Device Key (HKDF-derived, per device)
//! │   ├── Session Key (ephemeral, per connection)
//! │   └── Storage Key (for vault encryption)
//! └── Recovery Key (Shamir secret sharing, offline)
//! ```
//!
//! # Planned API
//!
//! ```rust,ignore
//! let root = RootKeypair::generate();
//! let device_key = root.derive_device_key("laptop-01");
//! let session_key = device_key.derive_session_key();
//! ```
