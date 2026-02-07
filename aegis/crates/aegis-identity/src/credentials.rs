//! Verifiable Credentials (VCs).
//!
//! Issue, hold, and verify W3C Verifiable Credentials signed with
//! ML-DSA-65 post-quantum signatures.
//!
//! # Planned API
//!
//! ```rust,ignore
//! let vc = Credential::builder()
//!     .issuer(&issuer_did)
//!     .subject(&subject_did)
//!     .claim("role", "admin")
//!     .sign(&issuer_keypair)?;
//!
//! vc.verify(&issuer_public_key)?;
//! ```
