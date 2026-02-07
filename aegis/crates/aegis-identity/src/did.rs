//! Decentralized Identifiers (DIDs).
//!
//! Implements `did:aegis` method for self-sovereign identity.
//! DIDs are derived from the user's root public key and can be
//! resolved without a central authority.
//!
//! # Planned API
//!
//! ```rust,ignore
//! let did = Did::from_public_key(&root_pk);
//! // did:aegis:z6Mk...
//! let document = did.resolve()?;
//! ```
