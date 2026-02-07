//! Authentication challenges and responses.
//!
//! Implements challenge-response authentication using ML-DSA-65 signatures.
//! The server sends a random challenge; the client signs it with their
//! device key to prove identity.
//!
//! # Planned API
//!
//! ```rust,ignore
//! // Server side
//! let challenge = AuthChallenge::generate();
//! let challenge_bytes = challenge.to_bytes();
//!
//! // Client side
//! let response = AuthResponse::sign(&challenge_bytes, &device_keypair)?;
//!
//! // Server verifies
//! challenge.verify(&response, &client_public_key)?;
//! ```
