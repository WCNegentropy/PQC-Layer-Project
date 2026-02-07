//! PQ Double Ratchet messaging.
//!
//! Implements a post-quantum variant of the Signal Double Ratchet protocol
//! using ML-KEM-768 for ratchet key exchanges instead of X25519.
//!
//! # Security Properties
//!
//! - Forward secrecy: Compromising current keys doesn't reveal past messages.
//! - Post-compromise security: Protocol self-heals after key compromise.
//! - Quantum resistance: ML-KEM-768 protects against quantum adversaries.
//!
//! # Planned API
//!
//! ```rust,ignore
//! let (session_alice, init_msg) = RatchetSession::initiate(&bob_pk)?;
//! let session_bob = RatchetSession::respond(&bob_sk, &init_msg)?;
//!
//! let ct = session_alice.encrypt(b"hello bob")?;
//! let pt = session_bob.decrypt(&ct)?;
//! ```
