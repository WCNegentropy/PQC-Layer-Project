//! NAT proxy for forwarding decrypted tunnel traffic.
//!
//! After PQ-WG decryption, plaintext IP packets are forwarded through
//! a NAT (Network Address Translation) gateway to the public internet.
//! Responses are routed back through the tunnel.
//!
//! # Planned Features
//!
//! - Stateful NAT with connection tracking.
//! - Per-client bandwidth accounting.
//! - Configurable DNS resolver (to prevent DNS leaks).
//! - Rate limiting and abuse prevention.
