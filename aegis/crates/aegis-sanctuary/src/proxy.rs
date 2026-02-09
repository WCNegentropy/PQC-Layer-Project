//! NAT proxy for forwarding decrypted tunnel traffic.
//!
//! After PQ-WG decryption, plaintext IP packets are forwarded through
//! a NAT (Network Address Translation) gateway to the public internet.
//! Responses are routed back through the tunnel.
//!
//! # v0 Status: Stub
//!
//! In v0, the sanctuary server uses a simple echo-back mechanism for
//! demonstration purposes. Future versions will implement:
//!
//! - Stateful NAT with connection tracking.
//! - Per-client bandwidth accounting.
//! - Configurable DNS resolver (to prevent DNS leaks).
//! - Rate limiting and abuse prevention.
//! - TUN device integration for actual IP forwarding.

/// NAT proxy stub for v0.
///
/// This is a placeholder for future NAT functionality. In v0, the server
/// simply echoes packets back to demonstrate bidirectional tunnel operation.
pub struct NatProxy;

impl NatProxy {
    /// Create a new NAT proxy (stub).
    pub fn new() -> Self {
        Self
    }

    /// Forward a decrypted IP packet to the internet (stub).
    ///
    /// In v0, this is a no-op. Future versions will:
    /// 1. Parse the IP packet to extract dst IP/port
    /// 2. Create/lookup a NAT mapping for the client
    /// 3. Forward the packet via a TUN device or raw socket
    /// 4. Track return traffic and route it back through the tunnel
    pub fn forward(&self, _plaintext: &[u8]) -> Result<(), crate::SanctuaryError> {
        // Stub: no-op for v0
        Ok(())
    }
}

impl Default for NatProxy {
    fn default() -> Self {
        Self::new()
    }
}
