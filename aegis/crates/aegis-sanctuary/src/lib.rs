//! Aegis Sanctuary Node (Server)
//!
//! The Sanctuary is a PQ-WireGuard termination server that provides:
//!
//! - **Server** (`server`): PQ-WG listener accepting client tunnels.
//! - **Proxy** (`proxy`): NAT proxy forwarding decrypted traffic to the internet.
//! - **Config** (`config`): Server configuration and peer management.
//!
//! # Deployment
//!
//! Designed to run in Docker containers or bare-metal servers.
//! Each Sanctuary node terminates PQ-WG tunnels from Aegis clients
//! and forwards their traffic through a NAT proxy, providing IP privacy.
//!
//! ```text
//! Client ──PQ-WG──▶ Sanctuary ──NAT──▶ Internet
//! ```

pub mod config;
pub mod proxy;
pub mod server;

/// Errors from sanctuary operations.
#[derive(Debug, thiserror::Error)]
pub enum SanctuaryError {
    /// Failed to bind or listen on the server address.
    #[error("server bind error: {0}")]
    BindError(String),

    /// Handshake failed with a client.
    #[error("handshake failed: {0}")]
    HandshakeFailed(String),

    /// Peer not authorized (unknown public key, etc.).
    #[error("peer not authorized: {0}")]
    Unauthorized(String),

    /// I/O error during proxy operation.
    #[error("proxy error: {0}")]
    ProxyError(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_display() {
        let err = SanctuaryError::Unauthorized("unknown peer".into());
        assert!(err.to_string().contains("peer not authorized"));
    }
}
