//! Sanctuary server: PQ-WG listener.
//!
//! Accepts PQ-WireGuard connections from Aegis clients on a UDP port.
//! Each client authenticates via the PQ-WG handshake and receives a
//! tunnel session for encrypted traffic forwarding.
//!
//! # Planned API
//!
//! ```rust,ignore
//! let config = ServerConfig::load("sanctuary.toml")?;
//! let server = SanctuaryServer::bind(&config).await?;
//! server.run().await?;
//! ```
