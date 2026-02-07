//! Server configuration and peer management.
//!
//! Handles loading server configuration from files (TOML) and managing
//! the list of authorized peers (public keys, allowed IPs, etc.).
//!
//! # Planned Config Format
//!
//! ```toml,ignore
//! [server]
//! listen_addr = "0.0.0.0:51820"
//! private_key_file = "/etc/aegis/server.key"
//!
//! [[peers]]
//! public_key = "base64-encoded-hybrid-pk"
//! allowed_ips = ["10.0.0.2/32"]
//! ```
