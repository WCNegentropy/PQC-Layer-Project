//! Server configuration and peer management.
//!
//! Handles loading server configuration from files (TOML) and managing
//! the list of authorized peers (public keys, allowed IPs, etc.).
//!
//! # Config Format
//!
//! ```toml
//! [server]
//! listen_addr = "0.0.0.0:51820"
//! keypair_file = "/etc/aegis/sanctuary.key"
//! log_level = "info"
//!
//! # Optional: directory containing .pub files of authorized client keys
//! # If not specified, all clients are accepted (useful for testing)
//! # authorized_peers_dir = "/etc/aegis/peers"
//! ```

use serde::Deserialize;
use std::collections::HashSet;
use std::fs;
use std::path::Path;

use aegis_crypto::HybridPublicKey;
use crate::SanctuaryError;

/// Server configuration loaded from TOML.
#[derive(Debug, Deserialize, Clone)]
pub struct ServerConfig {
    /// Server settings.
    pub server: ServerSettings,
}

/// Server settings section.
#[derive(Debug, Deserialize, Clone)]
pub struct ServerSettings {
    /// UDP address to listen on (e.g., "0.0.0.0:51820").
    pub listen_addr: String,
    
    /// Path to the server's keypair file.
    pub keypair_file: String,
    
    /// Log level (e.g., "info", "debug", "warn").
    #[serde(default = "default_log_level")]
    pub log_level: String,
    
    /// Optional directory containing authorized peer public keys.
    /// Each .pub file in this directory is treated as an authorized peer.
    /// If not specified, all peers are accepted (open mode for testing).
    pub authorized_peers_dir: Option<String>,
}

fn default_log_level() -> String {
    "info".to_string()
}

impl ServerConfig {
    /// Load server configuration from a TOML file.
    pub fn load(path: &str) -> Result<Self, SanctuaryError> {
        let content = fs::read_to_string(path)
            .map_err(|e| SanctuaryError::BindError(format!("Failed to read config file '{}': {}", path, e)))?;
        
        toml::from_str(&content)
            .map_err(|e| SanctuaryError::BindError(format!("Failed to parse config file '{}': {}", path, e)))
    }
    
    /// Load authorized peer public keys from the configured directory.
    ///
    /// Returns a set of serialized public keys. If no directory is configured,
    /// returns an empty set (meaning all peers are accepted in open mode).
    pub fn load_authorized_peers(&self) -> Result<HashSet<Vec<u8>>, SanctuaryError> {
        let Some(ref dir) = self.server.authorized_peers_dir else {
            // No directory configured → open mode (accept all peers)
            return Ok(HashSet::new());
        };
        
        let dir_path = Path::new(dir);
        if !dir_path.is_dir() {
            return Err(SanctuaryError::BindError(format!(
                "Authorized peers directory '{}' does not exist or is not a directory",
                dir
            )));
        }
        
        let mut peers = HashSet::new();
        
        for entry in fs::read_dir(dir_path)
            .map_err(|e| SanctuaryError::BindError(format!("Failed to read authorized peers directory '{}': {}", dir, e)))?
        {
            let entry = entry.map_err(|e| SanctuaryError::BindError(format!("Failed to read directory entry: {}", e)))?;
            let path = entry.path();
            
            // Only process .pub files
            if path.extension().and_then(|s| s.to_str()) == Some("pub") {
                match fs::read(&path) {
                    Ok(bytes) => {
                        // Validate it's a valid public key
                        match HybridPublicKey::from_bytes(&bytes) {
                            Ok(_) => {
                                peers.insert(bytes);
                            }
                            Err(e) => {
                                tracing::warn!("Skipping invalid public key file {:?}: {}", path, e);
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!("Failed to read public key file {:?}: {}", path, e);
                    }
                }
            }
        }
        
        Ok(peers)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    
    #[test]
    fn parse_basic_config() {
        let toml = r#"
[server]
listen_addr = "0.0.0.0:51820"
keypair_file = "/etc/aegis/sanctuary.key"
"#;
        
        let config: ServerConfig = toml::from_str(toml).unwrap();
        assert_eq!(config.server.listen_addr, "0.0.0.0:51820");
        assert_eq!(config.server.keypair_file, "/etc/aegis/sanctuary.key");
        assert_eq!(config.server.log_level, "info"); // default
        assert!(config.server.authorized_peers_dir.is_none());
    }
    
    #[test]
    fn parse_config_with_peers_dir() {
        let toml = r#"
[server]
listen_addr = "127.0.0.1:51820"
keypair_file = "sanctuary.key"
log_level = "debug"
authorized_peers_dir = "/etc/aegis/peers"
"#;
        
        let config: ServerConfig = toml::from_str(toml).unwrap();
        assert_eq!(config.server.log_level, "debug");
        assert_eq!(config.server.authorized_peers_dir.unwrap(), "/etc/aegis/peers");
    }
    
    #[test]
    fn load_authorized_peers_open_mode() {
        let toml = r#"
[server]
listen_addr = "0.0.0.0:51820"
keypair_file = "test.key"
"#;
        
        let config: ServerConfig = toml::from_str(toml).unwrap();
        let peers = config.load_authorized_peers().unwrap();
        assert!(peers.is_empty()); // Open mode
    }
    
    #[test]
    fn load_authorized_peers_from_directory() {
        let dir = tempfile::tempdir().unwrap();
        let dir_path = dir.path();
        
        // Create a test public key file
        let (pk, _sk) = aegis_crypto::AegisCrypto::keygen();
        let pk_bytes = pk.to_bytes();
        let pk_file = dir_path.join("client1.pub");
        fs::write(&pk_file, &pk_bytes).unwrap();
        
        // Create a non-.pub file (should be ignored)
        fs::write(dir_path.join("readme.txt"), "ignored").unwrap();
        
        let toml = format!(
            r#"
[server]
listen_addr = "0.0.0.0:51820"
keypair_file = "test.key"
authorized_peers_dir = "{}"
"#,
            dir_path.display()
        );
        
        let config: ServerConfig = toml::from_str(&toml).unwrap();
        let peers = config.load_authorized_peers().unwrap();
        
        assert_eq!(peers.len(), 1);
        assert!(peers.contains(&pk_bytes));
    }
}
