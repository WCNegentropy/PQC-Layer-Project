//! Keypair persistence for the PQ-WireGuard tunnel.
//!
//! Handles loading and saving hybrid keypairs (X25519 + ML-KEM-768) to disk.
//! On first run, generates a new keypair and persists it. On subsequent runs,
//! loads the existing keypair from the configured paths.
//!
//! # File Permissions
//!
//! Private key files are created with mode `0o600` (owner read/write only) on Unix.

use std::fs;
use std::path::Path;

use aegis_crypto::{AegisCrypto, HybridPublicKey, HybridSecretKey};
use tracing::info;

/// Load an existing keypair from disk or generate and save a new one.
///
/// - `keypair_file`: Path to the private key file.
/// - On first run (file doesn't exist), generates a new keypair,
///   saves the private key to `keypair_file` and the public key to
///   `keypair_file` with `.pub` appended.
/// - On subsequent runs, loads the private key from `keypair_file`
///   and derives the public key.
pub fn load_or_generate_keypair(
    keypair_file: &str,
) -> anyhow::Result<(HybridPublicKey, HybridSecretKey)> {
    let sk_path = Path::new(keypair_file);

    if sk_path.exists() {
        info!("🔑 Loading keypair from {}", keypair_file);
        load_keypair(keypair_file)
    } else {
        info!("🔑 Generating new keypair → {}", keypair_file);
        let (pk, sk) = AegisCrypto::keygen();
        save_keypair(keypair_file, &pk, &sk)?;
        Ok((pk, sk))
    }
}

/// Load a public key from a file.
pub fn load_public_key(path: &str) -> anyhow::Result<HybridPublicKey> {
    let bytes = fs::read(path)
        .map_err(|e| anyhow::anyhow!("Failed to read public key from '{}': {}", path, e))?;
    HybridPublicKey::from_bytes(&bytes)
        .map_err(|e| anyhow::anyhow!("Invalid public key in '{}': {}", path, e))
}

/// Save a keypair to disk.
///
/// The secret key is written to `keypair_file` and the public key is
/// written to `keypair_file.pub`.
fn save_keypair(
    keypair_file: &str,
    pk: &HybridPublicKey,
    sk: &HybridSecretKey,
) -> anyhow::Result<()> {
    let sk_bytes = sk.to_bytes();
    let pk_bytes = pk.to_bytes();

    // Write secret key with restrictive permissions
    fs::write(keypair_file, sk_bytes.as_slice())
        .map_err(|e| anyhow::anyhow!("Failed to write secret key to '{}': {}", keypair_file, e))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(keypair_file, fs::Permissions::from_mode(0o600)).map_err(|e| {
            anyhow::anyhow!(
                "Failed to set permissions on '{}': {}",
                keypair_file,
                e
            )
        })?;
    }

    // Write public key
    let pk_path = format!("{}.pub", keypair_file);
    fs::write(&pk_path, &pk_bytes)
        .map_err(|e| anyhow::anyhow!("Failed to write public key to '{}': {}", pk_path, e))?;

    info!(
        "   Private key: {} ({} bytes)",
        keypair_file,
        sk_bytes.len()
    );
    info!("   Public key:  {} ({} bytes)", pk_path, pk_bytes.len());

    Ok(())
}

/// Load a keypair from disk.
///
/// Reads the secret key from `keypair_file` and the public key from
/// `keypair_file.pub`.
fn load_keypair(keypair_file: &str) -> anyhow::Result<(HybridPublicKey, HybridSecretKey)> {
    let sk_bytes = fs::read(keypair_file)
        .map_err(|e| anyhow::anyhow!("Failed to read secret key from '{}': {}", keypair_file, e))?;
    let sk = HybridSecretKey::from_bytes(&sk_bytes)
        .map_err(|e| anyhow::anyhow!("Invalid secret key in '{}': {}", keypair_file, e))?;

    let pk_path = format!("{}.pub", keypair_file);
    let pk_bytes = fs::read(&pk_path)
        .map_err(|e| anyhow::anyhow!("Failed to read public key from '{}': {}", pk_path, e))?;
    let pk = HybridPublicKey::from_bytes(&pk_bytes)
        .map_err(|e| anyhow::anyhow!("Invalid public key in '{}': {}", pk_path, e))?;

    info!(
        "   Loaded keypair: {} + {}",
        keypair_file, pk_path
    );

    Ok((pk, sk))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn save_and_load_keypair() {
        let dir = tempfile::tempdir().unwrap();
        let sk_path = dir.path().join("test.key");
        let sk_path_str = sk_path.to_str().unwrap();

        let (pk, sk) = AegisCrypto::keygen();
        save_keypair(sk_path_str, &pk, &sk).unwrap();

        // Verify files exist
        assert!(sk_path.exists());
        assert!(dir.path().join("test.key.pub").exists());

        // Load and verify
        let (loaded_pk, _loaded_sk) = load_keypair(sk_path_str).unwrap();
        assert_eq!(pk.to_bytes(), loaded_pk.to_bytes());
    }

    #[test]
    fn load_or_generate_creates_new() {
        let dir = tempfile::tempdir().unwrap();
        let sk_path = dir.path().join("new.key");
        let sk_path_str = sk_path.to_str().unwrap();

        assert!(!sk_path.exists());
        let (pk, _sk) = load_or_generate_keypair(sk_path_str).unwrap();
        assert!(sk_path.exists());

        // Loading again should return the same public key
        let (pk2, _sk2) = load_or_generate_keypair(sk_path_str).unwrap();
        assert_eq!(pk.to_bytes(), pk2.to_bytes());
    }

    #[test]
    fn load_public_key_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let pk_path = dir.path().join("test.pub");
        let pk_path_str = pk_path.to_str().unwrap();

        let (pk, _sk) = AegisCrypto::keygen();
        fs::write(pk_path_str, pk.to_bytes()).unwrap();

        let loaded = load_public_key(pk_path_str).unwrap();
        assert_eq!(pk.to_bytes(), loaded.to_bytes());
    }

    #[cfg(unix)]
    #[test]
    fn secret_key_file_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let sk_path = dir.path().join("perms.key");
        let sk_path_str = sk_path.to_str().unwrap();

        let (pk, sk) = AegisCrypto::keygen();
        save_keypair(sk_path_str, &pk, &sk).unwrap();

        let metadata = fs::metadata(&sk_path).unwrap();
        let mode = metadata.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "Secret key file should have mode 0600");
    }
}
