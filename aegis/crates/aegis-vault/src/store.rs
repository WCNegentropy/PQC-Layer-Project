//! Encrypted object storage backend.
//!
//! Provides per-file encryption using ChaCha20-Poly1305 with keys
//! derived from the vault master key via HKDF.
//!
//! # Planned API
//!
//! ```rust,ignore
//! let vault = VaultStore::open("/path/to/vault", &master_key)?;
//! vault.write("documents/secret.txt", plaintext)?;
//! let data = vault.read("documents/secret.txt")?;
//! ```

use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use aegis_crypto::{AeadCipher, AEAD_KEY_SIZE, AEAD_NONCE_SIZE};
use hkdf::Hkdf;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

use crate::VaultError;

const MANIFEST_DIR: &str = ".aegis";
const BLOBS_DIR: &str = ".aegis/blobs";
const KEYS_DIR: &str = ".aegis/keys";
const MANIFEST_FILE: &str = ".aegis/manifest.json";
const FILE_KEY_INFO: &[u8] = b"aegis-vault-file-key-v1";

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct VaultManifest {
    entries: BTreeMap<String, ManifestEntry>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ManifestEntry {
    blob_path: String,
    nonce: [u8; AEAD_NONCE_SIZE],
    updated_at: u64,
    plaintext_len: usize,
}

/// Minimal encrypted vault store with per-file AEAD encryption.
pub struct VaultStore {
    root: PathBuf,
    master_key: [u8; AEAD_KEY_SIZE],
}

impl VaultStore {
    /// Generate a new random 32-byte vault master key.
    pub fn generate_master_key() -> [u8; AEAD_KEY_SIZE] {
        let mut key = [0u8; AEAD_KEY_SIZE];
        rand::thread_rng().fill_bytes(&mut key);
        key
    }

    /// Initialize a new vault on disk.
    pub fn init(
        root: impl AsRef<Path>,
        master_key: &[u8; AEAD_KEY_SIZE],
    ) -> Result<Self, VaultError> {
        let root = root.as_ref().to_path_buf();
        std::fs::create_dir_all(root.join(MANIFEST_DIR))?;
        std::fs::create_dir_all(root.join(BLOBS_DIR))?;
        std::fs::create_dir_all(root.join(KEYS_DIR))?;
        let store = Self {
            root,
            master_key: *master_key,
        };
        store.save_manifest(&VaultManifest::default())?;
        Ok(store)
    }

    /// Open an existing vault.
    pub fn open(
        root: impl AsRef<Path>,
        master_key: &[u8; AEAD_KEY_SIZE],
    ) -> Result<Self, VaultError> {
        let root = root.as_ref().to_path_buf();
        if !root.join(MANIFEST_FILE).exists() {
            return Err(VaultError::NotFound(MANIFEST_FILE.into()));
        }
        Ok(Self {
            root,
            master_key: *master_key,
        })
    }

    /// Write an encrypted file to the vault.
    pub fn write(&self, logical_path: &str, plaintext: &[u8]) -> Result<(), VaultError> {
        let logical_path = normalize_logical_path(logical_path)?;
        let key = self.derive_file_key(&logical_path)?;
        let cipher = AeadCipher::new(&key);
        let mut nonce = [0u8; AEAD_NONCE_SIZE];
        rand::thread_rng().fill_bytes(&mut nonce);
        let ciphertext = cipher
            .encrypt(&nonce, plaintext, logical_path.as_bytes())
            .map_err(|err| VaultError::CryptoError(err.to_string()))?;
        let blob_path = self.blob_path_for(&logical_path);
        if let Some(parent) = blob_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&blob_path, ciphertext)?;

        let mut manifest = self.load_manifest()?;
        manifest.entries.insert(
            logical_path,
            ManifestEntry {
                blob_path: blob_path
                    .strip_prefix(&self.root)
                    .unwrap_or(&blob_path)
                    .to_string_lossy()
                    .to_string(),
                nonce,
                updated_at: now_secs()?,
                plaintext_len: plaintext.len(),
            },
        );
        self.save_manifest(&manifest)
    }

    /// Read and decrypt a file from the vault.
    pub fn read(&self, logical_path: &str) -> Result<Vec<u8>, VaultError> {
        let logical_path = normalize_logical_path(logical_path)?;
        let manifest = self.load_manifest()?;
        let entry = manifest
            .entries
            .get(&logical_path)
            .ok_or_else(|| VaultError::NotFound(logical_path.clone()))?;
        let ciphertext = std::fs::read(self.root.join(&entry.blob_path))?;
        let key = self.derive_file_key(&logical_path)?;
        let cipher = AeadCipher::new(&key);
        cipher
            .decrypt(&entry.nonce, &ciphertext, logical_path.as_bytes())
            .map(|bytes| bytes.to_vec())
            .map_err(|err| VaultError::CryptoError(err.to_string()))
    }

    /// Delete an encrypted file from the vault.
    pub fn delete(&self, logical_path: &str) -> Result<(), VaultError> {
        let logical_path = normalize_logical_path(logical_path)?;
        let mut manifest = self.load_manifest()?;
        let entry = manifest
            .entries
            .remove(&logical_path)
            .ok_or_else(|| VaultError::NotFound(logical_path.clone()))?;
        let blob_path = self.root.join(entry.blob_path);
        if blob_path.exists() {
            std::fs::remove_file(blob_path)?;
        }
        self.save_manifest(&manifest)
    }

    /// List the logical files currently stored in the vault.
    pub fn list(&self) -> Result<Vec<String>, VaultError> {
        let manifest = self.load_manifest()?;
        Ok(manifest.entries.keys().cloned().collect())
    }

    /// Bootstrap the private-node social layout defined by the project spec.
    pub fn initialize_social_layout(&self, owner_did: &str) -> Result<Vec<String>, VaultError> {
        let defaults = [
            (
                "social/space/index.html",
                format!(
                    "<!doctype html>\n<html><head><meta charset=\"utf-8\"><title>Aegis Space</title><link rel=\"stylesheet\" href=\"style.css\"></head><body><main class=\"space\"><h1>Welcome to {owner_did}</h1><p>Your private Aegis space is now hosted from your vault.</p></main></body></html>\n"
                ),
            ),
            (
                "social/space/style.css",
                "body { font-family: system-ui, sans-serif; background: #0b1020; color: #f3f4f6; margin: 0; }\n.space { max-width: 48rem; margin: 4rem auto; padding: 2rem; background: rgba(15, 23, 42, 0.9); border-radius: 1rem; }\n".into(),
            ),
            (
                "social/space/room.json",
                serde_json::to_string_pretty(&serde_json::json!({
                    "schema_version": "1.0",
                    "name": "My Aegis Space",
                    "description": "A private-node social space served from the local vault.",
                    "theme": "midnight",
                    "layout": "default"
                }))
                .map_err(|err| VaultError::CryptoError(err.to_string()))?,
            ),
            (
                "social/character/avatar.json",
                serde_json::to_string_pretty(&serde_json::json!({
                    "schema_version": "1.0",
                    "did": owner_did,
                    "display_name": "Aegis Explorer",
                    "base_sprite": "humanoid_v1",
                    "skin_tone": "#F5CBA7",
                    "equipped": {
                        "head": null,
                        "body": null,
                        "feet": null,
                        "background": null,
                        "accessory": null
                    }
                }))
                .map_err(|err| VaultError::CryptoError(err.to_string()))?,
            ),
            (
                "social/character/equipped.json",
                serde_json::to_string_pretty(&serde_json::json!({
                    "head": null,
                    "body": null,
                    "feet": null,
                    "background": null,
                    "accessory": null
                }))
                .map_err(|err| VaultError::CryptoError(err.to_string()))?,
            ),
            (
                "social/inventory/inventory.json",
                serde_json::to_string_pretty(&serde_json::json!({
                    "schema_version": "1.0",
                    "owner_did": owner_did,
                    "items": []
                }))
                .map_err(|err| VaultError::CryptoError(err.to_string()))?,
            ),
            (
                "social/profile/profile.json",
                serde_json::to_string_pretty(&serde_json::json!({
                    "schema_version": "1.0",
                    "did": owner_did,
                    "display_name": "Aegis Explorer",
                    "bio": "Local-first private-node identity",
                    "social_links": []
                }))
                .map_err(|err| VaultError::CryptoError(err.to_string()))?,
            ),
            (
                "social/feed/posts.json",
                serde_json::to_string_pretty(&serde_json::json!({
                    "schema_version": "1.0",
                    "posts": []
                }))
                .map_err(|err| VaultError::CryptoError(err.to_string()))?,
            ),
        ];

        let mut created = Vec::with_capacity(defaults.len());
        for (path, contents) in defaults {
            self.write(path, contents.as_bytes())?;
            created.push(path.to_string());
        }
        Ok(created)
    }

    fn derive_file_key(&self, logical_path: &str) -> Result<[u8; AEAD_KEY_SIZE], VaultError> {
        let mut salt_hasher = Sha3_256::new();
        salt_hasher.update(logical_path.as_bytes());
        let salt = salt_hasher.finalize();
        let hkdf = Hkdf::<Sha3_256>::new(Some(&salt), &self.master_key);
        let mut key = [0u8; AEAD_KEY_SIZE];
        hkdf.expand(FILE_KEY_INFO, &mut key)
            .map_err(|_| VaultError::CryptoError("failed to derive file key".into()))?;
        Ok(key)
    }

    fn blob_path_for(&self, logical_path: &str) -> PathBuf {
        let digest = Sha3_256::digest(logical_path.as_bytes());
        let digest_hex: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
        self.root
            .join(BLOBS_DIR)
            .join(&digest_hex[..2])
            .join(format!("{digest_hex}.blob"))
    }

    fn load_manifest(&self) -> Result<VaultManifest, VaultError> {
        let manifest_path = self.root.join(MANIFEST_FILE);
        let contents = std::fs::read_to_string(manifest_path)?;
        serde_json::from_str(&contents).map_err(|err| VaultError::CryptoError(err.to_string()))
    }

    fn save_manifest(&self, manifest: &VaultManifest) -> Result<(), VaultError> {
        let manifest_path = self.root.join(MANIFEST_FILE);
        let contents = serde_json::to_string_pretty(manifest)
            .map_err(|err| VaultError::CryptoError(err.to_string()))?;
        std::fs::write(manifest_path, contents)?;
        Ok(())
    }
}

fn normalize_logical_path(path: &str) -> Result<String, VaultError> {
    let normalized = Path::new(path)
        .components()
        .map(|component| match component {
            Component::Normal(value) => Ok(value.to_string_lossy().to_string()),
            _ => Err(VaultError::CryptoError(format!(
                "invalid logical path component in '{path}'"
            ))),
        })
        .collect::<Result<Vec<_>, _>>()?;

    if normalized.is_empty() {
        return Err(VaultError::CryptoError(
            "logical path cannot be empty".into(),
        ));
    }

    Ok(normalized.join("/"))
}

fn now_secs() -> Result<u64, VaultError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|err| VaultError::CryptoError(err.to_string()))
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::*;

    #[test]
    fn write_and_read_roundtrip() {
        let dir = tempdir().unwrap();
        let master_key = VaultStore::generate_master_key();
        let vault = VaultStore::init(dir.path(), &master_key).unwrap();

        vault.write("documents/hello.txt", b"vault secret").unwrap();
        assert_eq!(vault.read("documents/hello.txt").unwrap(), b"vault secret");
    }

    #[test]
    fn social_layout_bootstrap_creates_expected_files() {
        let dir = tempdir().unwrap();
        let master_key = VaultStore::generate_master_key();
        let vault = VaultStore::init(dir.path(), &master_key).unwrap();

        let created = vault
            .initialize_social_layout("did:aegis:demo-owner")
            .unwrap();

        assert!(created.contains(&"social/space/index.html".to_string()));
        let profile = vault.read("social/profile/profile.json").unwrap();
        assert!(String::from_utf8(profile)
            .unwrap()
            .contains("did:aegis:demo-owner"));
    }
}
