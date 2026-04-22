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
use serde::de::DeserializeOwned;
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
    #[serde(default)]
    created_at: u64,
    updated_at: u64,
    plaintext_len: usize,
    #[serde(default)]
    content_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    media_type: Option<String>,
    #[serde(default)]
    schema: VaultDocumentSchema,
    #[serde(default)]
    tombstone: bool,
    #[serde(default)]
    sync_generation: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    author_device: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    capability_labels: Vec<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VaultDocumentSchema {
    SpaceHtml,
    SpaceStyle,
    SpaceMetadata,
    CharacterProfile,
    Inventory,
    SocialProfile,
    Feed,
    Messages,
    Peers,
    SharedNodes,
    Apps,
    Runtime,
    Cache,
    #[default]
    Generic,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WriteOptions {
    pub author_device: Option<String>,
    pub capability_labels: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultEntryMetadata {
    pub logical_path: String,
    pub blob_path: String,
    pub plaintext_len: usize,
    pub content_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub media_type: Option<String>,
    pub schema: VaultDocumentSchema,
    pub created_at: u64,
    pub updated_at: u64,
    pub tombstone: bool,
    pub sync_generation: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub author_device: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capability_labels: Vec<String>,
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
        self.write_with_options(logical_path, plaintext, &WriteOptions::default())
    }

    /// Write an encrypted file to the vault with optional author/capability metadata.
    pub fn write_with_options(
        &self,
        logical_path: &str,
        plaintext: &[u8],
        options: &WriteOptions,
    ) -> Result<(), VaultError> {
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
        let now = now_secs()?;
        let prior_entry = manifest.entries.get(&logical_path).cloned();
        manifest.entries.insert(
            logical_path.clone(),
            ManifestEntry {
                blob_path: blob_path
                    .strip_prefix(&self.root)
                    .unwrap_or(&blob_path)
                    .to_string_lossy()
                    .to_string(),
                nonce,
                created_at: prior_entry
                    .as_ref()
                    .map(|entry| entry.created_at)
                    .filter(|value| *value != 0)
                    .unwrap_or(now),
                updated_at: now,
                plaintext_len: plaintext.len(),
                content_hash: content_hash(plaintext),
                media_type: infer_media_type(&logical_path),
                schema: infer_schema(&logical_path),
                tombstone: false,
                sync_generation: prior_entry
                    .as_ref()
                    .map(|entry| entry.sync_generation.saturating_add(1))
                    .unwrap_or(1),
                author_device: options.author_device.clone(),
                capability_labels: options.capability_labels.clone(),
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
        if entry.tombstone {
            return Err(VaultError::NotFound(logical_path));
        }
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
            .get_mut(&logical_path)
            .ok_or_else(|| VaultError::NotFound(logical_path.clone()))?;
        let blob_path = self.root.join(&entry.blob_path);
        if blob_path.exists() {
            std::fs::remove_file(blob_path)?;
        }
        entry.tombstone = true;
        entry.updated_at = now_secs()?;
        entry.sync_generation = entry.sync_generation.saturating_add(1);
        entry.plaintext_len = 0;
        entry.content_hash.clear();
        self.save_manifest(&manifest)
    }

    /// List the logical files currently stored in the vault.
    pub fn list(&self) -> Result<Vec<String>, VaultError> {
        let manifest = self.load_manifest()?;
        Ok(manifest
            .entries
            .iter()
            .filter(|(_, entry)| !entry.tombstone)
            .map(|(path, _)| path.clone())
            .collect())
    }

    /// List direct children under a logical directory.
    pub fn list_directory(&self, logical_dir: &str) -> Result<Vec<String>, VaultError> {
        let prefix = normalize_directory_prefix(logical_dir)?;
        let manifest = self.load_manifest()?;
        let mut children = Vec::new();
        let mut seen = std::collections::BTreeSet::new();
        for path in manifest.entries.keys() {
            if let Some(child) = immediate_child(path, prefix.as_deref()) {
                if seen.insert(child.clone()) {
                    children.push(child);
                }
            }
        }
        Ok(children)
    }

    /// Return metadata for all entries, optionally filtered to a logical prefix.
    pub fn list_metadata(
        &self,
        logical_prefix: Option<&str>,
    ) -> Result<Vec<VaultEntryMetadata>, VaultError> {
        let prefix = match logical_prefix {
            Some(prefix) => Some(normalize_directory_prefix(prefix)?.unwrap_or_default()),
            None => None,
        };
        let manifest = self.load_manifest()?;
        Ok(manifest
            .entries
            .iter()
            .filter(|(path, _)| matches_prefix(path, prefix.as_deref()))
            .map(|(logical_path, entry)| VaultEntryMetadata {
                logical_path: logical_path.clone(),
                blob_path: entry.blob_path.clone(),
                plaintext_len: entry.plaintext_len,
                content_hash: entry.content_hash.clone(),
                media_type: entry.media_type.clone(),
                schema: entry.schema.clone(),
                created_at: entry.created_at,
                updated_at: entry.updated_at,
                tombstone: entry.tombstone,
                sync_generation: entry.sync_generation,
                author_device: entry.author_device.clone(),
                capability_labels: entry.capability_labels.clone(),
            })
            .collect())
    }

    /// Serialize a JSON value and store it in the vault.
    pub fn write_json<T: Serialize>(
        &self,
        logical_path: &str,
        value: &T,
    ) -> Result<(), VaultError> {
        let bytes = serde_json::to_vec_pretty(value)
            .map_err(|err| VaultError::CryptoError(err.to_string()))?;
        self.write(logical_path, &bytes)
    }

    /// Read a JSON document from the vault and deserialize it.
    pub fn read_json<T: DeserializeOwned>(&self, logical_path: &str) -> Result<T, VaultError> {
        let bytes = self.read(logical_path)?;
        serde_json::from_slice(&bytes).map_err(|err| VaultError::CryptoError(err.to_string()))
    }

    /// Bootstrap the private-node social layout defined by the project spec.
    pub fn initialize_social_layout(&self, owner_did: &str) -> Result<Vec<String>, VaultError> {
        let defaults = [
            (
                "social/space/index.html",
                format!(
                    r#"<!doctype html>
<html>
  <head>
    <meta charset="utf-8">
    <title>Aegis Space</title>
    <link rel="stylesheet" href="style.css">
  </head>
  <body>
    <main class="space">
      <h1>Welcome to {owner_did}</h1>
      <p>Your private Aegis space is now hosted from your vault.</p>
    </main>
  </body>
</html>
"#
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
            (
                "social/messages/inbox.json",
                serde_json::to_string_pretty(&serde_json::json!({
                    "schema_version": "1.0",
                    "messages": []
                }))
                .map_err(|err| VaultError::CryptoError(err.to_string()))?,
            ),
            (
                "social/messages/sent.json",
                serde_json::to_string_pretty(&serde_json::json!({
                    "schema_version": "1.0",
                    "messages": []
                }))
                .map_err(|err| VaultError::CryptoError(err.to_string()))?,
            ),
            (
                "social/peers/known.json",
                serde_json::to_string_pretty(&serde_json::json!({
                    "schema_version": "1.0",
                    "peers": []
                }))
                .map_err(|err| VaultError::CryptoError(err.to_string()))?,
            ),
            (
                "social/shared_nodes/registry.json",
                serde_json::to_string_pretty(&serde_json::json!({
                    "schema_version": "1.0",
                    "nodes": []
                }))
                .map_err(|err| VaultError::CryptoError(err.to_string()))?,
            ),
            (
                "apps/registry.json",
                serde_json::to_string_pretty(&serde_json::json!({
                    "schema_version": "1.0",
                    "apps": []
                }))
                .map_err(|err| VaultError::CryptoError(err.to_string()))?,
            ),
            (
                "runtime/settings.json",
                serde_json::to_string_pretty(&serde_json::json!({
                    "schema_version": "1.0",
                    "owner_did": owner_did,
                    "feature_flags": {},
                    "active_connections": []
                }))
                .map_err(|err| VaultError::CryptoError(err.to_string()))?,
            ),
            (
                "cache/index.json",
                serde_json::to_string_pretty(&serde_json::json!({
                    "schema_version": "1.0",
                    "entries": []
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

fn normalize_directory_prefix(path: &str) -> Result<Option<String>, VaultError> {
    let trimmed = path.trim_matches('/');
    if trimmed.is_empty() {
        return Ok(None);
    }
    Ok(Some(normalize_logical_path(trimmed)?))
}

fn immediate_child(path: &str, prefix: Option<&str>) -> Option<String> {
    let suffix = match prefix {
        Some(prefix) => path.strip_prefix(prefix)?.strip_prefix('/')?,
        None => path,
    };
    suffix.split('/').next().map(str::to_string)
}

fn matches_prefix(path: &str, prefix: Option<&str>) -> bool {
    match prefix {
        Some(prefix) => path == prefix || path.starts_with(&format!("{prefix}/")),
        None => true,
    }
}

fn content_hash(bytes: &[u8]) -> String {
    let digest = Sha3_256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn infer_media_type(logical_path: &str) -> Option<String> {
    let extension = Path::new(logical_path).extension()?.to_string_lossy();
    Some(
        match extension.as_ref() {
            "html" => "text/html",
            "css" => "text/css",
            "json" => "application/json",
            "png" => "image/png",
            "jpg" | "jpeg" => "image/jpeg",
            "svg" => "image/svg+xml",
            "txt" => "text/plain",
            _ => "application/octet-stream",
        }
        .to_string(),
    )
}

fn infer_schema(logical_path: &str) -> VaultDocumentSchema {
    match logical_path {
        "social/space/index.html" => VaultDocumentSchema::SpaceHtml,
        "social/space/style.css" => VaultDocumentSchema::SpaceStyle,
        "social/space/room.json" => VaultDocumentSchema::SpaceMetadata,
        "social/character/avatar.json" | "social/character/equipped.json" => {
            VaultDocumentSchema::CharacterProfile
        }
        "social/inventory/inventory.json" => VaultDocumentSchema::Inventory,
        "social/profile/profile.json" => VaultDocumentSchema::SocialProfile,
        "social/feed/posts.json" => VaultDocumentSchema::Feed,
        path if path.starts_with("social/messages/") => VaultDocumentSchema::Messages,
        path if path.starts_with("social/peers/") => VaultDocumentSchema::Peers,
        path if path.starts_with("social/shared_nodes/") => VaultDocumentSchema::SharedNodes,
        path if path.starts_with("apps/") => VaultDocumentSchema::Apps,
        path if path.starts_with("runtime/") => VaultDocumentSchema::Runtime,
        path if path.starts_with("cache/") => VaultDocumentSchema::Cache,
        _ => VaultDocumentSchema::Generic,
    }
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
        assert!(created.contains(&"runtime/settings.json".to_string()));
        assert!(created.contains(&"social/messages/inbox.json".to_string()));
        let profile = vault.read("social/profile/profile.json").unwrap();
        assert!(String::from_utf8(profile)
            .unwrap()
            .contains("did:aegis:demo-owner"));
    }

    #[test]
    fn metadata_and_json_helpers_work() {
        let dir = tempdir().unwrap();
        let master_key = VaultStore::generate_master_key();
        let vault = VaultStore::init(dir.path(), &master_key).unwrap();

        vault
            .write_json(
                "runtime/settings.json",
                &serde_json::json!({"schema_version": "1.0", "feature_flags": {"browser": true}}),
            )
            .unwrap();

        let document: serde_json::Value = vault.read_json("runtime/settings.json").unwrap();
        assert_eq!(document["feature_flags"]["browser"], true);

        let metadata = vault.list_metadata(Some("runtime")).unwrap();
        assert_eq!(metadata.len(), 1);
        assert_eq!(metadata[0].schema, VaultDocumentSchema::Runtime);
        assert_eq!(metadata[0].media_type.as_deref(), Some("application/json"));
        assert!(!metadata[0].content_hash.is_empty());

        let children = vault.list_directory("runtime").unwrap();
        assert_eq!(children, vec!["settings.json".to_string()]);
    }

    #[test]
    fn delete_marks_tombstone_without_listing_file() {
        let dir = tempdir().unwrap();
        let master_key = VaultStore::generate_master_key();
        let vault = VaultStore::init(dir.path(), &master_key).unwrap();

        vault.write("social/feed/posts.json", b"{}").unwrap();
        vault.delete("social/feed/posts.json").unwrap();

        assert!(matches!(
            vault.read("social/feed/posts.json"),
            Err(VaultError::NotFound(_))
        ));
        assert!(vault.list().unwrap().is_empty());
        assert!(vault.list_metadata(Some("social/feed")).unwrap()[0].tombstone);
    }
}
