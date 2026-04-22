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
use aegis_platform::fs::{EncryptedFs, FileEntry};
use aegis_platform::PlatformError;
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
const UNLOCK_METADATA_FILE: &str = ".aegis/unlock.json";
const FILE_KEY_INFO: &[u8] = b"aegis-vault-file-key-v1";
const LEGACY_TIMESTAMP: u64 = 0;

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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VaultUnlockMode {
    FileKey,
    KeyringPreferred,
    PassphraseWrapPlanned,
    HardwareWrapPlanned,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultUnlockMetadata {
    pub mode: VaultUnlockMode,
    pub key_file: String,
    pub created_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum IntegrityIssueKind {
    MissingBlob,
    OrphanBlob,
    TombstoneBlobPresent,
    CiphertextUndecryptable,
    PlaintextLengthMismatch,
    ContentHashMismatch,
    DuplicateBlobReference,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntegrityIssue {
    pub kind: IntegrityIssueKind,
    pub logical_path: String,
    pub detail: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultIntegrityReport {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub issues: Vec<IntegrityIssue>,
}

impl VaultIntegrityReport {
    pub fn is_clean(&self) -> bool {
        self.issues.is_empty()
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct VaultRepairOptions {
    pub remove_orphan_blobs: bool,
    pub tombstone_missing_entries: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct VaultRepairReport {
    pub removed_orphan_blobs: Vec<String>,
    pub tombstoned_entries: Vec<String>,
    pub remaining_issues: Vec<IntegrityIssue>,
}

/// Minimal encrypted vault store with per-file AEAD encryption.
#[derive(Clone)]
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
        store.save_unlock_metadata(&VaultUnlockMetadata {
            mode: VaultUnlockMode::FileKey,
            key_file: default_master_key_path(),
            created_at: now_secs()?,
            note: Some("file-based MVP unlock path".into()),
        })?;
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

    /// Open an existing vault using the file-based master key MVP.
    pub fn open_with_file_key(root: impl AsRef<Path>) -> Result<Self, VaultError> {
        let root = root.as_ref().to_path_buf();
        let master_key = Self::read_master_key_file(&root)?;
        Self::open(root, &master_key)
    }

    /// Return the vault root on disk.
    pub fn root_path(&self) -> &Path {
        &self.root
    }

    /// Persist the vault master key to the default file-based unlock location.
    pub fn write_master_key_file(
        root: impl AsRef<Path>,
        master_key: &[u8; AEAD_KEY_SIZE],
    ) -> Result<(), VaultError> {
        let root = root.as_ref();
        let key_path = root.join(default_master_key_path());
        write_secure_bytes(&key_path, master_key)?;
        let metadata = VaultUnlockMetadata {
            mode: VaultUnlockMode::FileKey,
            key_file: default_master_key_path(),
            created_at: now_secs()?,
            note: Some("file-based MVP unlock path".into()),
        };
        let metadata_path = root.join(UNLOCK_METADATA_FILE);
        let contents = serde_json::to_vec_pretty(&metadata)
            .map_err(|err| VaultError::Serialization(err.to_string()))?;
        std::fs::write(metadata_path, contents)?;
        Ok(())
    }

    /// Load the current vault unlock metadata, defaulting to the file-key MVP when absent.
    pub fn load_unlock_metadata(root: impl AsRef<Path>) -> Result<VaultUnlockMetadata, VaultError> {
        let root = root.as_ref();
        let metadata_path = root.join(UNLOCK_METADATA_FILE);
        if !metadata_path.exists() {
            return Ok(VaultUnlockMetadata {
                mode: VaultUnlockMode::FileKey,
                key_file: default_master_key_path(),
                created_at: 0,
                note: Some("defaulted to file-based MVP unlock path".into()),
            });
        }
        let contents = std::fs::read_to_string(metadata_path)?;
        serde_json::from_str(&contents).map_err(|err| VaultError::Serialization(err.to_string()))
    }

    /// Read the persisted file-based vault master key.
    pub fn read_master_key_file(root: impl AsRef<Path>) -> Result<[u8; AEAD_KEY_SIZE], VaultError> {
        let metadata = Self::load_unlock_metadata(root.as_ref())?;
        let bytes = std::fs::read(root.as_ref().join(metadata.key_file))?;
        bytes
            .try_into()
            .map_err(|_| VaultError::Serialization("invalid master key length".into()))
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
                    .filter(|value| is_initialized_timestamp(*value))
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

    /// Check whether a non-tombstoned logical path exists in the vault.
    pub fn exists(&self, logical_path: &str) -> Result<bool, VaultError> {
        let logical_path = normalize_logical_path(logical_path)?;
        let manifest = self.load_manifest()?;
        Ok(manifest
            .entries
            .get(&logical_path)
            .map(|entry| !entry.tombstone)
            .unwrap_or(false))
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
        for (path, entry) in &manifest.entries {
            if entry.tombstone {
                continue;
            }
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
            Some(prefix) => normalize_directory_prefix(prefix)?,
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

    /// Return platform-style entries for the direct children of a logical directory.
    pub fn list_file_entries(&self, logical_dir: &str) -> Result<Vec<FileEntry>, VaultError> {
        let prefix = normalize_directory_prefix(logical_dir)?;
        let manifest = self.load_manifest()?;
        let mut directories = BTreeMap::<String, u64>::new();
        let mut files = BTreeMap::<String, FileEntry>::new();

        for (path, entry) in &manifest.entries {
            if entry.tombstone || !matches_prefix(path, prefix.as_deref()) {
                continue;
            }

            let suffix = match prefix.as_deref() {
                Some(prefix) => match path
                    .strip_prefix(prefix)
                    .and_then(|value| value.strip_prefix('/'))
                {
                    Some(value) => value,
                    None if path == prefix => "",
                    None => continue,
                },
                None => path.as_str(),
            };

            if suffix.is_empty() {
                continue;
            }

            let mut components = suffix.split('/');
            let child = components.next().unwrap_or_default();
            if child.is_empty() {
                continue;
            }

            let child_path = match prefix.as_deref() {
                Some(prefix) => format!("{prefix}/{child}"),
                None => child.to_string(),
            };

            if components.next().is_some() {
                directories
                    .entry(child_path.clone())
                    .and_modify(|modified| *modified = (*modified).max(entry.updated_at))
                    .or_insert(entry.updated_at);
            } else {
                files.insert(
                    child_path.clone(),
                    FileEntry {
                        path: child_path,
                        size: entry.plaintext_len as u64,
                        is_dir: false,
                        modified: entry.updated_at,
                    },
                );
            }
        }

        for (path, modified) in directories {
            files.entry(path.clone()).or_insert(FileEntry {
                path,
                size: 0,
                is_dir: true,
                modified,
            });
        }

        Ok(files.into_values().collect())
    }

    /// Serialize a JSON value and store it in the vault.
    pub fn write_json<T: Serialize>(
        &self,
        logical_path: &str,
        value: &T,
    ) -> Result<(), VaultError> {
        let bytes = serde_json::to_vec_pretty(value)
            .map_err(|err| VaultError::Serialization(err.to_string()))?;
        self.write(logical_path, &bytes)
    }

    /// Read a JSON document from the vault and deserialize it.
    pub fn read_json<T: DeserializeOwned>(&self, logical_path: &str) -> Result<T, VaultError> {
        let bytes = self.read(logical_path)?;
        serde_json::from_slice(&bytes).map_err(|err| VaultError::Serialization(err.to_string()))
    }

    /// Validate manifest/blob consistency and detect repairable integrity issues.
    pub fn validate_integrity(&self) -> Result<VaultIntegrityReport, VaultError> {
        let manifest = self.load_manifest()?;
        let mut report = VaultIntegrityReport::default();
        let mut referenced_blob_paths = BTreeMap::<String, String>::new();

        for (logical_path, entry) in &manifest.entries {
            if let Some(previous_owner) =
                referenced_blob_paths.insert(entry.blob_path.clone(), logical_path.clone())
            {
                report.issues.push(IntegrityIssue {
                    kind: IntegrityIssueKind::DuplicateBlobReference,
                    logical_path: logical_path.clone(),
                    detail: format!("blob also referenced by {previous_owner}"),
                });
            }

            let blob_path = self.root.join(&entry.blob_path);
            if entry.tombstone {
                if blob_path.exists() {
                    report.issues.push(IntegrityIssue {
                        kind: IntegrityIssueKind::TombstoneBlobPresent,
                        logical_path: logical_path.clone(),
                        detail: "tombstoned entry still has an encrypted blob".into(),
                    });
                }
                continue;
            }

            if !blob_path.exists() {
                report.issues.push(IntegrityIssue {
                    kind: IntegrityIssueKind::MissingBlob,
                    logical_path: logical_path.clone(),
                    detail: format!("missing blob {}", entry.blob_path),
                });
                continue;
            }

            let ciphertext = std::fs::read(&blob_path)?;
            let key = self.derive_file_key(logical_path)?;
            let cipher = AeadCipher::new(&key);
            let plaintext = match cipher.decrypt(&entry.nonce, &ciphertext, logical_path.as_bytes())
            {
                Ok(bytes) => bytes.to_vec(),
                Err(err) => {
                    report.issues.push(IntegrityIssue {
                        kind: IntegrityIssueKind::CiphertextUndecryptable,
                        logical_path: logical_path.clone(),
                        detail: err.to_string(),
                    });
                    continue;
                }
            };

            if plaintext.len() != entry.plaintext_len {
                report.issues.push(IntegrityIssue {
                    kind: IntegrityIssueKind::PlaintextLengthMismatch,
                    logical_path: logical_path.clone(),
                    detail: format!(
                        "expected {} bytes, recovered {} bytes",
                        entry.plaintext_len,
                        plaintext.len()
                    ),
                });
            }
            if content_hash(&plaintext) != entry.content_hash {
                report.issues.push(IntegrityIssue {
                    kind: IntegrityIssueKind::ContentHashMismatch,
                    logical_path: logical_path.clone(),
                    detail: "content hash does not match decrypted plaintext".into(),
                });
            }
        }

        for blob_path in self.list_blob_files()? {
            let relative = blob_path
                .strip_prefix(&self.root)
                .unwrap_or(&blob_path)
                .to_string_lossy()
                .to_string();
            if !referenced_blob_paths.contains_key(&relative) {
                report.issues.push(IntegrityIssue {
                    kind: IntegrityIssueKind::OrphanBlob,
                    logical_path: relative.clone(),
                    detail: "blob exists on disk without a manifest entry".into(),
                });
            }
        }

        Ok(report)
    }

    /// Apply conservative repairs for missing-entry tombstones and orphan blob cleanup.
    pub fn repair_integrity(
        &self,
        options: &VaultRepairOptions,
    ) -> Result<VaultRepairReport, VaultError> {
        let mut manifest = self.load_manifest()?;
        let report = self.validate_integrity()?;
        let mut repair = VaultRepairReport::default();

        for issue in &report.issues {
            match issue.kind {
                IntegrityIssueKind::OrphanBlob if options.remove_orphan_blobs => {
                    let orphan_path = self.root.join(&issue.logical_path);
                    if orphan_path.exists() {
                        std::fs::remove_file(&orphan_path)?;
                        repair.removed_orphan_blobs.push(issue.logical_path.clone());
                    }
                }
                IntegrityIssueKind::MissingBlob if options.tombstone_missing_entries => {
                    if let Some(entry) = manifest.entries.get_mut(&issue.logical_path) {
                        entry.tombstone = true;
                        entry.plaintext_len = 0;
                        entry.content_hash.clear();
                        entry.updated_at = now_secs()?;
                        entry.sync_generation = entry.sync_generation.saturating_add(1);
                        repair.tombstoned_entries.push(issue.logical_path.clone());
                    }
                }
                _ => {}
            }
        }

        if !repair.tombstoned_entries.is_empty() {
            self.save_manifest(&manifest)?;
        }

        repair.remaining_issues = self.validate_integrity()?.issues;
        Ok(repair)
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
        serde_json::from_str(&contents).map_err(|err| VaultError::Serialization(err.to_string()))
    }

    fn save_manifest(&self, manifest: &VaultManifest) -> Result<(), VaultError> {
        let manifest_path = self.root.join(MANIFEST_FILE);
        let contents = serde_json::to_string_pretty(manifest)
            .map_err(|err| VaultError::Serialization(err.to_string()))?;
        atomic_write(&manifest_path, contents.as_bytes())?;
        Ok(())
    }

    fn save_unlock_metadata(&self, metadata: &VaultUnlockMetadata) -> Result<(), VaultError> {
        let metadata_path = self.root.join(UNLOCK_METADATA_FILE);
        let contents = serde_json::to_string_pretty(metadata)
            .map_err(|err| VaultError::Serialization(err.to_string()))?;
        atomic_write(&metadata_path, contents.as_bytes())?;
        Ok(())
    }

    fn list_blob_files(&self) -> Result<Vec<PathBuf>, VaultError> {
        collect_files_recursively(&self.root.join(BLOBS_DIR))
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

fn default_master_key_path() -> String {
    format!("{KEYS_DIR}/master.key")
}

fn write_secure_bytes(path: &Path, contents: &[u8]) -> Result<(), VaultError> {
    atomic_write(path, contents)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

fn atomic_write(path: &Path, contents: &[u8]) -> Result<(), VaultError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let temp_path = path.with_extension(format!(
        "{}tmp",
        path.extension()
            .map(|extension| format!("{}.", extension.to_string_lossy()))
            .unwrap_or_default()
    ));
    std::fs::write(&temp_path, contents)?;
    std::fs::rename(temp_path, path)?;
    Ok(())
}

fn collect_files_recursively(path: &Path) -> Result<Vec<PathBuf>, VaultError> {
    if !path.exists() {
        return Ok(Vec::new());
    }

    let mut files = Vec::new();
    for entry in std::fs::read_dir(path)? {
        let entry = entry?;
        let entry_path = entry.path();
        if entry_path.is_dir() {
            files.extend(collect_files_recursively(&entry_path)?);
        } else if entry_path.is_file() {
            files.push(entry_path);
        }
    }
    Ok(files)
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

fn is_initialized_timestamp(value: u64) -> bool {
    // `0` is reserved for legacy/migrated entries where creation time was not recorded.
    value != LEGACY_TIMESTAMP
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

fn vault_to_platform_error(err: VaultError) -> PlatformError {
    match err {
        VaultError::Io(err) => PlatformError::Io(err),
        VaultError::Mount(message) => PlatformError::Unsupported(message),
        other => PlatformError::Unsupported(other.to_string()),
    }
}

impl EncryptedFs for VaultStore {
    fn read_file(&self, path: &str) -> Result<Vec<u8>, PlatformError> {
        self.read(path).map_err(vault_to_platform_error)
    }

    fn write_file(&self, path: &str, data: &[u8]) -> Result<(), PlatformError> {
        self.write(path, data).map_err(vault_to_platform_error)
    }

    fn delete_file(&self, path: &str) -> Result<(), PlatformError> {
        self.delete(path).map_err(vault_to_platform_error)
    }

    fn list_dir(&self, path: &str) -> Result<Vec<FileEntry>, PlatformError> {
        self.list_file_entries(path)
            .map_err(vault_to_platform_error)
    }

    fn exists(&self, path: &str) -> Result<bool, PlatformError> {
        self.exists(path).map_err(vault_to_platform_error)
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

    #[test]
    fn file_based_unlock_roundtrip() {
        let dir = tempdir().unwrap();
        let master_key = VaultStore::generate_master_key();
        let vault = VaultStore::init(dir.path(), &master_key).unwrap();
        VaultStore::write_master_key_file(dir.path(), &master_key).unwrap();

        vault
            .write("documents/secret.txt", b"open via unlock metadata")
            .unwrap();

        let reopened = VaultStore::open_with_file_key(dir.path()).unwrap();
        let unlock_metadata = VaultStore::load_unlock_metadata(dir.path()).unwrap();
        assert_eq!(unlock_metadata.mode, VaultUnlockMode::FileKey);
        assert_eq!(
            reopened.read("documents/secret.txt").unwrap(),
            b"open via unlock metadata"
        );
    }

    #[test]
    fn integrity_validation_detects_orphans_and_can_repair() {
        let dir = tempdir().unwrap();
        let master_key = VaultStore::generate_master_key();
        let vault = VaultStore::init(dir.path(), &master_key).unwrap();

        vault.write("documents/hello.txt", b"vault secret").unwrap();
        let orphan_dir = dir.path().join(BLOBS_DIR).join("zz");
        std::fs::create_dir_all(&orphan_dir).unwrap();
        std::fs::write(orphan_dir.join("orphan.blob"), b"junk").unwrap();

        let report = vault.validate_integrity().unwrap();
        assert!(report
            .issues
            .iter()
            .any(|issue| issue.kind == IntegrityIssueKind::OrphanBlob));

        let repair = vault
            .repair_integrity(&VaultRepairOptions {
                remove_orphan_blobs: true,
                tombstone_missing_entries: true,
            })
            .unwrap();
        assert_eq!(repair.removed_orphan_blobs.len(), 1);
        assert!(repair.remaining_issues.is_empty());
    }

    #[test]
    fn integrity_repair_tombstones_missing_blob_entries() {
        let dir = tempdir().unwrap();
        let master_key = VaultStore::generate_master_key();
        let vault = VaultStore::init(dir.path(), &master_key).unwrap();

        vault.write("documents/hello.txt", b"vault secret").unwrap();
        let metadata = vault.list_metadata(Some("documents")).unwrap();
        std::fs::remove_file(dir.path().join(&metadata[0].blob_path)).unwrap();

        let repair = vault
            .repair_integrity(&VaultRepairOptions {
                remove_orphan_blobs: false,
                tombstone_missing_entries: true,
            })
            .unwrap();

        assert_eq!(
            repair.tombstoned_entries,
            vec!["documents/hello.txt".to_string()]
        );
        assert!(matches!(
            vault.read("documents/hello.txt"),
            Err(VaultError::NotFound(_))
        ));
    }
}
