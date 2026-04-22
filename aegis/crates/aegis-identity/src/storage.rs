use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use aegis_crypto::{HybridPublicKey, HybridSecretKey, SigningKeypair};
use serde::{Deserialize, Serialize};

use crate::credentials::Credential;
use crate::did::{DidDocument, ServiceEndpoint};
use crate::keys::RootIdentity;
use crate::runtime::RuntimeIdentity;
use crate::IdentityError;

const CONTRACT_VERSION: u32 = 1;
const ROOT_DIR: &str = "root";
const DEVICES_DIR: &str = "devices";
const DOCUMENTS_DIR: &str = "documents";
const TRUST_DIR: &str = "trust";
const DISCOVERY_DIR: &str = "discovery";
const ROTATION_DIR: &str = "rotation";
const BACKUP_DIR: &str = "backup";
const OWNER_DID_FILE: &str = "owner.did";
const IDENTITY_METADATA_FILE: &str = "identity.json";
const ACTIVE_DEVICE_FILE: &str = "devices/active-device.txt";
const DID_DOCUMENT_FILE: &str = "documents/did-document.json";
const TRUST_STORE_FILE: &str = "trust/peers.json";
const DISCOVERY_FILE: &str = "discovery/endpoints.json";
const ROTATION_HISTORY_FILE: &str = "rotation/history.json";
const BACKUP_METADATA_FILE: &str = "backup/metadata.json";
const JOIN_REQUESTS_FILE: &str = "devices/join-requests.json";
const LEGACY_CONTRACT_VERSION: u32 = 0;
const LEGACY_DID_FILE: &str = "did.txt";
const LEGACY_DEVICE_NAME_FILE: &str = "device-name.txt";
const LEGACY_DID_DOCUMENT_FILE: &str = "did-document.json";
const LEGACY_DEVICE_CREDENTIAL_FILE: &str = "device-credential.json";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityDirectoryMetadata {
    pub contract_version: u32,
    pub owner_did: String,
    pub active_device_slug: String,
    pub created_at: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceMetadata {
    pub slug: String,
    pub name: String,
    pub owner_did: String,
    pub device_did: String,
    pub created_at: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PeerTrustState {
    Trusted,
    Pending,
    Blocked,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KnownPeerRecord {
    pub did: String,
    pub trust_state: PeerTrustState,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pinned_endpoints: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_seen_signed_record: Option<String>,
    pub updated_at: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RotationRecord {
    pub event_id: String,
    pub kind: RotationKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_device_slug: Option<String>,
    pub status: RotationStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    pub recorded_at: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RotationKind {
    RootKeyRotation,
    DeviceReissuance,
    DeviceRevocation,
    RecoveryExport,
    MultiDeviceJoin,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RotationStatus {
    Planned,
    Completed,
    Revoked,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupMetadata {
    pub strategy: String,
    pub requires_offline_copy: bool,
    pub export_format: String,
    pub updated_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_exported_at: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceJoinRequest {
    pub device_name: String,
    pub device_slug: String,
    pub requested_at: u64,
    pub status: JoinRequestStatus,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum JoinRequestStatus {
    Pending,
    Approved,
    Rejected,
}

#[derive(Clone, Debug, PartialEq)]
pub struct StoredIdentity {
    pub metadata: IdentityDirectoryMetadata,
    pub active_device: DeviceMetadata,
    pub did_document: DidDocument,
    pub device_credential: Credential,
}

/// Standardized on-disk identity directory contract for the private-node runtime.
pub struct IdentityDirectory {
    root: PathBuf,
}

impl IdentityDirectory {
    pub fn new(root: impl AsRef<Path>) -> Self {
        Self {
            root: root.as_ref().to_path_buf(),
        }
    }

    pub fn path(&self) -> &Path {
        &self.root
    }

    pub fn exists(&self) -> bool {
        self.root.exists()
    }

    pub fn initialize(
        &self,
        device_name: &str,
        endpoints: &[ServiceEndpoint],
    ) -> Result<StoredIdentity, IdentityError> {
        if self.metadata_path().exists() || self.legacy_did_path().exists() {
            return Err(IdentityError::InvalidState(format!(
                "identity already exists at {}",
                self.root.display()
            )));
        }

        std::fs::create_dir_all(&self.root)?;
        std::fs::create_dir_all(self.root.join(ROOT_DIR))?;
        std::fs::create_dir_all(self.root.join(DEVICES_DIR))?;
        std::fs::create_dir_all(self.root.join(DOCUMENTS_DIR))?;
        std::fs::create_dir_all(self.root.join(TRUST_DIR))?;
        std::fs::create_dir_all(self.root.join(DISCOVERY_DIR))?;
        std::fs::create_dir_all(self.root.join(ROTATION_DIR))?;
        std::fs::create_dir_all(self.root.join(BACKUP_DIR))?;

        let root_identity = RootIdentity::generate();
        let device = root_identity.issue_device(device_name)?;
        let did_document = root_identity.document(endpoints.to_vec());
        let device_slug = slugify_device_name(device_name);
        let created_at = now_secs()?;
        let metadata = IdentityDirectoryMetadata {
            contract_version: CONTRACT_VERSION,
            owner_did: root_identity.did().to_string(),
            active_device_slug: device_slug.clone(),
            created_at,
        };
        let active_device = DeviceMetadata {
            slug: device_slug.clone(),
            name: device.device_name().to_string(),
            owner_did: device.owner_did().to_string(),
            device_did: device.device_did().to_string(),
            created_at,
        };
        let device_dir = self.device_dir(&device_slug);

        std::fs::create_dir_all(&device_dir)?;
        write_secure_file(
            &self.root.join(OWNER_DID_FILE),
            root_identity.did().as_str().as_bytes(),
        )?;
        write_json(&self.metadata_path(), &metadata)?;
        write_json(&self.did_document_path(), &did_document)?;
        write_secure_file(
            &self.root.join(LEGACY_DID_FILE),
            root_identity.did().as_str().as_bytes(),
        )?;
        std::fs::write(
            self.root.join(LEGACY_DEVICE_NAME_FILE),
            device.device_name(),
        )?;
        write_json(&self.root.join(LEGACY_DID_DOCUMENT_FILE), &did_document)?;
        write_json(
            &self.root.join(LEGACY_DEVICE_CREDENTIAL_FILE),
            device.attestation(),
        )?;
        write_json(&self.trust_store_path(), &Vec::<KnownPeerRecord>::new())?;
        write_json(&self.discovery_path(), &did_document.service)?;
        write_json(&self.rotation_history_path(), &Vec::<RotationRecord>::new())?;
        write_json(&self.join_requests_path(), &Vec::<DeviceJoinRequest>::new())?;
        write_json(
            &self.backup_metadata_path(),
            &BackupMetadata {
                strategy: "offline-copy-required".into(),
                requires_offline_copy: true,
                export_format: "identity-directory-v1".into(),
                updated_at: created_at,
                last_exported_at: None,
            },
        )?;
        std::fs::write(self.active_device_path(), &device_slug)?;

        write_secure_file(
            &self.root.join(ROOT_DIR).join("signing.key"),
            &root_identity.signing_keypair().secret_key_bytes(),
        )?;
        std::fs::write(
            self.root.join(ROOT_DIR).join("signing.pub"),
            root_identity.signing_keypair().public_key_bytes(),
        )?;
        write_secure_file(
            &self.root.join(ROOT_DIR).join("exchange.key"),
            &root_identity.exchange_secret_key().to_bytes(),
        )?;
        std::fs::write(
            self.root.join(ROOT_DIR).join("exchange.pub"),
            root_identity.exchange_public_key().to_bytes(),
        )?;

        write_json(&device_dir.join("device.json"), &active_device)?;
        write_json(&device_dir.join("attestation.json"), device.attestation())?;
        write_secure_file(
            &device_dir.join("signing.key"),
            &device.signing_keypair().secret_key_bytes(),
        )?;
        std::fs::write(
            device_dir.join("signing.pub"),
            device.signing_keypair().public_key_bytes(),
        )?;
        write_secure_file(
            &device_dir.join("exchange.key"),
            &device.exchange_secret_key().to_bytes(),
        )?;
        std::fs::write(
            device_dir.join("exchange.pub"),
            device.exchange_public_key().to_bytes(),
        )?;

        Ok(StoredIdentity {
            metadata,
            active_device,
            did_document,
            device_credential: device.attestation().clone(),
        })
    }

    pub fn load(&self) -> Result<StoredIdentity, IdentityError> {
        if self.metadata_path().exists() {
            let metadata: IdentityDirectoryMetadata = read_json(&self.metadata_path())?;
            let active_device: DeviceMetadata = read_json(
                &self
                    .device_dir(&metadata.active_device_slug)
                    .join("device.json"),
            )?;
            let did_document: DidDocument = read_json(&self.did_document_path())?;
            let device_credential: Credential = read_json(
                &self
                    .device_dir(&metadata.active_device_slug)
                    .join("attestation.json"),
            )?;

            return Ok(StoredIdentity {
                metadata,
                active_device,
                did_document,
                device_credential,
            });
        }

        self.load_legacy()
    }

    pub fn read_owner_did(&self) -> Result<String, IdentityError> {
        if self.owner_did_path().exists() {
            return Ok(std::fs::read_to_string(self.owner_did_path())?
                .trim()
                .to_string());
        }
        if self.legacy_did_path().exists() {
            return Ok(std::fs::read_to_string(self.legacy_did_path())?
                .trim()
                .to_string());
        }
        Err(IdentityError::InvalidState(format!(
            "missing owner DID in {}",
            self.root.display()
        )))
    }

    pub fn load_runtime_identity(&self) -> Result<RuntimeIdentity, IdentityError> {
        let stored = self.load()?;
        let active_device_dir = self.device_dir(&stored.metadata.active_device_slug);
        RuntimeIdentity::new(
            stored,
            self.load_signing_keypair(
                &self.root.join(ROOT_DIR).join("signing.pub"),
                &self.root.join(ROOT_DIR).join("signing.key"),
            )?,
            self.load_exchange_public_key(&self.root.join(ROOT_DIR).join("exchange.pub"))?,
            self.load_exchange_secret_key(&self.root.join(ROOT_DIR).join("exchange.key"))?,
            self.load_signing_keypair(
                &active_device_dir.join("signing.pub"),
                &active_device_dir.join("signing.key"),
            )?,
            self.load_exchange_public_key(&active_device_dir.join("exchange.pub"))?,
            self.load_exchange_secret_key(&active_device_dir.join("exchange.key"))?,
        )
    }

    pub fn list_rotation_history(&self) -> Result<Vec<RotationRecord>, IdentityError> {
        read_json(&self.rotation_history_path())
    }

    pub fn list_known_peers(&self) -> Result<Vec<KnownPeerRecord>, IdentityError> {
        read_json(&self.trust_store_path())
    }

    pub fn append_rotation_record(&self, record: RotationRecord) -> Result<(), IdentityError> {
        let mut records = self.list_rotation_history()?;
        records.push(record);
        write_json(&self.rotation_history_path(), &records)
    }

    pub fn list_join_requests(&self) -> Result<Vec<DeviceJoinRequest>, IdentityError> {
        read_json(&self.join_requests_path())
    }

    pub fn record_join_request(
        &self,
        device_name: impl Into<String>,
    ) -> Result<DeviceJoinRequest, IdentityError> {
        let device_name = device_name.into();
        let request = DeviceJoinRequest {
            device_slug: slugify_device_name(&device_name),
            device_name,
            requested_at: now_secs()?,
            status: JoinRequestStatus::Pending,
        };
        let mut requests = self.list_join_requests()?;
        requests.push(request.clone());
        write_json(&self.join_requests_path(), &requests)?;
        Ok(request)
    }

    pub fn update_backup_metadata(&self, metadata: BackupMetadata) -> Result<(), IdentityError> {
        write_json(&self.backup_metadata_path(), &metadata)
    }

    pub fn load_backup_metadata(&self) -> Result<BackupMetadata, IdentityError> {
        read_json(&self.backup_metadata_path())
    }

    fn load_legacy(&self) -> Result<StoredIdentity, IdentityError> {
        let owner_did = std::fs::read_to_string(self.legacy_did_path())?
            .trim()
            .to_string();
        let device_name = std::fs::read_to_string(self.root.join(LEGACY_DEVICE_NAME_FILE))?
            .trim()
            .to_string();
        let did_document: DidDocument = read_json(&self.root.join(LEGACY_DID_DOCUMENT_FILE))?;
        let device_credential: Credential =
            read_json(&self.root.join(LEGACY_DEVICE_CREDENTIAL_FILE))?;
        let device_slug = slugify_device_name(&device_name);
        let legacy_created_at = device_credential.issued_at;
        Ok(StoredIdentity {
            metadata: IdentityDirectoryMetadata {
                contract_version: LEGACY_CONTRACT_VERSION,
                owner_did: owner_did.clone(),
                active_device_slug: device_slug.clone(),
                created_at: legacy_created_at,
            },
            active_device: DeviceMetadata {
                slug: device_slug,
                name: device_name,
                owner_did,
                device_did: device_credential.subject.to_string(),
                created_at: legacy_created_at,
            },
            did_document,
            device_credential,
        })
    }

    fn metadata_path(&self) -> PathBuf {
        self.root.join(IDENTITY_METADATA_FILE)
    }

    fn owner_did_path(&self) -> PathBuf {
        self.root.join(OWNER_DID_FILE)
    }

    fn did_document_path(&self) -> PathBuf {
        self.root.join(DID_DOCUMENT_FILE)
    }

    fn active_device_path(&self) -> PathBuf {
        self.root.join(ACTIVE_DEVICE_FILE)
    }

    fn trust_store_path(&self) -> PathBuf {
        self.root.join(TRUST_STORE_FILE)
    }

    fn discovery_path(&self) -> PathBuf {
        self.root.join(DISCOVERY_FILE)
    }

    fn rotation_history_path(&self) -> PathBuf {
        self.root.join(ROTATION_HISTORY_FILE)
    }

    fn backup_metadata_path(&self) -> PathBuf {
        self.root.join(BACKUP_METADATA_FILE)
    }

    fn join_requests_path(&self) -> PathBuf {
        self.root.join(JOIN_REQUESTS_FILE)
    }

    fn device_dir(&self, device_slug: &str) -> PathBuf {
        self.root.join(DEVICES_DIR).join(device_slug)
    }

    fn legacy_did_path(&self) -> PathBuf {
        self.root.join(LEGACY_DID_FILE)
    }

    fn load_signing_keypair(
        &self,
        public_key_path: &Path,
        secret_key_path: &Path,
    ) -> Result<SigningKeypair, IdentityError> {
        let public_key = std::fs::read(public_key_path)?;
        let secret_key = std::fs::read(secret_key_path)?;
        SigningKeypair::from_bytes(&public_key, &secret_key).map_err(IdentityError::from)
    }

    fn load_exchange_public_key(&self, path: &Path) -> Result<HybridPublicKey, IdentityError> {
        let bytes = std::fs::read(path)?;
        HybridPublicKey::from_bytes(&bytes).map_err(IdentityError::from)
    }

    fn load_exchange_secret_key(&self, path: &Path) -> Result<HybridSecretKey, IdentityError> {
        let bytes = std::fs::read(path)?;
        HybridSecretKey::from_bytes(&bytes).map_err(IdentityError::from)
    }
}

fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<(), IdentityError> {
    let contents = serde_json::to_vec_pretty(value)
        .map_err(|err| IdentityError::Serialization(err.to_string()))?;
    std::fs::write(path, contents)?;
    Ok(())
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T, IdentityError> {
    let contents = std::fs::read_to_string(path)?;
    serde_json::from_str(&contents).map_err(|err| IdentityError::Serialization(err.to_string()))
}

fn write_secure_file(path: &Path, contents: &[u8]) -> Result<(), IdentityError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, contents)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

fn slugify_device_name(name: &str) -> String {
    let mut slug = String::new();
    let mut last_was_dash = false;
    for ch in name.chars() {
        if ch.is_ascii_alphanumeric() {
            slug.push(ch.to_ascii_lowercase());
            last_was_dash = false;
        } else if !last_was_dash {
            slug.push('-');
            last_was_dash = true;
        }
    }
    let trimmed_slug = slug.trim_matches('-');
    if trimmed_slug.is_empty() {
        "default-device".into()
    } else {
        trimmed_slug.into()
    }
}

fn now_secs() -> Result<u64, IdentityError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|err| IdentityError::InvalidState(err.to_string()))
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::*;

    #[test]
    fn initialize_writes_identity_contract() {
        let dir = tempdir().unwrap();
        let identity_dir = IdentityDirectory::new(dir.path().join("identity"));
        let stored = identity_dir
            .initialize(
                "Laptop 01",
                &[ServiceEndpoint {
                    id: "#primary-node".into(),
                    service_type: "AegisNode".into(),
                    endpoint: "udp://127.0.0.1:51820".into(),
                }],
            )
            .unwrap();

        assert_eq!(stored.metadata.contract_version, CONTRACT_VERSION);
        assert_eq!(stored.active_device.slug, "laptop-01");
        assert!(identity_dir.path().join("root/signing.key").exists());
        assert!(identity_dir
            .path()
            .join("devices/laptop-01/attestation.json")
            .exists());
        assert!(identity_dir.path().join("trust/peers.json").exists());
        assert!(identity_dir.path().join("backup/metadata.json").exists());
        assert!(identity_dir
            .path()
            .join("devices/join-requests.json")
            .exists());
    }

    #[test]
    fn load_roundtrips_initialized_identity() {
        let dir = tempdir().unwrap();
        let identity_dir = IdentityDirectory::new(dir.path().join("identity"));
        let created = identity_dir.initialize("main-device", &[]).unwrap();

        let loaded = identity_dir.load().unwrap();
        assert_eq!(loaded.metadata, created.metadata);
        loaded.device_credential.verify().unwrap();
        assert_eq!(
            identity_dir.read_owner_did().unwrap(),
            created.metadata.owner_did
        );
    }

    #[test]
    fn runtime_identity_loads_and_validates_credentials() {
        let dir = tempdir().unwrap();
        let identity_dir = IdentityDirectory::new(dir.path().join("identity"));
        let created = identity_dir.initialize("main-device", &[]).unwrap();

        let runtime = identity_dir.load_runtime_identity().unwrap();
        assert_eq!(runtime.owner_did(), created.metadata.owner_did);
        assert_eq!(runtime.device_did(), created.active_device.device_did);
        assert_ne!(
            runtime.derive_storage_key(),
            runtime.derive_session_key("peer-a")
        );
    }

    #[test]
    fn join_requests_and_rotation_records_are_persisted() {
        let dir = tempdir().unwrap();
        let identity_dir = IdentityDirectory::new(dir.path().join("identity"));
        identity_dir.initialize("main-device", &[]).unwrap();

        let request = identity_dir.record_join_request("tablet").unwrap();
        identity_dir
            .append_rotation_record(RotationRecord {
                event_id: "rotate-1".into(),
                kind: RotationKind::MultiDeviceJoin,
                target_device_slug: Some(request.device_slug.clone()),
                status: RotationStatus::Planned,
                note: Some("Approve tablet join".into()),
                recorded_at: request.requested_at,
            })
            .unwrap();

        assert_eq!(identity_dir.list_join_requests().unwrap().len(), 1);
        assert_eq!(identity_dir.list_rotation_history().unwrap().len(), 1);
    }
}
