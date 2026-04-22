//! Key hierarchy management.
//!
//! Implements the Aegis key derivation tree:
//!
//! ```text
//! Root Key (ML-DSA-65 + Ed25519)
//! ├── Device Key (HKDF-derived, per device)
//! │   ├── Session Key (ephemeral, per connection)
//! │   └── Storage Key (for vault encryption)
//! └── Recovery Key (Shamir secret sharing, offline)
//! ```
//!
//! # Planned API
//!
//! ```rust,ignore
//! let root = RootKeypair::generate();
//! let device_key = root.derive_device_key("laptop-01");
//! let session_key = device_key.derive_session_key();
//! ```

use aegis_crypto::{AegisCrypto, HybridPublicKey, HybridSecretKey, SigningKeypair};
use serde_json::json;
use sha3::{Digest, Sha3_256};

use crate::credentials::Credential;
use crate::did::{Did, DidDocument, ServiceEndpoint};
use crate::IdentityError;

/// Root identity material for a user-owned private node.
pub struct RootIdentity {
    did: Did,
    signing_keypair: SigningKeypair,
    exchange_public_key: HybridPublicKey,
    exchange_secret_key: HybridSecretKey,
}

impl RootIdentity {
    /// Generate a new root signing + key-agreement identity.
    pub fn generate() -> Self {
        let signing_keypair = SigningKeypair::generate();
        let did = Did::from_signing_public_key_bytes(&signing_keypair.public_key_bytes());
        let (exchange_public_key, exchange_secret_key) = AegisCrypto::keygen();
        Self {
            did,
            signing_keypair,
            exchange_public_key,
            exchange_secret_key,
        }
    }

    /// Build a DID document for local discovery/bootstrap use.
    pub fn document(&self, services: Vec<ServiceEndpoint>) -> DidDocument {
        DidDocument::new(
            &self.signing_keypair.public_key_bytes(),
            &self.exchange_public_key.to_bytes(),
            services,
        )
    }

    /// Issue a device identity attested by the root signing key.
    pub fn issue_device(&self, device_name: &str) -> Result<DeviceIdentity, IdentityError> {
        let device_signing_keypair = SigningKeypair::generate();
        let device_did =
            Did::from_signing_public_key_bytes(&device_signing_keypair.public_key_bytes());
        let (device_exchange_public_key, device_exchange_secret_key) = AegisCrypto::keygen();
        let attestation = Credential::builder()
            .issuer(&self.did)
            .subject(&device_did)
            .credential_type("DeviceCredential")
            .claim("device_name", json!(device_name))
            .claim("device_did", json!(device_did.as_str()))
            .claim(
                "device_exchange_public_key",
                json!(crate::encode_hex(&device_exchange_public_key.to_bytes())),
            )
            .sign(&self.signing_keypair)?;

        Ok(DeviceIdentity {
            owner_did: self.did.clone(),
            device_name: device_name.into(),
            device_did,
            signing_keypair: device_signing_keypair,
            exchange_public_key: device_exchange_public_key,
            exchange_secret_key: device_exchange_secret_key,
            attestation,
        })
    }

    pub fn did(&self) -> &Did {
        &self.did
    }

    pub fn signing_keypair(&self) -> &SigningKeypair {
        &self.signing_keypair
    }

    pub fn exchange_public_key(&self) -> &HybridPublicKey {
        &self.exchange_public_key
    }

    pub fn exchange_secret_key(&self) -> &HybridSecretKey {
        &self.exchange_secret_key
    }
}

/// Device identity material scoped beneath a root identity.
pub struct DeviceIdentity {
    owner_did: Did,
    device_name: String,
    device_did: Did,
    signing_keypair: SigningKeypair,
    exchange_public_key: HybridPublicKey,
    exchange_secret_key: HybridSecretKey,
    attestation: Credential,
}

impl DeviceIdentity {
    /// Derive a stable storage key for the device.
    pub fn derive_storage_key(&self) -> [u8; 32] {
        self.derive_key("storage", &self.device_name)
    }

    /// Derive a context-bound session key.
    pub fn derive_session_key(&self, context: &str) -> [u8; 32] {
        self.derive_key("session", context)
    }

    fn derive_key(&self, label: &str, context: &str) -> [u8; 32] {
        derive_context_key(&self.exchange_secret_key, label, context)
    }

    pub fn owner_did(&self) -> &Did {
        &self.owner_did
    }

    pub fn device_name(&self) -> &str {
        &self.device_name
    }

    pub fn device_did(&self) -> &Did {
        &self.device_did
    }

    pub fn signing_keypair(&self) -> &SigningKeypair {
        &self.signing_keypair
    }

    pub fn exchange_public_key(&self) -> &HybridPublicKey {
        &self.exchange_public_key
    }

    pub fn exchange_secret_key(&self) -> &HybridSecretKey {
        &self.exchange_secret_key
    }

    pub fn attestation(&self) -> &Credential {
        &self.attestation
    }
}

/// Derive a stable 32-byte key from hybrid exchange secret material.
pub fn derive_context_key(
    exchange_secret_key: &HybridSecretKey,
    label: &str,
    context: &str,
) -> [u8; 32] {
    let secret_bytes = exchange_secret_key.to_bytes();
    let mut hasher = Sha3_256::new();
    hasher.update(&secret_bytes);
    hasher.update(label.as_bytes());
    hasher.update(context.as_bytes());
    let mut output = [0u8; 32];
    output.copy_from_slice(&hasher.finalize());
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issued_device_attestation_verifies() {
        let root = RootIdentity::generate();
        let device = root.issue_device("laptop-01").unwrap();

        assert_eq!(device.owner_did(), root.did());
        device.attestation().verify().unwrap();
    }

    #[test]
    fn derived_keys_are_context_sensitive() {
        let root = RootIdentity::generate();
        let device = root.issue_device("laptop-01").unwrap();

        assert_ne!(
            device.derive_storage_key(),
            device.derive_session_key("peer-a")
        );
        assert_ne!(
            device.derive_session_key("peer-a"),
            device.derive_session_key("peer-b")
        );
    }

    #[test]
    fn document_contains_services() {
        let root = RootIdentity::generate();
        let document = root.document(vec![ServiceEndpoint {
            id: "#primary-node".into(),
            service_type: "AegisNode".into(),
            endpoint: "udp://127.0.0.1:51820".into(),
        }]);

        assert_eq!(document.id, root.did().clone());
        assert_eq!(document.service.len(), 1);
    }
}
