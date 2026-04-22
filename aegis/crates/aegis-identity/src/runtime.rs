use std::time::{SystemTime, UNIX_EPOCH};

use aegis_crypto::{HybridPublicKey, HybridSecretKey, SigningKeypair, SigningPublicKey};
use serde::{Deserialize, Serialize};

use crate::did::{Did, ServiceEndpoint};
use crate::keys::derive_context_key;
use crate::storage::StoredIdentity;
use crate::{decode_hex, encode_hex, IdentityError};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeAdvertisement {
    pub owner_did: String,
    pub device_did: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub endpoints: Vec<ServiceEndpoint>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub protocol_capabilities: Vec<String>,
    pub version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub room_endpoint_hint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shared_node_hint: Option<String>,
    pub issued_at: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeAdvertisementProof {
    pub verification_method: String,
    pub signature: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedNodeAdvertisement {
    #[serde(flatten)]
    pub advertisement: NodeAdvertisement,
    pub proof: NodeAdvertisementProof,
}

/// Verified identity material ready for desktop/runtime bootstrap.
pub struct RuntimeIdentity {
    stored: StoredIdentity,
    root_signing_keypair: SigningKeypair,
    root_exchange_public_key: HybridPublicKey,
    root_exchange_secret_key: HybridSecretKey,
    active_device_signing_keypair: SigningKeypair,
    active_device_exchange_public_key: HybridPublicKey,
    active_device_exchange_secret_key: HybridSecretKey,
}

impl RuntimeIdentity {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        stored: StoredIdentity,
        root_signing_keypair: SigningKeypair,
        root_exchange_public_key: HybridPublicKey,
        root_exchange_secret_key: HybridSecretKey,
        active_device_signing_keypair: SigningKeypair,
        active_device_exchange_public_key: HybridPublicKey,
        active_device_exchange_secret_key: HybridSecretKey,
    ) -> Result<Self, IdentityError> {
        stored.device_credential.verify()?;
        if stored.metadata.owner_did != stored.did_document.id.to_string() {
            return Err(IdentityError::InvalidState(
                "DID document does not match stored owner DID".into(),
            ));
        }
        if stored.active_device.device_did != stored.device_credential.subject.to_string() {
            return Err(IdentityError::InvalidState(
                "device metadata does not match active device credential subject".into(),
            ));
        }
        if stored.metadata.owner_did != stored.device_credential.issuer.to_string() {
            return Err(IdentityError::InvalidState(
                "device credential issuer does not match stored owner DID".into(),
            ));
        }

        Ok(Self {
            stored,
            root_signing_keypair,
            root_exchange_public_key,
            root_exchange_secret_key,
            active_device_signing_keypair,
            active_device_exchange_public_key,
            active_device_exchange_secret_key,
        })
    }

    pub fn owner_did(&self) -> &str {
        &self.stored.metadata.owner_did
    }

    pub fn device_did(&self) -> &str {
        &self.stored.active_device.device_did
    }

    pub fn device_name(&self) -> &str {
        &self.stored.active_device.name
    }

    pub fn service_endpoints(&self) -> &[ServiceEndpoint] {
        &self.stored.did_document.service
    }

    pub fn stored_identity(&self) -> &StoredIdentity {
        &self.stored
    }

    pub fn root_exchange_public_key(&self) -> &HybridPublicKey {
        &self.root_exchange_public_key
    }

    pub fn root_exchange_secret_key(&self) -> &HybridSecretKey {
        &self.root_exchange_secret_key
    }

    pub fn active_device_exchange_public_key(&self) -> &HybridPublicKey {
        &self.active_device_exchange_public_key
    }

    pub fn active_device_exchange_secret_key(&self) -> &HybridSecretKey {
        &self.active_device_exchange_secret_key
    }

    pub fn active_device_signing_keypair(&self) -> &SigningKeypair {
        &self.active_device_signing_keypair
    }

    pub fn derive_storage_key(&self) -> [u8; 32] {
        derive_context_key(
            &self.active_device_exchange_secret_key,
            "storage",
            self.device_name(),
        )
    }

    pub fn derive_session_key(&self, context: &str) -> [u8; 32] {
        derive_context_key(&self.active_device_exchange_secret_key, "session", context)
    }

    pub fn sign_node_advertisement(
        &self,
        protocol_capabilities: Vec<String>,
        version: impl Into<String>,
        room_endpoint_hint: Option<String>,
        shared_node_hint: Option<String>,
    ) -> Result<SignedNodeAdvertisement, IdentityError> {
        SignedNodeAdvertisement::sign(
            NodeAdvertisement {
                owner_did: self.owner_did().to_string(),
                device_did: self.device_did().to_string(),
                endpoints: self.service_endpoints().to_vec(),
                protocol_capabilities,
                version: version.into(),
                room_endpoint_hint,
                shared_node_hint,
                issued_at: now_secs()?,
            },
            &self.root_signing_keypair,
        )
    }
}

impl SignedNodeAdvertisement {
    pub fn sign(
        advertisement: NodeAdvertisement,
        signing_keypair: &SigningKeypair,
    ) -> Result<Self, IdentityError> {
        let verification_method = encode_hex(&signing_keypair.public_key_bytes());
        let signature = signing_keypair.sign(&advertisement.to_signing_bytes()?)?;
        Ok(Self {
            advertisement,
            proof: NodeAdvertisementProof {
                verification_method,
                signature: encode_hex(&signature),
            },
        })
    }

    pub fn verify(&self) -> Result<(), IdentityError> {
        let public_key_bytes = decode_hex(&self.proof.verification_method)?;
        let public_key = SigningPublicKey::from_bytes(&public_key_bytes)?;
        let expected_owner = Did::from_signing_public_key_bytes(&public_key_bytes);
        if self.advertisement.owner_did != expected_owner.to_string() {
            return Err(IdentityError::InvalidState(
                "node advertisement owner DID does not match proof key".into(),
            ));
        }
        let signature = decode_hex(&self.proof.signature)?;
        public_key
            .verify(&self.advertisement.to_signing_bytes()?, &signature)
            .map_err(IdentityError::from)
    }
}

impl NodeAdvertisement {
    fn to_signing_bytes(&self) -> Result<Vec<u8>, IdentityError> {
        serde_json::to_vec(self).map_err(|err| IdentityError::Serialization(err.to_string()))
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
    use aegis_crypto::AegisCrypto;

    use super::*;
    use crate::credentials::Credential;
    use crate::did::DidDocument;
    use crate::storage::{DeviceMetadata, IdentityDirectoryMetadata};

    fn sample_runtime_identity() -> RuntimeIdentity {
        let root_signing_keypair = SigningKeypair::generate();
        let owner_did =
            Did::from_signing_public_key_bytes(&root_signing_keypair.public_key_bytes());
        let (root_exchange_public_key, root_exchange_secret_key) = AegisCrypto::keygen();

        let active_device_signing_keypair = SigningKeypair::generate();
        let device_did =
            Did::from_signing_public_key_bytes(&active_device_signing_keypair.public_key_bytes());
        let (active_device_exchange_public_key, active_device_exchange_secret_key) =
            AegisCrypto::keygen();

        let credential = Credential::builder()
            .issuer(&owner_did)
            .subject(&device_did)
            .credential_type("DeviceCredential")
            .sign(&root_signing_keypair)
            .unwrap();

        RuntimeIdentity::new(
            StoredIdentity {
                metadata: IdentityDirectoryMetadata {
                    contract_version: 1,
                    owner_did: owner_did.to_string(),
                    active_device_slug: "main-device".into(),
                    created_at: 1,
                },
                active_device: DeviceMetadata {
                    slug: "main-device".into(),
                    name: "main-device".into(),
                    owner_did: owner_did.to_string(),
                    device_did: device_did.to_string(),
                    created_at: 1,
                },
                did_document: DidDocument::new(
                    &root_signing_keypair.public_key_bytes(),
                    &root_exchange_public_key.to_bytes(),
                    vec![ServiceEndpoint {
                        id: "#primary-node".into(),
                        service_type: "AegisNode".into(),
                        endpoint: "udp://127.0.0.1:51820".into(),
                    }],
                ),
                device_credential: credential,
            },
            root_signing_keypair,
            root_exchange_public_key,
            root_exchange_secret_key,
            active_device_signing_keypair,
            active_device_exchange_public_key,
            active_device_exchange_secret_key,
        )
        .unwrap()
    }

    #[test]
    fn signed_advertisement_verifies() {
        let runtime = sample_runtime_identity();
        let advertisement = runtime
            .sign_node_advertisement(
                vec!["vault://".into(), "node://".into()],
                "0.1.0",
                Some("vault://social/space/index.html".into()),
                None,
            )
            .unwrap();

        advertisement.verify().unwrap();
        assert_eq!(advertisement.advertisement.owner_did, runtime.owner_did());
    }

    #[test]
    fn runtime_identity_derives_distinct_session_and_storage_keys() {
        let runtime = sample_runtime_identity();
        assert_ne!(
            runtime.derive_storage_key(),
            runtime.derive_session_key("peer-a")
        );
    }
}
