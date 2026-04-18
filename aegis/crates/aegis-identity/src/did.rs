//! Decentralized Identifiers (DIDs).
//!
//! Implements `did:aegis` method for self-sovereign identity.
//! DIDs are derived from the user's root public key and can be
//! resolved without a central authority.
//!
//! # Planned API
//!
//! ```rust,ignore
//! let did = Did::from_public_key(&root_pk);
//! // did:aegis:z6Mk...
//! let document = did.resolve()?;
//! ```

use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

use crate::{encode_hex, IdentityError};

const DID_PREFIX: &str = "did:aegis:";

/// A self-issued `did:aegis` identifier derived from a signing public key.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Did(String);

impl Did {
    /// Construct a DID directly from its string representation.
    pub fn new(value: impl Into<String>) -> Result<Self, IdentityError> {
        let value = value.into();
        if !value.starts_with(DID_PREFIX) {
            return Err(IdentityError::InvalidKey(format!(
                "DID must start with '{DID_PREFIX}'"
            )));
        }
        Ok(Self(value))
    }

    /// Derive a stable DID from ML-DSA public key bytes.
    pub fn from_signing_public_key_bytes(public_key: &[u8]) -> Self {
        let digest = Sha3_256::digest(public_key);
        Self(format!("{DID_PREFIX}{}", encode_hex(&digest)))
    }

    /// Borrow the DID string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for Did {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// A DID document service endpoint for private-node discovery or related roles.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceEndpoint {
    pub id: String,
    #[serde(rename = "type")]
    pub service_type: String,
    pub endpoint: String,
}

/// Minimal DID document for local/private-node discovery bootstrap.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DidDocument {
    pub id: Did,
    pub verification_method: String,
    pub key_agreement: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub service: Vec<ServiceEndpoint>,
}

impl DidDocument {
    /// Build a DID document from signing and key-agreement public keys.
    pub fn new(
        signing_public_key: &[u8],
        key_agreement_public_key: &[u8],
        service: Vec<ServiceEndpoint>,
    ) -> Self {
        Self {
            id: Did::from_signing_public_key_bytes(signing_public_key),
            verification_method: encode_hex(signing_public_key),
            key_agreement: encode_hex(key_agreement_public_key),
            service,
        }
    }

    /// Serialize the DID document as pretty JSON.
    pub fn to_pretty_json(&self) -> Result<String, IdentityError> {
        serde_json::to_string_pretty(self)
            .map_err(|err| IdentityError::Serialization(err.to_string()))
    }

    /// Parse a DID document from JSON.
    pub fn from_json(json: &str) -> Result<Self, IdentityError> {
        serde_json::from_str(json).map_err(|err| IdentityError::Serialization(err.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn did_is_stable_for_same_key() {
        let public_key = [0x42u8; 32];
        assert_eq!(
            Did::from_signing_public_key_bytes(&public_key),
            Did::from_signing_public_key_bytes(&public_key)
        );
    }

    #[test]
    fn document_roundtrip_json() {
        let document = DidDocument::new(
            &[0x11; 32],
            &[0x22; 64],
            vec![ServiceEndpoint {
                id: "#primary-node".into(),
                service_type: "AegisNode".into(),
                endpoint: "udp://127.0.0.1:51820".into(),
            }],
        );

        let json = document.to_pretty_json().unwrap();
        let parsed = DidDocument::from_json(&json).unwrap();
        assert_eq!(parsed, document);
    }
}
