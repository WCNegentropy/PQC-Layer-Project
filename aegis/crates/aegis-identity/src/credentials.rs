//! Verifiable Credentials (VCs).
//!
//! Issue, hold, and verify W3C Verifiable Credentials signed with
//! ML-DSA-65 post-quantum signatures.
//!
//! # Planned API
//!
//! ```rust,ignore
//! let vc = Credential::builder()
//!     .issuer(&issuer_did)
//!     .subject(&subject_did)
//!     .claim("role", "admin")
//!     .sign(&issuer_keypair)?;
//!
//! vc.verify(&issuer_public_key)?;
//! ```

use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use aegis_crypto::SigningPublicKey;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::did::Did;
use crate::{decode_hex, encode_hex, IdentityError};

/// Verifiable-credential proof block signed with ML-DSA-65.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CredentialProof {
    #[serde(rename = "type")]
    pub proof_type: String,
    pub verification_method: String,
    pub signature: String,
}

/// Minimal verifiable credential for device and inventory attestations.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Credential {
    #[serde(rename = "@context")]
    pub context: String,
    #[serde(rename = "type")]
    pub credential_type: Vec<String>,
    pub issuer: Did,
    pub subject: Did,
    pub issued_at: u64,
    #[serde(default)]
    pub claims: BTreeMap<String, Value>,
    pub proof: CredentialProof,
}

#[derive(Clone, Debug)]
struct UnsignedCredential {
    context: String,
    credential_type: Vec<String>,
    issuer: Did,
    subject: Did,
    issued_at: u64,
    claims: BTreeMap<String, Value>,
}

impl UnsignedCredential {
    fn to_signing_bytes(&self) -> Result<Vec<u8>, IdentityError> {
        serde_json::to_vec(self).map_err(|err| IdentityError::Serialization(err.to_string()))
    }
}

impl serde::Serialize for UnsignedCredential {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeMap;

        let mut map = serializer.serialize_map(Some(6))?;
        map.serialize_entry("@context", &self.context)?;
        map.serialize_entry("type", &self.credential_type)?;
        map.serialize_entry("issuer", &self.issuer)?;
        map.serialize_entry("subject", &self.subject)?;
        map.serialize_entry("issued_at", &self.issued_at)?;
        map.serialize_entry("claims", &self.claims)?;
        map.end()
    }
}

/// Builder for ML-DSA-signed credentials.
#[derive(Default)]
pub struct CredentialBuilder {
    issuer: Option<Did>,
    subject: Option<Did>,
    credential_type: Vec<String>,
    claims: BTreeMap<String, Value>,
}

impl Credential {
    /// Start building a credential.
    pub fn builder() -> CredentialBuilder {
        CredentialBuilder {
            credential_type: vec!["VerifiableCredential".into()],
            ..CredentialBuilder::default()
        }
    }

    fn unsigned(&self) -> UnsignedCredential {
        UnsignedCredential {
            context: self.context.clone(),
            credential_type: self.credential_type.clone(),
            issuer: self.issuer.clone(),
            subject: self.subject.clone(),
            issued_at: self.issued_at,
            claims: self.claims.clone(),
        }
    }

    /// Verify the credential signature and DID binding.
    pub fn verify(&self) -> Result<(), IdentityError> {
        let public_key_bytes = decode_hex(&self.proof.verification_method)?;
        let public_key = SigningPublicKey::from_bytes(&public_key_bytes)?;
        let expected_issuer = Did::from_signing_public_key_bytes(&public_key_bytes);
        if self.issuer != expected_issuer {
            return Err(IdentityError::CredentialInvalid(
                "issuer DID does not match proof key".into(),
            ));
        }

        let signature = decode_hex(&self.proof.signature)?;
        public_key
            .verify(&self.unsigned().to_signing_bytes()?, &signature)
            .map_err(|err| IdentityError::CredentialInvalid(err.to_string()))
    }
}

impl CredentialBuilder {
    pub fn issuer(mut self, issuer: &Did) -> Self {
        self.issuer = Some(issuer.clone());
        self
    }

    pub fn subject(mut self, subject: &Did) -> Self {
        self.subject = Some(subject.clone());
        self
    }

    pub fn credential_type(mut self, credential_type: impl Into<String>) -> Self {
        self.credential_type.push(credential_type.into());
        self
    }

    pub fn claim(mut self, name: impl Into<String>, value: impl Into<Value>) -> Self {
        self.claims.insert(name.into(), value.into());
        self
    }

    pub fn sign(
        self,
        issuer_keypair: &aegis_crypto::SigningKeypair,
    ) -> Result<Credential, IdentityError> {
        let issuer = self
            .issuer
            .ok_or_else(|| IdentityError::CredentialInvalid("missing issuer".into()))?;
        let subject = self
            .subject
            .ok_or_else(|| IdentityError::CredentialInvalid("missing subject".into()))?;

        let unsigned = UnsignedCredential {
            context: "https://www.w3.org/ns/credentials/v2".into(),
            credential_type: self.credential_type,
            issuer: issuer.clone(),
            subject: subject.clone(),
            issued_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|err| IdentityError::CredentialInvalid(err.to_string()))?
                .as_secs(),
            claims: self.claims,
        };

        let public_key_bytes = issuer_keypair.public_key_bytes();
        let signature = issuer_keypair.sign(&unsigned.to_signing_bytes()?)?;
        Ok(Credential {
            context: unsigned.context,
            credential_type: unsigned.credential_type,
            issuer,
            subject,
            issued_at: unsigned.issued_at,
            claims: unsigned.claims,
            proof: CredentialProof {
                proof_type: "ML-DSA-65".into(),
                verification_method: encode_hex(&public_key_bytes),
                signature: encode_hex(&signature),
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn signed_credential_verifies() {
        let signing = aegis_crypto::SigningKeypair::generate();
        let issuer = Did::from_signing_public_key_bytes(&signing.public_key_bytes());
        let subject = Did::new("did:aegis:subject".to_string()).unwrap();

        let credential = Credential::builder()
            .issuer(&issuer)
            .subject(&subject)
            .credential_type("DeviceCredential")
            .claim("device_name", json!("laptop-01"))
            .sign(&signing)
            .unwrap();

        credential.verify().unwrap();
    }

    #[test]
    fn tampered_claims_fail_verification() {
        let signing = aegis_crypto::SigningKeypair::generate();
        let issuer = Did::from_signing_public_key_bytes(&signing.public_key_bytes());
        let subject = Did::new("did:aegis:subject".to_string()).unwrap();

        let mut credential = Credential::builder()
            .issuer(&issuer)
            .subject(&subject)
            .claim("role", json!("member"))
            .sign(&signing)
            .unwrap();
        credential.claims.insert("role".into(), json!("admin"));

        assert!(credential.verify().is_err());
    }
}
