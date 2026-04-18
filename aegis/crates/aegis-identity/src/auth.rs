//! Authentication challenges and responses.
//!
//! Implements challenge-response authentication using ML-DSA-65 signatures.
//! The server sends a random challenge; the client signs it with their
//! device key to prove identity.
//!
//! # Planned API
//!
//! ```rust,ignore
//! // Server side
//! let challenge = AuthChallenge::generate();
//! let challenge_bytes = challenge.to_bytes();
//!
//! // Client side
//! let response = AuthResponse::sign(&challenge_bytes, &device_keypair)?;
//!
//! // Server verifies
//! challenge.verify(&response, &client_public_key)?;
//! ```

use std::time::{SystemTime, UNIX_EPOCH};

use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::did::Did;
use crate::{decode_hex, encode_hex, IdentityError};

/// A signed authentication challenge for proving device ownership.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AuthChallenge {
    pub nonce: String,
    pub audience: Did,
    pub created_at: u64,
}

impl AuthChallenge {
    /// Generate a new random challenge for the provided audience DID.
    pub fn generate(audience: &Did) -> Result<Self, IdentityError> {
        let mut nonce = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut nonce);
        Ok(Self {
            nonce: encode_hex(&nonce),
            audience: audience.clone(),
            created_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|err| IdentityError::AuthFailed(err.to_string()))?
                .as_secs(),
        })
    }

    /// Canonical bytes used for signing and verification.
    pub fn to_bytes(&self) -> Result<Vec<u8>, IdentityError> {
        serde_json::to_vec(self).map_err(|err| IdentityError::Serialization(err.to_string()))
    }

    /// Verify that a response was signed by the claimed device DID.
    pub fn verify(&self, response: &AuthResponse) -> Result<(), IdentityError> {
        let public_key_bytes = decode_hex(&response.public_key)?;
        let expected = Did::from_signing_public_key_bytes(&public_key_bytes);
        if expected != response.device_did {
            return Err(IdentityError::AuthFailed(
                "response DID does not match public key".into(),
            ));
        }

        let signature = decode_hex(&response.signature)?;
        let public_key = aegis_crypto::SigningPublicKey::from_bytes(&public_key_bytes)?;
        public_key
            .verify(&self.to_bytes()?, &signature)
            .map_err(|err| IdentityError::AuthFailed(err.to_string()))
    }
}

/// Signed challenge response from a device keypair.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AuthResponse {
    pub device_did: Did,
    pub public_key: String,
    pub signature: String,
}

impl AuthResponse {
    /// Sign a challenge with the supplied device signing key.
    pub fn sign(
        challenge: &AuthChallenge,
        device_keypair: &aegis_crypto::SigningKeypair,
    ) -> Result<Self, IdentityError> {
        let public_key = device_keypair.public_key_bytes();
        let signature = device_keypair.sign(&challenge.to_bytes()?)?;
        Ok(Self {
            device_did: Did::from_signing_public_key_bytes(&public_key),
            public_key: encode_hex(&public_key),
            signature: encode_hex(&signature),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn challenge_roundtrip_verifies() {
        let keypair = aegis_crypto::SigningKeypair::generate();
        let audience = Did::new("did:aegis:audience".to_string()).unwrap();
        let challenge = AuthChallenge::generate(&audience).unwrap();
        let response = AuthResponse::sign(&challenge, &keypair).unwrap();

        challenge.verify(&response).unwrap();
    }
}
