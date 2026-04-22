use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::SocialError;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalNodeRecord {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub endpoints: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub protocol_capabilities: Vec<String>,
    pub runtime_version: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PeerTrustState {
    Trusted,
    Pending,
    Blocked,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerRecord {
    pub did: String,
    pub trust_state: PeerTrustState,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pinned_endpoints: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_seen_signed_record: Option<String>,
    pub updated_at: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActiveConnection {
    pub peer_did: String,
    pub transport: String,
    pub connected_at: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateNodeState {
    pub owner_did: String,
    pub identity_dir: PathBuf,
    pub vault_dir: PathBuf,
    pub local_record: LocalNodeRecord,
    #[serde(default)]
    pub peer_trust_store: BTreeMap<String, PeerRecord>,
    #[serde(default)]
    pub active_connections: Vec<ActiveConnection>,
    #[serde(default)]
    pub feature_flags: BTreeMap<String, bool>,
}

impl PrivateNodeState {
    pub fn new(
        owner_did: impl Into<String>,
        identity_dir: impl AsRef<Path>,
        vault_dir: impl AsRef<Path>,
    ) -> Self {
        Self {
            owner_did: owner_did.into(),
            identity_dir: identity_dir.as_ref().to_path_buf(),
            vault_dir: vault_dir.as_ref().to_path_buf(),
            local_record: LocalNodeRecord {
                endpoints: Vec::new(),
                protocol_capabilities: vec![
                    "vault://".into(),
                    "node://".into(),
                    "sanctuary://".into(),
                ],
                runtime_version: env!("CARGO_PKG_VERSION").into(),
            },
            peer_trust_store: BTreeMap::new(),
            active_connections: Vec::new(),
            feature_flags: BTreeMap::new(),
        }
    }

    pub fn add_endpoint(&mut self, endpoint: impl Into<String>) {
        let endpoint = endpoint.into();
        if !self.local_record.endpoints.contains(&endpoint) {
            self.local_record.endpoints.push(endpoint);
        }
    }

    pub fn set_feature_flag(&mut self, name: impl Into<String>, enabled: bool) {
        self.feature_flags.insert(name.into(), enabled);
    }

    pub fn set_peer_trust(
        &mut self,
        did: impl Into<String>,
        trust_state: PeerTrustState,
        pinned_endpoints: Vec<String>,
    ) {
        let did = did.into();
        self.peer_trust_store.insert(
            did.clone(),
            PeerRecord {
                did,
                trust_state,
                pinned_endpoints,
                last_seen_signed_record: None,
                updated_at: now_secs().unwrap_or_default(),
            },
        );
    }

    pub fn record_signed_peer_record(
        &mut self,
        did: &str,
        signed_record: impl Into<String>,
    ) -> Result<(), SocialError> {
        let peer = self
            .peer_trust_store
            .get_mut(did)
            .ok_or_else(|| SocialError::InvalidNodeState(format!("unknown peer DID {did}")))?;
        peer.last_seen_signed_record = Some(signed_record.into());
        peer.updated_at = now_secs().unwrap_or_default();
        Ok(())
    }

    pub fn record_connection(
        &mut self,
        peer_did: impl Into<String>,
        transport: impl Into<String>,
    ) {
        self.active_connections.push(ActiveConnection {
            peer_did: peer_did.into(),
            transport: transport.into(),
            connected_at: now_secs().unwrap_or_default(),
        });
    }

    pub fn disconnect_peer(&mut self, peer_did: &str) {
        self.active_connections
            .retain(|connection| connection.peer_did != peer_did);
    }

    pub fn validate(&self) -> Result<(), SocialError> {
        if self.owner_did.trim().is_empty() {
            return Err(SocialError::InvalidNodeState(
                "owner DID cannot be empty".into(),
            ));
        }
        if !self.identity_dir.is_absolute() || !self.vault_dir.is_absolute() {
            return Err(SocialError::InvalidNodeState(
                "identity and vault paths must be absolute".into(),
            ));
        }
        if self
            .active_connections
            .iter()
            .any(|connection| !self.peer_trust_store.contains_key(&connection.peer_did))
        {
            return Err(SocialError::InvalidNodeState(
                "active connection references unknown peer".into(),
            ));
        }
        Ok(())
    }
}

fn now_secs() -> Result<u64, std::time::SystemTimeError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_state_tracks_peer_trust_and_connections() {
        let mut state = PrivateNodeState::new(
            "did:aegis:owner",
            "/tmp/aegis-identity",
            "/tmp/aegis-vault",
        );
        state.add_endpoint("udp://127.0.0.1:51820");
        state.set_feature_flag("browser-shell", true);
        state.set_peer_trust(
            "did:aegis:peer",
            PeerTrustState::Trusted,
            vec!["udp://10.0.0.2:51820".into()],
        );
        state
            .record_signed_peer_record("did:aegis:peer", "signed-node-record")
            .unwrap();
        state.record_connection("did:aegis:peer", "pqwg");

        state.validate().unwrap();
        assert!(state.feature_flags["browser-shell"]);
        assert_eq!(state.active_connections.len(), 1);
        assert_eq!(
            state.peer_trust_store["did:aegis:peer"].last_seen_signed_record.as_deref(),
            Some("signed-node-record")
        );
    }

    #[test]
    fn validate_rejects_unknown_active_peer() {
        let mut state = PrivateNodeState::new(
            "did:aegis:owner",
            "/tmp/aegis-identity",
            "/tmp/aegis-vault",
        );
        state.record_connection("did:aegis:missing", "pqwg");

        assert!(matches!(
            state.validate(),
            Err(SocialError::InvalidNodeState(_))
        ));
    }
}
