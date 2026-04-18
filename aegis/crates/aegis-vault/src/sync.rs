//! CRDT-based sync engine.
//!
//! Uses Conflict-free Replicated Data Types to synchronize vault
//! metadata across multiple devices without a central server.
//!
//! # Planned Approach
//!
//! - File operations are logged as CRDT operations (LWW-Register per file).
//! - Sync peers exchange operation logs over encrypted channels.
//! - Conflicts are resolved automatically by timestamp (last-writer-wins).
//! - Deleted files use tombstones with configurable retention.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::VaultError;

/// A last-writer-wins snapshot entry for a logical path.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncEntry {
    pub logical_path: String,
    pub updated_at: u64,
    pub deleted: bool,
}

/// Minimal CRDT-friendly manifest snapshot used for planned multi-device sync.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncSnapshot {
    pub entries: BTreeMap<String, SyncEntry>,
}

impl SyncSnapshot {
    /// Merge another snapshot using last-writer-wins semantics.
    pub fn merge(&mut self, other: &Self) {
        for (path, incoming) in &other.entries {
            match self.entries.get(path) {
                Some(existing) if existing.updated_at >= incoming.updated_at => {}
                _ => {
                    self.entries.insert(path.clone(), incoming.clone());
                }
            }
        }
    }

    /// Record or update an entry.
    pub fn record(&mut self, logical_path: impl Into<String>, updated_at: u64, deleted: bool) {
        let logical_path = logical_path.into();
        self.entries.insert(
            logical_path.clone(),
            SyncEntry {
                logical_path,
                updated_at,
                deleted,
            },
        );
    }

    /// Ensure the snapshot is internally consistent.
    pub fn validate(&self) -> Result<(), VaultError> {
        if self
            .entries
            .iter()
            .any(|(path, entry)| path != &entry.logical_path)
        {
            return Err(VaultError::SyncConflict(
                "snapshot entry path key mismatch".into(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merge_prefers_newer_entries() {
        let mut left = SyncSnapshot::default();
        left.record("social/profile/profile.json", 10, false);

        let mut right = SyncSnapshot::default();
        right.record("social/profile/profile.json", 20, true);

        left.merge(&right);
        assert!(left.entries["social/profile/profile.json"].deleted);
    }
}
