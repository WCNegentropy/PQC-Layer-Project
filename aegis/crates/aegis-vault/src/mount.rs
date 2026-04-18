//! FUSE filesystem mount.
//!
//! Provides a FUSE (Filesystem in Userspace) mount point that transparently
//! encrypts and decrypts files in the vault. Applications see a normal
//! directory; encryption is invisible.
//!
//! # Planned API
//!
//! ```rust,ignore
//! let vault = VaultStore::open("/path/to/vault", &master_key)?;
//! let mount = FuseMount::mount("/mnt/aegis", vault)?;
//! // Files in /mnt/aegis are transparently encrypted
//! mount.unmount()?;
//! ```

use std::path::{Path, PathBuf};

use crate::store::VaultStore;
use crate::VaultError;

/// Placeholder mount handle documenting the desired FUSE contract.
pub struct FuseMount {
    mount_point: PathBuf,
}

impl FuseMount {
    /// Record the intended mount point for a vault-backed filesystem.
    pub fn mount(mount_point: impl AsRef<Path>, _vault: &VaultStore) -> Result<Self, VaultError> {
        let mount_point = mount_point.as_ref().to_path_buf();
        if !mount_point.exists() {
            std::fs::create_dir_all(&mount_point)?;
        }
        Ok(Self { mount_point })
    }

    /// Return the configured mount point.
    pub fn mount_point(&self) -> &Path {
        &self.mount_point
    }

    /// Tear down the placeholder mount handle.
    pub fn unmount(self) -> Result<(), VaultError> {
        Ok(())
    }
}
