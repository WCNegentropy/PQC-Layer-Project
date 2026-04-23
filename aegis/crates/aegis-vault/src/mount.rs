//! Virtual vault mount.
//!
//! Provides a Linux-first virtual filesystem projection for the vault by
//! materializing decrypted files into a managed mount directory. The backing
//! storage remains encrypted in the vault, while selected runtime components
//! can interact with a normal directory tree during the mount lifetime.
//!
//! # API
//!
//! ```rust,ignore
//! let vault = VaultStore::open("/path/to/vault", &master_key)?;
//! let mount = FuseMount::mount_read_only("/mnt/aegis", &vault)?;
//! let writable_mount = FuseMount::mount_read_write("/mnt/aegis-rw", &vault)?;
//! writable_mount.unmount()?;
//! mount.unmount()?;
//! ```

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use crate::store::{sibling_temp_path, VaultStore};
use crate::VaultError;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MountMode {
    ReadOnly,
    ReadWrite,
}

/// Managed vault mount backed by a temporary plaintext projection.
pub struct FuseMount {
    mount_point: PathBuf,
    mode: MountMode,
    vault: VaultStore,
}

impl FuseMount {
    /// Mount the vault as a read-only plaintext projection.
    pub fn mount(mount_point: impl AsRef<Path>, vault: &VaultStore) -> Result<Self, VaultError> {
        Self::mount_read_only(mount_point, vault)
    }

    /// Mount the vault as a read-only plaintext projection.
    pub fn mount_read_only(
        mount_point: impl AsRef<Path>,
        vault: &VaultStore,
    ) -> Result<Self, VaultError> {
        Self::mount_with_mode(mount_point, vault, MountMode::ReadOnly)
    }

    /// Mount the vault as a read-write plaintext projection.
    pub fn mount_read_write(
        mount_point: impl AsRef<Path>,
        vault: &VaultStore,
    ) -> Result<Self, VaultError> {
        Self::mount_with_mode(mount_point, vault, MountMode::ReadWrite)
    }

    fn mount_with_mode(
        mount_point: impl AsRef<Path>,
        vault: &VaultStore,
        mode: MountMode,
    ) -> Result<Self, VaultError> {
        let mount_point = mount_point.as_ref().to_path_buf();
        prepare_mount_point(&mount_point, vault.root_path())?;

        let mount = Self {
            mount_point,
            mode,
            vault: vault.clone(),
        };
        mount.materialize_from_vault()?;
        Ok(mount)
    }

    /// Return the configured mount point.
    pub fn mount_point(&self) -> &Path {
        &self.mount_point
    }

    /// Return the configured mount mode.
    pub fn mode(&self) -> MountMode {
        self.mode
    }

    /// Refresh the mount directory from the encrypted vault.
    pub fn refresh(&self) -> Result<(), VaultError> {
        clear_mount_contents(&self.mount_point)?;
        self.materialize_from_vault()
    }

    /// Sync mount-side changes back into the encrypted vault.
    pub fn sync(&self) -> Result<(), VaultError> {
        if self.mode == MountMode::ReadOnly {
            return Err(VaultError::Mount(
                "read-only mounts cannot sync plaintext changes".into(),
            ));
        }

        let mounted_files = collect_plaintext_files(&self.mount_point)?;
        let mounted_paths = mounted_files.keys().cloned().collect::<BTreeSet<_>>();

        for (logical_path, plaintext) in mounted_files {
            match self.vault.read(&logical_path) {
                Ok(existing) if existing == plaintext => {}
                Ok(_) | Err(VaultError::NotFound(_)) => {
                    self.vault.write(&logical_path, &plaintext)?
                }
                Err(err) => return Err(err),
            }
        }

        for stale_path in self.vault.list()? {
            if !mounted_paths.contains(&stale_path) {
                self.vault.delete(&stale_path)?;
            }
        }

        Ok(())
    }

    fn materialize_from_vault(&self) -> Result<(), VaultError> {
        let mut directories = BTreeSet::from([self.mount_point.clone()]);
        for logical_path in self.vault.list()? {
            let mount_path = self.mount_point.join(&logical_path);
            record_parent_directories(&mut directories, &self.mount_point, &mount_path)?;
            if let Some(parent) = mount_path.parent() {
                std::fs::create_dir_all(parent)?;
            }

            let plaintext = self.vault.read(&logical_path)?;
            atomic_write_plaintext(&mount_path, &plaintext)?;
            set_file_permissions(&mount_path, self.mode)?;
        }
        set_directory_permissions(&directories, self.mode)?;
        Ok(())
    }

    /// Tear down the mount and remove the plaintext projection.
    pub fn unmount(self) -> Result<(), VaultError> {
        if self.mode == MountMode::ReadWrite {
            self.sync()?;
        }
        clear_mount_contents(&self.mount_point)
    }
}

fn prepare_mount_point(mount_point: &Path, vault_root: &Path) -> Result<(), VaultError> {
    if mount_point.exists()
        && std::fs::symlink_metadata(mount_point)?
            .file_type()
            .is_symlink()
    {
        return Err(VaultError::Mount(format!(
            "mount point '{}' must not be a symlink",
            mount_point.display()
        )));
    }
    if !mount_point.exists() {
        std::fs::create_dir_all(mount_point)?;
    }
    if !mount_point.is_dir() {
        return Err(VaultError::Mount(format!(
            "mount point '{}' is not a directory",
            mount_point.display()
        )));
    }
    if std::fs::read_dir(mount_point)?.next().is_some() {
        return Err(VaultError::Mount(format!(
            "mount point '{}' must be empty",
            mount_point.display()
        )));
    }

    let mount_point = mount_point.canonicalize()?;
    let vault_root = vault_root.canonicalize()?;
    if mount_point.starts_with(&vault_root) || vault_root.starts_with(&mount_point) {
        return Err(VaultError::Mount(
            "mount point must not overlap the encrypted vault root".into(),
        ));
    }

    Ok(())
}

fn clear_mount_contents(mount_point: &Path) -> Result<(), VaultError> {
    if !mount_point.exists() {
        return Ok(());
    }
    let mount_metadata = std::fs::symlink_metadata(mount_point)?;
    if mount_metadata.file_type().is_symlink() {
        return Err(VaultError::Mount(format!(
            "mount point '{}' must not be a symlink",
            mount_point.display()
        )));
    }
    if !mount_metadata.is_dir() {
        return Err(VaultError::Mount(format!(
            "mount point '{}' is not a directory",
            mount_point.display()
        )));
    }
    set_dir_permissions(mount_point, MountMode::ReadWrite)?;

    for entry in std::fs::read_dir(mount_point)? {
        let entry = entry?;
        let path = entry.path();
        let file_type = entry.file_type()?;
        if file_type.is_symlink() {
            return Err(VaultError::Mount(format!(
                "refusing to traverse symlink '{}'",
                path.display()
            )));
        }
        if file_type.is_dir() {
            make_tree_writable(&path)?;
            std::fs::remove_dir_all(path)?;
        } else {
            set_file_permissions(&path, MountMode::ReadWrite)?;
            std::fs::remove_file(path)?;
        }
    }

    Ok(())
}

fn collect_plaintext_files(root: &Path) -> Result<BTreeMap<String, Vec<u8>>, VaultError> {
    let mut files = BTreeMap::new();
    collect_plaintext_files_inner(root, root, &mut files)?;
    Ok(files)
}

fn collect_plaintext_files_inner(
    root: &Path,
    current: &Path,
    files: &mut BTreeMap<String, Vec<u8>>,
) -> Result<(), VaultError> {
    let current_metadata = std::fs::symlink_metadata(current)?;
    if current_metadata.file_type().is_symlink() {
        return Err(VaultError::Mount(format!(
            "mounted directory '{}' must not be a symlink",
            current.display()
        )));
    }
    if !current_metadata.is_dir() {
        return Err(VaultError::Mount(format!(
            "mounted path '{}' is not a directory",
            current.display()
        )));
    }

    for entry in std::fs::read_dir(current)? {
        let entry = entry?;
        let path = entry.path();
        let file_type = entry.file_type()?;
        if file_type.is_symlink() {
            return Err(VaultError::Mount(format!(
                "symlinks are not supported in mounted vaults: '{}'",
                path.display()
            )));
        }
        if file_type.is_dir() {
            collect_plaintext_files_inner(root, &path, files)?;
            continue;
        }
        if !file_type.is_file() {
            continue;
        }

        let relative = path
            .strip_prefix(root)
            .map_err(|_| VaultError::Mount("mounted file escaped mount root".into()))?
            .to_string_lossy()
            .replace('\\', "/");
        files.insert(relative, read_plaintext_file(&path)?);
    }

    Ok(())
}

fn record_parent_directories(
    directories: &mut BTreeSet<PathBuf>,
    mount_root: &Path,
    mount_path: &Path,
) -> Result<(), VaultError> {
    let parent = mount_path.parent().ok_or_else(|| {
        VaultError::Mount("mounted file path is missing a parent directory".into())
    })?;
    if !parent.starts_with(mount_root) {
        return Err(VaultError::Mount(
            "mounted file path escaped mount root".into(),
        ));
    }

    let mut current = Some(parent);
    while let Some(path) = current {
        if !path.starts_with(mount_root) {
            break;
        }
        directories.insert(path.to_path_buf());
        if path == mount_root {
            break;
        }
        current = path.parent();
    }
    Ok(())
}

fn atomic_write_plaintext(path: &Path, contents: &[u8]) -> Result<(), VaultError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let temp_path = sibling_temp_path(path);
    std::fs::write(&temp_path, contents)?;
    std::fs::rename(temp_path, path)?;
    Ok(())
}

fn set_directory_permissions(
    directories: &BTreeSet<PathBuf>,
    mode: MountMode,
) -> Result<(), VaultError> {
    for directory in directories {
        set_dir_permissions(directory, mode)?;
    }
    Ok(())
}

fn set_file_permissions(path: &Path, mode: MountMode) -> Result<(), VaultError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let value = match mode {
            MountMode::ReadOnly => 0o444,
            MountMode::ReadWrite => 0o644,
        };
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(value))?;
    }

    #[cfg(not(unix))]
    {
        let mut permissions = std::fs::metadata(path)?.permissions();
        permissions.set_readonly(mode == MountMode::ReadOnly);
        std::fs::set_permissions(path, permissions)?;
    }

    Ok(())
}

fn set_dir_permissions(path: &Path, mode: MountMode) -> Result<(), VaultError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let value = match mode {
            MountMode::ReadOnly => 0o555,
            MountMode::ReadWrite => 0o755,
        };
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(value))?;
    }

    #[cfg(not(unix))]
    {
        let mut permissions = std::fs::metadata(path)?.permissions();
        permissions.set_readonly(mode == MountMode::ReadOnly);
        std::fs::set_permissions(path, permissions)?;
    }

    Ok(())
}

fn read_plaintext_file(path: &Path) -> Result<Vec<u8>, VaultError> {
    #[cfg(unix)]
    {
        use std::io::Read;
        use std::os::unix::fs::OpenOptionsExt;

        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)?;
        let metadata = file.metadata()?;
        if !metadata.is_file() {
            return Err(VaultError::Mount(format!(
                "mounted path '{}' is not a regular file",
                path.display()
            )));
        }
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        file.read_to_end(&mut bytes)?;
        Ok(bytes)
    }

    #[cfg(not(unix))]
    {
        let metadata = std::fs::symlink_metadata(path)?;
        if metadata.file_type().is_symlink() {
            return Err(VaultError::Mount(format!(
                "mounted path '{}' must not be a symlink",
                path.display()
            )));
        }
        if !metadata.is_file() {
            return Err(VaultError::Mount(format!(
                "mounted path '{}' is not a regular file",
                path.display()
            )));
        }
        std::fs::read(path).map_err(VaultError::from)
    }
}

fn make_tree_writable(path: &Path) -> Result<(), VaultError> {
    if !path.exists() {
        return Ok(());
    }

    let file_type = std::fs::symlink_metadata(path)?.file_type();
    if file_type.is_symlink() {
        return Err(VaultError::Mount(format!(
            "refusing to chmod symlink '{}'",
            path.display()
        )));
    }

    if file_type.is_dir() {
        set_dir_permissions(path, MountMode::ReadWrite)?;
        for entry in std::fs::read_dir(path)? {
            let entry = entry?;
            make_tree_writable(&entry.path())?;
        }
    } else if file_type.is_file() {
        set_file_permissions(path, MountMode::ReadWrite)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::*;

    #[test]
    fn read_only_mount_materializes_plaintext_and_cleans_up() {
        let temp = tempdir().unwrap();
        let vault_dir = temp.path().join("vault");
        let mount_dir = temp.path().join("mount");
        let master_key = VaultStore::generate_master_key();
        let vault = VaultStore::init(&vault_dir, &master_key).unwrap();
        vault
            .write(
                "social/profile/profile.json",
                br#"{"did":"did:aegis:demo"}"#,
            )
            .unwrap();
        vault
            .write("social/space/index.html", b"<h1>Hello</h1>")
            .unwrap();

        let mount = FuseMount::mount_read_only(&mount_dir, &vault).unwrap();
        assert_eq!(mount.mode(), MountMode::ReadOnly);
        assert_eq!(
            std::fs::read_to_string(mount_dir.join("social/profile/profile.json")).unwrap(),
            r#"{"did":"did:aegis:demo"}"#
        );
        assert_eq!(
            std::fs::read_to_string(mount_dir.join("social/space/index.html")).unwrap(),
            "<h1>Hello</h1>"
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let mode = std::fs::metadata(mount_dir.join("social/profile/profile.json"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o444);
        }

        mount.unmount().unwrap();
        assert!(std::fs::read_dir(&mount_dir).unwrap().next().is_none());
    }

    #[test]
    fn mount_rejects_non_empty_directory() {
        let temp = tempdir().unwrap();
        let vault_dir = temp.path().join("vault");
        let mount_dir = temp.path().join("mount");
        std::fs::create_dir_all(&mount_dir).unwrap();
        std::fs::write(mount_dir.join("keep.txt"), b"occupied").unwrap();

        let master_key = VaultStore::generate_master_key();
        let vault = VaultStore::init(&vault_dir, &master_key).unwrap();

        assert!(matches!(
            FuseMount::mount_read_only(&mount_dir, &vault),
            Err(VaultError::Mount(_))
        ));
    }

    #[test]
    fn read_write_mount_syncs_new_changed_and_deleted_files_on_unmount() {
        let temp = tempdir().unwrap();
        let vault_dir = temp.path().join("vault");
        let mount_dir = temp.path().join("mount");
        let master_key = VaultStore::generate_master_key();
        let vault = VaultStore::init(&vault_dir, &master_key).unwrap();
        vault.write("documents/original.txt", b"before").unwrap();
        vault.write("documents/remove.txt", b"delete me").unwrap();

        let mount = FuseMount::mount_read_write(&mount_dir, &vault).unwrap();
        std::fs::write(mount_dir.join("documents/original.txt"), b"after").unwrap();
        std::fs::create_dir_all(mount_dir.join("documents/nested")).unwrap();
        std::fs::write(mount_dir.join("documents/nested/new.txt"), b"brand new").unwrap();
        std::fs::remove_file(mount_dir.join("documents/remove.txt")).unwrap();

        mount.unmount().unwrap();

        assert_eq!(vault.read("documents/original.txt").unwrap(), b"after");
        assert_eq!(
            vault.read("documents/nested/new.txt").unwrap(),
            b"brand new"
        );
        assert!(matches!(
            vault.read("documents/remove.txt"),
            Err(VaultError::NotFound(_))
        ));
        assert!(std::fs::read_dir(&mount_dir).unwrap().next().is_none());
    }
}
