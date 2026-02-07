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
