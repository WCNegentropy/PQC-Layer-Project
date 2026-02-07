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
