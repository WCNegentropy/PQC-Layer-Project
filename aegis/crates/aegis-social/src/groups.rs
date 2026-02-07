//! MLS-inspired group key management.
//!
//! Manages group encryption keys using a tree-based structure inspired
//! by the Messaging Layer Security (MLS) protocol, adapted for
//! post-quantum KEM operations.
//!
//! # Planned Features
//!
//! - Tree-based group key agreement with O(log n) update cost.
//! - Post-quantum KEM for key encapsulation at each tree node.
//! - Add/remove members with forward secrecy.
//! - Group epoch management for key rotation.
