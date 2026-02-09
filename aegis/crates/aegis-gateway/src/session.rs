//! Session management for PQ-WireGuard tunnel connections.
//!
//! Manages the lifecycle of tunnel sessions including:
//! - Active session tracking with receiver index mapping
//! - Send counter increment
//! - Key rotation after a configurable packet count or timeout
//! - Session creation from completed handshakes

use std::time::{Duration, Instant};

use aegis_crypto::AeadCipher;

use crate::anti_replay::AntiReplayWindow;
use crate::handshake::CompletedHandshake;

/// Default key rotation interval (120 seconds).
pub const DEFAULT_REKEY_INTERVAL: Duration = Duration::from_secs(120);

/// Default maximum packets before rekeying.
pub const DEFAULT_REKEY_AFTER_PACKETS: u64 = 1 << 16; // 65536

/// An active tunnel session holding transport keys and counters.
pub struct Session {
    /// AEAD cipher for encrypting outbound packets.
    pub send_cipher: AeadCipher,
    /// AEAD cipher for decrypting inbound packets.
    pub recv_cipher: AeadCipher,
    /// Next counter value for outbound packets.
    send_counter: u64,
    /// Anti-replay window for inbound packets.
    recv_window: AntiReplayWindow,
    /// Index the remote peer uses to identify this session.
    pub local_index: u32,
    /// Index we use to identify the remote session.
    pub remote_index: u32,
    /// When this session was created.
    created_at: Instant,
    /// Maximum lifetime before rekeying is required.
    rekey_interval: Duration,
    /// Maximum packets before rekeying is required.
    rekey_after_packets: u64,
}

impl Session {
    /// Create a new session from a completed handshake.
    pub fn from_handshake(hs: CompletedHandshake) -> Self {
        Self {
            send_cipher: AeadCipher::new(&hs.keys.send_key),
            recv_cipher: AeadCipher::new(&hs.keys.recv_key),
            send_counter: hs.send_counter,
            recv_window: hs.recv_window,
            local_index: hs.local_index,
            remote_index: hs.remote_index,
            created_at: Instant::now(),
            rekey_interval: DEFAULT_REKEY_INTERVAL,
            rekey_after_packets: DEFAULT_REKEY_AFTER_PACKETS,
        }
    }

    /// Get and increment the send counter.
    ///
    /// Returns the current counter value and advances it for the next packet.
    pub fn next_counter(&mut self) -> u64 {
        self.send_counter += 1;
        self.send_counter
    }

    /// Check and update the anti-replay window for a received counter.
    ///
    /// Returns `true` if the counter is fresh (not replayed), `false` if it
    /// should be rejected.
    pub fn check_replay(&mut self, counter: u64) -> bool {
        self.recv_window.check_and_update(counter)
    }

    /// Check whether this session needs rekeying.
    ///
    /// Returns `true` if the session has exceeded its maximum lifetime or
    /// packet count.
    pub fn needs_rekey(&self) -> bool {
        self.created_at.elapsed() >= self.rekey_interval
            || self.send_counter >= self.rekey_after_packets
    }

    /// Get the number of packets sent in this session.
    pub fn packets_sent(&self) -> u64 {
        self.send_counter
    }

    /// Get the age of this session.
    pub fn age(&self) -> Duration {
        self.created_at.elapsed()
    }
}

/// Manages a set of sessions indexed by receiver index.
///
/// In a full implementation this would be a concurrent map; for now it
/// holds an optional active session (single-peer).
pub struct SessionManager {
    /// The currently active session (single-peer for MVP).
    active: Option<Session>,
}

impl SessionManager {
    /// Create a new empty session manager.
    pub fn new() -> Self {
        Self { active: None }
    }

    /// Install a new active session from a completed handshake.
    ///
    /// Replaces any existing session.
    pub fn install(&mut self, hs: CompletedHandshake) {
        self.active = Some(Session::from_handshake(hs));
    }

    /// Get a reference to the active session, if any.
    pub fn active(&self) -> Option<&Session> {
        self.active.as_ref()
    }

    /// Get a mutable reference to the active session, if any.
    pub fn active_mut(&mut self) -> Option<&mut Session> {
        self.active.as_mut()
    }

    /// Look up a session by receiver index.
    ///
    /// For the single-peer MVP, this checks the active session's local_index.
    pub fn by_receiver_index(&mut self, index: u32) -> Option<&mut Session> {
        match &self.active {
            Some(session) if session.local_index == index => self.active.as_mut(),
            _ => None,
        }
    }

    /// Check whether the active session needs rekeying.
    pub fn needs_rekey(&self) -> bool {
        self.active.as_ref().is_some_and(|s| s.needs_rekey())
    }

    /// Remove the active session.
    pub fn clear(&mut self) {
        self.active = None;
    }

    /// Returns `true` if there is an active session.
    pub fn has_session(&self) -> bool {
        self.active.is_some()
    }
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::anti_replay::AntiReplayWindow;
    use crate::handshake::TransportKeys;
    use zeroize::Zeroizing;

    /// Build a fake CompletedHandshake for testing.
    fn fake_handshake(local_index: u32, remote_index: u32) -> CompletedHandshake {
        CompletedHandshake {
            keys: TransportKeys {
                send_key: Zeroizing::new([0x42u8; 32]),
                recv_key: Zeroizing::new([0x43u8; 32]),
            },
            send_counter: 0,
            recv_window: AntiReplayWindow::new(),
            local_index,
            remote_index,
        }
    }

    #[test]
    fn session_counter_increments() {
        let hs = fake_handshake(1, 2);
        let mut session = Session::from_handshake(hs);
        assert_eq!(session.next_counter(), 1);
        assert_eq!(session.next_counter(), 2);
        assert_eq!(session.next_counter(), 3);
    }

    #[test]
    fn session_replay_check() {
        let hs = fake_handshake(1, 2);
        let mut session = Session::from_handshake(hs);
        assert!(session.check_replay(1));
        assert!(!session.check_replay(1)); // duplicate
        assert!(session.check_replay(2));
    }

    #[test]
    fn session_manager_install_and_lookup() {
        let mut mgr = SessionManager::new();
        assert!(!mgr.has_session());

        let hs = fake_handshake(10, 20);
        mgr.install(hs);
        assert!(mgr.has_session());

        // Lookup by receiver index
        assert!(mgr.by_receiver_index(10).is_some());
        assert!(mgr.by_receiver_index(99).is_none());
    }

    #[test]
    fn session_manager_clear() {
        let mut mgr = SessionManager::new();
        mgr.install(fake_handshake(1, 2));
        assert!(mgr.has_session());
        mgr.clear();
        assert!(!mgr.has_session());
    }

    #[test]
    fn session_needs_rekey_by_packets() {
        let hs = fake_handshake(1, 2);
        let mut session = Session::from_handshake(hs);
        // Set a low rekey threshold for testing
        session.rekey_after_packets = 5;

        for _ in 0..4 {
            session.next_counter();
        }
        assert!(!session.needs_rekey());

        session.next_counter(); // 5th packet
        assert!(session.needs_rekey());
    }

    #[test]
    fn session_manager_replaces_session() {
        let mut mgr = SessionManager::new();
        mgr.install(fake_handshake(10, 20));
        assert!(mgr.by_receiver_index(10).is_some());

        // Replace with new session
        mgr.install(fake_handshake(30, 40));
        assert!(mgr.by_receiver_index(10).is_none());
        assert!(mgr.by_receiver_index(30).is_some());
    }
}
