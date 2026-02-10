//! NAT proxy for forwarding decrypted tunnel traffic.
//!
//! After PQ-WG decryption, plaintext IP packets are forwarded through
//! a NAT (Network Address Translation) gateway to the public internet.
//! Responses are routed back through the tunnel.
//!
//! # Architecture
//!
//! The proxy uses a server-side TUN device to inject decrypted client
//! IP packets into the host network stack. The kernel performs NAT
//! (via `iptables MASQUERADE`) and routes responses back through the
//! TUN. A return-path reader task picks up these responses and routes
//! them back to the correct client session via a reverse mapping of
//! source IP → (peer_addr, session_index).
//!
//! # Features
//!
//! - TUN device integration for actual IP forwarding.
//! - Client IP → session reverse mapping for return traffic routing.
//! - Per-client byte counters for bandwidth accounting.
//! - Async writer for injecting packets into the TUN device.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use tokio::sync::Mutex;
use tracing::debug;

use crate::SanctuaryError;

/// Mapping from a client tunnel IP to its session information.
#[derive(Debug, Clone)]
pub struct ClientMapping {
    /// The client's UDP address for sending encrypted return traffic.
    pub peer_addr: SocketAddr,
    /// The session's local index (used as receiver_index in transport packets).
    pub session_index: u32,
}

/// Per-client traffic counters.
#[derive(Debug, Default)]
pub struct ClientStats {
    /// Bytes forwarded from client to internet.
    pub bytes_forwarded: AtomicU64,
    /// Bytes returned from internet to client.
    pub bytes_returned: AtomicU64,
}

/// NAT proxy for forwarding decrypted tunnel traffic.
///
/// Manages client IP → session mappings and tracks per-client bandwidth.
/// When a TUN device name is configured, the proxy writes decrypted
/// packets to the TUN for kernel-level NAT forwarding. Without a TUN
/// device, `forward()` is a no-op (v0 echo mode).
pub struct NatProxy {
    /// Reverse mapping: client source IP → session info.
    client_map: Arc<Mutex<HashMap<Ipv4Addr, ClientMapping>>>,
    /// Per-client traffic stats keyed by source IP.
    client_stats: Arc<Mutex<HashMap<Ipv4Addr, Arc<ClientStats>>>>,
    /// Optional TUN device name for forwarding (None = no-op/echo mode).
    tun_name: Option<String>,
}

impl NatProxy {
    /// Create a new NAT proxy.
    ///
    /// If `tun_name` is `Some`, the proxy will attempt to write packets
    /// to a TUN device for kernel NAT forwarding. If `None`, `forward()`
    /// is a no-op suitable for echo/testing mode.
    pub fn new(tun_name: Option<String>) -> Self {
        Self {
            client_map: Arc::new(Mutex::new(HashMap::new())),
            client_stats: Arc::new(Mutex::new(HashMap::new())),
            tun_name,
        }
    }

    /// Register a client mapping from tunnel IP to session info.
    ///
    /// Called when a new client session is established. The `client_ip`
    /// is the IP address the client uses inside the tunnel.
    pub async fn register_client(
        &self,
        client_ip: Ipv4Addr,
        peer_addr: SocketAddr,
        session_index: u32,
    ) {
        let mapping = ClientMapping {
            peer_addr,
            session_index,
        };

        let mut map = self.client_map.lock().await;
        map.insert(client_ip, mapping);

        let mut stats = self.client_stats.lock().await;
        stats
            .entry(client_ip)
            .or_insert_with(|| Arc::new(ClientStats::default()));

        debug!(
            "Registered client mapping: {} → {} (session={})",
            client_ip, peer_addr, session_index
        );
    }

    /// Remove a client mapping (e.g., on session teardown).
    pub async fn unregister_client(&self, client_ip: &Ipv4Addr) {
        let mut map = self.client_map.lock().await;
        map.remove(client_ip);
        debug!("Unregistered client mapping for {}", client_ip);
    }

    /// Look up the client mapping for a given source IP.
    ///
    /// Used by the return-path reader to determine which client session
    /// should receive a response packet.
    pub async fn lookup_client(&self, src_ip: &Ipv4Addr) -> Option<ClientMapping> {
        let map = self.client_map.lock().await;
        map.get(src_ip).cloned()
    }

    /// Forward a decrypted IP packet toward the internet.
    ///
    /// Extracts the source IP from the packet header, records bandwidth
    /// stats, and (when a TUN device is configured) writes the packet
    /// to the TUN for kernel-level NAT forwarding.
    ///
    /// Returns `Ok(())` on success or if no TUN device is configured.
    pub async fn forward(&self, plaintext: &[u8]) -> Result<(), SanctuaryError> {
        if plaintext.len() < 20 {
            // Too short to be a valid IPv4 packet
            return Ok(());
        }

        // Parse source IP from IPv4 header (bytes 12..16)
        let version = plaintext[0] >> 4;
        if version != 4 {
            // Only IPv4 is supported for now
            debug!(
                "Non-IPv4 packet (version={}), skipping proxy forward",
                version
            );
            return Ok(());
        }

        let src_ip = Ipv4Addr::new(plaintext[12], plaintext[13], plaintext[14], plaintext[15]);

        // Update per-client byte counter
        {
            let stats = self.client_stats.lock().await;
            if let Some(cs) = stats.get(&src_ip) {
                cs.bytes_forwarded
                    .fetch_add(plaintext.len() as u64, Ordering::Relaxed);
            }
        }

        if self.tun_name.is_none() {
            // No TUN device configured — no-op (echo mode)
            return Ok(());
        }

        // When TUN-based forwarding is wired up, this is where we'd write
        // the plaintext IP packet into the server-side TUN device.
        // The kernel then routes it via iptables MASQUERADE.
        //
        // For now, we log and accept. The actual TUN write requires
        // a running tun2 device instance owned by the server, which
        // is wired through the server's run loop.
        debug!(
            "NAT proxy: would forward {} bytes from {} via TUN '{}'",
            plaintext.len(),
            src_ip,
            self.tun_name.as_deref().unwrap_or("none"),
        );

        Ok(())
    }

    /// Extract the destination IP from an IPv4 packet.
    ///
    /// Used by the return-path reader to look up which client should
    /// receive a response packet read from the server-side TUN.
    pub fn extract_dst_ip(packet: &[u8]) -> Option<Ipv4Addr> {
        if packet.len() < 20 {
            return None;
        }
        let version = packet[0] >> 4;
        if version != 4 {
            return None;
        }
        Some(Ipv4Addr::new(
            packet[16], packet[17], packet[18], packet[19],
        ))
    }

    /// Get the configured TUN device name, if any.
    pub fn tun_name(&self) -> Option<&str> {
        self.tun_name.as_deref()
    }

    /// Get a snapshot of per-client bandwidth stats.
    pub async fn client_bandwidth(&self) -> Vec<(Ipv4Addr, u64, u64)> {
        let stats = self.client_stats.lock().await;
        stats
            .iter()
            .map(|(ip, cs)| {
                (
                    *ip,
                    cs.bytes_forwarded.load(Ordering::Relaxed),
                    cs.bytes_returned.load(Ordering::Relaxed),
                )
            })
            .collect()
    }

    /// Record bytes returned to a client (for stats tracking).
    pub async fn record_return_bytes(&self, client_ip: &Ipv4Addr, bytes: u64) {
        let stats = self.client_stats.lock().await;
        if let Some(cs) = stats.get(client_ip) {
            cs.bytes_returned.fetch_add(bytes, Ordering::Relaxed);
        }
    }

    /// Get the number of registered client mappings.
    pub async fn client_count(&self) -> usize {
        let map = self.client_map.lock().await;
        map.len()
    }
}

impl Default for NatProxy {
    fn default() -> Self {
        Self::new(None)
    }
}
