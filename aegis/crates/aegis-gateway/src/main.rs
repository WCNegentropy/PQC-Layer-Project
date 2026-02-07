//! Aegis Gateway (Layer 3) — The Sentinel
//!
//! Quantum Gateway providing:
//! - TUN virtual network interface creation (via `tun2`)
//! - Safe IP header parsing (IPv4 + IPv6, no panics on malformed input)
//! - Protocol classification (ICMP, TCP, UDP)
//! - Platform-aware packet handling (macOS 4-byte AF header, Linux raw IP)
//! - Atomic pipeline statistics with periodic reporting
//! - Graceful shutdown via Ctrl+C with clean TUN teardown
//! - Structured logging with env-filter
//!
//! Run with: sudo cargo run -p aegis-gateway -- --tun-name aegis0
//! Test with: ping -c 4 10.0.0.254 (in another terminal)

use clap::Parser;
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use tokio::io::AsyncReadExt;
use tokio::signal;
use tracing::{debug, error, info, warn};

// ─── Platform Constants ─────────────────────────────────────────────────────

/// macOS utun interfaces prepend a 4-byte address family header
/// to every packet. Linux TUN (with PI disabled) gives raw IP.
#[cfg(target_os = "macos")]
const TUN_AF_HEADER_LEN: usize = 4;

#[cfg(target_os = "linux")]
const TUN_AF_HEADER_LEN: usize = 0;

// Fallback for other platforms during development
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
const TUN_AF_HEADER_LEN: usize = 0;

/// Buffer size: MTU (1420) + TUN header (4) + headroom (128).
/// Rounded up. Never allocate per-packet.
const PACKET_BUF_SIZE: usize = 2048;

// ─── Protocol Classification ────────────────────────────────────────────────

/// IP protocol numbers for classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Icmp,
    Tcp,
    Udp,
    IcmpV6,
    Other(u8),
}

impl Protocol {
    fn from_ip_protocol(proto: u8) -> Self {
        match proto {
            1 => Protocol::Icmp,
            6 => Protocol::Tcp,
            17 => Protocol::Udp,
            58 => Protocol::IcmpV6,
            other => Protocol::Other(other),
        }
    }
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Protocol::Icmp => write!(f, "ICMP"),
            Protocol::Tcp => write!(f, "TCP"),
            Protocol::Udp => write!(f, "UDP"),
            Protocol::IcmpV6 => write!(f, "ICMPv6"),
            Protocol::Other(n) => write!(f, "Proto({})", n),
        }
    }
}

// ─── Parsed Packet Info ─────────────────────────────────────────────────────

/// IP version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpVersion {
    V4,
    V6,
}

/// Source/destination address — either IPv4 or IPv6.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpAddr {
    V4(Ipv4Addr),
    V6(Ipv6Addr),
}

impl fmt::Display for IpAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IpAddr::V4(a) => write!(f, "{}", a),
            IpAddr::V6(a) => write!(f, "{}", a),
        }
    }
}

/// Parsed information from an IP packet header.
#[derive(Debug, Clone)]
pub struct PacketInfo {
    pub version: IpVersion,
    pub protocol: Protocol,
    pub src: IpAddr,
    pub dst: IpAddr,
    pub payload_len: usize,
}

/// Minimum IPv4 header size (no options).
const IPV4_MIN_HEADER: usize = 20;
/// IPv6 fixed header size.
const IPV6_HEADER: usize = 40;

impl PacketInfo {
    /// Safely parse an IP packet header. Returns `None` on malformed input.
    ///
    /// Handles both IPv4 and IPv6 with bounds validation at every step.
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.is_empty() {
            return None;
        }

        let version_nibble = data[0] >> 4;

        match version_nibble {
            4 => Self::parse_ipv4(data),
            6 => Self::parse_ipv6(data),
            _ => None,
        }
    }

    fn parse_ipv4(data: &[u8]) -> Option<Self> {
        if data.len() < IPV4_MIN_HEADER {
            return None;
        }

        // IHL: lower 4 bits of first byte, in 32-bit words
        let ihl = (data[0] & 0x0F) as usize;
        if ihl < 5 {
            return None; // IHL must be >= 5
        }
        let header_len = ihl * 4;
        if data.len() < header_len {
            return None;
        }

        let total_len = u16::from_be_bytes([data[2], data[3]]) as usize;
        let protocol = Protocol::from_ip_protocol(data[9]);

        let src = Ipv4Addr::new(data[12], data[13], data[14], data[15]);
        let dst = Ipv4Addr::new(data[16], data[17], data[18], data[19]);

        let payload_len = total_len.saturating_sub(header_len);

        Some(PacketInfo {
            version: IpVersion::V4,
            protocol,
            src: IpAddr::V4(src),
            dst: IpAddr::V4(dst),
            payload_len,
        })
    }

    fn parse_ipv6(data: &[u8]) -> Option<Self> {
        if data.len() < IPV6_HEADER {
            return None;
        }

        let payload_len = u16::from_be_bytes([data[4], data[5]]) as usize;
        let next_header = data[6];
        let protocol = Protocol::from_ip_protocol(next_header);

        let mut src_bytes = [0u8; 16];
        src_bytes.copy_from_slice(&data[8..24]);
        let src = Ipv6Addr::from(src_bytes);

        let mut dst_bytes = [0u8; 16];
        dst_bytes.copy_from_slice(&data[24..40]);
        let dst = Ipv6Addr::from(dst_bytes);

        Some(PacketInfo {
            version: IpVersion::V6,
            protocol,
            src: IpAddr::V6(src),
            dst: IpAddr::V6(dst),
            payload_len,
        })
    }
}

// ─── Pipeline Statistics ────────────────────────────────────────────────────

/// Atomic pipeline statistics for lock-free concurrent updates.
/// Using atomics so the stats reporter task doesn't block the hot path.
pub struct PipelineStats {
    pub packets_in: AtomicU64,
    pub bytes_in: AtomicU64,
    pub ipv4_packets: AtomicU64,
    pub ipv6_packets: AtomicU64,
    pub packets_dropped: AtomicU64,
    pub dropped_runt: AtomicU64,
    pub dropped_unknown: AtomicU64,
    pub parse_errors: AtomicU64,
}

impl PipelineStats {
    pub fn new() -> Self {
        Self {
            packets_in: AtomicU64::new(0),
            bytes_in: AtomicU64::new(0),
            ipv4_packets: AtomicU64::new(0),
            ipv6_packets: AtomicU64::new(0),
            packets_dropped: AtomicU64::new(0),
            dropped_runt: AtomicU64::new(0),
            dropped_unknown: AtomicU64::new(0),
            parse_errors: AtomicU64::new(0),
        }
    }

    pub fn record_packet(&self, byte_count: u64) {
        self.packets_in.fetch_add(1, Ordering::Relaxed);
        self.bytes_in.fetch_add(byte_count, Ordering::Relaxed);
    }

    pub fn record_parse_error(&self) {
        self.parse_errors.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_drop(&self) {
        self.packets_dropped.fetch_add(1, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> StatsSnapshot {
        StatsSnapshot {
            packets_in: self.packets_in.load(Ordering::Relaxed),
            bytes_in: self.bytes_in.load(Ordering::Relaxed),
            ipv4_packets: self.ipv4_packets.load(Ordering::Relaxed),
            ipv6_packets: self.ipv6_packets.load(Ordering::Relaxed),
            packets_dropped: self.packets_dropped.load(Ordering::Relaxed),
            dropped_runt: self.dropped_runt.load(Ordering::Relaxed),
            dropped_unknown: self.dropped_unknown.load(Ordering::Relaxed),
            parse_errors: self.parse_errors.load(Ordering::Relaxed),
        }
    }

    /// Log a periodic stats report.
    pub fn report(&self) {
        let snap = self.snapshot();
        info!(
            "📊 Pipeline Stats | packets: {} | bytes: {} | IPv4: {} | IPv6: {} | dropped: {} (runt: {}, unknown: {})",
            snap.packets_in,
            snap.bytes_in,
            snap.ipv4_packets,
            snap.ipv6_packets,
            snap.packets_dropped,
            snap.dropped_runt,
            snap.dropped_unknown,
        );
    }
}

impl Default for PipelineStats {
    fn default() -> Self {
        Self::new()
    }
}

/// A point-in-time snapshot of pipeline statistics.
#[derive(Debug, Clone)]
pub struct StatsSnapshot {
    pub packets_in: u64,
    pub bytes_in: u64,
    pub ipv4_packets: u64,
    pub ipv6_packets: u64,
    pub packets_dropped: u64,
    pub dropped_runt: u64,
    pub dropped_unknown: u64,
    pub parse_errors: u64,
}

impl fmt::Display for StatsSnapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "packets_in={} bytes_in={} ipv4={} ipv6={} dropped={} runt={} unknown={} parse_errors={}",
            self.packets_in, self.bytes_in, self.ipv4_packets, self.ipv6_packets,
            self.packets_dropped, self.dropped_runt, self.dropped_unknown, self.parse_errors
        )
    }
}

// ─── macOS TUN AF Header ────────────────────────────────────────────────────

/// macOS TUN devices prepend a 4-byte address family header.
/// AF_INET = 2 (IPv4), AF_INET6 = 30 (IPv6).
const TUN_AF_HEADER_SIZE: usize = 4;

/// Strip the macOS 4-byte AF header from a TUN packet, returning the raw IP payload.
pub fn strip_af_header(data: &[u8]) -> Option<&[u8]> {
    if data.len() <= TUN_AF_HEADER_SIZE {
        return None;
    }
    Some(&data[TUN_AF_HEADER_SIZE..])
}

// ─── Pipeline Processing ────────────────────────────────────────────────────

/// Process a single raw IP packet through the pipeline.
///
/// Currently: parse → log → drop (placeholder for future stages).
pub fn process_packet(data: &[u8], stats: &PipelineStats) {
    stats.record_packet(data.len() as u64);

    match PacketInfo::parse(data) {
        Some(info) => {
            match info.version {
                IpVersion::V4 => { stats.ipv4_packets.fetch_add(1, Ordering::Relaxed); }
                IpVersion::V6 => { stats.ipv6_packets.fetch_add(1, Ordering::Relaxed); }
            };

            debug!(
                version = ?info.version,
                proto = %info.protocol,
                src = %info.src,
                dst = %info.dst,
                payload_len = info.payload_len,
                "packet parsed"
            );

            // ┌─────────────────────────────────────────┐
            // │  FUTURE PIPELINE STAGES INSERT HERE:    │
            // │                                         │
            // │  1. antibodies.inspect(ip_packet)       │
            // │  2. split_tunnel.classify(ip_packet)    │
            // │  3. shaper.shape(ip_packet)             │
            // │  4. tunnel.encrypt_and_send(ip_packet)  │
            // └─────────────────────────────────────────┘

            // Steel Thread: log and drop.
            // Packets are consumed (not echoed back) to prevent loops.
            stats.record_drop();
        }
        None => {
            warn!(len = data.len(), "malformed packet, could not parse");
            stats.record_parse_error();
        }
    }
}

// ─── Root Privilege Detection ───────────────────────────────────────────────

/// Check if the current process has root (UID 0) privileges.
#[cfg(unix)]
pub fn is_root() -> bool {
    // SAFETY: geteuid() is a simple syscall with no unsafe memory access
    unsafe { libc::geteuid() == 0 }
}

#[cfg(not(unix))]
pub fn is_root() -> bool {
    false
}

// ─── CLI Arguments ──────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(
    name = "aegis-gateway",
    about = "Aegis Quantum Gateway — PQC-backed network sentinel",
    version
)]
struct Args {
    /// Name of the TUN interface
    #[arg(short, long, default_value = "aegis0")]
    tun_name: String,

    /// MTU for the tunnel interface (WireGuard standard: 1420)
    #[arg(long, default_value_t = 1420)]
    mtu: u16,

    /// Internal VPN IP address for this device
    #[arg(long, default_value = "10.0.0.1")]
    address: String,

    /// Peer (Sanctuary) IP address
    #[arg(long, default_value = "10.0.0.254")]
    peer: String,

    /// Stats reporting interval in seconds (0 = disabled)
    #[arg(long, default_value_t = 5)]
    stats_interval: u64,
}

// ─── TUN Device Setup ───────────────────────────────────────────────────────

/// Create and configure the TUN interface.
/// Separated from main() for clarity and future retry/platform workarounds.
fn create_tun_config(args: &Args) -> anyhow::Result<tun2::Configuration> {
    let mut config = tun2::Configuration::default();

    let addr: Ipv4Addr = args
        .address
        .parse()
        .map_err(|e| anyhow::anyhow!("Invalid --address '{}': {}", args.address, e))?;
    let peer: Ipv4Addr = args
        .peer
        .parse()
        .map_err(|e| anyhow::anyhow!("Invalid --peer '{}': {}", args.peer, e))?;

    config
        .address(addr)
        .destination(peer)
        .netmask((255, 255, 255, 0))
        .mtu(args.mtu)
        .up();

    config.tun_name(&args.tun_name);

    Ok(config)
}

// ─── Main Entry Point ───────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // ── 1. Initialize structured logging with env-filter ──
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "aegis_gateway=info".into()),
        )
        .with_target(false)
        .init();

    let args = Args::parse();

    info!("Aegis Gateway (The Sentinel) starting...");

    // ── 2. Check privileges ──
    #[cfg(unix)]
    {
        if is_root() {
            info!("running with root privileges — TUN creation available");
        } else {
            error!("Aegis Gateway requires root privileges to create TUN interfaces.");
            error!("Run with: sudo cargo run -p aegis-gateway");
            std::process::exit(1);
        }
    }

    // ── 3. Create TUN device ──
    let config = create_tun_config(&args)?;
    let dev = tun2::create_as_async(&config)
        .map_err(|e| anyhow::anyhow!(
            "Failed to create TUN device '{}': {}. \
             Ensure no other process is using this device name and that \
             the TUN kernel module is loaded (Linux: modprobe tun).",
            args.tun_name, e
        ))?;

    info!("🛡️  Aegis TUN interface '{}' created", args.tun_name);
    info!("   Address: {} → Peer: {}", args.address, args.peer);
    info!("   MTU: {} bytes", args.mtu);

    // ── 4. Shared state ──
    let stats = Arc::new(PipelineStats::new());
    let running = Arc::new(AtomicBool::new(true));

    // ── 5. Spawn stats reporter ──
    if args.stats_interval > 0 {
        let stats_clone = Arc::clone(&stats);
        let running_clone = Arc::clone(&running);
        let interval = std::time::Duration::from_secs(args.stats_interval);

        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            ticker.tick().await; // Skip the first immediate tick
            while running_clone.load(Ordering::Relaxed) {
                ticker.tick().await;
                stats_clone.report();
            }
        });
    }

    // ── 6. Spawn graceful shutdown handler ──
    let running_clone = Arc::clone(&running);
    tokio::spawn(async move {
        signal::ctrl_c().await.expect("Failed to listen for Ctrl+C");
        info!("🛑 Shutdown signal received. Tearing down...");
        running_clone.store(false, Ordering::SeqCst);
    });

    // ── 7. Packet processing pipeline ──
    info!("🚀 Quantum Pipeline active. Waiting for packets...");
    info!("   Test with: ping -c 4 {}", args.peer);

    // Split device for future concurrent read/write
    let (mut reader, _writer) = tokio::io::split(dev);

    // Pre-allocated buffer — reused every iteration, zero per-packet allocation
    let mut buf = [0u8; PACKET_BUF_SIZE];

    while running.load(Ordering::Relaxed) {
        // Use tokio::select! so we can check the running flag
        // even if read() is blocked waiting for a packet
        let read_result = tokio::select! {
            result = reader.read(&mut buf) => result,
            _ = tokio::time::sleep(std::time::Duration::from_millis(100)) => {
                continue; // Re-check running flag
            }
        };

        match read_result {
            Ok(n) if n > TUN_AF_HEADER_LEN => {
                // Strip platform-specific TUN header
                let ip_packet = &buf[TUN_AF_HEADER_LEN..n];

                // Process the packet through the pipeline
                process_packet(ip_packet, &stats);
            }
            Ok(n) => {
                stats.dropped_runt.fetch_add(1, Ordering::Relaxed);
                debug!("Runt packet: {} bytes, dropping", n);
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                continue;
            }
            Err(e) => {
                error!("TUN read error: {}", e);
                break;
            }
        }
    }

    // ── 8. Cleanup ──
    info!("🧹 Final statistics:");
    stats.report();
    info!("🛡️  Aegis Gateway shut down cleanly.");

    // The TUN device is dropped here, which closes the file descriptor.
    // On Linux, this automatically removes the TUN interface.
    // On macOS, utun interfaces are cleaned up by the kernel when the
    // controlling socket is closed.

    Ok(())
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal valid IPv4 packet.
    fn make_ipv4_packet(proto: u8, src: [u8; 4], dst: [u8; 4], payload: &[u8]) -> Vec<u8> {
        let total_len = (IPV4_MIN_HEADER + payload.len()) as u16;
        let mut pkt = vec![0u8; IPV4_MIN_HEADER + payload.len()];
        pkt[0] = 0x45; // version 4, IHL 5
        pkt[2..4].copy_from_slice(&total_len.to_be_bytes());
        pkt[9] = proto;
        pkt[12..16].copy_from_slice(&src);
        pkt[16..20].copy_from_slice(&dst);
        pkt[IPV4_MIN_HEADER..].copy_from_slice(payload);
        pkt
    }

    /// Build a minimal valid IPv6 packet.
    fn make_ipv6_packet(next_header: u8, src: [u8; 16], dst: [u8; 16], payload: &[u8]) -> Vec<u8> {
        let payload_len = payload.len() as u16;
        let mut pkt = vec![0u8; IPV6_HEADER + payload.len()];
        pkt[0] = 0x60; // version 6
        pkt[4..6].copy_from_slice(&payload_len.to_be_bytes());
        pkt[6] = next_header;
        pkt[7] = 64; // hop limit
        pkt[8..24].copy_from_slice(&src);
        pkt[24..40].copy_from_slice(&dst);
        pkt[IPV6_HEADER..].copy_from_slice(payload);
        pkt
    }

    #[test]
    fn parse_ipv4_tcp() {
        let pkt = make_ipv4_packet(6, [10, 0, 0, 1], [10, 0, 0, 2], &[0xAA; 20]);
        let info = PacketInfo::parse(&pkt).unwrap();
        assert_eq!(info.version, IpVersion::V4);
        assert_eq!(info.protocol, Protocol::Tcp);
        assert_eq!(info.src, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(info.dst, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
        assert_eq!(info.payload_len, 20);
    }

    #[test]
    fn parse_ipv4_udp() {
        let pkt = make_ipv4_packet(17, [192, 168, 1, 1], [8, 8, 8, 8], &[0; 8]);
        let info = PacketInfo::parse(&pkt).unwrap();
        assert_eq!(info.protocol, Protocol::Udp);
    }

    #[test]
    fn parse_ipv4_icmp() {
        let pkt = make_ipv4_packet(1, [127, 0, 0, 1], [127, 0, 0, 1], &[0; 8]);
        let info = PacketInfo::parse(&pkt).unwrap();
        assert_eq!(info.protocol, Protocol::Icmp);
    }

    #[test]
    fn parse_ipv6_tcp() {
        let src = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let dst = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        let pkt = make_ipv6_packet(6, src, dst, &[0; 20]);
        let info = PacketInfo::parse(&pkt).unwrap();
        assert_eq!(info.version, IpVersion::V6);
        assert_eq!(info.protocol, Protocol::Tcp);
        assert_eq!(info.payload_len, 20);
    }

    #[test]
    fn parse_ipv6_icmpv6() {
        let src = [0; 16];
        let dst = [0; 16];
        let pkt = make_ipv6_packet(58, src, dst, &[0; 8]);
        let info = PacketInfo::parse(&pkt).unwrap();
        assert_eq!(info.protocol, Protocol::IcmpV6);
    }

    #[test]
    fn parse_empty_returns_none() {
        assert!(PacketInfo::parse(&[]).is_none());
    }

    #[test]
    fn parse_too_short_ipv4_returns_none() {
        // Only 10 bytes — not enough for IPv4 header
        let mut pkt = vec![0u8; 10];
        pkt[0] = 0x45;
        assert!(PacketInfo::parse(&pkt).is_none());
    }

    #[test]
    fn parse_too_short_ipv6_returns_none() {
        let mut pkt = vec![0u8; 20];
        pkt[0] = 0x60;
        assert!(PacketInfo::parse(&pkt).is_none());
    }

    #[test]
    fn parse_unknown_version_returns_none() {
        let pkt = vec![0x30; 40]; // version nibble = 3
        assert!(PacketInfo::parse(&pkt).is_none());
    }

    #[test]
    fn parse_bad_ihl_returns_none() {
        let mut pkt = vec![0u8; 20];
        pkt[0] = 0x43; // version 4, IHL 3 (invalid, must be >= 5)
        assert!(PacketInfo::parse(&pkt).is_none());
    }

    #[test]
    fn strip_af_header_valid() {
        let data = vec![0, 0, 0, 2, 0x45, 0, 0, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let stripped = strip_af_header(&data).unwrap();
        assert_eq!(stripped[0] >> 4, 4); // IPv4
    }

    #[test]
    fn strip_af_header_too_short() {
        assert!(strip_af_header(&[0, 0, 0, 2]).is_none()); // exactly 4 bytes = no payload
        assert!(strip_af_header(&[0, 0]).is_none());
        assert!(strip_af_header(&[]).is_none());
    }

    #[test]
    fn pipeline_stats_counting() {
        let stats = PipelineStats::new();
        stats.record_packet(100);
        stats.record_packet(200);
        stats.record_parse_error();
        stats.record_drop();

        let snap = stats.snapshot();
        assert_eq!(snap.packets_in, 2);
        assert_eq!(snap.bytes_in, 300);
        assert_eq!(snap.parse_errors, 1);
        assert_eq!(snap.packets_dropped, 1);
    }

    #[test]
    fn process_packet_valid_ipv4() {
        let stats = PipelineStats::new();
        let pkt = make_ipv4_packet(6, [10, 0, 0, 1], [10, 0, 0, 2], &[0; 20]);
        process_packet(&pkt, &stats);
        let snap = stats.snapshot();
        assert_eq!(snap.packets_in, 1);
        assert_eq!(snap.packets_dropped, 1); // currently all are dropped
        assert_eq!(snap.parse_errors, 0);
        assert_eq!(snap.ipv4_packets, 1);
        assert_eq!(snap.ipv6_packets, 0);
    }

    #[test]
    fn process_packet_valid_ipv6() {
        let stats = PipelineStats::new();
        let src = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let dst = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        let pkt = make_ipv6_packet(17, src, dst, &[0; 8]);
        process_packet(&pkt, &stats);
        let snap = stats.snapshot();
        assert_eq!(snap.packets_in, 1);
        assert_eq!(snap.packets_dropped, 1);
        assert_eq!(snap.ipv4_packets, 0);
        assert_eq!(snap.ipv6_packets, 1);
    }

    #[test]
    fn process_packet_malformed() {
        let stats = PipelineStats::new();
        process_packet(&[0xFF], &stats); // unknown version nibble
        let snap = stats.snapshot();
        assert_eq!(snap.packets_in, 1);
        assert_eq!(snap.parse_errors, 1);
        assert_eq!(snap.packets_dropped, 0);
    }

    #[test]
    fn protocol_display() {
        assert_eq!(format!("{}", Protocol::Tcp), "TCP");
        assert_eq!(format!("{}", Protocol::Udp), "UDP");
        assert_eq!(format!("{}", Protocol::Icmp), "ICMP");
        assert_eq!(format!("{}", Protocol::IcmpV6), "ICMPv6");
        assert_eq!(format!("{}", Protocol::Other(47)), "Proto(47)");
    }

    #[test]
    fn stats_snapshot_display() {
        let stats = PipelineStats::new();
        stats.record_packet(42);
        let snap = stats.snapshot();
        let s = format!("{}", snap);
        assert!(s.contains("packets_in=1"));
        assert!(s.contains("bytes_in=42"));
    }

    #[test]
    fn tun_af_header_len_platform() {
        // On Linux CI, this should be 0; on macOS it would be 4
        #[cfg(target_os = "linux")]
        assert_eq!(TUN_AF_HEADER_LEN, 0);

        #[cfg(target_os = "macos")]
        assert_eq!(TUN_AF_HEADER_LEN, 4);
    }

    #[test]
    fn stats_ipv4_ipv6_counters() {
        let stats = PipelineStats::new();

        // IPv4 ICMP
        let pkt4 = make_ipv4_packet(1, [10, 0, 0, 1], [10, 0, 0, 254], &[0; 8]);
        process_packet(&pkt4, &stats);

        // IPv6 TCP
        let src6 = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let dst6 = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        let pkt6 = make_ipv6_packet(6, src6, dst6, &[0; 20]);
        process_packet(&pkt6, &stats);

        let snap = stats.snapshot();
        assert_eq!(snap.packets_in, 2);
        assert_eq!(snap.ipv4_packets, 1);
        assert_eq!(snap.ipv6_packets, 1);
        assert_eq!(snap.packets_dropped, 2);
    }

    #[test]
    fn stats_runt_and_unknown_counters() {
        let stats = PipelineStats::new();
        stats.dropped_runt.fetch_add(1, Ordering::Relaxed);
        stats.dropped_unknown.fetch_add(2, Ordering::Relaxed);

        let snap = stats.snapshot();
        assert_eq!(snap.dropped_runt, 1);
        assert_eq!(snap.dropped_unknown, 2);
    }
}
