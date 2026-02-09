use clap::Parser;
use std::net::Ipv4Addr;

// ─── Platform Constants ─────────────────────────────────────────────────────

/// macOS utun interfaces prepend a 4-byte address family header
/// to every packet. Linux TUN (with PI disabled) gives raw IP.
#[cfg(target_os = "macos")]
pub const TUN_AF_HEADER_LEN: usize = 4;

#[cfg(target_os = "linux")]
pub const TUN_AF_HEADER_LEN: usize = 0;

// Fallback for other platforms during development
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub const TUN_AF_HEADER_LEN: usize = 0;

/// Buffer size: MTU (1420) + TUN header (4) + headroom (128).
/// Rounded up. Never allocate per-packet.
pub const PACKET_BUF_SIZE: usize = 2048;

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
pub struct Args {
    /// Name of the TUN interface
    #[arg(short, long, default_value = "aegis0")]
    pub tun_name: String,

    /// MTU for the tunnel interface (WireGuard standard: 1420)
    #[arg(long, default_value_t = 1420)]
    pub mtu: u16,

    /// Internal VPN IP address for this device
    #[arg(long, default_value = "10.0.0.1")]
    pub address: String,

    /// Peer (Sanctuary) IP address
    #[arg(long, default_value = "10.0.0.254")]
    pub peer: String,

    /// Stats reporting interval in seconds (0 = disabled)
    #[arg(long, default_value_t = 5)]
    pub stats_interval: u64,

    /// Sanctuary UDP endpoint (e.g., "127.0.0.1:51820").
    /// If not provided, the gateway runs in log-and-drop mode.
    #[arg(long)]
    pub sanctuary_addr: Option<String>,

    /// Path to the Sanctuary's hybrid public key file
    #[arg(long, default_value = "sanctuary.pub")]
    pub sanctuary_pk_file: String,

    /// Path to our persisted hybrid keypair file
    #[arg(long, default_value = "aegis.key")]
    pub keypair_file: String,
}

// ─── TUN Device Setup ───────────────────────────────────────────────────────

/// Create and configure the TUN interface.
/// Separated from main() for clarity and future retry/platform workarounds.
pub fn create_tun_config(args: &Args) -> anyhow::Result<tun2::Configuration> {
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

    // Note: tun2 v4 always delivers raw IP packets without platform headers
    // on all platforms, so no explicit packet_information(false) call is needed.

    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tun_af_header_len_platform() {
        // On Linux CI, this should be 0; on macOS it would be 4
        #[cfg(target_os = "linux")]
        assert_eq!(TUN_AF_HEADER_LEN, 0);

        #[cfg(target_os = "macos")]
        assert_eq!(TUN_AF_HEADER_LEN, 4);
    }
}
