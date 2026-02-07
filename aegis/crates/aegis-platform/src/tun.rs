//! TUN/TAP virtual network interface abstraction.
//!
//! Defines the [`TunDevice`] trait that platform-specific implementations
//! (Linux, macOS, Windows) must satisfy. The gateway crate consumes this
//! trait to create and read from TUN interfaces.
//!
//! # Planned Implementations
//!
//! | Platform | Backend       | Status  |
//! |----------|---------------|---------|
//! | Linux    | `/dev/net/tun`| via tun2 crate |
//! | macOS    | `utun` socket | via tun2 crate |
//! | Windows  | Wintun.dll    | Planned |

use crate::PlatformError;

/// Configuration for creating a TUN device.
#[derive(Debug, Clone)]
pub struct TunConfig {
    /// Desired interface name (e.g., `"aegis0"`). May be overridden by the OS.
    pub name: String,
    /// MTU in bytes (default: 1420 for WireGuard compatibility).
    pub mtu: u16,
    /// Local VPN address.
    pub address: std::net::Ipv4Addr,
    /// Peer address (the other end of the point-to-point link).
    pub destination: std::net::Ipv4Addr,
}

impl Default for TunConfig {
    fn default() -> Self {
        Self {
            name: "aegis0".to_string(),
            mtu: 1420,
            address: std::net::Ipv4Addr::new(10, 0, 0, 1),
            destination: std::net::Ipv4Addr::new(10, 0, 0, 254),
        }
    }
}

/// Trait for a TUN network device.
///
/// Implementors provide platform-specific TUN creation and I/O.
/// The gateway crate uses this to abstract over OS differences.
pub trait TunDevice: Send {
    /// Read a packet from the TUN device into `buf`.
    /// Returns the number of bytes read.
    fn read_packet(&mut self, buf: &mut [u8]) -> Result<usize, PlatformError>;

    /// Write a packet to the TUN device.
    /// Returns the number of bytes written.
    fn write_packet(&mut self, packet: &[u8]) -> Result<usize, PlatformError>;

    /// Get the actual interface name assigned by the OS.
    fn name(&self) -> &str;

    /// Get the MTU of the device.
    fn mtu(&self) -> u16;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_tun_config() {
        let config = TunConfig::default();
        assert_eq!(config.name, "aegis0");
        assert_eq!(config.mtu, 1420);
        assert_eq!(config.address, std::net::Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(config.destination, std::net::Ipv4Addr::new(10, 0, 0, 254));
    }
}
