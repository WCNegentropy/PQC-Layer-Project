use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

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
    pub fn from_ip_protocol(proto: u8) -> Self {
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
pub const IPV4_MIN_HEADER: usize = 20;
/// IPv6 fixed header size.
pub const IPV6_HEADER: usize = 40;

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
    fn protocol_display() {
        assert_eq!(format!("{}", Protocol::Tcp), "TCP");
        assert_eq!(format!("{}", Protocol::Udp), "UDP");
        assert_eq!(format!("{}", Protocol::Icmp), "ICMP");
        assert_eq!(format!("{}", Protocol::IcmpV6), "ICMPv6");
        assert_eq!(format!("{}", Protocol::Other(47)), "Proto(47)");
    }
}
