use std::sync::atomic::Ordering;
use tracing::{debug, warn};

use crate::packet::*;
use crate::stats::PipelineStats;

// ─── macOS TUN AF Header ────────────────────────────────────────────────────

/// Size of the macOS utun 4-byte address family header (AF_INET=2, AF_INET6=30).
/// This is always 4 bytes on macOS regardless of platform, since this function
/// is specifically for parsing macOS AF headers.
pub const MACOS_AF_HEADER_SIZE: usize = 4;

/// Strip the macOS 4-byte AF header from a TUN packet, returning the raw IP payload.
/// This is specifically for macOS utun interfaces and always expects a 4-byte header.
pub fn strip_af_header(data: &[u8]) -> Option<&[u8]> {
    if data.len() <= MACOS_AF_HEADER_SIZE {
        return None;
    }
    Some(&data[MACOS_AF_HEADER_SIZE..])
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{IPV4_MIN_HEADER, IPV6_HEADER};

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
}
