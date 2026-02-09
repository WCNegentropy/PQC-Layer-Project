use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::info;

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
    pub packets_encrypted: AtomicU64,
    pub packets_decrypted: AtomicU64,
    pub replay_rejected: AtomicU64,
    pub handshakes_completed: AtomicU64,
    pub rekeys_initiated: AtomicU64,
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
            packets_encrypted: AtomicU64::new(0),
            packets_decrypted: AtomicU64::new(0),
            replay_rejected: AtomicU64::new(0),
            handshakes_completed: AtomicU64::new(0),
            rekeys_initiated: AtomicU64::new(0),
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
            packets_encrypted: self.packets_encrypted.load(Ordering::Relaxed),
            packets_decrypted: self.packets_decrypted.load(Ordering::Relaxed),
            replay_rejected: self.replay_rejected.load(Ordering::Relaxed),
            handshakes_completed: self.handshakes_completed.load(Ordering::Relaxed),
            rekeys_initiated: self.rekeys_initiated.load(Ordering::Relaxed),
        }
    }

    /// Log a periodic stats report.
    pub fn report(&self) {
        let snap = self.snapshot();
        info!(
            "📊 Pipeline Stats | packets: {} | bytes: {} | IPv4: {} | IPv6: {} | dropped: {} (runt: {}, unknown: {}) | encrypted: {} | decrypted: {} | replay_rejected: {} | handshakes: {} | rekeys: {}",
            snap.packets_in,
            snap.bytes_in,
            snap.ipv4_packets,
            snap.ipv6_packets,
            snap.packets_dropped,
            snap.dropped_runt,
            snap.dropped_unknown,
            snap.packets_encrypted,
            snap.packets_decrypted,
            snap.replay_rejected,
            snap.handshakes_completed,
            snap.rekeys_initiated,
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
    pub packets_encrypted: u64,
    pub packets_decrypted: u64,
    pub replay_rejected: u64,
    pub handshakes_completed: u64,
    pub rekeys_initiated: u64,
}

impl fmt::Display for StatsSnapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "packets_in={} bytes_in={} ipv4={} ipv6={} dropped={} runt={} unknown={} parse_errors={} encrypted={} decrypted={} replay_rejected={} handshakes={} rekeys={}",
            self.packets_in, self.bytes_in, self.ipv4_packets, self.ipv6_packets,
            self.packets_dropped, self.dropped_runt, self.dropped_unknown, self.parse_errors,
            self.packets_encrypted, self.packets_decrypted, self.replay_rejected,
            self.handshakes_completed, self.rekeys_initiated
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn stats_snapshot_display() {
        let stats = PipelineStats::new();
        stats.record_packet(42);
        let snap = stats.snapshot();
        let s = format!("{}", snap);
        assert!(s.contains("packets_in=1"));
        assert!(s.contains("bytes_in=42"));
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

    #[test]
    fn stats_tunnel_counters() {
        let stats = PipelineStats::new();
        stats.packets_encrypted.fetch_add(5, Ordering::Relaxed);
        stats.packets_decrypted.fetch_add(3, Ordering::Relaxed);
        stats.replay_rejected.fetch_add(1, Ordering::Relaxed);
        stats.handshakes_completed.fetch_add(2, Ordering::Relaxed);
        stats.rekeys_initiated.fetch_add(1, Ordering::Relaxed);

        let snap = stats.snapshot();
        assert_eq!(snap.packets_encrypted, 5);
        assert_eq!(snap.packets_decrypted, 3);
        assert_eq!(snap.replay_rejected, 1);
        assert_eq!(snap.handshakes_completed, 2);
        assert_eq!(snap.rekeys_initiated, 1);
    }

    #[test]
    fn stats_snapshot_display_includes_tunnel_counters() {
        let stats = PipelineStats::new();
        stats.packets_encrypted.fetch_add(10, Ordering::Relaxed);
        stats.packets_decrypted.fetch_add(7, Ordering::Relaxed);
        let snap = stats.snapshot();
        let s = format!("{}", snap);
        assert!(s.contains("encrypted=10"));
        assert!(s.contains("decrypted=7"));
    }
}
