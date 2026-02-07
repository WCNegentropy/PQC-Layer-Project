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
}
