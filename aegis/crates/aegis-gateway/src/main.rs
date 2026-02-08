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

pub mod packet;
pub mod pipeline;
pub mod platform;
pub mod stats;

use clap::Parser;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::io::AsyncReadExt;
use tokio::signal;
use tracing::{debug, error, info};

use crate::pipeline::process_packet;
use crate::platform::{create_tun_config, is_root, Args, PACKET_BUF_SIZE, TUN_AF_HEADER_LEN};
use crate::stats::PipelineStats;

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
    let dev = tun2::create_as_async(&config).map_err(|e| {
        anyhow::anyhow!(
            "Failed to create TUN device '{}': {}. \
             Ensure no other process is using this device name and that \
             the TUN kernel module is loaded (Linux: modprobe tun).",
            args.tun_name,
            e
        )
    })?;

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
