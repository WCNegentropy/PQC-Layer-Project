//! Aegis Gateway (Layer 3) — The Sentinel
//!
//! Quantum Gateway providing:
//! - TUN virtual network interface creation (via `tun2`)
//! - Safe IP header parsing (IPv4 + IPv6, no panics on malformed input)
//! - Protocol classification (ICMP, TCP, UDP)
//! - Platform-aware packet handling (macOS 4-byte AF header, Linux raw IP)
//! - PQ-WireGuard handshake over UDP (Noise IK + Hybrid KEM)
//! - Transport encryption/decryption (ChaCha20-Poly1305)
//! - Anti-replay protection (RFC 6479 sliding-window bitmap)
//! - Session management with automatic rekeying
//! - Atomic pipeline statistics with periodic reporting
//! - Graceful shutdown via Ctrl+C with clean TUN teardown
//! - Structured logging with env-filter
//!
//! Run with: sudo cargo run -p aegis-gateway -- --tun-name aegis0 --sanctuary-addr 127.0.0.1:51820 --sanctuary-pk-file sanctuary.pub
//! Test with: ping -c 4 10.0.0.254 (in another terminal)

pub mod anti_replay;
pub mod handshake;
pub mod keypair;
pub mod packet;
pub mod pipeline;
pub mod platform;
pub mod session;
pub mod stats;
pub mod transport;

use clap::Parser;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::signal;
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};

use crate::handshake::{
    build_handshake_init, process_handshake_response, MSG_HANDSHAKE_INIT, MSG_HANDSHAKE_RESPONSE,
    HANDSHAKE_RESPONSE_SIZE,
};
use crate::keypair::{load_or_generate_keypair, load_public_key};
use crate::pipeline::process_packet;
use crate::platform::{create_tun_config, is_root, Args, PACKET_BUF_SIZE, TUN_AF_HEADER_LEN};
use crate::session::SessionManager;
use crate::stats::PipelineStats;
use crate::transport::{parse_transport_header, transport_decrypt, transport_encrypt};

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

    // ── 7. Tunnel setup (if sanctuary address is configured) ──
    let session_mgr = Arc::new(Mutex::new(SessionManager::new()));
    let udp_socket: Option<Arc<UdpSocket>>;

    if let Some(ref sanctuary_addr) = args.sanctuary_addr {
        info!("🔗 Tunnel mode: connecting to Sanctuary at {}", sanctuary_addr);

        // Load or generate our static keypair
        let (our_pk, our_sk) = load_or_generate_keypair(&args.keypair_file)?;

        // Load the sanctuary's public key
        let sanctuary_pk = load_public_key(&args.sanctuary_pk_file)?;

        // Bind a UDP socket for tunnel traffic
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        socket.connect(sanctuary_addr).await?;
        info!("   UDP socket bound to {}", socket.local_addr()?);

        // Perform the handshake over UDP
        let sender_index = rand::random::<u32>();
        let (init_msg, init_state) =
            build_handshake_init(&sanctuary_pk, &our_pk, sender_index)?;

        socket.send(&init_msg).await?;
        info!("   Handshake init sent (sender_index={})", sender_index);

        // Wait for response
        let mut resp_buf = [0u8; HANDSHAKE_RESPONSE_SIZE + 64]; // extra headroom
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            socket.recv(&mut resp_buf),
        )
        .await
        .map_err(|_| anyhow::anyhow!("Handshake timeout: no response from Sanctuary"))??;

        let resp_msg = &resp_buf[..n];
        if resp_msg.is_empty() || resp_msg[0] != MSG_HANDSHAKE_RESPONSE {
            return Err(anyhow::anyhow!(
                "Unexpected response from Sanctuary (type=0x{:02x})",
                resp_msg.first().unwrap_or(&0)
            ));
        }

        let completed = process_handshake_response(
            resp_msg,
            init_state,
            &our_pk,
            &our_sk,
            &sanctuary_pk,
        )?;

        {
            let mut mgr = session_mgr.lock().await;
            mgr.install(completed);
        }

        stats.handshakes_completed.fetch_add(1, Ordering::Relaxed);
        info!("✅ Handshake complete — tunnel session established");

        udp_socket = Some(Arc::new(socket));
    } else {
        info!("📦 No sanctuary address configured — running in log-and-drop mode");
        info!("   Use --sanctuary-addr to enable tunnel mode");
        udp_socket = None;
    }

    // ── 8. Packet processing pipeline ──
    info!("🚀 Quantum Pipeline active. Waiting for packets...");
    info!("   Test with: ping -c 4 {}", args.peer);

    // Split device for concurrent read/write
    let (mut reader, writer) = tokio::io::split(dev);

    // Spawn inbound task: UDP recv → decrypt → TUN write (only if tunnel mode)
    if let Some(ref socket) = udp_socket {
        let socket_clone = Arc::clone(socket);
        let session_mgr_clone = Arc::clone(&session_mgr);
        let stats_clone = Arc::clone(&stats);
        let running_clone = Arc::clone(&running);
        let writer = Arc::new(Mutex::new(writer));

        tokio::spawn(async move {
            let mut buf = [0u8; PACKET_BUF_SIZE + 128]; // headroom for AEAD overhead
            while running_clone.load(Ordering::Relaxed) {
                let recv_result = tokio::select! {
                    result = socket_clone.recv(&mut buf) => result,
                    _ = tokio::time::sleep(std::time::Duration::from_millis(100)) => {
                        continue;
                    }
                };

                match recv_result {
                    Ok(n) => {
                        let data = &buf[..n];

                        // Check message type
                        if n > 0 && data[0] == MSG_HANDSHAKE_INIT {
                            debug!("Received handshake init on client — ignoring");
                            continue;
                        }

                        // Parse transport header
                        let header = match parse_transport_header(data) {
                            Some(h) => h,
                            None => {
                                debug!("Received packet too short for transport header");
                                continue;
                            }
                        };

                        // Look up session and decrypt
                        let mut mgr = session_mgr_clone.lock().await;
                        let session = match mgr.by_receiver_index(header.receiver_index) {
                            Some(s) => s,
                            None => {
                                debug!(
                                    "No session for receiver_index={}",
                                    header.receiver_index
                                );
                                continue;
                            }
                        };

                        // Anti-replay check
                        if !session.check_replay(header.counter) {
                            stats_clone.replay_rejected.fetch_add(1, Ordering::Relaxed);
                            debug!("Replay rejected: counter={}", header.counter);
                            continue;
                        }

                        // Decrypt
                        match transport_decrypt(&session.recv_cipher, data) {
                            Ok(plaintext) => {
                                stats_clone
                                    .packets_decrypted
                                    .fetch_add(1, Ordering::Relaxed);

                                // Write decrypted IP packet to TUN
                                let mut w = writer.lock().await;

                                // On macOS, prepend the AF header
                                #[cfg(target_os = "macos")]
                                {
                                    let af_header = if !plaintext.is_empty()
                                        && (plaintext[0] >> 4) == 6
                                    {
                                        [0, 0, 0, 30u8] // AF_INET6
                                    } else {
                                        [0, 0, 0, 2u8] // AF_INET
                                    };
                                    let mut full_pkt =
                                        Vec::with_capacity(af_header.len() + plaintext.len());
                                    full_pkt.extend_from_slice(&af_header);
                                    full_pkt.extend_from_slice(&plaintext);
                                    if let Err(e) = w.write_all(&full_pkt).await {
                                        error!("TUN write error: {}", e);
                                    }
                                }

                                #[cfg(not(target_os = "macos"))]
                                {
                                    if let Err(e) = w.write_all(&plaintext).await {
                                        error!("TUN write error: {}", e);
                                    }
                                }
                            }
                            Err(e) => {
                                debug!("Decrypt failed: {}", e);
                            }
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        continue;
                    }
                    Err(e) => {
                        error!("UDP recv error: {}", e);
                        break;
                    }
                }
            }
        });
    }

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

                // Process through pipeline (for stats and logging)
                process_packet(ip_packet, &stats);

                // If tunnel mode, encrypt and send over UDP
                if let Some(ref socket) = udp_socket {
                    let mut mgr = session_mgr.lock().await;

                    // Check if we need to rekey
                    if mgr.needs_rekey() {
                        warn!("⚠️  Session needs rekeying (not yet implemented)");
                        stats.rekeys_initiated.fetch_add(1, Ordering::Relaxed);
                    }

                    if let Some(session) = mgr.active_mut() {
                        let counter = session.next_counter();
                        match transport_encrypt(
                            &session.send_cipher,
                            session.remote_index,
                            counter,
                            ip_packet,
                        ) {
                            Ok(pkt) => {
                                if let Err(e) = socket.send(&pkt).await {
                                    error!("UDP send error: {}", e);
                                }
                                stats
                                    .packets_encrypted
                                    .fetch_add(1, Ordering::Relaxed);
                            }
                            Err(e) => {
                                error!("Encrypt error: {}", e);
                            }
                        }
                    } else {
                        debug!("No active session — packet dropped");
                    }
                }
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

    // ── 9. Cleanup ──
    info!("🧹 Final statistics:");
    stats.report();
    info!("🛡️  Aegis Gateway shut down cleanly.");

    Ok(())
}
