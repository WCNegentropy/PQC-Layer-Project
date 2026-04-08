//! Sanctuary server: PQ-WG listener.
//!
//! Accepts PQ-WireGuard connections from Aegis clients on a UDP port.
//! Each client authenticates via the PQ-WG handshake and receives a
//! tunnel session for encrypted traffic forwarding.
//!
//! # Architecture
//!
//! ```text
//! Client ──UDP──▶ SanctuaryServer ──NAT──▶ Internet
//!   (PQ-WG)         (decrypt/encrypt)
//! ```
//!
//! The server:
//! 1. Listens on a UDP socket for incoming handshake init messages
//! 2. Performs responder-side handshake (process_handshake_init)
//! 3. Maintains sessions per client (indexed by SocketAddr)
//! 4. Decrypts inbound transport packets from clients
//! 5. Forwards decrypted IP packets (via NAT proxy stub for v0)
//! 6. Encrypts and sends responses back to clients

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};

use aegis_crypto::{AeadCipher, AegisCrypto, CryptoError, HybridPublicKey, HybridSecretKey};
use hkdf::Hkdf;
use sha3::{Digest, Sha3_256};
use zeroize::Zeroizing;

use crate::config::ServerConfig;
use crate::proxy::NatProxy;
use crate::SanctuaryError;

// ─── Re-export constants and types from gateway ────────────────────────────

/// Message type for handshake initiation.
const MSG_HANDSHAKE_INIT: u8 = 0x01;
/// Message type for handshake response.
const MSG_HANDSHAKE_RESPONSE: u8 = 0x02;
/// Message type for transport data (used for protocol documentation;
/// actual dispatching treats any non-handshake message as transport).
#[allow(dead_code)]
const MSG_TRANSPORT_DATA: u8 = 0x04;

/// Size of a handshake init message.
const HANDSHAKE_INIT_SIZE: usize =
    1 + 4 + aegis_crypto::HYBRID_PK_SIZE + aegis_crypto::HYBRID_CT_SIZE;
/// Size of a handshake response message.
const HANDSHAKE_RESPONSE_SIZE: usize = 1 + 4 + 4 + aegis_crypto::HYBRID_CT_SIZE;

/// Size of transport packet header.
const TRANSPORT_HEADER_SIZE: usize = 12; // receiver_index(4) + counter(8)
/// Minimum transport packet size.
const TRANSPORT_MIN_SIZE: usize = TRANSPORT_HEADER_SIZE + aegis_crypto::AEAD_TAG_SIZE;

/// HKDF info string for transport key derivation.
const TRANSPORT_HKDF_INFO: &[u8] = b"aegis-pqwg-transport-v1";

/// A pair of transport keys (send, receive) derived from the handshake.
type TransportKeyPair = (Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>);
/// Label for handshake transcript binding.
const HANDSHAKE_TRANSCRIPT_LABEL: &[u8] = b"aegis-pqwg-handshake-transcript-v1";

const PACKET_BUF_SIZE: usize = 65536;

// ─── Session Management ─────────────────────────────────────────────────────

/// A client session with transport keys and anti-replay state.
#[allow(dead_code)]
struct ClientSession {
    /// Cipher for encrypting packets to the client.
    send_cipher: AeadCipher,
    /// Cipher for decrypting packets from the client.
    recv_cipher: AeadCipher,
    /// Next counter value for outbound packets to this client.
    send_counter: u64,
    /// Anti-replay window (simple bitmap for now).
    recv_window: AntiReplayWindow,
    /// Index the client uses to identify this session.
    local_index: u32,
    /// Index we use to identify the client session.
    remote_index: u32,
    /// Client's peer address.
    peer_addr: SocketAddr,
}

impl ClientSession {
    fn next_counter(&mut self) -> u64 {
        self.send_counter += 1;
        self.send_counter
    }
}

/// Simple anti-replay window (RFC 6479 sliding bitmap).
struct AntiReplayWindow {
    top: u64,
    bitmap: u128,
}

impl AntiReplayWindow {
    fn new() -> Self {
        Self { top: 0, bitmap: 0 }
    }

    fn check_and_update(&mut self, counter: u64) -> bool {
        const WINDOW_SIZE: u64 = 128;

        if counter == 0 {
            return false; // Counter 0 is reserved
        }

        if counter > self.top {
            let shift = counter - self.top;
            if shift >= WINDOW_SIZE {
                self.bitmap = 0;
            } else {
                self.bitmap <<= shift;
            }
            self.top = counter;
            self.bitmap |= 1;
            return true;
        }

        let offset = self.top - counter;
        if offset >= WINDOW_SIZE {
            return false;
        }

        let bit = 1u128 << offset;
        if self.bitmap & bit != 0 {
            return false;
        }

        self.bitmap |= bit;
        true
    }
}

#[derive(Debug, Clone, Copy)]
struct HandshakeRateLimit {
    window: Duration,
    max_attempts: u32,
}

#[derive(Debug, Clone, Copy)]
struct PeerHandshakeState {
    window_started_at: Instant,
    attempts: u32,
}

#[derive(Debug)]
struct HandshakeAdmissionTracker {
    limits: HandshakeRateLimit,
    peers: HashMap<SocketAddr, PeerHandshakeState>,
}

impl HandshakeAdmissionTracker {
    fn new(window: Duration, max_attempts: u32) -> Self {
        Self {
            limits: HandshakeRateLimit {
                window,
                max_attempts,
            },
            peers: HashMap::new(),
        }
    }

    fn check_and_record(&mut self, peer_addr: SocketAddr) -> bool {
        let now = Instant::now();
        self.prune(now);

        let entry = self.peers.entry(peer_addr).or_insert(PeerHandshakeState {
            window_started_at: now,
            attempts: 0,
        });

        if now.duration_since(entry.window_started_at) >= self.limits.window {
            entry.window_started_at = now;
            entry.attempts = 0;
        }

        if entry.attempts >= self.limits.max_attempts {
            return false;
        }

        entry.attempts += 1;
        true
    }

    fn prune(&mut self, now: Instant) {
        self.peers
            .retain(|_, state| now.duration_since(state.window_started_at) < self.limits.window);
    }
}

// ─── Handshake Helpers ──────────────────────────────────────────────────────

fn compute_transcript_hash(responder_pk: &[u8], initiator_pk: &[u8], kem_ct: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(HANDSHAKE_TRANSCRIPT_LABEL);
    hasher.update(responder_pk);
    hasher.update(initiator_pk);
    hasher.update(kem_ct);
    hasher.finalize().into()
}

fn extend_transcript_hash(base: &[u8; 32], ct_r: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(base);
    hasher.update(ct_r);
    hasher.finalize().into()
}

fn derive_transport_keys(
    ss1: &[u8; 32],
    ss2: &[u8; 32],
    transcript: &[u8; 32],
    is_initiator: bool,
) -> Result<TransportKeyPair, CryptoError> {
    let mut ikm = Zeroizing::new([0u8; 64]);
    ikm[..32].copy_from_slice(ss1);
    ikm[32..].copy_from_slice(ss2);

    let hkdf = Hkdf::<Sha3_256>::new(Some(transcript), ikm.as_ref());
    let mut out = Zeroizing::new([0u8; 64]);
    hkdf.expand(TRANSPORT_HKDF_INFO, out.as_mut_slice())
        .map_err(|_| CryptoError::KdfError)?;

    let mut send_key = Zeroizing::new([0u8; 32]);
    let mut recv_key = Zeroizing::new([0u8; 32]);

    if is_initiator {
        send_key.copy_from_slice(&out[0..32]);
        recv_key.copy_from_slice(&out[32..64]);
    } else {
        recv_key.copy_from_slice(&out[0..32]);
        send_key.copy_from_slice(&out[32..64]);
    }

    Ok((send_key, recv_key))
}

fn initiator_public_key_bytes(msg: &[u8]) -> Result<&[u8], CryptoError> {
    if msg.len() != HANDSHAKE_INIT_SIZE {
        return Err(CryptoError::InvalidLength {
            expected: HANDSHAKE_INIT_SIZE,
            got: msg.len(),
        });
    }

    if msg[0] != MSG_HANDSHAKE_INIT {
        return Err(CryptoError::AeadError);
    }

    Ok(&msg[5..5 + aegis_crypto::HYBRID_PK_SIZE])
}

/// Process a handshake init message (responder side) and build a response.
fn process_handshake_init(
    msg: &[u8],
    responder_pk: &HybridPublicKey,
    responder_sk: &HybridSecretKey,
    responder_index: u32,
    peer_addr: SocketAddr,
) -> Result<(Vec<u8>, ClientSession), CryptoError> {
    if msg.len() != HANDSHAKE_INIT_SIZE {
        return Err(CryptoError::InvalidLength {
            expected: HANDSHAKE_INIT_SIZE,
            got: msg.len(),
        });
    }

    if msg[0] != MSG_HANDSHAKE_INIT {
        return Err(CryptoError::AeadError);
    }

    let initiator_index = u32::from_le_bytes(msg[1..5].try_into().unwrap());
    let initiator_pk_bytes = &msg[5..5 + aegis_crypto::HYBRID_PK_SIZE];
    let ct_bytes = &msg[5 + aegis_crypto::HYBRID_PK_SIZE..];

    // Deserialize
    let initiator_pk = HybridPublicKey::from_bytes(initiator_pk_bytes)?;
    let ct = aegis_crypto::HybridCiphertext::from_bytes(ct_bytes)?;

    // Decapsulate to recover shared_secret_1
    let shared_secret_1 = AegisCrypto::decapsulate(&ct, responder_sk, responder_pk)?;

    // Compute transcript hash
    let transcript_hash_1 =
        compute_transcript_hash(&responder_pk.to_bytes(), initiator_pk_bytes, ct_bytes);

    // Encapsulate back to initiator's PK → shared_secret_2
    let encap_r = AegisCrypto::encapsulate(&initiator_pk)?;
    let ct_r_bytes = encap_r.ciphertext.to_bytes();

    let transcript_hash_2 = extend_transcript_hash(&transcript_hash_1, &ct_r_bytes);

    // Derive transport keys (we are the responder)
    let (send_key, recv_key) = derive_transport_keys(
        &shared_secret_1,
        &encap_r.shared_secret,
        &transcript_hash_2,
        false, // responder
    )?;

    // Build response message
    let mut resp = Vec::with_capacity(HANDSHAKE_RESPONSE_SIZE);
    resp.push(MSG_HANDSHAKE_RESPONSE);
    resp.extend_from_slice(&responder_index.to_le_bytes());
    resp.extend_from_slice(&initiator_index.to_le_bytes());
    resp.extend_from_slice(&ct_r_bytes);

    let session = ClientSession {
        send_cipher: AeadCipher::new(&send_key),
        recv_cipher: AeadCipher::new(&recv_key),
        send_counter: 0,
        recv_window: AntiReplayWindow::new(),
        local_index: responder_index,
        remote_index: initiator_index,
        peer_addr,
    };

    Ok((resp, session))
}

// ─── Transport Encryption/Decryption ────────────────────────────────────────

fn counter_to_nonce(counter: u64) -> [u8; aegis_crypto::AEAD_NONCE_SIZE] {
    let mut nonce = [0u8; aegis_crypto::AEAD_NONCE_SIZE];
    nonce[4..12].copy_from_slice(&counter.to_le_bytes());
    nonce
}

fn transport_encrypt(
    cipher: &AeadCipher,
    receiver_index: u32,
    counter: u64,
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let nonce = counter_to_nonce(counter);
    let ciphertext = cipher.encrypt(&nonce, plaintext, &[])?;

    let mut pkt = Vec::with_capacity(TRANSPORT_HEADER_SIZE + ciphertext.len());
    pkt.extend_from_slice(&receiver_index.to_le_bytes());
    pkt.extend_from_slice(&counter.to_le_bytes());
    pkt.extend_from_slice(&ciphertext);
    Ok(pkt)
}

fn transport_decrypt(cipher: &AeadCipher, data: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    if data.len() < TRANSPORT_MIN_SIZE {
        return Err(CryptoError::InvalidLength {
            expected: TRANSPORT_MIN_SIZE,
            got: data.len(),
        });
    }

    let counter = u64::from_le_bytes(data[4..12].try_into().unwrap());
    let nonce = counter_to_nonce(counter);
    let ciphertext_with_tag = &data[TRANSPORT_HEADER_SIZE..];

    cipher.decrypt(&nonce, ciphertext_with_tag, &[])
}

struct TransportHeader {
    receiver_index: u32,
    counter: u64,
}

fn parse_transport_header(data: &[u8]) -> Option<TransportHeader> {
    if data.len() < TRANSPORT_MIN_SIZE {
        return None;
    }
    let receiver_index = u32::from_le_bytes(data[0..4].try_into().unwrap());
    let counter = u64::from_le_bytes(data[4..12].try_into().unwrap());
    Some(TransportHeader {
        receiver_index,
        counter,
    })
}

// ─── Statistics ─────────────────────────────────────────────────────────────

#[derive(Debug, Default)]
pub struct ServerStats {
    pub handshakes_completed: AtomicU64,
    pub handshakes_rate_limited: AtomicU64,
    pub unauthorized_handshakes: AtomicU64,
    pub packets_encrypted: AtomicU64,
    pub packets_decrypted: AtomicU64,
    pub replay_rejected: AtomicU64,
    pub bytes_received: AtomicU64,
    pub bytes_sent: AtomicU64,
}

impl ServerStats {
    pub fn report(&self) {
        info!(
            "📊 Server Stats: handshakes={} | rate_limited={} | unauthorized={} | encrypted={} | decrypted={} | replay_rejected={} | rx_bytes={} | tx_bytes={}",
            self.handshakes_completed.load(Ordering::Relaxed),
            self.handshakes_rate_limited.load(Ordering::Relaxed),
            self.unauthorized_handshakes.load(Ordering::Relaxed),
            self.packets_encrypted.load(Ordering::Relaxed),
            self.packets_decrypted.load(Ordering::Relaxed),
            self.replay_rejected.load(Ordering::Relaxed),
            self.bytes_received.load(Ordering::Relaxed),
            self.bytes_sent.load(Ordering::Relaxed),
        );
    }
}

// ─── Sanctuary Server ───────────────────────────────────────────────────────

/// The main sanctuary server managing PQ-WG connections.
pub struct SanctuaryServer {
    socket: Arc<UdpSocket>,
    keypair: (HybridPublicKey, HybridSecretKey),
    sessions: Arc<Mutex<HashMap<u32, ClientSession>>>, // indexed by local_index
    peer_to_index: Arc<Mutex<HashMap<SocketAddr, u32>>>, // map peer addr → local_index
    authorized_peers: std::collections::HashSet<Vec<u8>>,
    handshake_admission: Arc<Mutex<HandshakeAdmissionTracker>>,
    stats: Arc<ServerStats>,
    running: Arc<AtomicBool>,
    proxy: Arc<NatProxy>,
}

impl SanctuaryServer {
    /// Bind and create a new sanctuary server.
    pub async fn bind(config: &ServerConfig) -> Result<Self, SanctuaryError> {
        info!("🏰 Sanctuary Server starting...");
        info!("   Listening on {}", config.server.listen_addr);

        // Load or generate keypair
        let (pk, sk) = load_or_generate_keypair(&config.server.keypair_file)
            .map_err(|e| SanctuaryError::BindError(e.to_string()))?;

        info!(
            "   Server public key loaded ({} bytes)",
            pk.to_bytes().len()
        );

        // Load authorized peers
        let authorized_peers = config.load_authorized_peers()?;
        if authorized_peers.is_empty() {
            warn!("⚠️  No authorized peers configured — accepting all clients (open mode)");
        } else {
            info!("   {} authorized peer(s) loaded", authorized_peers.len());
        }
        info!(
            "   Handshake rate limit: {} attempt(s) per {}s per peer",
            config.server.handshake_rate_limit_max_attempts,
            config.server.handshake_rate_limit_window_secs
        );

        // Bind UDP socket
        let socket = UdpSocket::bind(&config.server.listen_addr)
            .await
            .map_err(|e| SanctuaryError::BindError(e.to_string()))?;

        info!("✅ Server bound to {}", socket.local_addr().unwrap());

        Ok(Self {
            socket: Arc::new(socket),
            keypair: (pk, sk),
            sessions: Arc::new(Mutex::new(HashMap::new())),
            peer_to_index: Arc::new(Mutex::new(HashMap::new())),
            authorized_peers,
            handshake_admission: Arc::new(Mutex::new(HandshakeAdmissionTracker::new(
                Duration::from_secs(config.server.handshake_rate_limit_window_secs),
                config.server.handshake_rate_limit_max_attempts,
            ))),
            stats: Arc::new(ServerStats::default()),
            running: Arc::new(AtomicBool::new(true)),
            proxy: Arc::new(NatProxy::default()),
        })
    }

    /// Run the server event loop.
    pub async fn run(&self) -> Result<(), SanctuaryError> {
        info!("🚀 Sanctuary server running. Waiting for clients...");

        // Spawn stats reporter
        let stats_clone = Arc::clone(&self.stats);
        let running_clone = Arc::clone(&self.running);
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(std::time::Duration::from_secs(30));
            ticker.tick().await;
            while running_clone.load(Ordering::Relaxed) {
                ticker.tick().await;
                stats_clone.report();
            }
        });

        let mut buf = [0u8; PACKET_BUF_SIZE];

        loop {
            if !self.running.load(Ordering::Relaxed) {
                break;
            }

            let (n, peer_addr) = match self.socket.recv_from(&mut buf).await {
                Ok(result) => result,
                Err(e) => {
                    error!("UDP recv error: {}", e);
                    continue;
                }
            };

            self.stats
                .bytes_received
                .fetch_add(n as u64, Ordering::Relaxed);

            let data = &buf[..n];
            if data.is_empty() {
                continue;
            }

            match data[0] {
                MSG_HANDSHAKE_INIT => {
                    self.handle_handshake_init(data, peer_addr).await;
                }
                _ => {
                    // All non-handshake-init messages are transport data.
                    // MSG_HANDSHAKE_RESPONSE (0x02) should never arrive at
                    // the server (we are always the responder), but we treat
                    // it the same — the transport decryption will fail and
                    // the packet will be silently dropped.
                    self.handle_transport_data(data, peer_addr).await;
                }
            }
        }

        info!("🛑 Sanctuary server stopped");
        Ok(())
    }

    async fn handle_handshake_init(&self, data: &[u8], peer_addr: SocketAddr) {
        debug!("Received handshake init from {}", peer_addr);

        {
            let mut admission = self.handshake_admission.lock().await;
            if !admission.check_and_record(peer_addr) {
                self.stats
                    .handshakes_rate_limited
                    .fetch_add(1, Ordering::Relaxed);
                warn!("Rate-limited handshake init from {}", peer_addr);
                return;
            }
        }

        let initiator_pk_bytes = match initiator_public_key_bytes(data) {
            Ok(bytes) => bytes,
            Err(e) => {
                warn!("Malformed handshake init from {}: {}", peer_addr, e);
                return;
            }
        };

        if !self.authorized_peers.is_empty() && !self.authorized_peers.contains(initiator_pk_bytes) {
            self.stats
                .unauthorized_handshakes
                .fetch_add(1, Ordering::Relaxed);
            warn!("Unauthorized peer attempted connection from {}", peer_addr);
            return;
        }

        // Generate a unique local index for this session
        let local_index = rand::random::<u32>();

        match process_handshake_init(
            data,
            &self.keypair.0,
            &self.keypair.1,
            local_index,
            peer_addr,
        ) {
            Ok((resp, session)) => {
                // If this peer already has a session, remove the old one (rekey)
                {
                    let mut sessions = self.sessions.lock().await;
                    let mut peer_map = self.peer_to_index.lock().await;
                    if let Some(old_index) = peer_map.remove(&peer_addr) {
                        sessions.remove(&old_index);
                        debug!(
                            "Replaced existing session {} for peer {} (rekey)",
                            old_index, peer_addr
                        );
                    }
                    sessions.insert(local_index, session);
                    peer_map.insert(peer_addr, local_index);
                }

                // Send response
                if let Err(e) = self.socket.send_to(&resp, peer_addr).await {
                    error!("Failed to send handshake response to {}: {}", peer_addr, e);
                } else {
                    self.stats
                        .handshakes_completed
                        .fetch_add(1, Ordering::Relaxed);
                    self.stats
                        .bytes_sent
                        .fetch_add(resp.len() as u64, Ordering::Relaxed);
                    info!(
                        "✅ Handshake complete with {} (session={})",
                        peer_addr, local_index
                    );
                }
            }
            Err(e) => {
                warn!("Handshake init processing failed from {}: {}", peer_addr, e);
            }
        }
    }

    async fn handle_transport_data(&self, data: &[u8], peer_addr: SocketAddr) {
        let header = match parse_transport_header(data) {
            Some(h) => h,
            None => {
                debug!("Invalid transport header from {}", peer_addr);
                return;
            }
        };

        // Look up session
        let mut sessions = self.sessions.lock().await;
        let session = match sessions.get_mut(&header.receiver_index) {
            Some(s) => s,
            None => {
                debug!(
                    "No session for receiver_index={} from {}",
                    header.receiver_index, peer_addr
                );
                return;
            }
        };

        // Anti-replay check
        if !session.recv_window.check_and_update(header.counter) {
            self.stats.replay_rejected.fetch_add(1, Ordering::Relaxed);
            debug!(
                "Replay rejected: counter={} from {}",
                header.counter, peer_addr
            );
            return;
        }

        // Decrypt
        match transport_decrypt(&session.recv_cipher, data) {
            Ok(plaintext) => {
                self.stats.packets_decrypted.fetch_add(1, Ordering::Relaxed);
                debug!("Decrypted {} bytes from {}", plaintext.len(), peer_addr);

                // Forward through NAT proxy (no-op when TUN not configured)
                if let Err(e) = self.proxy.forward(&plaintext).await {
                    warn!("Proxy forward error from {}: {}", peer_addr, e);
                }

                // Echo back for v0 demonstration / connectivity testing.
                // When TUN-based NAT forwarding is active, the return path
                // is handled by a separate reader task on the TUN device.
                let counter = session.next_counter();
                match transport_encrypt(
                    &session.send_cipher,
                    session.remote_index,
                    counter,
                    &plaintext,
                ) {
                    Ok(encrypted) => {
                        if let Err(e) = self.socket.send_to(&encrypted, peer_addr).await {
                            error!("Failed to send encrypted response to {}: {}", peer_addr, e);
                        } else {
                            self.stats.packets_encrypted.fetch_add(1, Ordering::Relaxed);
                            self.stats
                                .bytes_sent
                                .fetch_add(encrypted.len() as u64, Ordering::Relaxed);
                            debug!("Sent encrypted response to {}", peer_addr);
                        }
                    }
                    Err(e) => {
                        error!("Failed to encrypt response: {}", e);
                    }
                }
            }
            Err(e) => {
                debug!("Decrypt failed from {}: {}", peer_addr, e);
            }
        }
    }

    /// Get server statistics.
    pub fn stats(&self) -> &ServerStats {
        &self.stats
    }

    /// Get a reference to the NAT proxy.
    pub fn proxy(&self) -> &Arc<NatProxy> {
        &self.proxy
    }

    /// Get the local address the server is listening on.
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// Create a handle for shutdown signaling.
    pub fn clone_for_shutdown(&self) -> ShutdownHandle {
        ShutdownHandle {
            running: Arc::clone(&self.running),
        }
    }

    /// Gracefully stop the server.
    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }
}

/// Handle for signaling server shutdown.
pub struct ShutdownHandle {
    running: Arc<AtomicBool>,
}

impl ShutdownHandle {
    /// Stop the server.
    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }
}

// ─── Keypair Loading (re-use gateway's logic) ───────────────────────────────

fn load_or_generate_keypair(
    keypair_file: &str,
) -> anyhow::Result<(HybridPublicKey, HybridSecretKey)> {
    use std::path::Path;
    let sk_path = Path::new(keypair_file);

    if sk_path.exists() {
        info!("🔑 Loading server keypair from {}", keypair_file);
        load_keypair(keypair_file)
    } else {
        info!("🔑 Generating new server keypair → {}", keypair_file);
        let (pk, sk) = AegisCrypto::keygen();
        save_keypair(keypair_file, &pk, &sk)?;
        Ok((pk, sk))
    }
}

fn load_keypair(keypair_file: &str) -> anyhow::Result<(HybridPublicKey, HybridSecretKey)> {
    use std::fs;
    let sk_bytes = fs::read(keypair_file)
        .map_err(|e| anyhow::anyhow!("Failed to read secret key from '{}': {}", keypair_file, e))?;
    let sk = HybridSecretKey::from_bytes(&sk_bytes)
        .map_err(|e| anyhow::anyhow!("Invalid secret key in '{}': {}", keypair_file, e))?;

    let pk_path = format!("{}.pub", keypair_file);
    let pk_bytes = fs::read(&pk_path)
        .map_err(|e| anyhow::anyhow!("Failed to read public key from '{}': {}", pk_path, e))?;
    let pk = HybridPublicKey::from_bytes(&pk_bytes)
        .map_err(|e| anyhow::anyhow!("Invalid public key in '{}': {}", pk_path, e))?;

    info!("   Loaded server keypair: {} + {}", keypair_file, pk_path);
    Ok((pk, sk))
}

fn save_keypair(
    keypair_file: &str,
    pk: &HybridPublicKey,
    sk: &HybridSecretKey,
) -> anyhow::Result<()> {
    use std::fs;
    let sk_bytes = sk.to_bytes();
    let pk_bytes = pk.to_bytes();

    fs::write(keypair_file, sk_bytes.as_slice())
        .map_err(|e| anyhow::anyhow!("Failed to write secret key to '{}': {}", keypair_file, e))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(keypair_file, fs::Permissions::from_mode(0o600)).map_err(|e| {
            anyhow::anyhow!("Failed to set permissions on '{}': {}", keypair_file, e)
        })?;
    }

    let pk_path = format!("{}.pub", keypair_file);
    fs::write(&pk_path, &pk_bytes)
        .map_err(|e| anyhow::anyhow!("Failed to write public key to '{}': {}", pk_path, e))?;

    info!(
        "   Server private key: {} ({} bytes)",
        keypair_file,
        sk_bytes.len()
    );
    info!(
        "   Server public key:  {} ({} bytes)",
        pk_path,
        pk_bytes.len()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn peer(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
    }

    #[test]
    fn anti_replay_window_matches_gateway_behavior() {
        let mut window = AntiReplayWindow::new();
        assert!(window.check_and_update(128));
        assert!(window.check_and_update(1));
        assert!(!window.check_and_update(1));
        assert!(window.check_and_update(129));
        assert!(!window.check_and_update(1));
    }

    #[test]
    fn handshake_admission_tracker_limits_per_peer() {
        let mut tracker = HandshakeAdmissionTracker::new(Duration::from_secs(60), 2);
        assert!(tracker.check_and_record(peer(1001)));
        assert!(tracker.check_and_record(peer(1001)));
        assert!(!tracker.check_and_record(peer(1001)));
        assert!(tracker.check_and_record(peer(1002)));
    }

    #[test]
    fn initiator_public_key_bytes_rejects_short_messages() {
        let err = initiator_public_key_bytes(&[MSG_HANDSHAKE_INIT]).unwrap_err();
        assert!(matches!(err, CryptoError::InvalidLength { .. }));
    }
}
