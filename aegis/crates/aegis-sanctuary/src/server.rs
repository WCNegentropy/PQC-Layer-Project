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

use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};

use aegis_crypto::{AeadCipher, AegisCrypto, CryptoError, HybridPublicKey, HybridSecretKey};
use hkdf::Hkdf;
use sha3::{Digest, Sha3_256};
use zeroize::Zeroizing;

use crate::config::ServerConfig;
use crate::SanctuaryError;

// ─── Re-export constants and types from gateway ────────────────────────────

/// Message type for handshake initiation.
const MSG_HANDSHAKE_INIT: u8 = 0x01;
/// Message type for handshake response.
const MSG_HANDSHAKE_RESPONSE: u8 = 0x02;
/// Message type for transport data.
const MSG_TRANSPORT_DATA: u8 = 0x04;

/// Size of a handshake init message.
const HANDSHAKE_INIT_SIZE: usize = 1 + 4 + aegis_crypto::HYBRID_PK_SIZE + aegis_crypto::HYBRID_CT_SIZE;
/// Size of a handshake response message.
const HANDSHAKE_RESPONSE_SIZE: usize = 1 + 4 + 4 + aegis_crypto::HYBRID_CT_SIZE;

/// Size of transport packet header.
const TRANSPORT_HEADER_SIZE: usize = 12; // receiver_index(4) + counter(8)
/// Minimum transport packet size.
const TRANSPORT_MIN_SIZE: usize = TRANSPORT_HEADER_SIZE + aegis_crypto::AEAD_TAG_SIZE;

/// HKDF info string for transport key derivation.
const TRANSPORT_HKDF_INFO: &[u8] = b"aegis-pqwg-transport-v1";
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
    last_counter: u64,
    bitmap: u64,
}

impl AntiReplayWindow {
    fn new() -> Self {
        Self {
            last_counter: 0,
            bitmap: 0,
        }
    }

    fn check_and_update(&mut self, counter: u64) -> bool {
        const WINDOW_SIZE: u64 = 64;

        if counter == 0 {
            return false; // Counter 0 is reserved
        }

        if counter > self.last_counter {
            // Advance window
            let delta = counter - self.last_counter;
            if delta < WINDOW_SIZE {
                self.bitmap = (self.bitmap << delta) | 1;
            } else {
                self.bitmap = 1;
            }
            self.last_counter = counter;
            true
        } else if self.last_counter - counter < WINDOW_SIZE {
            // Within window
            let bit_index = self.last_counter - counter;
            let mask = 1u64 << bit_index;
            if self.bitmap & mask != 0 {
                false // Replay
            } else {
                self.bitmap |= mask;
                true
            }
        } else {
            false // Too old
        }
    }
}

// ─── Handshake Helpers ──────────────────────────────────────────────────────

fn compute_transcript_hash(
    responder_pk: &[u8],
    initiator_pk: &[u8],
    kem_ct: &[u8],
) -> [u8; 32] {
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
) -> Result<(Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>), CryptoError> {
    let mut combined = [0u8; 96];
    combined[0..32].copy_from_slice(ss1);
    combined[32..64].copy_from_slice(ss2);
    combined[64..96].copy_from_slice(transcript);

    let hkdf = Hkdf::<Sha3_256>::new(None, &combined);
    let mut out = Zeroizing::new([0u8; 64]);
    hkdf.expand(TRANSPORT_HKDF_INFO, out.as_mut_slice())
        .map_err(|_| CryptoError::AeadError)?;

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
    let transcript_hash_1 = compute_transcript_hash(
        &responder_pk.to_bytes(),
        initiator_pk_bytes,
        ct_bytes,
    );

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

fn transport_decrypt(
    cipher: &AeadCipher,
    data: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
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
    pub packets_encrypted: AtomicU64,
    pub packets_decrypted: AtomicU64,
    pub replay_rejected: AtomicU64,
    pub bytes_received: AtomicU64,
    pub bytes_sent: AtomicU64,
}

impl ServerStats {
    pub fn report(&self) {
        info!(
            "📊 Server Stats: handshakes={} | encrypted={} | decrypted={} | replay_rejected={} | rx_bytes={} | tx_bytes={}",
            self.handshakes_completed.load(Ordering::Relaxed),
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
    stats: Arc<ServerStats>,
    running: Arc<AtomicBool>,
}

impl SanctuaryServer {
    /// Bind and create a new sanctuary server.
    pub async fn bind(config: &ServerConfig) -> Result<Self, SanctuaryError> {
        info!("🏰 Sanctuary Server starting...");
        info!("   Listening on {}", config.server.listen_addr);

        // Load or generate keypair
        let (pk, sk) = load_or_generate_keypair(&config.server.keypair_file)
            .map_err(|e| SanctuaryError::BindError(e.to_string()))?;

        info!("   Server public key loaded ({} bytes)", pk.to_bytes().len());

        // Load authorized peers
        let authorized_peers = config.load_authorized_peers()?;
        if authorized_peers.is_empty() {
            warn!("⚠️  No authorized peers configured — accepting all clients (open mode)");
        } else {
            info!("   {} authorized peer(s) loaded", authorized_peers.len());
        }

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
            stats: Arc::new(ServerStats::default()),
            running: Arc::new(AtomicBool::new(true)),
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

            self.stats.bytes_received.fetch_add(n as u64, Ordering::Relaxed);

            let data = &buf[..n];
            if data.is_empty() {
                continue;
            }

            match data[0] {
                MSG_HANDSHAKE_INIT => {
                    self.handle_handshake_init(data, peer_addr).await;
                }
                MSG_TRANSPORT_DATA => {
                    self.handle_transport_data(data, peer_addr).await;
                }
                _ => {
                    debug!("Unknown message type: 0x{:02x} from {}", data[0], peer_addr);
                }
            }
        }

        info!("🛑 Sanctuary server stopped");
        Ok(())
    }

    async fn handle_handshake_init(&self, data: &[u8], peer_addr: SocketAddr) {
        debug!("Received handshake init from {}", peer_addr);

        // Generate a unique local index for this session
        let local_index = rand::random::<u32>();

        match process_handshake_init(data, &self.keypair.0, &self.keypair.1, local_index, peer_addr) {
            Ok((resp, session)) => {
                // Check if peer is authorized (if we're not in open mode)
                if !self.authorized_peers.is_empty() {
                    // Extract initiator's public key from the init message
                    let initiator_pk_bytes = &data[5..5 + aegis_crypto::HYBRID_PK_SIZE];
                    if !self.authorized_peers.contains(initiator_pk_bytes) {
                        warn!("Unauthorized peer attempted connection from {}", peer_addr);
                        return;
                    }
                }

                // Store session
                {
                    let mut sessions = self.sessions.lock().await;
                    let mut peer_map = self.peer_to_index.lock().await;
                    sessions.insert(local_index, session);
                    peer_map.insert(peer_addr, local_index);
                }

                // Send response
                if let Err(e) = self.socket.send_to(&resp, peer_addr).await {
                    error!("Failed to send handshake response to {}: {}", peer_addr, e);
                } else {
                    self.stats.handshakes_completed.fetch_add(1, Ordering::Relaxed);
                    self.stats.bytes_sent.fetch_add(resp.len() as u64, Ordering::Relaxed);
                    info!("✅ Handshake complete with {} (session={})", peer_addr, local_index);
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
                debug!("No session for receiver_index={} from {}", header.receiver_index, peer_addr);
                return;
            }
        };

        // Anti-replay check
        if !session.recv_window.check_and_update(header.counter) {
            self.stats.replay_rejected.fetch_add(1, Ordering::Relaxed);
            debug!("Replay rejected: counter={} from {}", header.counter, peer_addr);
            return;
        }

        // Decrypt
        match transport_decrypt(&session.recv_cipher, data) {
            Ok(plaintext) => {
                self.stats.packets_decrypted.fetch_add(1, Ordering::Relaxed);
                debug!("Decrypted {} bytes from {}", plaintext.len(), peer_addr);

                // For v0: Just log-and-drop (NAT proxy stub)
                // In a real implementation, this would forward to a TUN device or NAT proxy
                // For now, we'll echo a simple response back to demonstrate bidirectional tunnel

                // Echo back: encrypt and send a dummy response
                // (In real use, this would be the return traffic from the internet)
                let counter = session.next_counter();
                match transport_encrypt(&session.send_cipher, session.remote_index, counter, &plaintext) {
                    Ok(encrypted) => {
                        if let Err(e) = self.socket.send_to(&encrypted, peer_addr).await {
                            error!("Failed to send encrypted response to {}: {}", peer_addr, e);
                        } else {
                            self.stats.packets_encrypted.fetch_add(1, Ordering::Relaxed);
                            self.stats.bytes_sent.fetch_add(encrypted.len() as u64, Ordering::Relaxed);
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

    info!("   Server private key: {} ({} bytes)", keypair_file, sk_bytes.len());
    info!("   Server public key:  {} ({} bytes)", pk_path, pk_bytes.len());
    Ok(())
}
