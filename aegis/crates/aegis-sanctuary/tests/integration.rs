//! Integration tests for Sanctuary ↔ Gateway tunnel.
//!
//! These tests verify end-to-end PQ-WireGuard handshake and encrypted
//! transport between the Aegis Gateway (client) and Sanctuary (server).

use std::sync::Arc;

use tokio::net::UdpSocket;

use aegis_crypto::{AeadCipher, AegisCrypto, HybridPublicKey, HybridSecretKey};
use aegis_sanctuary::config::{ServerConfig, ServerSettings};
use aegis_sanctuary::server::SanctuaryServer;

// Import handshake functions (these are in gateway, need to be public or we replicate)
// For now, we'll use a simplified version that directly calls the server's process_handshake_init

/// Helper to create a test server config with a unique keypair file.
fn test_server_config(suffix: &str) -> ServerConfig {
    ServerConfig {
        server: ServerSettings {
            listen_addr: "127.0.0.1:0".to_string(), // bind to random port
            keypair_file: format!("/tmp/test_sanctuary_{}.key", suffix),
            log_level: "debug".to_string(),
            authorized_peers_dir: None, // open mode for testing
        },
    }
}

/// Set up server keypair files for testing.
fn setup_server_keypair(
    config: &ServerConfig,
) -> (aegis_crypto::HybridPublicKey, aegis_crypto::HybridSecretKey) {
    let (pk, sk) = AegisCrypto::keygen();
    let sk_bytes = sk.to_bytes();
    let pk_bytes = pk.to_bytes();
    std::fs::write(&config.server.keypair_file, sk_bytes.as_slice()).unwrap();
    std::fs::write(format!("{}.pub", &config.server.keypair_file), &pk_bytes).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            &config.server.keypair_file,
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
    }
    (pk, sk)
}

/// Clean up test keypair files.
fn cleanup_server_keypair(config: &ServerConfig) {
    let _ = std::fs::remove_file(&config.server.keypair_file);
    let _ = std::fs::remove_file(format!("{}.pub", &config.server.keypair_file));
}

#[tokio::test]
async fn sanctuary_binds_and_starts() {
    // This test just verifies the server can bind to a port
    let config = test_server_config("bind");
    let (_, _) = setup_server_keypair(&config);
    let server = SanctuaryServer::bind(&config).await.unwrap();
    assert!(server.local_addr().is_ok());

    // We don't call run() because it would block forever
    // Just verifying bind() succeeds is enough for this test
    drop(server);
    cleanup_server_keypair(&config);
}

#[tokio::test]
async fn client_server_handshake_roundtrip() {
    tracing_subscriber::fmt()
        .with_test_writer()
        .with_max_level(tracing::Level::DEBUG)
        .try_init()
        .ok();

    // 1. Generate keypairs for both client and server
    let (client_pk, _client_sk) = AegisCrypto::keygen();
    let (server_pk, server_sk) = AegisCrypto::keygen();

    // 2. Start sanctuary server
    let config = test_server_config("roundtrip");

    // For testing, we'll manually create the server's keypair files
    let sk_bytes = server_sk.to_bytes();
    let pk_bytes = server_pk.to_bytes();
    std::fs::write(&config.server.keypair_file, sk_bytes.as_slice()).unwrap();
    std::fs::write(format!("{}.pub", &config.server.keypair_file), &pk_bytes).unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            &config.server.keypair_file,
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
    }

    let _server = Arc::new(SanctuaryServer::bind(&config).await.unwrap());

    // Instead of using the server, let's do a simpler test:
    // We'll manually construct handshake messages and verify the crypto works

    // Build handshake init message (client → server)
    let sender_index = 12345u32;
    let (init_msg, _init_state) =
        build_handshake_init_simple(&server_pk, &client_pk, sender_index).unwrap();

    // Parse and process the init message (server side)
    let responder_index = 67890u32;
    let (_response_msg, _session) =
        process_handshake_init_simple(&init_msg, &server_pk, &server_sk, responder_index).unwrap();

    // If we get here without errors, the handshake crypto works!
    cleanup_server_keypair(&config);
}

#[tokio::test]
async fn live_udp_handshake() {
    tracing_subscriber::fmt()
        .with_test_writer()
        .with_max_level(tracing::Level::DEBUG)
        .try_init()
        .ok();

    // 1. Create server config and keypair
    let config = test_server_config("live_udp");
    let (server_pk, _server_sk) = setup_server_keypair(&config);

    // 2. Bind and start the server
    let server = Arc::new(SanctuaryServer::bind(&config).await.unwrap());
    let server_addr = server.local_addr().unwrap();
    let shutdown = server.clone_for_shutdown();

    // Run server in background
    let server_clone = Arc::clone(&server);
    let server_task = tokio::spawn(async move {
        let _ = server_clone.run().await;
    });

    // Give the server a moment to start
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // 3. Create client and perform handshake
    let (client_pk, client_sk) = AegisCrypto::keygen();
    let client_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    let sender_index = 42u32;
    let (init_msg, init_state) =
        build_handshake_init_full(&server_pk, &client_pk, sender_index).unwrap();

    // Send handshake init
    client_socket.send_to(&init_msg, server_addr).await.unwrap();

    // 4. Receive handshake response
    let mut resp_buf = [0u8; 65536];
    let (n, _from) = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        client_socket.recv_from(&mut resp_buf),
    )
    .await
    .expect("Handshake response timeout")
    .expect("UDP recv error");

    let resp_msg = &resp_buf[..n];
    assert_eq!(
        resp_msg[0], 0x02,
        "Expected handshake response message type"
    );

    // 5. Process response and derive transport keys
    let completed =
        process_handshake_response_full(resp_msg, init_state, &client_pk, &client_sk, &server_pk)
            .unwrap();

    // 6. Send encrypted transport packet
    let send_cipher = AeadCipher::new(&completed.send_key);
    let recv_cipher = AeadCipher::new(&completed.recv_key);
    let test_payload = b"Hello, post-quantum tunnel!";
    let counter = 1u64;

    let encrypted =
        transport_encrypt_simple(&send_cipher, completed.remote_index, counter, test_payload)
            .unwrap();

    client_socket
        .send_to(&encrypted, server_addr)
        .await
        .unwrap();

    // 7. Receive echoed encrypted response
    let (n, _) = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        client_socket.recv_from(&mut resp_buf),
    )
    .await
    .expect("Transport response timeout")
    .expect("UDP recv error");

    let transport_resp = &resp_buf[..n];

    // 8. Decrypt and verify content matches
    let decrypted = transport_decrypt_simple(&recv_cipher, transport_resp).unwrap();
    assert_eq!(
        decrypted.as_slice(),
        test_payload,
        "Decrypted response must match sent payload"
    );

    // Verify server stats
    assert_eq!(
        server
            .stats()
            .handshakes_completed
            .load(std::sync::atomic::Ordering::Relaxed),
        1
    );
    assert_eq!(
        server
            .stats()
            .packets_decrypted
            .load(std::sync::atomic::Ordering::Relaxed),
        1
    );

    // Cleanup
    shutdown.stop();
    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), server_task).await;
    cleanup_server_keypair(&config);
}

#[tokio::test]
async fn unauthorized_peer_rejected() {
    tracing_subscriber::fmt()
        .with_test_writer()
        .with_max_level(tracing::Level::DEBUG)
        .try_init()
        .ok();

    // Create a server with an authorized peers directory
    let peers_dir = tempfile::tempdir().unwrap();

    // Add one authorized peer
    let (authorized_pk, _authorized_sk) = AegisCrypto::keygen();
    let auth_pk_bytes = authorized_pk.to_bytes();
    std::fs::write(peers_dir.path().join("authorized.pub"), &auth_pk_bytes).unwrap();

    let config = ServerConfig {
        server: ServerSettings {
            listen_addr: "127.0.0.1:0".to_string(),
            keypair_file: "/tmp/test_sanctuary_authz.key".to_string(),
            log_level: "debug".to_string(),
            authorized_peers_dir: Some(peers_dir.path().to_string_lossy().to_string()),
        },
    };

    let (server_pk, _server_sk) = setup_server_keypair(&config);

    let server = Arc::new(SanctuaryServer::bind(&config).await.unwrap());
    let server_addr = server.local_addr().unwrap();
    let shutdown = server.clone_for_shutdown();

    let server_clone = Arc::clone(&server);
    let server_task = tokio::spawn(async move {
        let _ = server_clone.run().await;
    });

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // Try connecting with an unauthorized key
    let (unauthorized_pk, _) = AegisCrypto::keygen();
    let client_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    let (init_msg, _) = build_handshake_init_full(&server_pk, &unauthorized_pk, 1).unwrap();

    client_socket.send_to(&init_msg, server_addr).await.unwrap();

    // The server should silently drop the connection — no response expected
    let mut resp_buf = [0u8; 65536];
    let result = tokio::time::timeout(
        std::time::Duration::from_millis(500),
        client_socket.recv_from(&mut resp_buf),
    )
    .await;

    assert!(
        result.is_err(),
        "Unauthorized peer should not receive a response (timeout expected)"
    );

    // Verify: no handshake completed
    assert_eq!(
        server
            .stats()
            .handshakes_completed
            .load(std::sync::atomic::Ordering::Relaxed),
        0
    );

    shutdown.stop();
    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), server_task).await;
    cleanup_server_keypair(&config);
}

#[tokio::test]
async fn multiple_concurrent_clients() {
    tracing_subscriber::fmt()
        .with_test_writer()
        .with_max_level(tracing::Level::DEBUG)
        .try_init()
        .ok();

    let config = test_server_config("multi_client");
    let (server_pk, _) = setup_server_keypair(&config);

    let server = Arc::new(SanctuaryServer::bind(&config).await.unwrap());
    let server_addr = server.local_addr().unwrap();
    let shutdown = server.clone_for_shutdown();

    let server_clone = Arc::clone(&server);
    let server_task = tokio::spawn(async move {
        let _ = server_clone.run().await;
    });

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // Connect 3 clients, each with different keypairs
    let num_clients = 3;
    let mut client_sessions = Vec::new();

    for i in 0..num_clients {
        let (client_pk, client_sk) = AegisCrypto::keygen();
        let client_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let sender_index = (100 + i) as u32;

        let (init_msg, init_state) =
            build_handshake_init_full(&server_pk, &client_pk, sender_index).unwrap();

        client_socket.send_to(&init_msg, server_addr).await.unwrap();

        let mut resp_buf = [0u8; 65536];
        let (n, _) = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            client_socket.recv_from(&mut resp_buf),
        )
        .await
        .unwrap_or_else(|_| panic!("Client {} handshake timeout", i))
        .expect("recv error");

        let resp_msg = &resp_buf[..n];
        assert_eq!(resp_msg[0], 0x02);

        let completed = process_handshake_response_full(
            resp_msg, init_state, &client_pk, &client_sk, &server_pk,
        )
        .unwrap();

        client_sessions.push((client_socket, completed));
    }

    // Verify all sessions established independently
    assert_eq!(
        server
            .stats()
            .handshakes_completed
            .load(std::sync::atomic::Ordering::Relaxed),
        num_clients as u64,
    );

    // Send and receive from each client to verify no cross-session leakage
    for (i, (socket, session)) in client_sessions.iter().enumerate() {
        let send_cipher = AeadCipher::new(&session.send_key);
        let recv_cipher = AeadCipher::new(&session.recv_key);
        let payload = format!("Message from client {}", i);
        let counter = 1u64;

        let encrypted = transport_encrypt_simple(
            &send_cipher,
            session.remote_index,
            counter,
            payload.as_bytes(),
        )
        .unwrap();

        socket.send_to(&encrypted, server_addr).await.unwrap();

        let mut resp_buf = [0u8; 65536];
        let (n, _) = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            socket.recv_from(&mut resp_buf),
        )
        .await
        .unwrap_or_else(|_| panic!("Client {} transport timeout", i))
        .expect("recv error");

        let decrypted = transport_decrypt_simple(&recv_cipher, &resp_buf[..n]).unwrap();
        assert_eq!(
            std::str::from_utf8(&decrypted).unwrap(),
            payload,
            "Client {} should receive its own message back",
            i
        );
    }

    shutdown.stop();
    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), server_task).await;
    cleanup_server_keypair(&config);
}

#[tokio::test]
async fn rekey_replaces_session() {
    tracing_subscriber::fmt()
        .with_test_writer()
        .with_max_level(tracing::Level::DEBUG)
        .try_init()
        .ok();

    let config = test_server_config("rekey");
    let (server_pk, _) = setup_server_keypair(&config);

    let server = Arc::new(SanctuaryServer::bind(&config).await.unwrap());
    let server_addr = server.local_addr().unwrap();
    let shutdown = server.clone_for_shutdown();

    let server_clone = Arc::clone(&server);
    let server_task = tokio::spawn(async move {
        let _ = server_clone.run().await;
    });

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // Connect a client
    let (client_pk, client_sk) = AegisCrypto::keygen();
    let client_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    // First handshake
    let (init_msg, init_state) = build_handshake_init_full(&server_pk, &client_pk, 1).unwrap();
    client_socket.send_to(&init_msg, server_addr).await.unwrap();

    let mut resp_buf = [0u8; 65536];
    let (n, _) = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        client_socket.recv_from(&mut resp_buf),
    )
    .await
    .unwrap()
    .unwrap();

    let session1 = process_handshake_response_full(
        &resp_buf[..n],
        init_state,
        &client_pk,
        &client_sk,
        &server_pk,
    )
    .unwrap();

    // Second handshake (rekey) from the same client socket
    let (init_msg2, init_state2) = build_handshake_init_full(&server_pk, &client_pk, 2).unwrap();
    client_socket
        .send_to(&init_msg2, server_addr)
        .await
        .unwrap();

    let (n, _) = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        client_socket.recv_from(&mut resp_buf),
    )
    .await
    .unwrap()
    .unwrap();

    let session2 = process_handshake_response_full(
        &resp_buf[..n],
        init_state2,
        &client_pk,
        &client_sk,
        &server_pk,
    )
    .unwrap();

    // Verify the new session works (old session should be replaced)
    let send_cipher = AeadCipher::new(&session2.send_key);
    let recv_cipher = AeadCipher::new(&session2.recv_key);
    let payload = b"rekeyed tunnel data";

    let encrypted =
        transport_encrypt_simple(&send_cipher, session2.remote_index, 1, payload).unwrap();

    client_socket
        .send_to(&encrypted, server_addr)
        .await
        .unwrap();

    let (n, _) = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        client_socket.recv_from(&mut resp_buf),
    )
    .await
    .unwrap()
    .unwrap();

    let decrypted = transport_decrypt_simple(&recv_cipher, &resp_buf[..n]).unwrap();
    assert_eq!(decrypted.as_slice(), payload);

    // Verify old session keys DON'T work on the server anymore
    // (the old session was replaced)
    let old_send_cipher = AeadCipher::new(&session1.send_key);
    let old_encrypted =
        transport_encrypt_simple(&old_send_cipher, session1.remote_index, 2, b"old key data")
            .unwrap();

    client_socket
        .send_to(&old_encrypted, server_addr)
        .await
        .unwrap();

    // Should timeout — server no longer has the old session
    let result = tokio::time::timeout(
        std::time::Duration::from_millis(500),
        client_socket.recv_from(&mut resp_buf),
    )
    .await;

    assert!(
        result.is_err(),
        "Old session keys should not work after rekey"
    );

    // Verify 2 handshakes completed
    assert_eq!(
        server
            .stats()
            .handshakes_completed
            .load(std::sync::atomic::Ordering::Relaxed),
        2
    );

    shutdown.stop();
    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), server_task).await;
    cleanup_server_keypair(&config);
}

// ─── Full Handshake Helpers for Live UDP Testing ────────────────────────────

use hkdf::Hkdf;
use sha3::{Digest, Sha3_256};
use zeroize::Zeroizing;

const MSG_HANDSHAKE_INIT: u8 = 0x01;
const HANDSHAKE_INIT_SIZE: usize =
    1 + 4 + aegis_crypto::HYBRID_PK_SIZE + aegis_crypto::HYBRID_CT_SIZE;
const HANDSHAKE_RESPONSE_SIZE: usize = 1 + 4 + 4 + aegis_crypto::HYBRID_CT_SIZE;
const HANDSHAKE_TRANSCRIPT_LABEL: &[u8] = b"aegis-pqwg-handshake-transcript-v1";
const TRANSPORT_HKDF_INFO: &[u8] = b"aegis-pqwg-transport-v1";
const TRANSPORT_HEADER_SIZE: usize = 12; // receiver_index(4) + counter(8)

/// A pair of transport keys (send, receive) derived from the handshake.
type TransportKeyPair = (Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>);

/// Completed handshake result for the client.
struct CompletedSession {
    send_key: Zeroizing<[u8; 32]>,
    recv_key: Zeroizing<[u8; 32]>,
    _local_index: u32,
    remote_index: u32,
}

/// Initiator state after sending handshake init.
struct InitiatorState {
    shared_secret_1: Zeroizing<[u8; 32]>,
    transcript_hash: [u8; 32],
    sender_index: u32,
}

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

fn build_handshake_init_simple(
    responder_pk: &HybridPublicKey,
    initiator_pk: &HybridPublicKey,
    sender_index: u32,
) -> Result<(Vec<u8>, [u8; 32]), aegis_crypto::CryptoError> {
    let encap = AegisCrypto::encapsulate(responder_pk)?;
    let ct_bytes = encap.ciphertext.to_bytes();
    let initiator_pk_bytes = initiator_pk.to_bytes();

    let transcript_hash =
        compute_transcript_hash(&responder_pk.to_bytes(), &initiator_pk_bytes, &ct_bytes);

    let mut msg = Vec::with_capacity(HANDSHAKE_INIT_SIZE);
    msg.push(MSG_HANDSHAKE_INIT);
    msg.extend_from_slice(&sender_index.to_le_bytes());
    msg.extend_from_slice(&initiator_pk_bytes);
    msg.extend_from_slice(&ct_bytes);

    Ok((msg, transcript_hash))
}

fn build_handshake_init_full(
    responder_pk: &HybridPublicKey,
    initiator_pk: &HybridPublicKey,
    sender_index: u32,
) -> Result<(Vec<u8>, InitiatorState), aegis_crypto::CryptoError> {
    let encap = AegisCrypto::encapsulate(responder_pk)?;
    let ct_bytes = encap.ciphertext.to_bytes();
    let initiator_pk_bytes = initiator_pk.to_bytes();

    let transcript_hash =
        compute_transcript_hash(&responder_pk.to_bytes(), &initiator_pk_bytes, &ct_bytes);

    let mut msg = Vec::with_capacity(HANDSHAKE_INIT_SIZE);
    msg.push(MSG_HANDSHAKE_INIT);
    msg.extend_from_slice(&sender_index.to_le_bytes());
    msg.extend_from_slice(&initiator_pk_bytes);
    msg.extend_from_slice(&ct_bytes);

    let state = InitiatorState {
        shared_secret_1: encap.shared_secret,
        transcript_hash,
        sender_index,
    };

    Ok((msg, state))
}

fn process_handshake_response_full(
    msg: &[u8],
    state: InitiatorState,
    initiator_pk: &HybridPublicKey,
    initiator_sk: &HybridSecretKey,
    _responder_pk: &HybridPublicKey,
) -> Result<CompletedSession, aegis_crypto::CryptoError> {
    if msg.len() != HANDSHAKE_RESPONSE_SIZE {
        return Err(aegis_crypto::CryptoError::InvalidLength {
            expected: HANDSHAKE_RESPONSE_SIZE,
            got: msg.len(),
        });
    }

    if msg[0] != 0x02 {
        return Err(aegis_crypto::CryptoError::AeadError);
    }

    let responder_index = u32::from_le_bytes(msg[1..5].try_into().unwrap());
    let initiator_index = u32::from_le_bytes(msg[5..9].try_into().unwrap());

    if initiator_index != state.sender_index {
        return Err(aegis_crypto::CryptoError::AeadError);
    }

    let ct_r_bytes = &msg[9..];
    let ct_r = aegis_crypto::HybridCiphertext::from_bytes(ct_r_bytes)?;

    let shared_secret_2 = AegisCrypto::decapsulate(&ct_r, initiator_sk, initiator_pk)?;

    let transcript_hash_2 = extend_transcript_hash(&state.transcript_hash, ct_r_bytes);

    let (send_key, recv_key) = derive_transport_keys_simple(
        &state.shared_secret_1,
        &shared_secret_2,
        &transcript_hash_2,
        true, // initiator
    )?;

    Ok(CompletedSession {
        send_key,
        recv_key,
        _local_index: state.sender_index,
        remote_index: responder_index,
    })
}

struct SimpleSession {
    #[allow(dead_code)]
    send_cipher: AeadCipher,
    #[allow(dead_code)]
    recv_cipher: AeadCipher,
}

fn process_handshake_init_simple(
    msg: &[u8],
    responder_pk: &HybridPublicKey,
    responder_sk: &HybridSecretKey,
    responder_index: u32,
) -> Result<(Vec<u8>, SimpleSession), aegis_crypto::CryptoError> {
    use aegis_crypto::CryptoError;

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

    let initiator_pk = HybridPublicKey::from_bytes(initiator_pk_bytes)?;
    let ct = aegis_crypto::HybridCiphertext::from_bytes(ct_bytes)?;

    let shared_secret_1 = AegisCrypto::decapsulate(&ct, responder_sk, responder_pk)?;

    let transcript_hash_1 =
        compute_transcript_hash(&responder_pk.to_bytes(), initiator_pk_bytes, ct_bytes);

    let encap_r = AegisCrypto::encapsulate(&initiator_pk)?;
    let ct_r_bytes = encap_r.ciphertext.to_bytes();

    let transcript_hash_2 = extend_transcript_hash(&transcript_hash_1, &ct_r_bytes);

    let (send_key, recv_key) = derive_transport_keys_simple(
        &shared_secret_1,
        &encap_r.shared_secret,
        &transcript_hash_2,
        false, // responder
    )?;

    let mut resp = Vec::new();
    resp.push(0x02); // MSG_HANDSHAKE_RESPONSE
    resp.extend_from_slice(&responder_index.to_le_bytes());
    resp.extend_from_slice(&initiator_index.to_le_bytes());
    resp.extend_from_slice(&ct_r_bytes);

    let session = SimpleSession {
        send_cipher: AeadCipher::new(&send_key),
        recv_cipher: AeadCipher::new(&recv_key),
    };

    Ok((resp, session))
}

fn derive_transport_keys_simple(
    ss1: &[u8; 32],
    ss2: &[u8; 32],
    transcript: &[u8; 32],
    is_initiator: bool,
) -> Result<TransportKeyPair, aegis_crypto::CryptoError> {
    let mut combined = [0u8; 96];
    combined[0..32].copy_from_slice(ss1);
    combined[32..64].copy_from_slice(ss2);
    combined[64..96].copy_from_slice(transcript);

    let hkdf = Hkdf::<Sha3_256>::new(None, &combined);
    let mut out = Zeroizing::new([0u8; 64]);
    hkdf.expand(TRANSPORT_HKDF_INFO, out.as_mut_slice())
        .map_err(|_| aegis_crypto::CryptoError::AeadError)?;

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

// ─── Transport Helpers for Testing ──────────────────────────────────────────

fn counter_to_nonce(counter: u64) -> [u8; aegis_crypto::AEAD_NONCE_SIZE] {
    let mut nonce = [0u8; aegis_crypto::AEAD_NONCE_SIZE];
    nonce[4..12].copy_from_slice(&counter.to_le_bytes());
    nonce
}

fn transport_encrypt_simple(
    cipher: &AeadCipher,
    receiver_index: u32,
    counter: u64,
    plaintext: &[u8],
) -> Result<Vec<u8>, aegis_crypto::CryptoError> {
    let nonce = counter_to_nonce(counter);
    let ciphertext = cipher.encrypt(&nonce, plaintext, &[])?;

    let mut pkt = Vec::with_capacity(TRANSPORT_HEADER_SIZE + ciphertext.len());
    pkt.extend_from_slice(&receiver_index.to_le_bytes());
    pkt.extend_from_slice(&counter.to_le_bytes());
    pkt.extend_from_slice(&ciphertext);
    Ok(pkt)
}

fn transport_decrypt_simple(
    cipher: &AeadCipher,
    data: &[u8],
) -> Result<Vec<u8>, aegis_crypto::CryptoError> {
    if data.len() < TRANSPORT_HEADER_SIZE + aegis_crypto::AEAD_TAG_SIZE {
        return Err(aegis_crypto::CryptoError::InvalidLength {
            expected: TRANSPORT_HEADER_SIZE + aegis_crypto::AEAD_TAG_SIZE,
            got: data.len(),
        });
    }

    let counter = u64::from_le_bytes(data[4..12].try_into().unwrap());
    let nonce = counter_to_nonce(counter);
    let ciphertext_with_tag = &data[TRANSPORT_HEADER_SIZE..];

    let plaintext = cipher.decrypt(&nonce, ciphertext_with_tag, &[])?;
    Ok(plaintext.to_vec())
}
