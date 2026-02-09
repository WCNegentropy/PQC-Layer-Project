//! PQ-WireGuard handshake state machine (Noise IK + Hybrid KEM).
//!
//! Implements a two-message handshake between an initiator and responder:
//!
//! 1. **Handshake Init (0x01):** Initiator encapsulates to responder's static PK,
//!    producing `shared_secret_1` and sending the KEM ciphertext.
//! 2. **Handshake Response (0x02):** Responder encapsulates back to the initiator's
//!    static PK (sent inside the init message), producing `shared_secret_2`.
//!
//! Transport keys are derived via HKDF over both shared secrets and a transcript hash.
//!
//! # Wire Messages
//!
//! | Message | ID | Contents |
//! |---------|----|----------|
//! | Handshake Init | `0x01` | `initiator_static_pk` + `kem_ct_i` |
//! | Handshake Response | `0x02` | `kem_ct_r` |
//! | Transport Data | `0x04` | (see `transport.rs`) |

use aegis_crypto::{
    AegisCrypto, CryptoError, HybridCiphertext, HybridPublicKey, HybridSecretKey, HYBRID_CT_SIZE,
    HYBRID_PK_SIZE,
};
use hkdf::Hkdf;
use sha3::{Digest, Sha3_256};
use zeroize::Zeroizing;

use crate::anti_replay::AntiReplayWindow;

// ─── Wire Message IDs ───────────────────────────────────────────────────────

/// Message type for handshake initiation.
pub const MSG_HANDSHAKE_INIT: u8 = 0x01;
/// Message type for handshake response.
pub const MSG_HANDSHAKE_RESPONSE: u8 = 0x02;

/// Size of a serialized handshake init message:
/// msg_type (1) + sender_index (4) + initiator_static_pk (HYBRID_PK_SIZE) + kem_ct (HYBRID_CT_SIZE).
pub const HANDSHAKE_INIT_SIZE: usize = 1 + 4 + HYBRID_PK_SIZE + HYBRID_CT_SIZE;

/// Size of a serialized handshake response message:
/// msg_type (1) + sender_index (4) + receiver_index (4) + kem_ct (HYBRID_CT_SIZE).
pub const HANDSHAKE_RESPONSE_SIZE: usize = 1 + 4 + 4 + HYBRID_CT_SIZE;

/// HKDF info string for transport key derivation.
const TRANSPORT_HKDF_INFO: &[u8] = b"aegis-pqwg-transport-v1";

/// Label for handshake transcript binding.
const HANDSHAKE_TRANSCRIPT_LABEL: &[u8] = b"aegis-pqwg-handshake-transcript-v1";

// ─── Transport Key Pair ─────────────────────────────────────────────────────

/// Derived transport keys for bidirectional communication.
pub struct TransportKeys {
    /// Key for encrypting outbound packets.
    pub send_key: Zeroizing<[u8; 32]>,
    /// Key for decrypting inbound packets.
    pub recv_key: Zeroizing<[u8; 32]>,
}

// ─── Handshake State Machine ────────────────────────────────────────────────

/// Handshake state for the initiator side.
pub enum InitiatorState {
    /// Initiator has created msg1 and is waiting for the response.
    InitSent {
        /// Shared secret from the initiator's encapsulation (ss1).
        shared_secret_1: Zeroizing<[u8; 32]>,
        /// Transcript hash accumulated so far.
        transcript_hash: [u8; 32],
        /// Sender index chosen by the initiator.
        sender_index: u32,
    },
}

/// Handshake state for the responder side.
pub enum ResponderState {
    /// Responder has processed msg1 and created msg2; keys are ready.
    Complete {
        /// Derived transport keys.
        keys: TransportKeys,
        /// The sender index from the initiator (becomes our receiver_index).
        initiator_index: u32,
        /// Our own sender index.
        responder_index: u32,
    },
}

/// A completed handshake session from either side.
pub struct CompletedHandshake {
    /// Derived transport keys.
    pub keys: TransportKeys,
    /// Counter for outbound packets.
    pub send_counter: u64,
    /// Anti-replay window for inbound packets.
    pub recv_window: AntiReplayWindow,
    /// Index the remote side uses to identify us.
    pub local_index: u32,
    /// Index we use to identify the remote side.
    pub remote_index: u32,
}

// ─── Handshake Messages (serialization) ─────────────────────────────────────

/// Build a handshake init message.
///
/// The initiator encapsulates to the responder's static public key,
/// then serializes:
/// `[0x01] [sender_index: 4B LE] [initiator_static_pk] [kem_ct_i]`
pub fn build_handshake_init(
    responder_static_pk: &HybridPublicKey,
    initiator_static_pk: &HybridPublicKey,
    sender_index: u32,
) -> Result<(Vec<u8>, InitiatorState), CryptoError> {
    // Encapsulate to responder's static key
    let encap = AegisCrypto::encapsulate(responder_static_pk)?;
    let ct_bytes = encap.ciphertext.to_bytes();
    let initiator_pk_bytes = initiator_static_pk.to_bytes();

    // Compute transcript hash: label || responder_pk || initiator_pk || ct
    let transcript_hash = compute_transcript_hash(
        &responder_static_pk.to_bytes(),
        &initiator_pk_bytes,
        &ct_bytes,
    );

    // Serialize the message
    let mut msg = Vec::with_capacity(HANDSHAKE_INIT_SIZE);
    msg.push(MSG_HANDSHAKE_INIT);
    msg.extend_from_slice(&sender_index.to_le_bytes());
    msg.extend_from_slice(&initiator_pk_bytes);
    msg.extend_from_slice(&ct_bytes);

    let state = InitiatorState::InitSent {
        shared_secret_1: encap.shared_secret,
        transcript_hash,
        sender_index,
    };

    Ok((msg, state))
}

/// Parse and process a received handshake init message (responder side).
///
/// Returns a response message and completed handshake state.
pub fn process_handshake_init(
    msg: &[u8],
    responder_static_pk: &HybridPublicKey,
    responder_static_sk: &HybridSecretKey,
    responder_index: u32,
) -> Result<(Vec<u8>, ResponderState), CryptoError> {
    if msg.len() != HANDSHAKE_INIT_SIZE {
        return Err(CryptoError::InvalidLength {
            expected: HANDSHAKE_INIT_SIZE,
            got: msg.len(),
        });
    }

    if msg[0] != MSG_HANDSHAKE_INIT {
        return Err(CryptoError::AeadError); // wrong message type
    }

    let initiator_index = u32::from_le_bytes(msg[1..5].try_into().unwrap());
    let initiator_pk_bytes = &msg[5..5 + HYBRID_PK_SIZE];
    let ct_bytes = &msg[5 + HYBRID_PK_SIZE..];

    // Deserialize initiator's public key and ciphertext
    let initiator_pk = HybridPublicKey::from_bytes(initiator_pk_bytes)?;
    let ct = HybridCiphertext::from_bytes(ct_bytes)?;

    // Decapsulate to recover shared_secret_1
    let shared_secret_1 = AegisCrypto::decapsulate(&ct, responder_static_sk, responder_static_pk)?;

    // Compute transcript hash (same inputs as initiator)
    let transcript_hash_1 = compute_transcript_hash(
        &responder_static_pk.to_bytes(),
        initiator_pk_bytes,
        ct_bytes,
    );

    // Encapsulate back to initiator's static PK → shared_secret_2
    let encap_r = AegisCrypto::encapsulate(&initiator_pk)?;
    let ct_r_bytes = encap_r.ciphertext.to_bytes();

    // Extended transcript hash including the response ciphertext
    let transcript_hash_2 = extend_transcript_hash(&transcript_hash_1, &ct_r_bytes);

    // Derive transport keys
    let keys = derive_transport_keys(
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

    let state = ResponderState::Complete {
        keys,
        initiator_index,
        responder_index,
    };

    Ok((resp, state))
}

/// Process a received handshake response (initiator side).
///
/// Completes the handshake and derives transport keys.
pub fn process_handshake_response(
    msg: &[u8],
    state: InitiatorState,
    initiator_static_pk: &HybridPublicKey,
    initiator_static_sk: &HybridSecretKey,
    // Kept for API consistency; will be used for extended transcript binding.
    _responder_static_pk: &HybridPublicKey,
) -> Result<CompletedHandshake, CryptoError> {
    if msg.len() != HANDSHAKE_RESPONSE_SIZE {
        return Err(CryptoError::InvalidLength {
            expected: HANDSHAKE_RESPONSE_SIZE,
            got: msg.len(),
        });
    }

    if msg[0] != MSG_HANDSHAKE_RESPONSE {
        return Err(CryptoError::AeadError); // wrong message type
    }

    let InitiatorState::InitSent {
        shared_secret_1,
        transcript_hash,
        sender_index,
    } = state;

    let responder_index = u32::from_le_bytes(msg[1..5].try_into().unwrap());
    let initiator_index = u32::from_le_bytes(msg[5..9].try_into().unwrap());

    if initiator_index != sender_index {
        return Err(CryptoError::AeadError); // index mismatch
    }

    let ct_r_bytes = &msg[9..];
    let ct_r = HybridCiphertext::from_bytes(ct_r_bytes)?;

    // Decapsulate responder's ciphertext → shared_secret_2
    let shared_secret_2 =
        AegisCrypto::decapsulate(&ct_r, initiator_static_sk, initiator_static_pk)?;

    // Extended transcript hash (same as responder computed)
    let transcript_hash_2 = extend_transcript_hash(&transcript_hash, ct_r_bytes);

    // Derive transport keys (initiator perspective)
    let keys = derive_transport_keys(
        &shared_secret_1,
        &shared_secret_2,
        &transcript_hash_2,
        true, // initiator
    )?;

    Ok(CompletedHandshake {
        keys,
        send_counter: 0,
        recv_window: AntiReplayWindow::new(),
        local_index: sender_index,
        remote_index: responder_index,
    })
}

/// Convert a [`ResponderState::Complete`] into a [`CompletedHandshake`].
pub fn responder_to_completed(state: ResponderState) -> CompletedHandshake {
    match state {
        ResponderState::Complete {
            keys,
            initiator_index,
            responder_index,
        } => CompletedHandshake {
            keys,
            send_counter: 0,
            recv_window: AntiReplayWindow::new(),
            local_index: responder_index,
            remote_index: initiator_index,
        },
    }
}

// ─── Key Derivation Helpers ─────────────────────────────────────────────────

/// Compute the transcript hash for the handshake init.
fn compute_transcript_hash(responder_pk: &[u8], initiator_pk: &[u8], ct: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(HANDSHAKE_TRANSCRIPT_LABEL);
    hasher.update(responder_pk);
    hasher.update(initiator_pk);
    hasher.update(ct);
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

/// Extend the transcript hash with additional data (e.g., response ciphertext).
fn extend_transcript_hash(prev_hash: &[u8; 32], extra: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(prev_hash);
    hasher.update(extra);
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

/// Derive transport keys from two shared secrets and a transcript hash.
///
/// Produces 64 bytes of keying material via HKDF, then splits into
/// `send_key` and `recv_key`. The `is_initiator` flag determines which
/// half is which (the initiator's send key is the responder's recv key).
fn derive_transport_keys(
    ss1: &[u8; 32],
    ss2: &[u8; 32],
    transcript_hash: &[u8; 32],
    is_initiator: bool,
) -> Result<TransportKeys, CryptoError> {
    // IKM = ss1 || ss2
    let mut ikm = Zeroizing::new([0u8; 64]);
    ikm[..32].copy_from_slice(ss1);
    ikm[32..].copy_from_slice(ss2);

    // HKDF with transcript hash as salt
    let hk = Hkdf::<Sha3_256>::new(Some(transcript_hash), ikm.as_ref());
    let mut okm = Zeroizing::new([0u8; 64]);
    hk.expand(TRANSPORT_HKDF_INFO, okm.as_mut())
        .map_err(|_| CryptoError::KdfError)?;

    // Split: first 32 bytes = initiator-to-responder key,
    //        last  32 bytes = responder-to-initiator key.
    let mut key_i2r = Zeroizing::new([0u8; 32]);
    let mut key_r2i = Zeroizing::new([0u8; 32]);
    key_i2r.copy_from_slice(&okm[..32]);
    key_r2i.copy_from_slice(&okm[32..]);

    if is_initiator {
        Ok(TransportKeys {
            send_key: key_i2r,
            recv_key: key_r2i,
        })
    } else {
        Ok(TransportKeys {
            send_key: key_r2i,
            recv_key: key_i2r,
        })
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handshake_roundtrip() {
        // Generate keypairs for both sides
        let (initiator_pk, initiator_sk) = AegisCrypto::keygen();
        let (responder_pk, responder_sk) = AegisCrypto::keygen();

        let initiator_index = 42u32;
        let responder_index = 99u32;

        // Step 1: Initiator builds handshake init
        let (init_msg, init_state) =
            build_handshake_init(&responder_pk, &initiator_pk, initiator_index).unwrap();
        assert_eq!(init_msg.len(), HANDSHAKE_INIT_SIZE);
        assert_eq!(init_msg[0], MSG_HANDSHAKE_INIT);

        // Step 2: Responder processes init and builds response
        let (resp_msg, resp_state) =
            process_handshake_init(&init_msg, &responder_pk, &responder_sk, responder_index)
                .unwrap();
        assert_eq!(resp_msg.len(), HANDSHAKE_RESPONSE_SIZE);
        assert_eq!(resp_msg[0], MSG_HANDSHAKE_RESPONSE);

        // Step 3: Initiator processes response
        let initiator_session = process_handshake_response(
            &resp_msg,
            init_state,
            &initiator_pk,
            &initiator_sk,
            &responder_pk,
        )
        .unwrap();

        // Step 4: Convert responder state to completed
        let responder_session = responder_to_completed(resp_state);

        // Verify: initiator's send_key == responder's recv_key and vice versa
        assert_eq!(
            initiator_session.keys.send_key.as_ref(),
            responder_session.keys.recv_key.as_ref(),
            "initiator send_key must equal responder recv_key"
        );
        assert_eq!(
            initiator_session.keys.recv_key.as_ref(),
            responder_session.keys.send_key.as_ref(),
            "initiator recv_key must equal responder send_key"
        );

        // Verify indices
        assert_eq!(initiator_session.local_index, initiator_index);
        assert_eq!(initiator_session.remote_index, responder_index);
        assert_eq!(responder_session.local_index, responder_index);
        assert_eq!(responder_session.remote_index, initiator_index);
    }

    #[test]
    fn wrong_static_key_produces_different_keys() {
        // If the responder has the wrong key, the decapsulated secret
        // will differ (ML-KEM implicit rejection), so transport keys
        // won't match.
        let (initiator_pk, initiator_sk) = AegisCrypto::keygen();
        let (responder_pk, _responder_sk) = AegisCrypto::keygen();
        let (_wrong_pk, wrong_sk) = AegisCrypto::keygen();

        let (init_msg, init_state) = build_handshake_init(&responder_pk, &initiator_pk, 1).unwrap();

        // Responder uses wrong secret key
        let (resp_msg, resp_state) =
            process_handshake_init(&init_msg, &responder_pk, &wrong_sk, 2).unwrap();

        let initiator_session = process_handshake_response(
            &resp_msg,
            init_state,
            &initiator_pk,
            &initiator_sk,
            &responder_pk,
        )
        .unwrap();

        let responder_session = responder_to_completed(resp_state);

        // Keys should NOT match
        assert_ne!(
            initiator_session.keys.send_key.as_ref(),
            responder_session.keys.recv_key.as_ref(),
            "wrong key should produce mismatched transport keys"
        );
    }

    #[test]
    fn transport_encrypt_decrypt_after_handshake() {
        let (initiator_pk, initiator_sk) = AegisCrypto::keygen();
        let (responder_pk, responder_sk) = AegisCrypto::keygen();

        let (init_msg, init_state) = build_handshake_init(&responder_pk, &initiator_pk, 1).unwrap();
        let (resp_msg, resp_state) =
            process_handshake_init(&init_msg, &responder_pk, &responder_sk, 2).unwrap();
        let i_session = process_handshake_response(
            &resp_msg,
            init_state,
            &initiator_pk,
            &initiator_sk,
            &responder_pk,
        )
        .unwrap();
        let r_session = responder_to_completed(resp_state);

        // Initiator sends a transport packet
        let send_cipher = aegis_crypto::AeadCipher::new(&i_session.keys.send_key);
        let recv_cipher = aegis_crypto::AeadCipher::new(&r_session.keys.recv_key);

        let plaintext = b"test IP packet data";
        let pkt =
            crate::transport::transport_encrypt(&send_cipher, i_session.remote_index, 1, plaintext)
                .unwrap();

        let decrypted = crate::transport::transport_decrypt(&recv_cipher, &pkt).unwrap();
        assert_eq!(decrypted.as_slice(), plaintext);
    }

    #[test]
    fn invalid_init_message_length_rejected() {
        let (responder_pk, responder_sk) = AegisCrypto::keygen();
        let short_msg = vec![0u8; 10];
        assert!(process_handshake_init(&short_msg, &responder_pk, &responder_sk, 1).is_err());
    }

    #[test]
    fn invalid_response_message_length_rejected() {
        let (initiator_pk, initiator_sk) = AegisCrypto::keygen();
        let (responder_pk, _) = AegisCrypto::keygen();

        let (_, init_state) = build_handshake_init(&responder_pk, &initiator_pk, 1).unwrap();

        let short_msg = vec![0u8; 10];
        assert!(process_handshake_response(
            &short_msg,
            init_state,
            &initiator_pk,
            &initiator_sk,
            &responder_pk,
        )
        .is_err());
    }

    #[test]
    fn handshake_init_message_format() {
        let (initiator_pk, _) = AegisCrypto::keygen();
        let (responder_pk, _) = AegisCrypto::keygen();

        let (msg, _) = build_handshake_init(&responder_pk, &initiator_pk, 0xAABBCCDD).unwrap();

        assert_eq!(msg[0], MSG_HANDSHAKE_INIT);
        assert_eq!(
            u32::from_le_bytes(msg[1..5].try_into().unwrap()),
            0xAABBCCDD
        );
        // Remaining bytes: initiator PK + KEM ciphertext
        assert_eq!(msg.len(), HANDSHAKE_INIT_SIZE);
    }
}
