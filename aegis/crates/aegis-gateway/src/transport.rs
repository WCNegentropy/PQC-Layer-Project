//! Transport packet encryption and decryption for the PQ-WireGuard tunnel.
//!
//! Implements the wire format for encrypted transport packets:
//!
//! ```text
//! ┌──────────┬──────────┬────────────────┬──────────┐
//! │ Receiver │ Counter  │ Encrypted      │ Auth Tag │
//! │ Index    │ (8B LE)  │ IP Packet      │ (16B)    │
//! │ (4B LE)  │          │ (variable)     │          │
//! └──────────┴──────────┴────────────────┴──────────┘
//! ```
//!
//! Uses ChaCha20-Poly1305 via `aegis-crypto` with a counter-derived nonce.

use aegis_crypto::{AeadCipher, AEAD_NONCE_SIZE, AEAD_TAG_SIZE};

/// Message type ID for transport data packets on the wire.
pub const MSG_TRANSPORT_DATA: u8 = 0x04;

/// Size of the transport packet header: receiver index (4) + counter (8) = 12 bytes.
pub const TRANSPORT_HEADER_SIZE: usize = 4 + 8;

/// Minimum size of a valid transport packet: header + tag (no payload is allowed).
pub const TRANSPORT_MIN_SIZE: usize = TRANSPORT_HEADER_SIZE + AEAD_TAG_SIZE;

/// Build a 12-byte AEAD nonce from a 64-bit counter.
///
/// The first 4 bytes are zero (per WireGuard convention), followed by
/// the 8-byte little-endian counter.
fn counter_to_nonce(counter: u64) -> [u8; AEAD_NONCE_SIZE] {
    let mut nonce = [0u8; AEAD_NONCE_SIZE];
    nonce[4..12].copy_from_slice(&counter.to_le_bytes());
    nonce
}

/// Encrypt an IP packet into a transport-format message.
///
/// Returns a buffer containing: `receiver_index (4B LE) || counter (8B LE) || AEAD(plaintext) || tag`.
pub fn transport_encrypt(
    cipher: &AeadCipher,
    receiver_index: u32,
    counter: u64,
    plaintext: &[u8],
) -> Result<Vec<u8>, aegis_crypto::CryptoError> {
    let nonce = counter_to_nonce(counter);

    // Encrypt with empty AAD (receiver_index + counter are in the clear
    // but bound to the nonce / key schedule)
    let ciphertext = cipher.encrypt(&nonce, plaintext, &[])?;

    // Assemble transport packet
    let mut pkt = Vec::with_capacity(TRANSPORT_HEADER_SIZE + ciphertext.len());
    pkt.extend_from_slice(&receiver_index.to_le_bytes());
    pkt.extend_from_slice(&counter.to_le_bytes());
    pkt.extend_from_slice(&ciphertext);
    Ok(pkt)
}

/// Parsed header fields from an incoming transport packet.
pub struct TransportHeader {
    /// Receiver index identifying the session on this side.
    pub receiver_index: u32,
    /// Packet counter for anti-replay and nonce derivation.
    pub counter: u64,
}

/// Parse the header of a transport packet without decrypting.
///
/// Returns `None` if the packet is too short to contain a valid header + tag.
pub fn parse_transport_header(data: &[u8]) -> Option<TransportHeader> {
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

/// Decrypt a transport packet, returning the original IP packet.
///
/// Expects the full wire-format packet (header + ciphertext + tag).
pub fn transport_decrypt(
    cipher: &AeadCipher,
    data: &[u8],
) -> Result<Vec<u8>, aegis_crypto::CryptoError> {
    if data.len() < TRANSPORT_MIN_SIZE {
        return Err(aegis_crypto::CryptoError::InvalidLength {
            expected: TRANSPORT_MIN_SIZE,
            got: data.len(),
        });
    }

    let counter = u64::from_le_bytes(data[4..12].try_into().unwrap());
    let nonce = counter_to_nonce(counter);
    let ciphertext_with_tag = &data[TRANSPORT_HEADER_SIZE..];

    let plaintext = cipher.decrypt(&nonce, ciphertext_with_tag, &[])?;
    Ok(plaintext.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_crypto::AEAD_KEY_SIZE;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = [0x42u8; AEAD_KEY_SIZE];
        let cipher = AeadCipher::new(&key);
        let plaintext = b"Hello, post-quantum tunnel!";
        let receiver_index = 0xDEAD_BEEF;
        let counter = 1;

        let pkt = transport_encrypt(&cipher, receiver_index, counter, plaintext).unwrap();

        // Verify header
        let hdr = parse_transport_header(&pkt).unwrap();
        assert_eq!(hdr.receiver_index, receiver_index);
        assert_eq!(hdr.counter, counter);

        // Verify packet size: header + plaintext + tag
        assert_eq!(
            pkt.len(),
            TRANSPORT_HEADER_SIZE + plaintext.len() + AEAD_TAG_SIZE
        );

        // Decrypt
        let decrypted = transport_decrypt(&cipher, &pkt).unwrap();
        assert_eq!(decrypted.as_slice(), plaintext);
    }

    #[test]
    fn wrong_key_decrypt_fails() {
        let key1 = [0x42u8; AEAD_KEY_SIZE];
        let key2 = [0x43u8; AEAD_KEY_SIZE];
        let cipher1 = AeadCipher::new(&key1);
        let cipher2 = AeadCipher::new(&key2);

        let pkt = transport_encrypt(&cipher1, 1, 1, b"secret").unwrap();
        assert!(transport_decrypt(&cipher2, &pkt).is_err());
    }

    #[test]
    fn tampered_packet_fails() {
        let key = [0x42u8; AEAD_KEY_SIZE];
        let cipher = AeadCipher::new(&key);
        let mut pkt = transport_encrypt(&cipher, 1, 1, b"secret").unwrap();

        // Flip a bit in the ciphertext portion
        let idx = TRANSPORT_HEADER_SIZE + 1;
        pkt[idx] ^= 0x01;

        assert!(transport_decrypt(&cipher, &pkt).is_err());
    }

    #[test]
    fn too_short_packet_returns_none() {
        assert!(parse_transport_header(&[0u8; 10]).is_none());
    }

    #[test]
    fn too_short_decrypt_fails() {
        let key = [0x42u8; AEAD_KEY_SIZE];
        let cipher = AeadCipher::new(&key);
        assert!(transport_decrypt(&cipher, &[0u8; 10]).is_err());
    }

    #[test]
    fn counter_nonce_derivation() {
        let nonce = counter_to_nonce(0x0102030405060708);
        // First 4 bytes zero, then LE counter
        assert_eq!(&nonce[..4], &[0, 0, 0, 0]);
        assert_eq!(&nonce[4..], &0x0102030405060708u64.to_le_bytes());
    }

    #[test]
    fn different_counters_produce_different_ciphertext() {
        let key = [0x42u8; AEAD_KEY_SIZE];
        let cipher = AeadCipher::new(&key);
        let plaintext = b"same data";

        let pkt1 = transport_encrypt(&cipher, 1, 1, plaintext).unwrap();
        let pkt2 = transport_encrypt(&cipher, 1, 2, plaintext).unwrap();

        // Ciphertexts should differ (different nonces)
        assert_ne!(
            &pkt1[TRANSPORT_HEADER_SIZE..],
            &pkt2[TRANSPORT_HEADER_SIZE..]
        );
    }

    #[test]
    fn empty_payload_roundtrip() {
        let key = [0x42u8; AEAD_KEY_SIZE];
        let cipher = AeadCipher::new(&key);

        let pkt = transport_encrypt(&cipher, 1, 1, b"").unwrap();
        assert_eq!(pkt.len(), TRANSPORT_HEADER_SIZE + AEAD_TAG_SIZE);

        let decrypted = transport_decrypt(&cipher, &pkt).unwrap();
        assert!(decrypted.is_empty());
    }
}
