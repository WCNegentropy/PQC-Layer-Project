# Aegis Wire Protocol Specification

> **Status:** Implemented — PQ-WireGuard handshake, transport encryption,
> anti-replay, and rekeying are functional end-to-end.
>
> **Last Updated:** 2026-02-10

## Overview

The Aegis wire protocol defines the on-the-wire format for encrypted tunnel
communication between Aegis clients and Sanctuary nodes. It is based on
WireGuard's Noise IK pattern, extended with hybrid post-quantum key encapsulation.

**Implementation:** [`crates/aegis-gateway/src/handshake.rs`](../crates/aegis-gateway/src/handshake.rs),
[`crates/aegis-gateway/src/transport.rs`](../crates/aegis-gateway/src/transport.rs),
[`crates/aegis-sanctuary/src/server.rs`](../crates/aegis-sanctuary/src/server.rs)

## Protocol Messages

| Message Type | ID | Direction | Description | Status |
|---|---|---|---|---|
| Handshake Init | `0x01` | Client → Server | Initiator message with hybrid KEM ciphertext | ✅ Implemented |
| Handshake Response | `0x02` | Server → Client | Responder message with KEM response | ✅ Implemented |
| Transport Data | `0x04` | Bidirectional | Encrypted tunnel packet (counter + AEAD) | ✅ Implemented |
| Cookie Reply | `0x03` | Server → Client | DoS mitigation (optional) | ❌ Planned |

## Handshake (Noise IK + Hybrid KEM)

The handshake uses the Noise IK pattern augmented with ML-KEM-768 for
quantum resistance. The initiator knows the responder's static public key
in advance (pre-configured or via out-of-band exchange).

### Handshake Init (`0x01`)

```text
┌──────────┬──────────────┬──────────────────────────┬───────────────────────┐
│ msg_type │ sender_index │ initiator_static_pk      │ kem_ct_i              │
│ (1B)     │ (4B LE)      │ (1216B = X25519 + ML-KEM)│ (1120B = eph + ct)    │
└──────────┴──────────────┴──────────────────────────┴───────────────────────┘
Total: 2341 bytes
```

The initiator encapsulates to the responder's static public key, producing a
shared secret (`ss1`) and ciphertext (`kem_ct_i`). The initiator's static
public key is sent in the clear (Noise IK: responder identity is pre-known).

### Handshake Response (`0x02`)

```text
┌──────────┬──────────────┬────────────────┬───────────────────────┐
│ msg_type │ sender_index │ receiver_index │ kem_ct_r              │
│ (1B)     │ (4B LE)      │ (4B LE)        │ (1120B = eph + ct)    │
└──────────┴──────────────┴────────────────┴───────────────────────┘
Total: 1129 bytes
```

The responder encapsulates back to the initiator's static public key,
producing a second shared secret (`ss2`) and ciphertext (`kem_ct_r`).

### Key Schedule

1. Both parties derive two hybrid shared secrets (`ss1`, `ss2`) via dual KEM
   encapsulation (`AegisCrypto::encapsulate` / `decapsulate`).
2. A transcript hash binds the handshake messages:
   ```
   transcript = SHA3-256(
       b"aegis-pqwg-handshake-transcript-v1" ||
       responder_pk || initiator_pk || kem_ct_i
   )
   extended_transcript = SHA3-256(transcript || kem_ct_r)
   ```
3. Transport keys are derived via HKDF:
   ```
   okm = HKDF-SHA3-256(
       ikm  = ss1 || ss2,         // 64 bytes
       salt = extended_transcript, // 32 bytes
       info = b"aegis-pqwg-transport-v1"
   )
   initiator_to_responder_key = okm[0..32]
   responder_to_initiator_key = okm[32..64]
   ```
4. Each direction gets its own ChaCha20-Poly1305 key and independent counter.

**Implementation:** `derive_transport_keys()`, `compute_transcript_hash()`,
`extend_transcript_hash()` in `handshake.rs`

## Transport Packet Format

```text
┌──────────┬──────────┬────────────────┬──────────┐
│ Receiver │ Counter  │ Encrypted      │ Auth Tag │
│ Index    │ (8B LE)  │ IP Packet      │ (16B)    │
│ (4B LE)  │          │ (variable)     │          │
└──────────┴──────────┴────────────────┴──────────┘
Header: 12 bytes (TRANSPORT_HEADER_SIZE)
Minimum packet: 28 bytes (header + 16B tag)
```

- **Receiver Index:** Identifies the session/keypair on the receiver side.
- **Counter:** 64-bit little-endian; MUST be strictly increasing (anti-replay).
- **Encrypted IP Packet:** ChaCha20-Poly1305 encrypted with nonce derived from counter.
- **Auth Tag:** 16-byte Poly1305 authentication tag.

### Nonce Construction

The 12-byte AEAD nonce is derived from the 64-bit counter:

```text
nonce[0..4]  = 0x00 0x00 0x00 0x00   (4 zero bytes)
nonce[4..12] = counter (8B LE)
```

This follows the WireGuard convention. Implemented as `counter_to_nonce()` in
`transport.rs`.

**Implementation:** `transport_encrypt()`, `transport_decrypt()`,
`parse_transport_header()` in `transport.rs`

## Anti-Replay

A sliding window bitmap detects and rejects replayed packets, following
RFC 6479. The `AntiReplayWindow` maintains:

- `top`: the highest counter value seen
- `bitmap`: a 128-bit sliding window (gateway) / 64-bit (sanctuary)

Rules:
1. Counter `0` is always rejected.
2. Counters above `top` advance the window and are accepted.
3. Counters within the window are checked against the bitmap — accepted only
   if not previously seen.
4. Counters below `top - WINDOW_SIZE` are rejected as too old.

**Implementation:** `AntiReplayWindow::check_and_update()` in
[`anti_replay.rs`](../crates/aegis-gateway/src/anti_replay.rs)

## Key Rotation

Transport keys are rotated after a configurable number of packets or time
interval, triggering a new handshake. This provides forward secrecy —
compromising current keys does not reveal past traffic.

**Defaults:**
- `DEFAULT_REKEY_INTERVAL`: 120 seconds (matching WireGuard's `REKEY_AFTER_TIME`)
- `DEFAULT_REKEY_AFTER_PACKETS`: 65 536 (2¹⁶)

A session's `needs_rekey()` method returns `true` when either threshold is
exceeded, triggering re-handshake.

**Implementation:** `Session::needs_rekey()` in
[`session.rs`](../crates/aegis-gateway/src/session.rs)
