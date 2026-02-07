# Aegis Wire Protocol Specification

> **Status:** Stub — to be written when the PQ-WireGuard handshake is implemented.

## Overview

The Aegis wire protocol defines the on-the-wire format for encrypted tunnel
communication between Aegis clients and Sanctuary nodes. It is based on
WireGuard's Noise IK pattern, extended with hybrid post-quantum key encapsulation.

## Protocol Messages

| Message Type | ID | Direction | Description | Status |
|---|---|---|---|---|
| Handshake Init | `0x01` | Client → Server | Initiator message with hybrid KEM ciphertext | ❌ Planned |
| Handshake Response | `0x02` | Server → Client | Responder message with KEM response | ❌ Planned |
| Transport Data | `0x04` | Bidirectional | Encrypted tunnel packet (counter + AEAD) | ❌ Planned |
| Cookie Reply | `0x03` | Server → Client | DoS mitigation (optional) | ❌ Planned |

## Handshake (Noise IK + Hybrid KEM)

The handshake will use the Noise IK pattern augmented with ML-KEM-768 for
quantum resistance. The initiator knows the responder's static public key
in advance (pre-configured or via out-of-band exchange).

### Key Schedule

1. Both parties derive a hybrid shared secret via `AegisCrypto::encapsulate` / `decapsulate`.
2. The shared secret is split into transport keys using HKDF.
3. Each direction gets its own ChaCha20-Poly1305 key and counter.

## Transport Packet Format

```text
┌──────────┬──────────┬────────────────┬──────────┐
│ Receiver │ Counter  │ Encrypted      │ Auth Tag │
│ Index    │ (8B LE)  │ IP Packet      │ (16B)    │
│ (4B LE)  │          │ (variable)     │          │
└──────────┴──────────┴────────────────┴──────────┘
```

- **Receiver Index:** Identifies the session/keypair on the receiver side.
- **Counter:** 64-bit little-endian; MUST be strictly increasing (anti-replay).
- **Encrypted IP Packet:** ChaCha20-Poly1305 encrypted with nonce derived from counter.
- **Auth Tag:** 16-byte Poly1305 authentication tag.

## Anti-Replay

A sliding window bitmap will be used to detect and reject replayed packets,
similar to WireGuard's approach (RFC 6479 style).

## Key Rotation

Transport keys will be rotated after a configurable number of packets or time
interval, requiring a new handshake. This provides forward secrecy.
