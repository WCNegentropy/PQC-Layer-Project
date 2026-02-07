# Aegis Threat Model

> **Status:** Stub — to be expanded as the implementation progresses.

## Overview

This document describes the threat model for Project Aegis, a post-quantum secure
communication platform. It identifies adversary capabilities, trust boundaries,
and the security properties each layer is designed to provide.

## Adversary Model

| Adversary Class | Capabilities | Mitigations |
|---|---|---|
| **Passive Network Observer** | Full traffic capture, timing analysis | PQ-WG tunnel encryption, traffic shaping (Phase 2) |
| **Active Network Attacker** | Packet injection, modification, replay | AEAD authentication, transcript binding, nonce management |
| **Harvest-Now-Decrypt-Later** | Store encrypted traffic for future quantum attack | ML-KEM-768 hybrid KEM (quantum-resistant) |
| **Compromised Endpoint** | Access to one peer's memory | Zeroizing key material, ephemeral secrets, forward secrecy |
| **Malicious Sanctuary Node** | Modified server software | AGPLv3 source disclosure, client-side verification (Phase 2) |

## Trust Boundaries

1. **TUN Interface ↔ Pipeline** — Untrusted input; packets must be validated before processing.
2. **Client ↔ Sanctuary Node** — Authenticated via PQ-WG handshake; mutual authentication required.
3. **Key Material ↔ Memory** — Secret keys must be zeroized on drop; no logging of key material.

## Security Properties by Layer

| Layer | Property | Status |
|---|---|---|
| L2 (Crypto) | Hybrid KEM with transcript binding | ✅ Implemented |
| L2 (Crypto) | AEAD (ChaCha20-Poly1305) | ✅ Implemented |
| L2 (Crypto) | ML-DSA-65 signatures | ✅ Implemented |
| L2 (Crypto) | Secret key zeroization | ✅ Implemented |
| L3 (Gateway) | Safe packet parsing (no panics) | ✅ Implemented |
| L3 (Gateway) | Root privilege check | ✅ Implemented |
| L3 (Gateway) | PQ-WG handshake | ❌ Not yet implemented |
| L3 (Gateway) | Transport encryption | ❌ Not yet implemented |

## Known Gaps

- No fuzz testing on packet parser or crypto inputs yet.
- No formal verification of cryptographic constructions.
- Transport layer not yet encrypting packets (steel thread drops them).
- No rate limiting or DoS protection on the gateway.
