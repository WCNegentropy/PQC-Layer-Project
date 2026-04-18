# Aegis Threat Model

> **Status:** Active — updated to reflect implemented security properties.
>
> **Last Updated:** 2026-04-18

## Overview

This document describes the threat model for Project Aegis, a post-quantum secure
communication platform. It identifies adversary capabilities, trust boundaries,
and the security properties each layer is designed to provide.

The intended social topology is now **private-node first**: each user should be
able to run a private node by default, connect directly to other private nodes,
and optionally join shared Sanctuary/community nodes. The implemented transport
security properties below are current; several node/discovery properties remain planned.

## Adversary Model

| Adversary Class | Capabilities | Mitigations |
|---|---|---|
| **Passive Network Observer** | Full traffic capture, timing analysis | PQ-WG tunnel encryption, traffic shaping (Phase 2) |
| **Active Network Attacker** | Packet injection, modification, replay | AEAD authentication, transcript binding, anti-replay window (RFC 6479) |
| **Harvest-Now-Decrypt-Later** | Store encrypted traffic for future quantum attack | ML-KEM-768 hybrid KEM (quantum-resistant) |
| **Compromised Endpoint** | Access to one peer's memory | Zeroizing key material, ephemeral secrets, forward secrecy via rekeying |
| **Malicious Shared Node Operator** | Modified optional node software, metadata observation | End-to-end encryption, client verification, self-hosting |
| **Malicious Discovery / Bootstrap Node** | Fake, stale, or manipulative peer hints | DID verification, signed records, multiple bootstrap sources |

## Trust Boundaries

1. **TUN Interface ↔ Pipeline** — Untrusted input; packets must be validated before processing.
2. **Private Node ↔ Remote Private / Shared Node** — Intended authenticated PQ transport boundary for direct visits and messaging.
3. **Discovery / Bootstrap ↔ Client** — Discovery hints are untrusted until verified against DID/public-key material.
4. **Key Material ↔ Memory** — Secret keys must be zeroized on drop; no logging of key material.
5. **Sanctuary ↔ Internet** — Current transport/NAT boundary for implemented Sanctuary testing mode.

## Security Properties by Layer

| Layer | Property | Status |
|---|---|---|
| L2 (Crypto) | Hybrid KEM with transcript binding | ✅ Implemented |
| L2 (Crypto) | AEAD (ChaCha20-Poly1305) | ✅ Implemented |
| L2 (Crypto) | ML-DSA-65 signatures | ✅ Implemented |
| L2 (Crypto) | Secret key zeroization | ✅ Implemented |
| L3 (Gateway) | Safe packet parsing (no panics) | ✅ Implemented |
| L3 (Gateway) | Root privilege check | ✅ Implemented |
| L3 (Gateway) | PQ-WG handshake (dual hybrid KEM) | ✅ Implemented |
| L3 (Gateway) | Transport encryption (ChaCha20-Poly1305 AEAD) | ✅ Implemented |
| L3 (Gateway) | Anti-replay (RFC 6479 sliding window) | ✅ Implemented |
| L3 (Gateway) | Session rekeying / forward secrecy (120s / 65,536 pkts) | ✅ Implemented |
| L3 (Gateway) | Keypair persistence (load/save to file) | ✅ Implemented |
| Sanctuary transport primitive | Responder handshake + session management | ✅ Implemented |
| Sanctuary transport primitive | Peer authorization (public-key allowlist) | ✅ Implemented |
| Sanctuary transport primitive | NAT proxy (IP forwarding for tunnel clients) | ✅ Implemented |
| Sanctuary transport primitive | Anti-replay (per-client sliding window) | ✅ Implemented |
| Layer 7 private node default runtime | User-owned node serves vault-backed social space | ❌ Planned |
| Layer 4/7 discovery verification | Local DID documents + signed service records for manual discovery | 🟡 Foundation implemented |
| Layer 7 shared node participation | Optional shared/community nodes only | ❌ Planned |

## Fuzz Testing

Three fuzz targets exist for the crypto layer (since PR #4):
- `fuzz_kem_deser` — Fuzzes hybrid KEM deserialization
- `fuzz_aead` — Fuzzes AEAD encrypt/decrypt
- `fuzz_sign` — Fuzzes ML-DSA-65 signature operations

## Known Gaps

- No formal verification of cryptographic constructions.
- No DNS membrane yet (local resolver, DoH over tunnel).
- No rate limiting or DoS protection on the Sanctuary server.
- NAT proxy does not enforce per-client bandwidth limits.
- Cookie Reply (`0x03`) DoS mitigation not yet implemented.
- No `check.aegis.dev` verification endpoint.
- No private-node social runtime yet.
- No bootstrap discovery or DID-based node resolution implementation yet.
