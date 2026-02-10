# Aegis Threat Model

> **Status:** Active — updated to reflect implemented security properties.
>
> **Last Updated:** 2026-02-10

## Overview

This document describes the threat model for Project Aegis, a post-quantum secure
communication platform. It identifies adversary capabilities, trust boundaries,
and the security properties each layer is designed to provide.

## Adversary Model

| Adversary Class | Capabilities | Mitigations |
|---|---|---|
| **Passive Network Observer** | Full traffic capture, timing analysis | PQ-WG tunnel encryption, traffic shaping (Phase 2) |
| **Active Network Attacker** | Packet injection, modification, replay | AEAD authentication, transcript binding, anti-replay window (RFC 6479) |
| **Harvest-Now-Decrypt-Later** | Store encrypted traffic for future quantum attack | ML-KEM-768 hybrid KEM (quantum-resistant) |
| **Compromised Endpoint** | Access to one peer's memory | Zeroizing key material, ephemeral secrets, forward secrecy via rekeying |
| **Malicious Sanctuary Node** | Modified server software | AGPLv3 source disclosure, client-side verification (Phase 2) |

## Trust Boundaries

1. **TUN Interface ↔ Pipeline** — Untrusted input; packets must be validated before processing.
2. **Client ↔ Sanctuary Node** — Authenticated via PQ-WG handshake; peer authorization via allowlist.
3. **Key Material ↔ Memory** — Secret keys must be zeroized on drop; no logging of key material.
4. **Sanctuary ↔ Internet** — NAT proxy forwards decrypted traffic; client IP is hidden behind Sanctuary IP.

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
| Sanctuary | Responder handshake + session management | ✅ Implemented |
| Sanctuary | Peer authorization (public-key allowlist) | ✅ Implemented |
| Sanctuary | NAT proxy (IP forwarding for tunnel clients) | ✅ Implemented |
| Sanctuary | Anti-replay (per-client sliding window) | ✅ Implemented |

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
