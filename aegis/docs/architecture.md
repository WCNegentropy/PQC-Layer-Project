# Project Aegis — Architecture Specification v0.2

> **Status:** Steel Thread in progress (Phase 1)
> **Last Updated:** 2026-02-07
> **Authors:** WCNegentropy, Copilot

---

## 1. Vision

Project Aegis is a **layered, modular platform** providing individuals with
quantum-resistant control over their data, identity, and communications. It
operates as a composable stack — each layer independently useful, exponentially
powerful when combined.

### Core Principles

1. **Sovereignty** — User data never exists in plaintext on untrusted infrastructure.
2. **Crypto-Agility** — Every primitive is swappable via trait boundaries.
3. **Defense in Depth** — No single layer's compromise exposes the user.
4. **Progressive Disclosure** — Simple app for users, configurable modules for power users, composable SDK for developers.

---

## 2. System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    LAYER 7: SOCIAL FABRIC                       │
│         Decentralized social, messaging, collaboration          │
├─────────────────────────────────────────────────────────────────┤
│                    LAYER 6: APPLICATION SHELL                   │
│         Desktop/Mobile UI (Tauri), CLI, Browser Extension       │
├─────────────────────────────────────────────────────────────────┤
│                    LAYER 5: DATA SOVEREIGNTY VAULT              │
│         Encrypted FS (FUSE), Object Store, CRDT Sync Engine     │
├─────────────────────────────────────────────────────────────────┤
│                    LAYER 4: IDENTITY ANCHOR                     │
│         DID, Verifiable Credentials, Key Hierarchy, Auth        │
├─────────────────────────────────────────────────────────────────┤
│                    LAYER 3: QUANTUM GATEWAY ("The Sentinel")    │
│         PQ-WG Tunnel, DNS Oblivion, Traffic Shaping, AI Filter  │
├─────────────────────────────────────────────────────────────────┤
│                    LAYER 2: CRYPTO ENGINE                       │
│         Hybrid PQC (ML-KEM + X25519), ML-DSA, AEAD, KDF        │
├─────────────────────────────────────────────────────────────────┤
│                    LAYER 1: PLATFORM ABSTRACTION                │
│         TUN/TAP, FUSE, Keyring, HSM/TPM, Entropy               │
└─────────────────────────────────────────────────────────────────┘
```

Each layer is a separate Rust crate in a Cargo workspace.

---

## 3. Workspace Structure

```
aegis/
├── Cargo.toml                      # Workspace root
├── crates/
│   ├── aegis-crypto/               # Layer 2: Cryptographic engine ✅ IMPLEMENTED
│   │   ├── Cargo.toml
│   │   └── src/lib.rs              # Hybrid KEM, transcript binding, zeroization
│   ├── aegis-gateway/              # Layer 3: Quantum Gateway ✅ IMPLEMENTED (Steel Thread)
│   │   ├── Cargo.toml
│   │   └── src/main.rs             # TUN device, async packet pipeline
│   ├── aegis-platform/             # Layer 1: OS abstraction (planned)
│   ├── aegis-identity/             # Layer 4: Identity (planned)
│   ├── aegis-vault/                # Layer 5: Encrypted storage (planned)
│   ├── aegis-social/               # Layer 7: Social fabric (planned)
│   └── aegis-sanctuary/            # Sanctuary Node server (planned)
├── apps/
│   ├── aegis-desktop/              # Tauri desktop app (planned)
│   ├── aegis-cli/                  # CLI interface (planned)
│   └── aegis-web/                  # Web frontend (planned)
├── tests/
│   ├── integration/
│   ├── fuzz/
│   └── benchmarks/
└── docs/
    ├── architecture.md             # This document
    ├── threat-model.md
    ├── cryptography.md
    └── protocol-spec.md
```

---

## 4. Layer 2: Crypto Engine (`aegis-crypto`) — ✅ IMPLEMENTED

### 4.1 Algorithm Suite

| Function           | Primary          | Fallback        | Classical Hybrid | Standard  |
|--------------------|------------------|-----------------|------------------|-----------|
| Key Encapsulation  | ML-KEM-768       | HQC-128 (future)| X25519           | FIPS 203  |
| Digital Signatures | ML-DSA-65        | SLH-DSA-128s    | Ed25519          | FIPS 204  |
| Symmetric AEAD     | ChaCha20-Poly1305| AES-256-GCM     | —                | —         |
| Hashing            | BLAKE3           | SHA3-256         | —                | —         |
| KDF                | HKDF-SHA3-256    | Argon2id (passwords) | —           | —         |

### 4.2 Hybrid KEM Design

**Formula:**
```
SharedSecret = HKDF-SHA3-256(
    ikm  = X25519_SharedSecret || ML-KEM-768_SharedSecret,
    salt = SHA3-256(label || recipient_pk || ephemeral_pk || ml_kem_ct),
    info = b"aegis-hybrid-kem-v1"
)
```

**Security Properties:**
- If EITHER X25519 OR ML-KEM is secure, the combined secret is secure.
- Transcript binding (salt) prevents cross-protocol replay attacks.
- All intermediate key material is zeroized after use via `Zeroizing<Vec<u8>>`.
- ML-KEM uses implicit rejection (no error on bad ciphertext — AEAD catches mismatch).

### 4.3 Dependencies

| Crate               | Purpose                         |
|----------------------|---------------------------------|
| `x25519-dalek` 2.0  | Classical ECDH                  |
| `pqcrypto-kyber` 0.8| ML-KEM-768 (PQClean bindings)   |
| `sha3` 0.10         | SHA3-256 for transcript hash    |
| `hkdf` 0.12         | Key derivation                  |
| `zeroize` 1.7       | Secret material wiping          |
| `thiserror` 1.0     | Error types                     |

### 4.4 API Surface

```rust
// Key generation (once per identity)
let (public_key, secret_key) = AegisCrypto::keygen();

// Encapsulation (sender side)
let result = AegisCrypto::encapsulate(&recipient_public_key)?;
// result.shared_secret: [u8; 32]  — use for AEAD
// result.ciphertext: HybridCiphertext  — send to recipient

// Decapsulation (recipient side)
let shared_secret = AegisCrypto::decapsulate(
    &received_ciphertext,
    &my_secret_key,
    &my_public_key,  // needed for transcript binding
)?;

// Serialization (for wire transmission)
let bytes = ciphertext.to_bytes();     // 1120 bytes
let ct = HybridCiphertext::from_bytes(&bytes)?;
let pk_bytes = public_key.to_bytes();  // 1216 bytes
let pk = HybridPublicKey::from_bytes(&pk_bytes)?;
```

### 4.5 Test Coverage

| Test                              | What it proves                           |
|-----------------------------------|------------------------------------------|
| `hybrid_key_exchange_roundtrip`   | Encapsulate → serialize → deserialize → decapsulate yields same secret |
| `different_recipients_different`  | Different public keys → different secrets |
| `wrong_key_decapsulation_fails`   | Attacker with wrong key gets wrong secret |
| `public_key_serialization`        | PK survives roundtrip through bytes       |
| `ciphertext_serialization`        | CT survives roundtrip through bytes       |
| `invalid_lengths_rejected`        | Malformed input returns error, no panic   |

---

## 5. Layer 3: Quantum Gateway (`aegis-gateway`) — ✅ IMPLEMENTED (Steel Thread)

### 5.1 Current Capabilities (Steel Thread)

- [x] Platform-aware packet reading (handles macOS 4-byte AF header)
- [x] Safe IP header parsing (IPv4 + IPv6, no panics on malformed input)
- [x] Protocol classification (ICMP, TCP, UDP)
- [x] Atomic pipeline statistics (packet/byte counters)
- [x] Graceful shutdown (Ctrl+C → clean teardown)
- [x] Root privilege detection
- [x] Structured logging with env-filter

### 5.2 Packet Pipeline Architecture

```
    ┌───────────────────────────┐
    │    OS Network Stack       │
    │  (app sends TCP/UDP/ICMP) │
    └───────────┬───────────────┘
                │ raw IP packets
    ┌───────────▼───────────────┐
    │    TUN Device (aegis0)    │
    │  Platform-specific read:  │
    │  Linux: raw IP            │
    │  macOS: 4B AF + IP        │
    └───────────┬───────────────┘
                │
    ┌───────────▼───────────────┐
    │    Header Strip           │
    │  Remove TUN_AF_HEADER     │
    └───────────┬───────────────┘
                │ ip_packet: &[u8]
    ┌───────────▼───────────────┐
    │    PacketInfo::parse()    │
    │  - Bounds validation      │
    │  - Version (4/6)          │
    │  - Protocol (TCP/UDP/ICMP)│
    │  - Src/Dst addresses      │
    │  - Payload length         │
    └───────────┬───────────────┘
                │ PacketInfo
    ┌───────────▼───────────────┐    ← FUTURE: Antibodies (Tier 1 bloom filter)
    │    [PLACEHOLDER]          │    ← FUTURE: Split Tunnel classify
    │    Log & Drop             │    ← FUTURE: Traffic Shaper
    │                           │    ← FUTURE: PQ-WG encrypt + UDP send
    └───────────────────────────┘
```

### 5.3 Platform Differences

| Aspect              | Linux                       | macOS                     | Windows (future) |
|----------------------|-----------------------------|---------------------------|------------------|
| TUN driver           | `/dev/net/tun`              | `utun` kernel socket      | Wintun.dll       |
| Packet prefix        | None (PI disabled)          | 4-byte AF family header   | None             |
| Interface naming     | User-specified (`aegis0`)   | Kernel-assigned (`utun3`)  | User-specified   |
| Privileges           | `CAP_NET_ADMIN` or root     | root                      | Admin            |
| Cleanup on exit      | Automatic (fd close)        | Automatic (socket close)  | Manual           |

---

## 6. Implementation Roadmap

### Phase 0: Foundation ✅ COMPLETE
- [x] Cargo workspace with CI
- [x] `aegis-crypto`: Hybrid KEM with transcript binding
- [x] Fuzz targets, unit tests, zeroization

### Phase 1: Sentinel MVP (Current — Weeks 3-12)
- [x] Async packet pipeline with safe parsing
- [x] Pipeline statistics and graceful shutdown
- [ ] PQ-WireGuard handshake implementation
- [ ] Tunnel engine (encrypt/decrypt transport packets)
- [ ] Sanctuary Node v0 (Docker, PQ-WG termination + NAT)
- [ ] DNS Membrane (local resolver, DoH over tunnel)
- [ ] CLI: `aegis up`, `aegis down`, `aegis status`
- [ ] `check.aegis.dev` verification endpoint
