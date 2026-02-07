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
- [x] CLI: `aegis up`, `aegis down`, `aegis status`, `aegis keygen`
- [ ] PQ-WireGuard handshake implementation
- [ ] Tunnel engine (encrypt/decrypt transport packets)
- [ ] Sanctuary Node v0 (Docker, PQ-WG termination + NAT)
- [ ] DNS Membrane (local resolver, DoH over tunnel)
- [ ] `check.aegis.dev` verification endpoint

### Phase 2: Identity & Vault (Weeks 13-24)
- [ ] Key hierarchy (root → device → session)
- [ ] DID (`did:aegis`) implementation
- [ ] Verifiable Credentials with ML-DSA-65
- [ ] Encrypted vault storage (per-file AEAD)
- [ ] FUSE filesystem mount
- [ ] CRDT-based multi-device sync

### Phase 3: Social Fabric (Weeks 25-36)
- [ ] PQ Double Ratchet messaging
- [ ] MLS-inspired group encryption
- [ ] ActivityPub federation
- [ ] Desktop app (Tauri 2.0)

---

## 7. Wire Protocol (PQ-WireGuard)

The Aegis tunnel uses a WireGuard-inspired protocol extended with hybrid
post-quantum key encapsulation.

### 7.1 Handshake (Noise IK + Hybrid KEM)

```text
Initiator (Client)                         Responder (Sanctuary)
──────────────────                         ─────────────────────
knows responder's static PK

msg1: e_i, s_i, KEM_ct_i ────────────────▶
                                           decapsulate KEM_ct_i
                                           derive transport keys
                          ◀──────────────── msg2: e_r, KEM_ct_r
decapsulate KEM_ct_r
derive transport keys

        ◀════════ encrypted tunnel data ════════▶
```

### 7.2 Transport Packet Format

```text
┌──────────────┬──────────┬──────────────────────┬──────────┐
│ Receiver Idx │ Counter  │ Encrypted IP Packet  │ Auth Tag │
│   (4B LE)    │ (8B LE)  │    (variable)        │  (16B)   │
└──────────────┴──────────┴──────────────────────┴──────────┘
```

- **Receiver Index:** Identifies the session keypair on the receiver.
- **Counter:** 64-bit LE, strictly increasing (anti-replay via sliding window).
- **Encrypted Payload:** ChaCha20-Poly1305 AEAD with nonce derived from counter.
- **Auth Tag:** 16-byte Poly1305 tag.

### 7.3 Key Rotation

Transport keys are rotated after 2^64 - 1 packets or a configurable time
interval (default: 120 seconds, matching WireGuard's `REKEY_AFTER_TIME`).
This triggers a new handshake, providing forward secrecy — compromising
current keys does not reveal past traffic. The 120-second default balances
forward secrecy granularity against PQ-WG handshake overhead (hybrid KEM
is ~10× slower than classical WireGuard).

---

## 8. Sanctuary Network

The Sanctuary is a network of PQ-WG termination servers that provide:

1. **IP Privacy** — Client traffic exits through the Sanctuary's IP.
2. **DNS Oblivion** — DNS queries are resolved by the Sanctuary, not the ISP.
3. **NAT Proxy** — Stateful NAT with connection tracking.

### 8.1 Deployment Model

```text
┌─────────┐     PQ-WG      ┌──────────────┐      NAT      ┌──────────┐
│  Aegis  │ ──────────────▶ │  Sanctuary   │ ────────────▶ │ Internet │
│  Client │   UDP tunnel    │    Node      │   cleartext   │          │
└─────────┘                 └──────────────┘               └──────────┘
```

Sanctuary nodes run as Docker containers with minimal attack surface:
- Read-only root filesystem
- No shell access
- PQ-WG + NAT proxy only
- Automatic key rotation

### 8.2 Peer Authorization

Each client registers its hybrid public key with the Sanctuary. Only
authorized peers can establish tunnels. Unauthorized handshake attempts
receive no response (silent drop to prevent enumeration).

---

## 9. Identity Anchor (Layer 4)

### 9.1 Key Hierarchy

```text
Root Keypair (ML-DSA-65 + Ed25519)
├── Device Key (HKDF-SHA3-256, per device)
│   ├── Session Key (ephemeral, per connection)
│   └── Storage Key (for vault master key derivation)
└── Recovery Key (Shamir secret sharing, offline backup)
```

### 9.2 Decentralized Identifiers

Aegis uses a `did:aegis` method:

```
did:aegis:z6MkhaXgBZDvotDkL...
```

The DID document contains:
- ML-DSA-65 public key (verification)
- ML-KEM-768 public key (key agreement)
- Service endpoints (Sanctuary addresses)

### 9.3 Verifiable Credentials

W3C VC format signed with ML-DSA-65. Use cases:
- Proving device ownership to a Sanctuary
- Peer identity verification for social messaging
- Authorization for vault access delegation

---

## 10. Data Sovereignty Vault (Layer 5)

### 10.1 Encryption Model

Each file is encrypted with a unique key:

```text
file_key = HKDF-SHA3-256(
    ikm  = vault_master_key,
    salt = SHA3-256(file_path),
    info = b"aegis-vault-file-key-v1"
)
```

Encryption uses ChaCha20-Poly1305 AEAD with a random nonce per write.

### 10.2 Storage Layout

```text
vault/
├── .aegis/
│   ├── metadata.db          # Encrypted SQLite (file index, CRDT state)
│   └── keys/                # Encrypted key material
├── 00/                      # Content-addressed blob storage
│   ├── aa/
│   │   └── 00aabb...hex     # Encrypted file blob
│   └── ...
```

### 10.3 Sync Engine

Multi-device sync uses CRDTs (Conflict-free Replicated Data Types):
- **File operations:** LWW-Register (last-writer-wins by timestamp)
- **Directory structure:** OR-Set (observed-remove set)
- **Conflict resolution:** Automatic via CRDT semantics; no user intervention

---

## 11. Social Fabric (Layer 7)

### 11.1 PQ Double Ratchet

Adapts the Signal Double Ratchet for post-quantum security:
- DH ratchet step uses ML-KEM-768 instead of X25519
- Symmetric ratchet uses HKDF-SHA3-256
- Message keys use ChaCha20-Poly1305 AEAD

Properties:
- Forward secrecy per message
- Post-compromise security (self-healing after key compromise)
- Quantum resistance via ML-KEM

### 11.2 Group Messaging (MLS-inspired)

Tree-based group key agreement:
- Binary tree with ML-KEM at each node
- O(log n) cost for member add/remove
- Epoch-based key rotation
- Forward secrecy between epochs

### 11.3 Federation (ActivityPub)

ActivityPub extensions for Aegis:
- Standard ActivityPub for public posts
- `aegis:EncryptedMessage` type for PQ-encrypted DMs
- WebFinger discovery for `did:aegis` identities
- ML-DSA-65 HTTP Signatures for server-to-server auth

---

## 12. Platform Matrix

| Feature              | Linux             | macOS              | Windows (future)   | iOS/Android (future) |
|----------------------|-------------------|--------------------|--------------------|--------------------|
| TUN interface        | `/dev/net/tun`    | `utun` kernel      | Wintun.dll         | NetworkExtension   |
| Keyring              | libsecret/DBUS    | Keychain Services  | Credential Manager | Keychain/Keystore  |
| FUSE mount           | `libfuse3`        | `macfuse`          | WinFsp             | N/A                |
| TPM/HSM              | `tpm2-tss`        | Secure Enclave     | Windows TPM        | Secure Enclave     |
| System tray          | `dbus` indicators | NSStatusItem       | System Tray API    | N/A                |
| Privileges           | CAP_NET_ADMIN/root| root               | Admin              | VPN entitlement    |
| Entropy              | `/dev/urandom`    | `SecRandomCopyBytes`| `BCryptGenRandom` | System CSPRNG      |

---

## 13. Threat Model Summary

### 13.1 Adversary Capabilities

| Adversary Class           | Capabilities                         | Mitigations                              |
|---------------------------|--------------------------------------|------------------------------------------|
| Passive Network Observer  | Traffic capture, timing analysis     | PQ-WG encryption, traffic shaping        |
| Active Network Attacker   | Injection, modification, replay      | AEAD auth, transcript binding, counters  |
| Harvest-Now-Decrypt-Later | Store ciphertext for quantum attack  | ML-KEM-768 hybrid KEM                    |
| Compromised Endpoint      | Memory access on one peer            | Zeroizing keys, ephemeral secrets        |
| Malicious Sanctuary       | Modified server software             | Client-side verification, open source    |
| Supply Chain Attack       | Compromised dependencies             | `cargo-audit`, reproducible builds       |

### 13.2 Trust Boundaries

1. **TUN ↔ Pipeline** — Untrusted input; all packets validated before processing.
2. **Client ↔ Sanctuary** — Mutually authenticated via PQ-WG handshake.
3. **Key Material ↔ Memory** — Zeroized on drop; never logged.
4. **Vault ↔ Filesystem** — Encrypted at rest; plaintext only in FUSE buffer.

---

## 14. CI/CD Pipeline

### 14.1 Current Pipeline (`.github/workflows/ci.yml`)

| Job        | What It Does                           | Runs On        |
|------------|----------------------------------------|----------------|
| `fmt`      | `cargo fmt --all --check`              | ubuntu-latest  |
| `clippy`   | `cargo clippy -- -D warnings`          | ubuntu-latest  |
| `check`    | `cargo check --workspace --all-targets`| ubuntu-latest  |
| `test`     | `cargo test --workspace`               | ubuntu + macOS |
| `audit`    | `cargo-audit` vulnerability scan       | ubuntu-latest  |

### 14.2 Planned Additions

| Job           | What It Does                                  | Priority |
|---------------|-----------------------------------------------|----------|
| `miri`        | Undefined behavior detection on `aegis-crypto`| Medium   |
| `fuzz`        | `cargo-fuzz` on hybrid KEM (30 min)           | Medium   |
| `bench`       | Criterion benchmarks, regression detection    | Low      |
| `coverage`    | `cargo-tarpaulin` or `llvm-cov`               | Low      |
| `release`     | Cross-compile + sign release artifacts        | Phase 2  |

---

## 15. Technology Decisions

### 15.1 Why Rust?

- Memory safety without GC (critical for crypto code)
- Zero-cost abstractions for performance-sensitive packet pipeline
- `#[cfg]` for platform-specific code without runtime dispatch
- `zeroize` crate for deterministic secret wiping
- Strong async ecosystem (tokio) for network I/O

### 15.2 Why Hybrid KEM (X25519 + ML-KEM-768)?

- **Defense in depth:** If ML-KEM is broken, X25519 still protects.
- **If X25519 is broken by quantum computers**, ML-KEM-768 still protects.
- **Transcript binding** prevents one component's ciphertext from being
  replayed in a different protocol context.
- NIST Level 3 security (ML-KEM-768) matches our threat model.

### 15.3 Why ChaCha20-Poly1305 over AES-GCM?

- Constant-time in software (no AES-NI required)
- Better performance on ARM devices without hardware AES
- Widely deployed and audited (used by WireGuard, TLS 1.3)
- Avoids AES-GCM nonce-misuse catastrophe (though both require unique nonces)

### 15.4 Why ML-DSA-65 (Dilithium3)?

- NIST FIPS 204 standard (2024)
- NIST Level 3 security (consistent with ML-KEM-768)
- Reasonable signature size (~3.3 KB) for handshake messages
- `pqcrypto-mldsa` crate (actively maintained, replaces deprecated `pqcrypto-dilithium`)

### 15.5 Why tun2 over other TUN libraries?

- Actively maintained fork of the original `tun` crate
- Async support via tokio (feature flag)
- Cross-platform: Linux, macOS, Windows
- v4 API: always delivers raw IP packets (no PI header confusion)

### 15.6 Dependency Selection Criteria

1. **Actively maintained** — recent commits, responsive to issues
2. **Audited where possible** — especially for crypto dependencies
3. **Minimal transitive dependencies** — reduce supply chain risk
4. **No unsafe where avoidable** — prefer safe Rust abstractions
5. **`cargo-audit` clean** — no known vulnerabilities
