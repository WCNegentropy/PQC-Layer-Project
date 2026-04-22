# Project Aegis — Architecture Specification v0.5

> **Status:** Phase 1 complete — crypto + gateway + Sanctuary are implemented; identity/vault are the next substrate to harden before the Browser/runtime phase
> **Last Updated:** 2026-04-21
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

### Architecture Direction Update

Aegis is now explicitly targeting a **private-node-by-default** social topology:

1. Every user will ultimately run a private Aegis node containing their vault, identity, and social space.
2. Direct private-node-to-private-node connections are the default path for visits, messaging, and user-controlled content serving.
3. Shared Sanctuary nodes are **opt-in** spaces that a user, community, creator, or platform operator may host.
4. Minimal bootstrap/discovery infrastructure may exist to help peers find one another, but it should not sit in the normal content/data path.

The currently implemented `aegis-gateway` and `aegis-sanctuary` crates remain transport-layer building blocks. The private-node runtime, discovery system, and social application layer described here are largely **planned**, not yet implemented.

The canonical product sequence is:

1. complete the private-node substrate in `aegis-identity` + `aegis-vault`,
2. turn `apps/aegis-desktop` into the **Aegis Browser / runtime shell**,
3. add direct visits, sync, messaging, and optional shared nodes,
4. package the stable runtime later as an immutable **AegisOS** target.

---

## 2. System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    LAYER 7: SOCIAL FABRIC                       │
│   Private nodes by default, opt-in shared nodes, federation     │
├─────────────────────────────────────────────────────────────────┤
│                    LAYER 6: APPLICATION SHELL                   │
│   Browser/runtime shell, CLI, editors, local protocol surface   │
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
│   ├── aegis-gateway/              # Layer 3: Quantum Gateway ✅ IMPLEMENTED
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── main.rs             # Gateway entry point, TUN setup, tunnel loop
│   │       ├── handshake.rs        # PQ-WG initiator/responder, dual KEM, transcript hash
│   │       ├── transport.rs        # Encrypt/decrypt, counter-nonce, header parsing
│   │       ├── anti_replay.rs      # RFC 6479 sliding-window replay protection (128-bit)
│   │       ├── session.rs          # Session lifecycle, counters, rekey triggers
│   │       ├── keypair.rs          # Keypair persistence (load/save)
│   │       ├── packet.rs           # Safe IPv4/IPv6 parsing, protocol classification
│   │       ├── pipeline.rs         # Async packet pipeline
│   │       ├── platform.rs         # CLI args, TUN config, root check
│   │       └── stats.rs            # Atomic pipeline statistics (13 counters)
│   ├── aegis-sanctuary/            # PQ-WG responder/server primitive ✅ IMPLEMENTED
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── main.rs             # Sanctuary server entry point
│   │       ├── server.rs           # UDP listener, responder handshake, session mgmt
│   │       ├── config.rs           # TOML config loading, authorized peers
│   │       ├── proxy.rs            # NAT proxy, client IP mapping, bandwidth stats
│   │       └── lib.rs              # Library exports
│   ├── aegis-platform/             # Layer 1: OS abstraction (trait definitions)
│   ├── aegis-identity/             # Layer 4: Identity + discovery metadata ✅ foundations
│   ├── aegis-vault/                # Layer 5: Encrypted storage ✅ foundations
│   └── aegis-social/               # Layer 7: Private/shared node social runtime (planned)
├── apps/
│   ├── aegis-cli/                  # CLI: up/down/status/keygen ✅ FUNCTIONAL
│   ├── aegis-desktop/              # Future Aegis Browser / runtime shell (placeholder)
│   └── aegis-web/                  # Auxiliary API/status/web surface (placeholder)
├── tests/
│   ├── integration/
│   ├── fuzz/                       # 3 fuzz targets: fuzz_kem_deser, fuzz_aead, fuzz_sign
│   └── benchmarks/
├── docs/
│   ├── architecture.md             # This document
│   ├── threat-model.md
│   ├── cryptography.md
│   └── protocol-spec.md
├── Dockerfile.sanctuary            # Multi-stage Docker build for Sanctuary
├── docker-compose.sanctuary.yml    # Docker Compose for Sanctuary deployment
├── sanctuary.toml                  # Sanctuary server configuration
└── test_sanctuary.sh               # Shell test script
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

## 5. Layer 3: Quantum Gateway (`aegis-gateway`) — ✅ IMPLEMENTED

### 5.1 Current Capabilities

- [x] Platform-aware packet reading (handles macOS 4-byte AF header)
- [x] Safe IP header parsing (IPv4 + IPv6, no panics on malformed input)
- [x] Protocol classification (ICMP, TCP, UDP)
- [x] Atomic pipeline statistics (13 counters: packets, bytes, encrypted, decrypted, replay rejected, etc.)
- [x] Graceful shutdown (Ctrl+C → clean teardown)
- [x] Root privilege detection
- [x] Structured logging with env-filter
- [x] PQ-WG handshake (dual hybrid KEM, transcript binding)
- [x] Transport encryption (ChaCha20-Poly1305 AEAD)
- [x] Anti-replay (RFC 6479, 128-bit sliding window)
- [x] Session management with rekey triggers (120s / 65,536 packets)
- [x] Keypair persistence (load/save to file)

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
    ┌───────────▼───────────────┐
    │  Session::needs_rekey()?  │    ← Re-handshake if expired
    │  transport_encrypt()      │    ← ChaCha20-Poly1305 AEAD
    │  AntiReplayWindow::check  │    ← RFC 6479 replay protection
    │  UDP send → Sanctuary     │    ← Encrypted tunnel packet
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

### Phase 1 Complete ✅
- [x] `aegis-crypto`: hybrid KEM, AEAD, ML-DSA foundations
- [x] `aegis-gateway`: packet pipeline, handshake, transport encryption, anti-replay, rekey triggers
- [x] `aegis-sanctuary`: responder/server primitive, Docker deployment, configuration, tests
- [x] `aegis-cli`: `up/down/status/keygen` plus identity/vault bootstrap flows

### Phase 2A: Identity/Vault Hardening
- [x] Key hierarchy foundations (root → device → session/storage)
- [x] `did:aegis` generation and DID document/service record output
- [x] ML-DSA-65 verifiable credentials and auth challenge/response foundations
- [x] Encrypted vault storage and private-node social bootstrap layout
- [ ] Production FUSE filesystem mount
- [ ] Real CRDT-based multi-device/network sync
- [ ] Recovery, rotation, and multi-device coordination flows
- [ ] Loopback proof of two local private nodes connecting directly

### Phase 2B: Private Node Runtime + Aegis Browser
- [ ] Private node runtime enabled by default for each user
- [ ] Direct private-node visits and vault-backed space serving
- [ ] `aegis-desktop` becomes the Aegis Browser / runtime shell
- [ ] Local protocol/router for `vault://`, `node://`, and `sanctuary://`
- [ ] Identity/vault management UI, diagnostics, and editor flows

### Phase 2C: Sync, Messaging, and Shared Nodes
- [ ] PQ Double Ratchet messaging
- [ ] Optional shared nodes with MLS-inspired group encryption
- [ ] Bootstrap discovery outside the normal data path
- [ ] DID-based node discovery / resolution
- [ ] Shared-room operator tooling and multi-process integration tests

### Phase 2D: Federation, Packaging, and Optional AegisOS Image
- [ ] ActivityPub federation
- [ ] Auxiliary `aegis-web` service/API surface
- [ ] Ecosystem packaging and creator/distribution tooling
- [ ] Immutable AegisOS image as packaging/hardening for the mature runtime

---

## 7. Canonical Runtime Topology

- **`aegis-desktop`** is intended to become the primary **Aegis Browser / runtime shell**.
- **`aegis-cli`** is the bootstrap, ops, automation, and diagnostics interface.
- **`aegis-web`** is a future auxiliary service/API/web surface, not the main sovereign runtime.
- **`aegis-sanctuary`** is a transport/server primitive for optional private/shared-node roles, not a mandatory central dependency.
- **AegisOS** is a later immutable packaging target built on top of the runtime once the browser/private-node stack is real.

---

## 8. Wire Protocol (PQ-WireGuard)

The Aegis tunnel uses a WireGuard-inspired protocol extended with hybrid
post-quantum key encapsulation.

Today this protocol is implemented for gateway ↔ Sanctuary transport. The
intended private-node architecture is expected to reuse or adapt this transport
for direct node-to-node connections rather than requiring a permanent platform hop.

### 8.1 Handshake (Noise IK + Hybrid KEM)

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

### 8.2 Transport Packet Format

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

### 8.3 Key Rotation

Transport keys are rotated after 2^64 - 1 packets or a configurable time
interval (default: 120 seconds, matching WireGuard's `REKEY_AFTER_TIME`).
This triggers a new handshake, providing forward secrecy — compromising
current keys does not reveal past traffic. The 120-second default balances
forward secrecy granularity against PQ-WG handshake overhead (hybrid KEM
is ~10× slower than classical WireGuard).

---

## 9. Node Topology & Sanctuary Role

### 9.1 Intended Topology (Planned)

The target social architecture is:

```text
Default path:
┌──────────────────┐      direct PQC tunnel      ┌──────────────────┐
│ User A Private   │ ───────────────────────────▶ │ User B Private   │
│ Node / Vault     │                              │ Node / Vault     │
└──────────────────┘                              └──────────────────┘

Optional shared space:
┌──────────────────┐      PQC tunnel             ┌──────────────────┐
│ User A Private   │ ───────────────────────────▶ │ Shared Sanctuary │
│ Node / Vault     │                              │ / Community Node │
└──────────────────┘                              └──────────────────┘
```

Core implications:

1. The user's private node becomes the default Aegis runtime for identity, vault-backed content, and direct social interaction.
2. Shared Sanctuary nodes are not mandatory coordination hops; they are optional rooms/events/community spaces.
3. The core product should remain functional with only user-run nodes.
4. Any bootstrap/discovery infrastructure should help peers find one another without becoming a content host or permanent dependency.

### 9.2 Discovery Model (Planned)

Discovery is the main new systems problem introduced by the private-node-first design.

Planned progression:

1. **Manual exchange (MVP):** users share node address + public identity material directly.
2. **Bootstrap discovery nodes:** minimal well-known nodes provide peer hints but are not in the data path.
3. **DID document resolution:** `did:aegis` records advertise current node/discovery endpoints.

### 9.3 Sanctuary Role in the New Architecture

`aegis-sanctuary` remains important, but its role changes:

- it is no longer assumed to be a mandatory platform hop for normal user-to-user interaction,
- it can be reused or adapted as the transport/server primitive for self-hosted private nodes,
- it can power opt-in shared/community/platform spaces,
- it may support optional bootstrap or relay-style infrastructure later, but those services are not prerequisites for the core product.

### 9.4 Current Implemented Transport Primitive — ✅ IMPLEMENTED

The current Sanctuary server (`aegis-sanctuary`) consists of:

| Module | Role |
|--------|------|
| `server.rs` | UDP listener, responder handshake, multi-client session management |
| `config.rs` | TOML configuration loading, authorized peer discovery |
| `proxy.rs` | NAT proxy, per-client IP mapping, bandwidth statistics |
| `main.rs` | Entry point, Ctrl+C shutdown handler |

Current configuration:

```toml
[server]
listen_addr = "0.0.0.0:51820"
keypair_file = "sanctuary.key"
log_level = "info"
authorized_peers_dir = "peers/"    # Optional: directory of peer public keys
```

This implemented transport layer is useful for current testing, but it should not be confused with the future fully user-controlled private-node social runtime.

---

## 10. Identity Anchor (Layer 4)

### 10.1 Key Hierarchy

```text
Root identity (ML-DSA-65 signing + hybrid KEM)
├── Device identity (issued and attested by root signing key)
│   ├── Session key material (context-derived from device exchange secret)
│   └── Storage key material (device-local derivation)
└── Recovery / backup flow (still planned)
```

Current implementation:
- `RootIdentity::generate()` creates root signing + hybrid key-agreement material.
- `RootIdentity::issue_device()` generates a primary device identity and signs a device VC.
- `DeviceIdentity::derive_session_key()` / `derive_storage_key()` provide local key-hierarchy primitives for subsequent layers.

### 10.2 Decentralized Identifiers

Aegis currently uses a local `did:aegis` method derived from the root signing public key:

```
did:aegis:<sha3-256(root-signing-public-key)>
```

The DID document contains:
- ML-DSA-65 public key (verification)
- ML-KEM-768 public key (key agreement)
- Service endpoints / discovery records for a user's private node
- Optional shared-node memberships or published room endpoints

Current implementation note: local DID documents are emitted as JSON by the CLI and can already advertise manual private-node endpoints for MVP discovery.

### 10.3 Verifiable Credentials

W3C VC format signed with ML-DSA-65. Use cases:
- Proving device ownership to a private node or optional shared node
- Peer identity verification for social messaging
- Authorization for vault access delegation

Current implementation note: the `aegis-identity` crate now issues and verifies ML-DSA-65-signed device credentials and challenge/response payloads.

---

## 11. Data Sovereignty Vault (Layer 5)

### 11.1 Encryption Model

Each file is encrypted with a unique key:

```text
file_key = HKDF-SHA3-256(
    ikm  = vault_master_key,
    salt = SHA3-256(file_path),
    info = b"aegis-vault-file-key-v1"
)
```

Encryption uses ChaCha20-Poly1305 AEAD with a random nonce per write.

### 11.2 Storage Layout

```text
vault/
├── .aegis/
│   ├── manifest.json        # Encrypted-file manifest and logical path metadata
│   ├── blobs/               # Encrypted blob storage
│   │   ├── aa/
│   │   │   └── aa...hex.blob
│   │   └── ...
│   └── keys/                # Vault master key and related material
├── social/
│   ├── space/
│   ├── character/
│   ├── inventory/
│   ├── profile/
│   └── feed/
│   └── ...
```

### 11.3 Sync Engine

Multi-device sync uses CRDTs (Conflict-free Replicated Data Types):
- **File operations:** LWW-Register (last-writer-wins by timestamp)
- **Directory structure:** OR-Set (observed-remove set)
- **Conflict resolution:** Automatic via CRDT semantics; no user intervention

Current implementation note: `aegis-vault` now includes an encrypted per-file store and a `SyncSnapshot` merge primitive, while a full networked CRDT sync engine remains planned.

---

## 12. Social Fabric (Layer 7)

### 12.0 Default Social Runtime

The intended Layer 7 runtime is a user's **private node**, not a platform-owned server.
Their vault, profile, room HTML/JSON, inventory, and messaging state live there by
default. Shared rooms are additive, opt-in spaces layered on top of that baseline.

### 12.1 PQ Double Ratchet

Adapts the Signal Double Ratchet for post-quantum security:
- DH ratchet step uses ML-KEM-768 instead of X25519
- Symmetric ratchet uses HKDF-SHA3-256
- Message keys use ChaCha20-Poly1305 AEAD

Properties:
- Forward secrecy per message
- Post-compromise security (self-healing after key compromise)
- Quantum resistance via ML-KEM

### 12.2 Group Messaging (MLS-inspired)

Tree-based group key agreement:
- Binary tree with ML-KEM at each node
- O(log n) cost for member add/remove
- Epoch-based key rotation
- Forward secrecy between epochs

### 12.3 Federation (ActivityPub)

ActivityPub extensions for Aegis:
- Standard ActivityPub for public posts
- `aegis:EncryptedMessage` type for PQ-encrypted DMs
- WebFinger discovery for `did:aegis` identities
- ML-DSA-65 HTTP Signatures for server-to-server auth

---

## 13. Platform Matrix

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

## 14. Threat Model Summary

### 14.1 Adversary Capabilities

| Adversary Class           | Capabilities                         | Mitigations                              |
|---------------------------|--------------------------------------|------------------------------------------|
| Passive Network Observer  | Traffic capture, timing analysis     | PQ-WG encryption, traffic shaping        |
| Active Network Attacker   | Injection, modification, replay      | AEAD auth, transcript binding, counters  |
| Harvest-Now-Decrypt-Later | Store ciphertext for quantum attack  | ML-KEM-768 hybrid KEM                    |
| Compromised Endpoint      | Memory access on one peer            | Zeroizing keys, ephemeral secrets        |
| Malicious Shared Node     | Modified optional node software      | Client-side verification, open source    |
| Malicious Discovery Node  | Fake or stale peer hints             | DID verification, signed records, retry  |
| Supply Chain Attack       | Compromised dependencies             | `cargo-audit`, reproducible builds       |

### 14.2 Trust Boundaries

1. **TUN ↔ Pipeline** — Untrusted input; all packets validated before processing.
2. **Private Node ↔ Remote Private/Shared Node** — Intended to be mutually authenticated via PQ transport + identity checks.
3. **Discovery/Bootstrap ↔ Client** — Hints are untrusted until verified against identity material.
4. **Key Material ↔ Memory** — Zeroized on drop; never logged.
5. **Vault ↔ Filesystem** — Encrypted at rest; plaintext only in FUSE buffer.

---

## 15. CI/CD Pipeline

### 15.1 Current Pipeline (`.github/workflows/ci.yml`)

| Job        | What It Does                           | Runs On        |
|------------|----------------------------------------|----------------|
| `fmt`      | `cargo fmt --all --check`              | ubuntu-latest  |
| `clippy`   | `cargo clippy -- -D warnings`          | ubuntu-latest  |
| `check`    | `cargo check --workspace --all-targets`| ubuntu-latest  |
| `test`     | `cargo test --workspace`               | ubuntu + macOS |
| `audit`    | `cargo-audit` vulnerability scan       | ubuntu-latest  |

### 15.2 Planned Additions

| Job           | What It Does                                  | Priority |
|---------------|-----------------------------------------------|----------|
| `miri`        | Undefined behavior detection on `aegis-crypto`| Medium   |
| `fuzz`        | `cargo-fuzz` on hybrid KEM (30 min)           | Medium   |
| `bench`       | Criterion benchmarks, regression detection    | Low      |
| `coverage`    | `cargo-tarpaulin` or `llvm-cov`               | Low      |
| `release`     | Cross-compile + sign release artifacts        | Phase 2  |

---

## 16. Technology Decisions

### 16.1 Why Rust?

- Memory safety without GC (critical for crypto code)
- Zero-cost abstractions for performance-sensitive packet pipeline
- `#[cfg]` for platform-specific code without runtime dispatch
- `zeroize` crate for deterministic secret wiping
- Strong async ecosystem (tokio) for network I/O

### 16.2 Why Hybrid KEM (X25519 + ML-KEM-768)?

- **Defense in depth:** If ML-KEM is broken, X25519 still protects.
- **If X25519 is broken by quantum computers**, ML-KEM-768 still protects.
- **Transcript binding** prevents one component's ciphertext from being
  replayed in a different protocol context.
- NIST Level 3 security (ML-KEM-768) matches our threat model.

### 16.3 Why ChaCha20-Poly1305 over AES-GCM?

- Constant-time in software (no AES-NI required)
- Better performance on ARM devices without hardware AES
- Widely deployed and audited (used by WireGuard, TLS 1.3)
- Avoids AES-GCM nonce-misuse catastrophe (though both require unique nonces)

### 16.4 Why ML-DSA-65 (Dilithium3)?

- NIST FIPS 204 standard (2024)
- NIST Level 3 security (consistent with ML-KEM-768)
- Reasonable signature size (~3.3 KB) for handshake messages
- `pqcrypto-mldsa` crate (actively maintained, replaces deprecated `pqcrypto-dilithium`)

### 16.5 Why tun2 over other TUN libraries?

- Actively maintained fork of the original `tun` crate
- Async support via tokio (feature flag)
- Cross-platform: Linux, macOS, Windows
- v4 API: always delivers raw IP packets (no PI header confusion)

### 16.6 Dependency Selection Criteria

1. **Actively maintained** — recent commits, responsive to issues
2. **Audited where possible** — especially for crypto dependencies
3. **Minimal transitive dependencies** — reduce supply chain risk
4. **No unsafe where avoidable** — prefer safe Rust abstractions
5. **`cargo-audit` clean** — no known vulnerabilities
