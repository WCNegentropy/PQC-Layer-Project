# Project Aegis — PQC Layer

A **post-quantum cryptographic platform** providing individuals with quantum-resistant
control over their data, identity, and communications.

## Highlights

- 🔐 **Hybrid KEM:** X25519 + ML-KEM-768 (NIST Level 3) — secure against both classical and quantum attacks
- 🛡️ **AEAD:** ChaCha20-Poly1305 authenticated encryption for tunnel transport
- ✍️ **Signatures:** ML-DSA-65 (FIPS 204) post-quantum digital signatures
- 🌐 **Gateway:** PQ-WG tunnel client with TUN, handshake, transport encryption, anti-replay, rekeying
- 🏠 **Private-node-first direction:** intended social topology gives every user their own node by default; shared Sanctuary nodes are opt-in
- 🏰 **Sanctuary:** current PQ-WG server primitive for self-hosted private/shared nodes, NAT experiments, and future optional shared infrastructure
- 🔑 **CLI:** `aegis up/down/status/keygen` commands
- 🧪 **90+ tests**, 3 fuzz targets, CI pipeline with fmt/clippy/test/audit

## Quick Start

```bash
cd aegis
cargo test --workspace             # Run all 90+ tests
cargo run -p aegis-cli -- status   # Show crypto status
cargo run -p aegis-cli -- keygen   # Generate hybrid keypair

# Start the Sanctuary server
cargo run -p aegis-sanctuary -- --config sanctuary.toml
```

## Architecture Direction

Aegis is moving toward a **private-node-by-default** model for its social layer:

- Every user is intended to run their own private Aegis node and serve their own vault-backed social space.
- Direct private-node-to-private-node connections are the default social path.
- Shared Sanctuary/community nodes are **opt-in**, not required for the core product.
- The currently implemented gateway/Sanctuary transport is a foundation for that direction, not proof that the private-node social runtime already exists.

## Architecture

```
Layer 7: Social Fabric     — Private nodes by default, opt-in shared nodes, PQ messaging, ActivityPub
Layer 5: Data Vault         — Encrypted FS (FUSE), per-file AEAD, CRDT sync
Layer 4: Identity Anchor    — DIDs, VCs, key hierarchy
Layer 3: Quantum Gateway    — PQ-WG tunnel, DNS, traffic shaping     ✅
         Sanctuary Server   — PQ-WG server primitive for optional/shared nodes ✅
Layer 2: Crypto Engine      — Hybrid KEM, AEAD, ML-DSA, KDF          ✅
Layer 1: Platform Abstract  — TUN, keyring, entropy, FUSE traits     ✅
```

## Documentation

See [`aegis/docs/`](aegis/docs/) for full documentation:

- [Architecture Specification](aegis/docs/architecture.md) — 15-section system design
- [Cryptography](aegis/docs/cryptography.md) — Algorithm suite, hybrid KEM, transport key derivation
- [Threat Model](aegis/docs/threat-model.md) — Adversary capabilities and mitigations
- [Wire Protocol](aegis/docs/protocol-spec.md) — PQ-WireGuard handshake and transport format
- [Social Platform Spec](aegis-social-platform-spec-v2.md) — intended private-node social architecture and product direction

## License

MIT OR Apache-2.0
