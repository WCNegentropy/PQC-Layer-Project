# Project Aegis — PQC Layer

A **post-quantum cryptographic platform** providing individuals with quantum-resistant
control over their data, identity, and communications.

## Highlights

- 🔐 **Hybrid KEM:** X25519 + ML-KEM-768 (NIST Level 3) — secure against both classical and quantum attacks
- 🛡️ **AEAD:** ChaCha20-Poly1305 authenticated encryption for tunnel transport
- ✍️ **Signatures:** ML-DSA-65 (FIPS 204) post-quantum digital signatures
- 🌐 **Gateway:** Async TUN-based packet pipeline with safe IP parsing
- 🔑 **CLI:** `aegis up/down/status/keygen` commands
- 🧪 **50 tests**, 3 fuzz targets, CI pipeline with fmt/clippy/test/audit/miri

## Quick Start

```bash
cd aegis
cargo test --workspace      # Run all 50 tests
cargo run -p aegis-cli -- status   # Show crypto status
cargo run -p aegis-cli -- keygen   # Generate hybrid keypair
```

## Architecture

```
Layer 7: Social Fabric     — PQ Double Ratchet, MLS groups, ActivityPub
Layer 5: Data Vault         — Encrypted FS (FUSE), per-file AEAD, CRDT sync
Layer 4: Identity Anchor    — DIDs, VCs, key hierarchy
Layer 3: Quantum Gateway    — PQ-WG tunnel, DNS, traffic shaping     ✅
Layer 2: Crypto Engine      — Hybrid KEM, AEAD, ML-DSA, KDF          ✅
Layer 1: Platform Abstract  — TUN, keyring, entropy, FUSE traits     ✅
```

## Documentation

See [`aegis/docs/`](aegis/docs/) for full documentation:

- [Architecture Specification](aegis/docs/architecture.md) — 15-section system design
- [Cryptography](aegis/docs/cryptography.md) — Algorithm suite and hybrid KEM
- [Threat Model](aegis/docs/threat-model.md) — Adversary capabilities and mitigations
- [Wire Protocol](aegis/docs/protocol-spec.md) — PQ-WireGuard transport format

## License

MIT OR Apache-2.0
