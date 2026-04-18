# Aegis Documentation

Welcome to the Aegis platform documentation.

## Project Overview

Aegis is a **layered, modular platform** providing individuals with quantum-resistant
control over their data, identity, and communications. It uses hybrid post-quantum
cryptography (X25519 + ML-KEM-768) to defend against both classical and quantum adversaries.

The intended social architecture is now **private-node first**: each user will
run their own private node by default, direct node-to-node connections are the
core path, and shared Sanctuary nodes are optional spaces users may host or join.
Current transport/server crates are implemented foundations for that direction,
not evidence that the full private-node social runtime already exists.

## Documentation Index

| Document | Description |
|----------|-------------|
| [Architecture](architecture.md) | Full system architecture, wire protocol, deployment model |
| [Cryptography](cryptography.md) | Algorithm suite, hybrid KEM construction, transport key derivation |
| [Threat Model](threat-model.md) | Adversary capabilities, trust boundaries, mitigations |
| [Protocol Spec](protocol-spec.md) | PQ-WireGuard wire protocol, handshake, transport format |
| [Social Platform Spec](../../aegis-social-platform-spec-v2.md) | Intended private-node social product and node model |

## Architecture

The project is organized as a 7-layer Rust workspace:

### Core Crates (Layers)
| Crate | Layer | Description | Status |
|-------|-------|-------------|--------|
| `aegis-platform` | L1 | TUN/Keyring/Entropy/FS traits | Trait definitions |
| `aegis-crypto` | L2 | Hybrid KEM, AEAD, ML-DSA-65 signatures | ✅ Implemented |
| `aegis-gateway` | L3 | PQ-WG tunnel client: TUN, handshake, transport, anti-replay, rekeying | ✅ Implemented |
| `aegis-identity` | L4 | DIDs, key hierarchy, VCs, discovery/auth | ✅ Foundation implemented |
| `aegis-vault` | L5 | Encrypted storage, FUSE, CRDT sync | ✅ Foundation implemented |
| `aegis-social` | L7 | Private-node social runtime, optional shared nodes, federation | Module stubs |
| `aegis-sanctuary` | — | Current PQ-WG responder/server for optional/private/shared node roles | ✅ Implemented |

### Applications
| App | Description | Status |
|-----|-------------|--------|
| `aegis-cli` | CLI: `aegis up/down/status/keygen`, `identity new/show`, `vault init` | ✅ Functional |
| `aegis-desktop` | Tauri 2.0 desktop app | Placeholder |
| `aegis-web` | Axum web server | Placeholder |

## Getting Started

```bash
# Build all crates
cd aegis
cargo build

# Run tests (90+ tests across the workspace)
cargo test --workspace

# Use the CLI
cargo run -p aegis-cli -- status
cargo run -p aegis-cli -- keygen
cargo run -p aegis-cli -- identity new --identity-dir .aegis/identity
cargo run -p aegis-cli -- vault init --vault-dir vault --identity-dir .aegis/identity

# Run the gateway (requires root and Sanctuary server)
sudo cargo run -p aegis-gateway -- \
    --sanctuary-addr 127.0.0.1:51820 \
    --sanctuary-pk-file sanctuary.pub \
    --keypair-file client.key

# Run the Sanctuary server
cargo run -p aegis-sanctuary -- --config sanctuary.toml
```

## Development

```bash
# Format check
cargo fmt --all --check

# Lint
cargo clippy --all-targets -- -D warnings

# Run fuzz tests (requires nightly)
cd crates/aegis-crypto
cargo +nightly fuzz run fuzz_kem_deser -- -max_total_time=60
```

For development guidelines and contribution instructions, see the main repository README.
