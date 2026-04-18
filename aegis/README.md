# Aegis - PQC Layer Project

A comprehensive Post-Quantum Cryptography (PQC) platform for secure data ownership, sovereignty, and security.

## Architecture Direction

The intended long-term topology is **private-node first**:

- every user gets their own private Aegis node by default,
- direct node-to-node connections are the primary social path,
- shared Sanctuary nodes are optional community/platform spaces rather than mandatory hops,
- the current implemented gateway and Sanctuary crates are transport primitives that future private/shared node runtimes will build on.

## Project Structure

```
aegis/
├── Cargo.toml              # Workspace root configuration
├── crates/                 # Core library crates
│   ├── aegis-crypto/       # Cryptographic primitives and PQC implementations
│   ├── aegis-gateway/      # PQ-WG tunnel client: TUN, handshake, transport, anti-replay, rekeying
│   ├── aegis-platform/     # OS abstraction: TUN, keyring, entropy, FS traits
│   ├── aegis-identity/     # Identity, DIDs, discovery records, and authentication
│   ├── aegis-vault/        # Secure data storage and retrieval
│   ├── aegis-social/       # Planned private-node social runtime and optional shared rooms
│   └── aegis-sanctuary/    # Current PQ-WG server primitive for self-hosted private/shared nodes
├── apps/                   # Application binaries
│   ├── aegis-desktop/      # Desktop client application
│   ├── aegis-cli/          # Command-line interface
│   └── aegis-web/          # Web-based interface
├── tests/                  # Test suites
│   ├── integration/        # Integration tests
│   ├── fuzz/               # Fuzz testing
│   └── benchmarks/         # Performance benchmarks
└── docs/                   # Documentation
```

## Getting Started

### Prerequisites

- Rust 1.70+ (edition 2021)
- Cargo
- Root/admin privileges (for gateway TUN device)

### Building

Build all crates in the workspace:

```bash
cargo build
```

Build in release mode with optimizations:

```bash
cargo build --release
```

### Testing

Run all tests:

```bash
cargo test
```

Run tests for a specific crate:

```bash
cargo test -p aegis-crypto
```

### Running Applications

Run the Sanctuary server (current PQ-WG server primitive):

```bash
cargo run -p aegis-sanctuary -- --config sanctuary.toml
```

Run the gateway (PQ-WG tunnel client — requires root and a running Sanctuary-compatible responder):

```bash
sudo cargo run -p aegis-gateway -- \
    --sanctuary-addr 127.0.0.1:51820 \
    --sanctuary-pk-file sanctuary.pub \
    --keypair-file client.key
```

Run the CLI tool:

```bash
cargo run -p aegis-cli -- status
cargo run -p aegis-cli -- keygen
cargo run -p aegis-cli -- identity new --identity-dir .aegis/identity
cargo run -p aegis-cli -- vault init --vault-dir vault --identity-dir .aegis/identity
cargo run -p aegis-cli -- up --server 127.0.0.1:51820 --interface aegis0
cargo run -p aegis-cli -- down --interface aegis0
```

### Docker Deployment (Sanctuary)

```bash
docker build -t aegis-sanctuary -f Dockerfile.sanctuary .
docker compose -f docker-compose.sanctuary.yml up -d
```

## Core Crates

### aegis-crypto

Provides cryptographic primitives and post-quantum cryptography implementations. This is the foundation for all security operations in the platform.

### aegis-gateway

PQ-WireGuard tunnel client: async TUN-based packet pipeline with hybrid KEM
handshake, ChaCha20-Poly1305 transport encryption, RFC 6479 anti-replay,
session rekeying, and keypair persistence.

### aegis-sanctuary

Current PQ-WireGuard responder/server: UDP listener with responder handshake,
multi-client session management, NAT proxy for IP forwarding, peer authorization
via public-key allowlist, TOML configuration, and Docker deployment. In the
intended architecture it becomes a reusable building block for private and
shared self-hosted nodes, not a mandatory central platform hop.

### aegis-platform

OS abstraction layer: TUN device, keyring, entropy, and filesystem trait definitions.

### aegis-identity

Identity and authentication management system with support for decentralized
identity, DID-based peer discovery, verifiable credentials, and signed
challenge/response authentication. Current foundations include local
`did:aegis` document generation, service records, root→device identity issuance,
and ML-DSA-65-signed credentials.

### aegis-vault

Secure data storage and retrieval with per-file AEAD encryption, logical-path
key derivation, and bootstrap creation of the private-node social vault layout.

### aegis-social

Planned social layer for private-node spaces, direct visits, optional shared
nodes, messaging, and federation.

## Development

### Workspace Configuration

This project uses Cargo workspaces. All crates share common metadata defined in the workspace root `Cargo.toml`:

- Version: 0.1.0
- Edition: 2021
- License: MIT OR Apache-2.0

### Adding Dependencies

To add a dependency to a specific crate, edit that crate's `Cargo.toml` file.

For workspace-wide dependencies, add them to the `[workspace.dependencies]` section in the root `Cargo.toml`.

### Code Organization

- Each crate in `crates/` is a library crate (except `aegis-gateway` and `aegis-sanctuary` which are also binaries)
- Each crate in `apps/` is a binary application
- Follow Rust naming conventions and API guidelines

## Testing

### Integration Tests

Located in `tests/integration/`, these tests verify cross-crate functionality:

```bash
cargo test --test integration
```

### Fuzz Tests

Located in `tests/fuzz/`, these tests use fuzzing to find edge cases:

```bash
cargo fuzz run <target>
```

### Benchmarks

Located in `tests/benchmarks/`, these benchmarks measure performance:

```bash
cargo bench
```

## Documentation

For detailed documentation, see the `docs/` directory or generate Rust documentation:

```bash
cargo doc --open
```

## Contributing

When contributing to this project:

1. Follow the Rust style guidelines
2. Add tests for new functionality
3. Update documentation as needed
4. Ensure all tests pass before submitting

## License

This project is licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.
