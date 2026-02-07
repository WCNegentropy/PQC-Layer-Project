# Aegis - PQC Layer Project

A comprehensive Post-Quantum Cryptography (PQC) platform for secure data ownership, sovereignty, and security.

## Project Structure

```
aegis/
├── Cargo.toml              # Workspace root configuration
├── crates/                 # Core library crates
│   ├── aegis-crypto/       # Cryptographic primitives and PQC implementations
│   ├── aegis-gateway/      # Gateway service for routing and access control
│   ├── aegis-platform/     # Core platform functionality
│   ├── aegis-identity/     # Identity and authentication management
│   ├── aegis-vault/        # Secure data storage and retrieval
│   ├── aegis-social/       # Social networking features
│   └── aegis-sanctuary/    # Secure communication and collaboration
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

Run the gateway service:

```bash
cargo run -p aegis-gateway
```

Run the CLI tool:

```bash
cargo run -p aegis-cli
```

Run the desktop application:

```bash
cargo run -p aegis-desktop
```

Run the web server:

```bash
cargo run -p aegis-web
```

## Core Crates

### aegis-crypto

Provides cryptographic primitives and post-quantum cryptography implementations. This is the foundation for all security operations in the platform.

### aegis-gateway

Gateway service that handles routing, access control, and API management for the platform.

### aegis-platform

Core platform functionality, including shared utilities and common interfaces.

### aegis-identity

Identity and authentication management system with support for decentralized identity.

### aegis-vault

Secure data storage and retrieval with end-to-end encryption.

### aegis-social

Social networking features with privacy-preserving protocols.

### aegis-sanctuary

Secure communication and collaboration tools with PQC encryption.

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

- Each crate in `crates/` is a library crate (except `aegis-gateway` which is a binary)
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
