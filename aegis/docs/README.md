# Aegis Documentation

Welcome to the Aegis platform documentation.

## Project Overview

Aegis is a Post-Quantum Cryptography (PQC) encrypted digital layer for user data ownership, sovereignty, and security.

## Architecture

The project is organized as a Rust workspace with the following components:

### Core Crates
- **aegis-crypto**: Cryptographic primitives and PQC implementations
- **aegis-gateway**: Gateway service for routing and access control
- **aegis-platform**: Core platform functionality
- **aegis-identity**: Identity and authentication management
- **aegis-vault**: Secure data storage and retrieval
- **aegis-social**: Social networking features
- **aegis-sanctuary**: Secure communication and collaboration

### Applications
- **aegis-desktop**: Desktop client application
- **aegis-cli**: Command-line interface
- **aegis-web**: Web-based interface

## Getting Started

```bash
# Build all crates
cargo build

# Run tests
cargo test

# Run a specific application
cargo run -p aegis-cli
```

## Development

For development guidelines and contribution instructions, see the main repository README.
