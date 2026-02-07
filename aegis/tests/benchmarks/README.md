# Benchmarks

This directory will contain performance benchmarks for the Aegis platform
using Criterion.rs.

## Planned Benchmarks

| Benchmark | What It Measures |
|-----------|------------------|
| `kem_keygen` | Hybrid X25519 + ML-KEM-768 keypair generation |
| `kem_encapsulate` | Encapsulation latency |
| `kem_decapsulate` | Decapsulation latency |
| `aead_encrypt_1kb` | ChaCha20-Poly1305 encrypt 1KB |
| `aead_encrypt_64kb` | ChaCha20-Poly1305 encrypt 64KB (typical packet) |
| `sign_message` | ML-DSA-65 signing |
| `verify_signature` | ML-DSA-65 verification |
| `packet_parse` | IP header parsing throughput |

## Running Benchmarks

```bash
cargo bench
```
