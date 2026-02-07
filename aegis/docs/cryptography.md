# Aegis Cryptography Specification

> **Status:** Stub — to be expanded as additional primitives are implemented.

## Overview

Project Aegis uses a layered cryptographic architecture designed to be secure
against both classical and quantum adversaries. All cryptographic operations
are implemented in the `aegis-crypto` crate (Layer 2).

## Algorithm Suite

| Primitive | Algorithm | Standard | Security Level | Status |
|---|---|---|---|---|
| Key Encapsulation | X25519 + ML-KEM-768 Hybrid | FIPS 203 (ML-KEM) | NIST Level 3 | ✅ Implemented |
| Authenticated Encryption | ChaCha20-Poly1305 | RFC 8439 | 256-bit | ✅ Implemented |
| Digital Signatures | ML-DSA-65 | FIPS 204 | NIST Level 3 | ✅ Implemented |
| Key Derivation | HKDF-SHA3-256 | RFC 5869 + FIPS 202 | 256-bit | ✅ Implemented |
| Hashing | SHA3-256 (transcript) | FIPS 202 | 256-bit | ✅ Used in KDF |
| Hashing | BLAKE3 | — | 256-bit | ❌ Planned |
| Password KDF | Argon2id | RFC 9106 | Configurable | ❌ Planned |

## Hybrid KEM Construction

The hybrid key encapsulation combines X25519 (classical ECDH) with ML-KEM-768
(post-quantum lattice-based KEM) using a dual-PRF combiner:

```text
SharedSecret = HKDF-SHA3-256(
    ikm  = X25519_SharedSecret || ML-KEM-768_SharedSecret,
    salt = SHA3-256(b"aegis-hybrid-kem-v1-transcript" || recipient_pk || ephemeral_pk || ml_kem_ct),
    info = b"aegis-hybrid-kem-v1"
)
```

### Security Property

If **either** X25519 **or** ML-KEM-768 remains secure, the derived shared secret
is computationally indistinguishable from random. This provides defense-in-depth
against both classical and quantum attacks.

### Key Zeroization

- X25519 `StaticSecret` is wrapped in `Zeroizing<StaticSecret>` for automatic memory scrubbing.
- ML-KEM secret key bytes are stored as `Zeroizing<Vec<u8>>` and reconstructed on demand.
- All intermediate key material (IKM concatenation) is `Zeroizing`.

## AEAD Construction

ChaCha20-Poly1305 (RFC 8439) is used for transport packet encryption:

- **Key:** 256-bit (32 bytes), derived from the hybrid KEM shared secret.
- **Nonce:** 96-bit (12 bytes), counter-based (must never reuse under the same key).
- **Tag:** 128-bit (16 bytes), appended to ciphertext.
- **AAD:** Protocol-specific associated data (e.g., packet headers).

## ML-DSA-65 Signatures

ML-DSA-65 (FIPS 204, formerly Dilithium3) is used for handshake authentication:

- **Security Level:** NIST Level 3 (equivalent to AES-192).
- **Signing key** is stored as `Zeroizing<Vec<u8>>`.
- Uses `pqcrypto-mldsa` crate (successor to deprecated `pqcrypto-dilithium`).

## Dependencies

| Crate | Version | Purpose |
|---|---|---|
| `x25519-dalek` | 2.0 | X25519 ECDH |
| `pqcrypto-kyber` | 0.8 | ML-KEM-768 |
| `pqcrypto-mldsa` | 0.1 | ML-DSA-65 signatures |
| `chacha20poly1305` | 0.10 | AEAD |
| `sha3` | 0.10 | SHA3-256 |
| `hkdf` | 0.12 | HKDF |
| `zeroize` | 1.7 | Memory scrubbing |
