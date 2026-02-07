# Integration Tests

This directory will contain cross-crate integration tests for the Aegis platform.

## Planned Tests

| Test | What It Proves | Status |
|------|----------------|--------|
| `crypto_kem_aead_roundtrip` | KEM → derive key → AEAD encrypt → decrypt | Planned |
| `crypto_sign_verify_message` | Sign → serialize → verify with deserialized PK | Planned |
| `gateway_packet_pipeline` | TUN read → parse → stats tracking | Requires root |
| `cli_commands` | `aegis status` / `aegis keygen` exit codes | Planned |

## Running Tests

```bash
cargo test --test integration
```
