# Fuzz Tests

Fuzz targets live in the `aegis-crypto` crate at:

```
crates/aegis-crypto/fuzz/fuzz_targets/
├── fuzz_kem_deser.rs      # HybridPublicKey/HybridCiphertext::from_bytes
├── fuzz_aead_decrypt.rs   # ChaCha20-Poly1305 decrypt with arbitrary input
└── fuzz_sig_verify.rs     # ML-DSA-65 signature verification with arbitrary input
```

## Running Fuzz Tests

Requires nightly Rust and `cargo-fuzz`:

```bash
cargo install cargo-fuzz
cd crates/aegis-crypto
cargo +nightly fuzz run fuzz_kem_deser    -- -max_total_time=60
cargo +nightly fuzz run fuzz_aead_decrypt -- -max_total_time=60
cargo +nightly fuzz run fuzz_sig_verify   -- -max_total_time=60
```

## What They Test

All fuzz targets verify that arbitrary byte inputs never cause panics or
undefined behavior. The expected results are either `Ok(valid_output)` or
`Err(CryptoError)` — never a crash.
