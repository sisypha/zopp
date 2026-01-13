---
sidebar_position: 3
title: Cryptographic Primitives
description: Cryptographic algorithms used by zopp.
---

# Cryptographic Primitives

This page details the cryptographic algorithms used by zopp.

## Algorithms

| Purpose | Algorithm | Library |
|---------|-----------|---------|
| Symmetric encryption | XChaCha20-Poly1305 | `chacha20poly1305` |
| Key agreement | X25519 ECDH | `x25519-dalek` |
| Signing | Ed25519 | `ed25519-dalek` |
| Key derivation | HKDF-SHA256 | `hkdf` |
| Password hashing | Argon2id | `argon2` |
| Random | CSPRNG | `rand` (OS entropy) |

## XChaCha20-Poly1305

Used for encrypting secrets and wrapping keys.

**Properties:**
- 256-bit key
- 192-bit nonce (extended nonce allows random generation)
- AEAD (authenticated encryption with associated data)
- Constant-time implementation

**Why XChaCha20 over AES-GCM:**
- Larger nonce prevents collisions with random generation
- No hardware timing side channels
- Simpler to implement correctly

## X25519 ECDH

Used for key agreement when wrapping KEKs.

**Properties:**
- Curve25519 elliptic curve
- 256-bit keys
- Constant-time implementation

**Key wrapping process:**
```
shared_secret = X25519(my_private, their_public)
wrap_key = HKDF-SHA256(shared_secret, info="zopp-kek-wrap", length=32)
wrapped = XChaCha20-Poly1305(wrap_key, kek)
```

## Ed25519

Used for request signing and authentication.

**Properties:**
- Edwards curve (Ed25519)
- 256-bit keys
- 512-bit signatures
- Deterministic signatures

**Usage:**
- Principals sign all API requests
- Server verifies signatures for authentication

## HKDF-SHA256

Used for deriving encryption keys from shared secrets.

**Parameters:**
- Hash: SHA-256
- Salt: None (using IKM directly)
- Info: Context-specific string
- Output: 32 bytes

## Argon2id

Used for password-derived keys (future feature).

**Parameters:**
- Memory: 64 MiB
- Iterations: 3
- Parallelism: 4
- Output: 32 bytes

## Random Number Generation

All randomness uses the operating system's CSPRNG:

- Linux: `getrandom()`
- macOS: `SecRandomCopyBytes()`
- Windows: `BCryptGenRandom()`

## Memory Safety

Sensitive data is handled carefully:

- Keys use `zeroize` crate for secure erasure
- `ZeroizeOnDrop` trait ensures cleanup
- No logging of sensitive values

## Implementation Notes

1. **No custom crypto**: All primitives from well-audited Rust crates
2. **No compression before encryption**: Prevents CRIME-style attacks
3. **Constant-time comparisons**: For signature verification
4. **Explicit key types**: Prevents key confusion attacks

## Audit Status

zopp has not yet undergone a formal security audit. The cryptographic design follows established best practices and uses standard, well-audited libraries.

## Next Steps

- [Architecture](/security/architecture) - How these primitives are used
- [Self-Hosting](/self-hosting) - Production deployment
