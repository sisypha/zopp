---
sidebar_position: 2
title: Security Architecture
description: How zopp's zero-knowledge encryption works.
---

# Security Architecture

This page explains how zopp achieves zero-knowledge encryption.

## Key Hierarchy

```
User
 └── Principal (device)
      ├── Ed25519 keypair (signing/authentication)
      └── X25519 keypair (encryption)
           └── Workspace
                └── KEK (Key Encryption Key, wrapped per-principal)
                     └── Environment
                          └── DEK (Data Encryption Key, wrapped with KEK)
                               └── Secrets (encrypted with DEK)
```

## Principal Keys

Each principal (device/credential) has two keypairs:

| Key Type | Purpose | Usage |
|----------|---------|-------|
| Ed25519 | Signing | Authenticate requests to server |
| X25519 | Encryption | ECDH for key wrapping |

Keys are generated client-side and the private keys never leave the device.

## Workspace KEK

The Key Encryption Key (KEK) protects all data within a workspace:

1. Generated when workspace is created (32 random bytes)
2. Wrapped separately for each principal with access
3. Wrapping uses X25519 ECDH + XChaCha20-Poly1305

### KEK Wrapping

```
1. Generate ephemeral X25519 keypair
2. Perform ECDH: shared_secret = ECDH(ephemeral_private, principal_public)
3. Derive key: wrap_key = HKDF(shared_secret, "zopp-kek-wrap")
4. Generate nonce: nonce = random(24 bytes)
5. Encrypt: wrapped_kek = XChaCha20-Poly1305(wrap_key, nonce, kek)
6. Store: (ephemeral_public, wrapped_kek, nonce)
```

The server stores only the wrapped form. Unwrapping requires the principal's private key.

## Environment DEK

The Data Encryption Key (DEK) encrypts secrets within an environment:

1. Generated when environment is created (32 random bytes)
2. Wrapped with the workspace KEK
3. Stored on server in wrapped form

## Secret Encryption

Secrets are encrypted with XChaCha20-Poly1305 AEAD:

```
plaintext = secret_value
key = environment_dek
nonce = random_24_bytes
aad = workspace_id || project_id || environment_id || secret_key
ciphertext = XChaCha20-Poly1305.encrypt(key, nonce, plaintext, aad)
```

The AAD (Additional Authenticated Data) cryptographically binds the secret to its location.

## Invite Flow

Workspace invites securely transfer the KEK to new members:

1. **Creator**: Generates random 32-byte invite secret
2. **Creator**: Wraps KEK with invite secret
3. **Creator**: Sends `hash(invite_secret)` to server
4. **Invitee**: Receives full invite code (includes encrypted KEK)
5. **Invitee**: Unwraps KEK with invite secret
6. **Invitee**: Re-wraps KEK for their own principal
7. **Server**: Verifies hash, stores new wrapped KEK

The server only sees the hash—never the invite secret or plaintext KEK.

## Request Authentication

All API requests are authenticated with Ed25519 signatures:

```
timestamp = current_unix_timestamp
message = timestamp || request_body
signature = Ed25519.sign(principal_private_key, message)
```

The signature and timestamp are sent as gRPC metadata. The server verifies:

1. Signature is valid
2. Timestamp is within acceptable window (prevents replay)

## Data at Rest

What the server stores:

| Data | Format | Can Server Decrypt? |
|------|--------|---------------------|
| Secrets | Ciphertext + nonce | No |
| DEKs | Wrapped with KEK | No |
| KEKs | Wrapped per-principal | No |
| Public keys | Plaintext | N/A (public) |
| Invite hashes | SHA256 | No (hash only) |

## Next Steps

- [Cryptography](/security/cryptography) - Primitive details
- [Core Concepts](/guides/core-concepts) - Key hierarchy overview
