---
sidebar_position: 1
title: Security
description: Understand zopp's security model and zero-knowledge architecture.
---

# Security

zopp is built on a zero-knowledge architecture where the server never has access to your plaintext secrets.

## Sections

- [Architecture](/zopp/security/architecture) - Understand how zopp's zero-knowledge encryption works
- [Cryptography](/zopp/security/cryptography) - Deep dive into the cryptographic primitives used by zopp

## Zero-Knowledge Design

zopp's core security principle: **the server never sees plaintext**.

| Data | Client | Server |
|------|--------|--------|
| Secret values | Plaintext | Ciphertext only |
| Workspace KEK | Plaintext | Wrapped (encrypted) |
| Environment DEK | Plaintext | Wrapped (encrypted) |
| Private keys | Plaintext | Never sent |
| Invite secrets | Plaintext | Hash only |

## Security Properties

### Confidentiality

- All secrets are encrypted with XChaCha20-Poly1305 before leaving your machine
- Keys are wrapped using X25519 ECDH, so only intended recipients can decrypt
- The server cannot decrypt any stored data

### Integrity

- AEAD (Authenticated Encryption with Associated Data) detects tampering
- Ed25519 signatures authenticate all requests
- Workspace/project/environment names are bound to secret encryption

### Access Control

- RBAC with three levels: workspace, project, environment
- Three roles: read, write, admin
- Principals (devices) can be individually revoked
- All access is logged in the audit trail

### Key Management

- No master key or recovery key exists
- If a user loses their device keys, they lose access (by design)
- Workspace access is cryptographically enforced, not just policy

## Threat Model

### What zopp protects against

| Threat | Protection |
|--------|------------|
| Server compromise | Attacker gets only encrypted data |
| Database leak | Secrets remain encrypted |
| Network interception | TLS encryption + E2E encryption |
| Malicious insider (server) | Cannot decrypt without client keys |
| Unauthorized access | RBAC + cryptographic enforcement |

### What requires additional protection

| Threat | Mitigation |
|--------|------------|
| Client device compromise | Secure your device; use OS disk encryption |
| Phishing for credentials | User education; don't share `~/.zopp/config.json` |
| Supply chain attacks | Verify binary signatures; build from source |

## Security Best Practices

1. **Enable TLS** - Always use HTTPS in production
2. **Use strong passphrases** - For any password-derived keys
3. **Limit production access** - Use environment-level permissions
4. **Audit regularly** - Review `zopp audit list` output
5. **Rotate secrets** - Update compromised credentials promptly
6. **Backup safely** - Encrypted backups only

## Reporting Vulnerabilities

If you discover a security vulnerability, please email security@faisca.dev with:

1. Description of the vulnerability
2. Steps to reproduce
3. Potential impact

We'll respond within 48 hours and work with you on coordinated disclosure.

## Next Steps

- [Architecture](/zopp/security/architecture) - How zero-knowledge encryption works
- [Cryptography](/zopp/security/cryptography) - Cryptographic details
