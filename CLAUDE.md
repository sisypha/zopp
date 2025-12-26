# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**zopp** is an open-source, self-hostable, CLI-first secrets manager with zero-knowledge encryption. It's being built as part of the sisypha organization, which develops open-source alternatives to commercial SaaS products.

Key principles:
- **Zero-knowledge**: Server never sees plaintext keys or secrets
- **Client-side encryption**: All crypto operations happen in the CLI
- **Multi-user workspaces**: Teams share workspace KEKs (wrapped per-principal)
- **Local-first**: Works fully offline; no vendor lock-in

## Development Commands

### Build
```bash
cargo build --workspace --release
```

### Testing
```bash
# All tests (runs unit + integration)
cargo test --workspace --all-features

# Single test
cargo test --package zopp-crypto test_name

# E2E test (requires binaries built first)
cargo build --bins
cargo run --bin zopp-e2e-test
```

### Linting & Formatting
```bash
cargo fmt --all
cargo clippy --workspace --all-targets --all-features
```

### Pre-PR Checklist
Before opening a PR, run this sequence:
```bash
cargo fmt --all
cargo clippy --workspace --all-targets --all-features
cargo test --workspace --all-features
cargo build --bins && cargo run --bin zopp-e2e-test
```

### Running Server & CLI
```bash
# Terminal 1: Start server (default port 50051)
cargo run --bin zopp-server serve

# Terminal 2: Use CLI
cargo run --bin zopp -- <command>

# Production build
cargo build --release
./target/release/zopp-server serve
./target/release/zopp --help
```

### SQLite-Specific: sqlx Offline Mode
This project uses SQLite with `sqlx` compile-time verification. The `.sqlx/` directory contains prepared query metadata.

**When you modify SQL queries**, regenerate the metadata:
```bash
# Set environment variables for SQLite
export SQLX_OFFLINE=false
export DATABASE_URL=sqlite::memory:

# Run migrations (if needed)
DATABASE_URL=sqlite:///tmp/zopp-prepare.db sqlx migrate run --source crates/zopp-store-sqlite/migrations

# Prepare metadata
DATABASE_URL=sqlite:///tmp/zopp-prepare.db cargo sqlx prepare --package zopp-store-sqlite

# Or combine:
SQLX_OFFLINE=false DATABASE_URL=sqlite::memory: cargo sqlx prepare --package zopp-store-sqlite
```

**DO NOT** commit code that breaks offline builds. If you see `sqlx` errors, regenerate the metadata.

## Architecture

### Workspace Structure
```
apps/
  e2e-test/        - End-to-end integration test
  zopp-cli/        - Main CLI binary
  zopp-server/     - gRPC server binary

crates/
  zopp-crypto/     - Cryptographic primitives (Argon2id, XChaCha20-Poly1305, X25519 ECDH)
  zopp-proto/      - gRPC service definitions (protobuf)
  zopp-storage/    - Storage trait (backend-agnostic)
  zopp-store-sqlite/ - SQLite storage implementation
```

### Crypto Architecture

**Key Hierarchy:**
```
User
 └── Principal (device/credential)
      ├── Ed25519 keypair (authentication/signatures)
      └── X25519 keypair (encryption via ECDH)
           └── Workspace
                └── KEK (32-byte, wrapped per-principal via ECDH)
                     └── Environment
                          └── DEK (32-byte, wrapped with KEK)
                               └── Secret (encrypted with DEK using AEAD)
```

**Critical crypto details:**
- **KEK wrapping**: Server stores `(ephemeral_pub, kek_wrapped, kek_nonce)`. Client performs ECDH with principal's X25519 private key to derive shared secret, then unwraps KEK.
- **DEK wrapping**: Client unwraps KEK, then unwraps DEK using KEK as AEAD key.
- **Secret encryption**: Uses XChaCha20-Poly1305 AEAD with context AAD (workspace/project/env/key name).
- **Invite flow**: Workspace invites encrypt KEK with random 32-byte secret. Server stores SHA256(secret) for lookup. Invitee uses secret to decrypt KEK, then re-wraps for their own principal.

**All encryption happens client-side.** The server is a blind storage layer.

### Storage Layer

`zopp-storage` defines traits (`Store`, `StoreError`, typed IDs). `zopp-store-sqlite` implements these traits using SQLx with compile-time query verification.

Important types:
- `UserId`, `PrincipalId`, `WorkspaceId`, `ProjectId`, `EnvironmentId` (strongly-typed UUIDs)
- `SecretRow { nonce, ciphertext }` - secrets stored as encrypted blobs

### gRPC Service

Defined in `crates/zopp-proto/proto/zopp.proto`. Key RPCs:
- Authentication: `Register`, `Join`
- Workspaces: `CreateWorkspace`, `ListWorkspaces`
- Secrets: `GetSecret`, `UpsertSecret`, `ListSecrets`
- Invites: `CreateInvite`, `GetInvite`, `ConsumeInvite`

All requests require Ed25519 signature authentication via gRPC metadata.

### CLI Commands

The CLI uses `clap` with subcommands:
- `zopp join <token> <email>` - Bootstrap first user or accept workspace invite
- `zopp workspace create <name>` - Create new workspace (generates KEK)
- `zopp environment create <name> --workspace <ws> --project <proj>` - Create environment (generates DEK)
- `zopp secret set <key> <value> -w <ws> -p <proj> -e <env>` - Encrypt & store secret
- `zopp secret get <key> -w <ws> -p <proj> -e <env>` - Fetch & decrypt secret
- `zopp secret export -w <ws> -p <proj> -e <env> -o <file>` - Export secrets to `.env` format
- `zopp secret import -w <ws> -p <proj> -e <env> -i <file>` - Import secrets from `.env` format
- `zopp invite create --workspace <ws> --expires-hours <n>` - Create workspace invite

Config stored in `~/.zopp/config.json` with principal credentials.

## Testing Strategy

1. **Unit tests**: In each crate (e.g., `zopp-crypto`, `zopp-storage`)
2. **E2E test**: `apps/e2e-test` simulates the full DEMO.md flow:
   - Server invite → Alice registers → creates workspace
   - Workspace invite → Bob joins
   - Both users read/write secrets (validates zero-knowledge)
   - Export/import `.env` files
3. **Manual validation**: Follow DEMO.md for exploratory testing

**When adding features:** Follow TDD. Write E2E test steps first, then implement CLI commands, then update DEMO.md to match.

## Important Notes

- **No co-authored commits**: Do NOT add "Co-Authored-By: Claude" trailers to commits
- **DEMO.md alignment**: Keep DEMO.md steps 1:1 with E2E test steps
- **Security**: Never log or expose plaintext keys/secrets in server code
- **Zeroizing types**: Use `zeroize::Zeroize` and `zeroize::ZeroizeOnDrop` for sensitive data (see `zopp-crypto/src/lib.rs`)
