# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**zopp** is an open-source, self-hostable, CLI-first secrets manager with zero-knowledge encryption.

Key principles:
- **Zero-knowledge**: Server never sees plaintext keys or secrets
- **Client-side encryption**: All crypto operations happen in the CLI
- **Multi-user workspaces**: Teams share workspace KEKs (wrapped per-principal)
- **Local-first**: Works fully offline; no vendor lock-in

## Development Commands

### Docker Images

```bash
# Build images
docker build -f server.Dockerfile -t zopp-server:latest .
docker build -f operator.Dockerfile -t zopp-operator:latest .
docker build -f cli.Dockerfile -t zopp-cli:latest .

# Run server
docker run -p 50051:50051 zopp-server:latest

# Run server with PostgreSQL
docker run -e DATABASE_URL=postgres://user:pass@host/db -p 50051:50051 zopp-server:latest

# Run server with TLS
docker run -v /path/to/certs:/certs -p 50051:50051 zopp-server:latest serve --tls-cert /certs/server.crt --tls-key /certs/server.key

# Use CLI via Docker (mount config directory)
docker run --rm -v ~/.zopp:/home/zopp/.zopp zopp-cli:latest workspace list

# Use CLI with custom server
docker run --rm -v ~/.zopp:/home/zopp/.zopp zopp-cli:latest --server https://zopp.example.com workspace list
```

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

#### SQLite (development/default)
```bash
# Terminal 1: Start server (default port 50051)
cargo run --bin zopp-server serve

# With explicit SQLite path
cargo run --bin zopp-server serve --db mydata.db

# Terminal 2: Use CLI
cargo run --bin zopp -- <command>
```

#### PostgreSQL (production)
```bash
# Start Postgres (Docker example)
docker run --name zopp-pg -e POSTGRES_PASSWORD=postgres -p 5432:5432 -d postgres:16

# Terminal 1: Start server with Postgres
DATABASE_URL=postgres://postgres:postgres@localhost/postgres cargo run --bin zopp-server serve

# Terminal 2: Use CLI (same as above)
cargo run --bin zopp -- <command>
```

#### Production Build
```bash
cargo build --release

# Run with SQLite (default)
./target/release/zopp-server serve

# Run with Postgres
DATABASE_URL=postgres://user:pass@host/db ./target/release/zopp-server serve

# Run with TLS (production)
./target/release/zopp-server serve \
  --tls-cert /path/to/server.crt \
  --tls-key /path/to/server.key

# Run with mTLS (mutual TLS)
./target/release/zopp-server serve \
  --tls-cert /path/to/server.crt \
  --tls-key /path/to/server.key \
  --tls-client-ca /path/to/ca.crt
```

**TLS Configuration:**
- `--tls-cert` and `--tls-key`: Enable server-side TLS
- `--tls-client-ca`: Enable mTLS for client certificate verification
- Client automatically uses TLS when connecting to `https://` URLs
- Environment variables: `ZOPP_TLS_CERT`, `ZOPP_TLS_KEY`, `ZOPP_TLS_CLIENT_CA`

### Database: sqlx Offline Mode
This project supports both **SQLite** (development/small deployments) and **PostgreSQL** (production). Both use `sqlx` compile-time verification with prepared query metadata in `.sqlx/`.

**When you modify SQL queries**, regenerate the metadata:

#### SQLite
```bash
export SQLX_OFFLINE=false
DATABASE_URL=sqlite:///tmp/zopp-prepare.db sqlx migrate run --source crates/zopp-store-sqlite/migrations
DATABASE_URL=sqlite:///tmp/zopp-prepare.db cargo sqlx prepare --package zopp-store-sqlite
```

#### PostgreSQL
```bash
export SQLX_OFFLINE=false
# Start a local Postgres instance (Docker recommended):
docker run --name zopp-postgres -e POSTGRES_PASSWORD=postgres -p 5432:5432 -d postgres:16

# Run migrations and prepare
DATABASE_URL=postgres://postgres:postgres@localhost/postgres sqlx migrate run --source crates/zopp-store-postgres/migrations
DATABASE_URL=postgres://postgres:postgres@localhost/postgres cargo sqlx prepare --package zopp-store-postgres

# Clean up
docker stop zopp-postgres && docker rm zopp-postgres
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
  zopp-crypto/       - Cryptographic primitives (Argon2id, XChaCha20-Poly1305, X25519 ECDH)
  zopp-proto/        - gRPC service definitions (protobuf)
  zopp-storage/      - Storage trait (backend-agnostic)
  zopp-store-postgres/ - PostgreSQL storage implementation (production)
  zopp-store-sqlite/ - SQLite storage implementation (development)
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
- `zopp environment create <name>` - Create environment (generates DEK; uses zopp.toml defaults)
- `zopp secret set <key> <value>` - Encrypt & store secret (uses zopp.toml defaults)
- `zopp secret get <key>` - Fetch & decrypt secret (uses zopp.toml defaults)
- `zopp secret export -o <file>` - Export secrets to `.env` format (uses zopp.toml defaults)
- `zopp secret import -i <file>` - Import secrets from `.env` format (uses zopp.toml defaults)
- `zopp run -- <command>` - Inject secrets into command environment (uses zopp.toml defaults)
- `zopp invite create` - Create workspace invite (uses zopp.toml defaults)

All `-w`, `-p`, `-e` flags are optional when `zopp.toml` (or `.yaml`/`.json`) is present in the directory tree.

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
