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

## Contributing Guides

Detailed standards live in `contributing/`:

- [DEVELOPMENT.md](./contributing/DEVELOPMENT.md) - Setup, building, running locally
- [TESTING.md](./contributing/TESTING.md) - Testing philosophy, coverage targets
- [DOCUMENTING.md](./contributing/DOCUMENTING.md) - Docs workflow and guidelines
- [RELEASING.md](./contributing/RELEASING.md) - Release process

### Testing

See [TESTING.md](./contributing/TESTING.md) for full testing standards.

**Use real implementations, only mock to reproduce specific error conditions.**
- Every user-facing feature must have an E2E test
- Aim for 100% unit test coverage (some code is impractical to unit test—use E2E instead)
- Test trait implementations with real dependencies (real SQLite, real PostgreSQL)

### Documentation

See [DOCUMENTING.md](./contributing/DOCUMENTING.md) for docs workflow and guidelines.

**Documentation is product.** Always consider whether code changes require doc updates:
- New CLI commands/flags → update `docs/docs/reference/cli/`
- New features → add or update guides
- Changed behavior → update relevant docs

Run docs locally: `cd docs && npm run dev`

## Planning and Implementation

When planning implementation tasks, always consider:

1. **Tests**: What tests are needed?
   - E2E tests for user-facing features (`apps/e2e-tests/tests/`)
   - **RBAC tests**: Always consider if the feature needs permission testing (see [TESTING.md](./contributing/TESTING.md#rbac-testing))
   - Unit tests for new logic in crates

2. **Documentation**: What docs need updating?
   - CLI command docs (`docs/docs/reference/cli/`)
   - Feature guides if adding new functionality
   - Ensure docs match actual implementation

3. **Local Verification**: Before creating a PR, run:
   ```bash
   cargo fmt --all
   cargo clippy --workspace --all-targets --all-features
   cargo test --workspace --all-features
   ```

4. **Opening a PR**: Plan should include opening a PR and monitoring CI/Cubic review (see below)

## Pull Request Workflow

When creating PRs and working through CI:

1. **Create the PR**: Use `gh pr create` with a clear title and description
2. **Monitor CI**: Watch for CI check results
   - **Ignore docker builds** - they are slow and not required for most PRs
   - Focus on: clippy, tests, fmt checks, E2E tests, web-e2e tests
3. **Work with Cubic reviews**: Cubic is an AI code reviewer that does two types of reviews:
   - **Incremental reviews**: Automatically triggered on each push, reviews only changed files
   - **Full reviews**: Triggered by tagging `@cubic-dev-ai` in a PR comment

### Cubic Review Workflow

1. **Initial full review**: When PR is created, Cubic does a full review of all changes
2. **Address issues**: Fix any issues Cubic identifies, commit and push
3. **Incremental review**: Cubic automatically reviews only the new changes (not the whole PR)
   - Check the CI check output: "AI review completed with X review. Y issues found across Z files (changes from recent commits)"
   - If issues found in the incremental review, fix them and push again
   - If 0 issues found, your fixes are good - but this only covers the recent changes
4. **Request full re-review**: Once incremental reviews pass, comment `@cubic-dev-ai Please do a full re-review of the PR.`
5. **Wait for full review**: The full re-review examines the entire PR again and may find new issues
6. **Iterate**: Repeat steps 2-5 until full review passes with 0 issues or only acceptable minor issues
7. **Merge**: Only merge after the full re-review completes successfully - never merge while it's pending

### Reading Cubic Results

- **CI Check**: Look at the "cubic-dev-ai / cubic · AI code reviewer" check for quick status
- **Review comments**: Cubic posts detailed issues as PR review comments
- **Addressed marker**: When you fix an issue, Cubic edits its comment to show "✅ Addressed in <commit>" - check if comments are marked as addressed rather than waiting for a new review
- **Outdated comments**: GitHub may mark comments as "outdated" if the code changed - these can often be ignored
- **Confidence score**: Higher is better (5/5 means high confidence the code is good)
- **Priority levels**: P1 (critical), P2 (important), P3 (minor) - always fix P1/P2

Example workflow:
```bash
# Create branch and make changes
git checkout -b feat/my-feature
# ... make changes ...
git add -A && git commit -m "Add my feature"
git push -u origin feat/my-feature

# Create PR
gh pr create --title "Add my feature" --body "Description..."

# Monitor CI (ignore docker builds)
gh pr checks

# Check Cubic's initial review, fix issues, push
# Cubic does incremental review automatically
# When incremental shows 0 issues, request full re-review:
gh pr comment --body "@cubic-dev-ai Please do a full re-review of the PR."

# Repeat until all checks pass and Cubic is satisfied
```

## Important Notes

- **No co-authored commits**: Do NOT add "Co-Authored-By: Claude" trailers to commits
- **No AI attribution**: Do NOT add "Generated with Claude" or similar to PR descriptions
- **DEMO.md alignment**: Keep DEMO.md steps 1:1 with E2E test steps
- **Security**: Never log or expose plaintext keys/secrets in server code
- **Zeroizing types**: Use `zeroize::Zeroize` and `zeroize::ZeroizeOnDrop` for sensitive data (see `zopp-crypto/src/lib.rs`)
