# Zopp E2E Test

End-to-end test that validates the complete zero-knowledge encryption flow.

## What it tests

This test executes the entire workflow from [DEMO.md](../../DEMO.md), verifying:
- Server and user setup (invites, registration, workspace creation)
- `zopp.toml` configuration file with defaults
- Cross-user secret sharing with zero-knowledge encryption
- `.env` file import/export
- Secret injection via `run` command
- Flag overrides (e.g., `-e production` overriding zopp.toml defaults)

## Running the test

```bash
# From repo root - requires binaries to be built first
cargo build --bins
cargo run --bin zopp-e2e-test
```

## What gets verified

✅ Server spawns and accepts connections
✅ Server invites work (admin → users)
✅ Workspace invites work (user → user)
✅ `zopp.toml` config file created with defaults
✅ KEK generation and wrapping (per-principal)
✅ DEK generation and wrapping (per-environment)
✅ Secret encryption (client-side only)
✅ Secret decryption (client-side only)
✅ Multi-user workspace access with shared KEK
✅ Commands use zopp.toml defaults (no -w/-p/-e flags needed)
✅ Flag overrides work (e.g., `-e production` overrides zopp.toml)
✅ `.env` file export (decrypt all secrets)
✅ `.env` file import (parse and encrypt secrets)
✅ Import/export roundtrip verification
✅ Secret injection via `run` command
✅ Zero-knowledge: server never sees plaintext keys or secrets

## Test isolation

- Uses `/tmp/zopp-e2e-test` directory
- Separate home dirs for Alice and Bob
- Temporary database
- Cleans up on completion
