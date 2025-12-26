# Zopp E2E Test

End-to-end test that validates the complete zero-knowledge encryption flow from DEMO.md.

## What it tests

**Steps 0-7: Server and User Setup**
1. Server starts and listens on port 50051
2. Admin creates server invite for Alice
3. Alice joins server, creates workspace/project/environment
4. Alice creates workspace invite for Bob
5. Bob joins server using workspace invite

**Steps 8-11: Cross-User Secret Sharing**
6. Bob writes secret to production environment
7. Alice reads Bob's secret (E2E encrypted)
8. Alice writes secret to production environment
9. Bob reads Alice's secret (E2E encrypted)

**Steps 12-15: Import/Export Workflow**
10. Alice exports secrets to `.env` file
11. Bob creates staging environment
12. Bob imports secrets from `.env` file
13. Verify imported secrets match originals

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
✅ KEK generation and wrapping (per-principal)
✅ DEK generation and wrapping (per-environment)
✅ Secret encryption (client-side only)
✅ Secret decryption (client-side only)
✅ Multi-user workspace access with shared KEK
✅ `.env` file export (decrypt all secrets)
✅ `.env` file import (parse and encrypt secrets)
✅ Import/export roundtrip verification
✅ Zero-knowledge: server never sees plaintext keys or secrets

## Test isolation

- Uses `/tmp/zopp-e2e-test` directory
- Separate home dirs for Alice and Bob
- Temporary database
- Cleans up on completion
