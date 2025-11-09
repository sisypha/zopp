# Zopp E2E Test

End-to-end test that validates the complete zero-knowledge encryption flow from DEMO.md.

## What it tests

1. **Server Setup** - Starts zopp-server
2. **Alice Flow**:
   - Joins with server invite
   - Creates workspace, project, environment
   - Creates workspace invite for Bob
   - Writes secrets
3. **Bob Flow**:
   - Joins with server invite
   - Accepts workspace invite
   - Writes secrets
4. **Cross-User Verification**:
   - Alice reads Bob's secret (encrypted E2E)
   - Bob reads Alice's secret (encrypted E2E)

## Running the test

```bash
# From repo root
cargo run --bin zopp-e2e-test

# Or with cargo test (runs as integration test)
cargo test --package zopp-e2e-test
```

## What gets verified

✅ Server spawns and accepts connections
✅ Server invites work (admin → users)
✅ Workspace invites work (user → user)
✅ KEK generation and wrapping
✅ DEK generation and wrapping
✅ Secret encryption (client-side)
✅ Secret decryption (client-side)
✅ Multi-user workspace access
✅ Zero-knowledge: server never sees plaintext

## Test isolation

- Uses `/tmp/zopp-e2e-test` directory
- Separate home dirs for Alice and Bob
- Temporary database
- Cleans up on completion
