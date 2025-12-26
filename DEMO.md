# Complete Zero-Knowledge Encryption Demo

This demonstrates the full workflow from the very beginning: Admin starts server, Alice registers and creates workspace, invites Bob, both can read/write secrets with automatic encryption.

## Step 0: Admin Starts the Server

First, the admin (or any operator) needs to build and start the Zopp server.

```bash
# Terminal 1 (Admin)
# Build the server
cd /Users/lucas/code/zopp
cargo build --release

# Start the server (listens on port 50051 by default)
cargo run --bin zopp-server serve
```

**What's running:**
- gRPC server listening on `127.0.0.1:50051`
- SQLite database at `~/.zopp/zopp.db` (auto-created)
- Server has ZERO knowledge of encryption keys or plaintext secrets
- All authentication via Ed25519 signatures
- All encryption key wrapping via X25519 ECDH

The server is now ready to accept client connections. Keep this terminal running.

## Step 1: Admin Creates Server Invite for Alice

The first user(s) must be bootstrapped using a server invite that goes directly into the database.

```bash
# Terminal 2 (Admin)
# Create a server invite for Alice (valid for 48 hours)
zopp-server invite create --expires-hours 48 --db ~/.zopp/zopp.db

# Output:
# ✓ Server invite created!
#
# Token:   inv_abc123def456...
# Expires: 2025-11-11 14:30:00 UTC
#
# Use this token to join this server using zopp join
```

**What happened:**
- Admin generated a server invite token directly in the database
- This token allows Alice to register on the server
- Server invites are NOT workspace-specific - they just allow registration

**Share the invite token with Alice via secure channel (email, slack, etc.)**

## Step 2: Alice Joins Server and Creates Workspace

```bash
# Terminal 3 (Alice)
# Alice joins the server using the invite token
# (principal name defaults to hostname if not specified)
zopp join inv_abc123def456... alice@example.com

# Output:
# ✓ Joined successfully!
# User ID:      usr_...
# Principal ID: prn_...
# Principal:    alice-macbook
#
# Config saved to: /Users/alice/.zopp/config.json

# Alice creates a workspace (generates random KEK, wraps it with her X25519 key)
zopp workspace create acme
```

**What happened:**
- Alice used the server invite token to register
- Alice's principal generated:
  - Ed25519 keypair (authentication)
  - X25519 keypair (encryption)
- Workspace "acme" generated random 32-byte KEK
- KEK wrapped using ephemeral X25519 ECDH for Alice
- Server stored: `(workspace_id, alice_principal_id, ephemeral_pub, kek_wrapped, kek_nonce)`
- Server NEVER saw the plaintext KEK

## Step 3: Alice Creates Project and Development Environment

```bash
# Create project
zopp project create api --workspace acme

# Create development environment (generates random DEK, wraps with workspace KEK automatically)
zopp environment create development --workspace acme --project api

# Create zopp.toml to set defaults for this project
cat > zopp.toml <<EOF
[defaults]
workspace = "acme"
project = "api"
environment = "development"
EOF
```

**What happened:**
- Alice's CLI unwrapped her workspace KEK using her X25519 private key
- Alice's CLI generated random 32-byte DEK for environment "development"
- Alice's CLI wrapped DEK using workspace KEK with XChaCha20-Poly1305
- Server stored: `(environment_id, dek_wrapped, dek_nonce)`
- **Server never saw the plaintext DEK**
- Alice created `zopp.toml` to avoid repeating `-w -p -e` flags on every command

## Step 4: Alice Creates Workspace Invite for Bob

Alice creates a workspace invite that encrypts the KEK with a randomly generated secret.

```bash
# Terminal 3 (Alice) - Create workspace invite (workspace comes from zopp.toml)
zopp invite create --expires-hours 168

# Output:
# ✓ Workspace invite created!
#
# Invite code: inv_4f8a2b3c1de56f789a0b1c2d3e4f56789a0b1c2d3e4f56789a0b1c2d3e4f5678
# Expires:     2025-11-16 14:30:00 UTC
#
# ⚠️  Share this invite code with the invitee via secure channel
#    The server does NOT have the plaintext - it's needed to decrypt the workspace key
```

**What happened:**
- Alice's CLI unwrapped her workspace KEK
- Alice's CLI generated random 32-byte invite secret
- Alice's CLI encrypted KEK with invite secret using XChaCha20-Poly1305
- Alice's CLI hashed the secret (SHA256) to create lookup token
- Server stored: `(invite_id, SHA256(secret), kek_encrypted, kek_nonce, workspace_id)`
- **Invite secret NEVER sent to server** - only the hash for lookup

**Alice shares the single invite code with Bob via secure channel (Signal, encrypted email, etc.)**

## Step 5: Bob Joins Server (First-Time)

Bob first needs a server invite to register on the server.

```bash
# Terminal 2 (Admin) - Create server invite for Bob
zopp-server invite create --expires-hours 48 --db ~/.zopp/zopp.db

# Output:
# ✓ Server invite created!
#
# Token:   inv_server_xyz789...
# Expires: 2025-11-11 14:30:00 UTC
```

```bash
# Terminal 4 (Bob) - Join the server
zopp join inv_server_xyz789... bob@example.com

# Output:
# ✓ Joined successfully!
# User ID:      usr_...
# Principal ID: prn_...
# Principal:    bob-thinkpad
```

**What happened:**
- Bob used the server invite token to register
- Bob's principal generated:
  - Ed25519 keypair (authentication)
  - X25519 keypair (encryption)
- Bob is now registered but doesn't have access to any workspaces yet

## Step 6: Bob Accepts Alice's Workspace Invite

Bob uses the single workspace invite code that Alice shared to join her workspace.

```bash
# Terminal 4 (Bob) - Accept workspace invite
zopp join inv_4f8a2b3c1de56f789a0b1c2d3e4f56789a0b1c2d3e4f56789a0b1c2d3e4f5678 \
  bob@example.com

# Output:
# ✓ Joined successfully!
# User ID:      usr_...
# Principal ID: prn_...
# Principal:    bob-thinkpad
#
# Workspaces:
#   - acme (wks_...)
```

**What happened (all client-side):**
1. Bob's CLI detected `inv_` prefix → this is a workspace invite
2. Bob's CLI stripped prefix and decoded the 32-byte secret
3. Bob's CLI hashed the secret to look up the invite on server
4. Bob's CLI fetched encrypted KEK from server
5. Bob's CLI decrypted workspace KEK using the invite secret
6. Bob generated fresh Ed25519 + X25519 keypairs
7. Bob's CLI generated ephemeral X25519 keypair
8. Bob's CLI re-wrapped KEK for himself using ECDH with his X25519 public key
9. Bob's CLI sent wrapped KEK to server
10. Server stored Bob's wrapped KEK: `(workspace_id, bob_principal_id, ephemeral_pub, kek_wrapped, kek_nonce)`
11. **Server never saw KEK plaintext - it was re-wrapped client-side**

## Step 7: Bob Writes a Secret (Auto-Encryption)

Bob can now write secrets to the development environment (using defaults from zopp.toml)!

```bash
# Terminal 4 (Bob) - Write secret (workspace/project/environment from zopp.toml)
zopp secret set "FLUXMAIL_API_TOKEN" "fxt_8k2m9p4x7n1q5w3e6r8t0y2u4i6o8p0a"
```

**What happened (client-side only):**
1. Bob's CLI read defaults from `zopp.toml`: workspace=acme, project=api, environment=development
2. Bob's CLI unwrapped workspace KEK using his X25519 private key + ECDH
3. Bob's CLI unwrapped environment DEK using the KEK
4. Bob's CLI encrypted `"fxt_8k2m9p4x7n1q5w3e6r8t0y2u4i6o8p0a"` using DEK
5. Bob's CLI sent `(workspace, project, env, key, nonce, ciphertext)` to server
6. Server stored encrypted blob - **never saw plaintext**

## Step 8: Alice Reads Bob's Secret (Auto-Decryption)

Alice can read the secret Bob just wrote!

```bash
# Terminal 3 (Alice) - Read Bob's secret (defaults from zopp.toml)
zopp secret get "FLUXMAIL_API_TOKEN"

# Output:
# fxt_8k2m9p4x7n1q5w3e6r8t0y2u4i6o8p0a
```

**What happened (client-side only):**
1. Alice's CLI read defaults from `zopp.toml`
2. Alice's CLI fetched encrypted secret from server
3. Alice's CLI unwrapped workspace KEK using her X25519 private key + ECDH
4. Alice's CLI unwrapped environment DEK using the KEK
5. Alice's CLI decrypted secret using DEK
6. Alice's CLI printed plaintext value
7. **Server never saw any plaintext**

## Step 9: Alice Writes More Secrets

```bash
# Terminal 3 (Alice) - Write another secret
zopp secret set "PAYFLOW_MERCHANT_ID" "mch_9x8v7c6b5n4m3"
```

## Step 10: Bob Reads Alice's Secret

```bash
# Terminal 4 (Bob) - Read Alice's secret
zopp secret get "PAYFLOW_MERCHANT_ID"

# Output:
# mch_9x8v7c6b5n4m3
```

**Why this works:**
- Both Alice and Bob have the same workspace KEK (wrapped differently per-principal)
- Both can unwrap it using their own X25519 keys
- Both share the same `zopp.toml` with defaults, making commands simple and clean
- Both can unwrap the environment DEK
- Both can encrypt/decrypt secrets
- **Server sees ZERO plaintext at any point**

## Step 11: Alice Exports Secrets to .env File

Alice can export all secrets from development (using zopp.toml defaults):

```bash
# Terminal 3 (Alice) - Export secrets to .env file (defaults from zopp.toml)
zopp secret export --output development.env

# Output:
# ✓ Exported 2 secrets to development.env

cat development.env
# FLUXMAIL_API_TOKEN=fxt_8k2m9p4x7n1q5w3e6r8t0y2u4i6o8p0a
# PAYFLOW_MERCHANT_ID=mch_9x8v7c6b5n4m3
```

**What happened:**
- Alice's CLI read defaults from `zopp.toml` (development environment)
- Alice's CLI listed all secrets in the development environment
- Alice's CLI decrypted each secret value using the development DEK
- Formatted as sorted KEY=value lines and wrote to file
- **File contains plaintext - keep it secure!**

## Step 12: Alice Creates Production Environment

Now Alice creates production and imports the secrets there (using `-e` flag to override zopp.toml):

```bash
# Terminal 3 (Alice) - Create production environment (override default with -e flag)
zopp environment create production -e production

# Output:
# ✓ Environment 'production' created
```

**What happened:**
- Alice used `-e production` to override the zopp.toml default (development)
- Alice's CLI generated a new random 32-byte DEK for production
- Alice's CLI wrapped production DEK with workspace KEK
- Server stored the wrapped production DEK
- **Production has different encryption key than development**

## Step 13: Alice Imports Secrets to Production

```bash
# Terminal 3 (Alice) - Import secrets to production (override with -e flag)
zopp secret import -e production --input development.env

# Output:
# ✓ Imported 2 secrets
```

**What happened:**
- Alice's CLI read defaults from `zopp.toml` for workspace/project, but used `-e production` to override environment
- Alice's CLI read and parsed the `.env` file (KEY=value format, skips comments)
- Alice's CLI encrypted each secret with production's DEK
- Alice's CLI sent encrypted blobs to server
- **Same plaintext values, different encryption (different environment = different DEK)**

## Step 14: Verify Imported Secrets in Production

```bash
# Terminal 3 (Alice) - Read imported secret from production (override with -e flag)
zopp secret get FLUXMAIL_API_TOKEN -e production

# Output:
# fxt_8k2m9p4x7n1q5w3e6r8t0y2u4i6o8p0a
```

**Import/export roundtrip verified!**
- Alice exported from development (using zopp.toml defaults)
- Alice imported to production (using `-e production` flag to override)
- Alice can read from production (using `-e production` flag)
- **Server never saw plaintext during the transfer - only encrypted blobs in each environment**
- **Flags override zopp.toml defaults when needed!**

## Step 15: Run Command with Injected Secrets

Alice can run any command with secrets automatically injected as environment variables:

```bash
# Terminal 3 (Alice) - Run command with secrets injected from development (zopp.toml defaults)
zopp run -- printenv FLUXMAIL_API_TOKEN

# Output:
# fxt_8k2m9p4x7n1q5w3e6r8t0y2u4i6o8p0a
```

**What happened:**
- Alice's CLI read defaults from `zopp.toml` (development environment)
- Alice's CLI fetched all secrets from development environment
- Alice's CLI decrypted each secret client-side
- Alice's CLI spawned `printenv` with secrets as environment variables
- The command ran with full access to decrypted secrets
- **Server never saw plaintext - only encrypted blobs were transmitted**

**Real-world usage:**
```bash
# Start your app with development secrets (from zopp.toml)
zopp run -- npm start

# Run with production secrets (override with -e flag)
zopp run -e production -- npm start

# Run database migrations with staging secrets
zopp run -e staging -- python manage.py migrate

# Deploy with production secrets (explicit override)
zopp run -e production -- ./deploy.sh
```

## Architecture Summary

```
┌─────────────────────────────────────────────────────────────┐
│                    CLIENT (Alice/Bob)                       │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │ X25519 Priv  │→│ Unwrap KEK   │→│ Unwrap DEK   │→     │
│  │    (local)   │  │  (ECDH)      │  │  (decrypt)   │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
│                                             ↓                │
│                                    ┌──────────────┐          │
│                                    │ Encrypt/     │          │
│                                    │ Decrypt      │          │
│                                    │ Secrets      │          │
│                                    └──────────────┘          │
└─────────────────────────────────────────────────────────────┘
                           ↕ (only encrypted data)
┌─────────────────────────────────────────────────────────────┐
│                         SERVER                              │
│  Storage:                                                   │
│  - workspace_principals (KEK wrapped per-principal)         │
│  - environments (DEK wrapped with KEK)                      │
│  - secrets (ciphertext encrypted with DEK)                  │
│                                                             │
│  Server is BLIND - never sees any plaintext                 │
└─────────────────────────────────────────────────────────────┘
```

## Security Properties

✅ **Zero-Knowledge Server**: Server never has access to plaintext keys or secrets
✅ **Multi-Principal Access**: Multiple users can access same workspace with different wrapped KEKs
✅ **Forward Secrecy**: Ephemeral keys used for wrapping
✅ **Authenticated Encryption**: AEAD with context (workspace/project/env/key)
✅ **Memory Safety**: Zeroizing types protect key material
✅ **Invite Security**: Invite secrets never stored in database

## Key Hierarchy

```
User
 └── Principal (Ed25519 + X25519 keypairs)
      └── Workspace
           └── KEK (wrapped per-principal via ECDH)
                └── Environment
                     └── DEK (wrapped with KEK)
                          └── Secret (encrypted with DEK)
```

Every layer is encrypted. Server stores only wrapped/encrypted blobs.
