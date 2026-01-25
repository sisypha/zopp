# Implementation Plan: Email Verification for New Principals (Issue #46)

## Executive Summary

Implement email verification using **6-digit codes** with support for **2 email providers** (Resend, SMTP). Email verification will be **enabled by default** but configurable by server admin.

## Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| **Verification default** | Enabled | Secure by default |
| **Email providers** | Resend + SMTP | Resend for simplicity, SMTP for universality |
| **Config validation** | Fail to start | Strict - prevents misconfiguration |
| **Rate limiting** | Basic | 5 attempts/code, 3 codes/hour per email |
| **Code format** | 6-digit | 1M combinations, CLI-friendly |
| **Code expiration** | 15 minutes | Balance security vs UX |

---

## 1. Email Provider Libraries

### Chosen Crates

| Provider | Crate | Version | Notes |
|----------|-------|---------|-------|
| **Resend** | `resend-rs` | 0.20.0 | Official SDK, simple API, built-in rate limiting |
| **SMTP** | `lettre` | 0.11.19 | Universal fallback, works with any provider |

### Dependencies to Add

```toml
# In apps/zopp-server/Cargo.toml
[dependencies]
# Email providers (both optional)
resend-rs = { version = "0.20", optional = true }
lettre = { version = "0.11", features = ["tokio1-rustls", "smtp-transport"], optional = true }

# Random number generation for verification codes
rand = "0.9"

[features]
email-resend = ["resend-rs"]
email-smtp = ["lettre"]

# Default: SMTP for maximum compatibility
default = ["email-smtp"]
```

---

## 2. Database Schema

### New Table: `email_verifications`

**SQLite:**
```sql
CREATE TABLE IF NOT EXISTS email_verifications (
  id TEXT PRIMARY KEY NOT NULL,              -- UUID string
  email TEXT NOT NULL,                       -- Email being verified (lowercased)
  code TEXT NOT NULL,                        -- 6-digit verification code
  attempts INTEGER NOT NULL DEFAULT 0,       -- Failed verification attempts
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now')),
  expires_at TEXT NOT NULL                   -- 15 minutes from created_at
);

CREATE INDEX idx_email_verifications_email ON email_verifications(email);
CREATE INDEX idx_email_verifications_expires_at ON email_verifications(expires_at);
```

**PostgreSQL:**
```sql
CREATE TABLE IF NOT EXISTS email_verifications (
  id UUID PRIMARY KEY NOT NULL,
  email TEXT NOT NULL,
  code TEXT NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX idx_email_verifications_email ON email_verifications(email);
CREATE INDEX idx_email_verifications_expires_at ON email_verifications(expires_at);
```

### New Column: `principals.verified`

```sql
-- SQLite
ALTER TABLE principals ADD COLUMN verified INTEGER NOT NULL DEFAULT 1;

-- PostgreSQL  
ALTER TABLE principals ADD COLUMN verified BOOLEAN NOT NULL DEFAULT TRUE;
```

---

## 3. Storage Trait Extensions

```rust
/// Email verification record
pub struct EmailVerification {
    pub id: EmailVerificationId,
    pub email: String,
    pub code: String,
    pub attempts: i32,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// Parameters for creating an email verification
pub struct CreateEmailVerificationParams {
    pub email: String,
    pub code: String,
    pub expires_at: DateTime<Utc>,
}

// New Store trait methods
async fn create_email_verification(&self, params: &CreateEmailVerificationParams) -> Result<EmailVerification, StoreError>;
async fn get_email_verification(&self, email: &str) -> Result<EmailVerification, StoreError>;
async fn increment_email_verification_attempts(&self, id: &EmailVerificationId) -> Result<i32, StoreError>;
async fn delete_email_verification(&self, id: &EmailVerificationId) -> Result<(), StoreError>;
async fn cleanup_expired_email_verifications(&self) -> Result<u64, StoreError>;
async fn count_recent_email_verifications(&self, email: &str) -> Result<u64, StoreError>;
async fn mark_principal_verified(&self, principal_id: &PrincipalId) -> Result<(), StoreError>;
```

---

## 4. Server Configuration

### Config Structure

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub email: Option<EmailConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailConfig {
    pub verification_required: bool,
    pub provider: EmailProviderConfig,
    pub from_address: String,
    pub from_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum EmailProviderConfig {
    Resend { api_key: String },
    Smtp {
        host: String,
        port: u16,
        username: Option<String>,
        password: Option<String>,
        use_tls: bool,
    },
}
```

### Environment Variables

```bash
# Core settings
ZOPP_EMAIL_VERIFICATION_REQUIRED=true  # enabled by default

# Provider: Resend
ZOPP_EMAIL_PROVIDER=resend
RESEND_API_KEY=re_...

# Provider: SMTP (works with Gmail, AWS SES SMTP, Sendgrid, etc.)
ZOPP_EMAIL_PROVIDER=smtp
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=user@example.com
SMTP_PASSWORD=app_password
SMTP_USE_TLS=true

# Sender config
ZOPP_EMAIL_FROM=noreply@zopp.dev
ZOPP_EMAIL_FROM_NAME="Zopp Security"
```

---

## 5. Proto Changes

```protobuf
// Modified JoinResponse
message JoinResponse {
  string user_id = 1;
  string principal_id = 2;
  repeated Workspace workspaces = 3;
  bool verification_required = 4;  // NEW
}

// New RPCs
message VerifyEmailRequest {
  string email = 1;
  string code = 2;
  string principal_id = 3;
}

message VerifyEmailResponse {
  bool success = 1;
  string message = 2;
  int32 attempts_remaining = 3;
}

message ResendVerificationRequest {
  string email = 1;
}

message ResendVerificationResponse {
  bool success = 1;
  string message = 2;
}

service Zopp {
  // ... existing RPCs ...
  rpc VerifyEmail(VerifyEmailRequest) returns (VerifyEmailResponse);
  rpc ResendVerification(ResendVerificationRequest) returns (ResendVerificationResponse);
}
```

---

## 6. Modified Join Flow

```
Before:
User → Join RPC → Create User+Principal → Save credentials → Done

After (verification enabled):
User → Join RPC → Create User+Principal(unverified) → Send email → Return verification_required=true
  → CLI prompts for code → VerifyEmail RPC → Mark principal verified → Save credentials → Done
```

---

## 7. Email Templates

### Text Version
```
Welcome to Zopp!

Your verification code is: {CODE}

This code will expire in 15 minutes.

If you didn't request this code, please ignore this email.

-- 
Zopp Security Team
```

### HTML Version
```html
<!DOCTYPE html>
<html>
<head>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .code { font-size: 32px; font-weight: bold; letter-spacing: 4px; color: #2563eb; 
                text-align: center; padding: 20px; background: #f3f4f6; border-radius: 8px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Welcome to Zopp!</h1>
        <p>Your verification code is:</p>
        <div class="code">{CODE}</div>
        <p>This code will expire in 15 minutes.</p>
    </div>
</body>
</html>
```

---

## 8. Security Considerations

### Rate Limiting
- Max 5 verification attempts per code
- Max 3 verification codes per email per hour
- Automatic cleanup of expired verifications (background task)

### Code Generation
- Cryptographically secure random 6-digit codes (000000-999999)
- Constant-time comparison to prevent timing attacks
- Codes expire after 15 minutes

### Privacy
- Don't reveal if email exists in timing or error messages
- Constant-time operations for verification lookups
- Hash email addresses in logs

---

## 9. Implementation Checklist

### Phase 1: Database & Storage (16 tasks)
- [x] Create SQLite migration `20260121000001_add_email_verification.sql`
- [x] Create PostgreSQL migration `20260121000001_add_email_verification.sql`
- [x] Create SQLite migration `20260121000002_add_principal_verified.sql`
- [x] Create PostgreSQL migration `20260121000002_add_principal_verified.sql`
- [x] Add `EmailVerification` struct and methods to `zopp-storage` trait
- [x] Implement email verification methods in SQLite store
- [x] Implement email verification methods in PostgreSQL store
- [ ] Run `sqlx prepare` for both stores
- [ ] Unit tests: Storage `create_email_verification`
- [ ] Unit tests: Storage `get_email_verification`
- [ ] Unit tests: Storage `increment_verification_attempts`
- [ ] Unit tests: Storage `mark_principal_verified`
- [ ] Unit tests: Storage `delete_email_verification`
- [ ] Unit tests: Storage `cleanup_expired_verifications`
- [ ] Unit tests: Verification code expiration logic
- [ ] Unit tests: Attempt counting and limits

### Phase 2: Configuration (7 tasks)
- [ ] Create `apps/zopp-server/src/config.rs` with `ServerConfig`
- [ ] Add config validation (fail if verification enabled but no provider)
- [ ] Add environment variable parsing
- [ ] Unit tests: Config environment variable parsing
- [ ] Unit tests: Config validation (missing provider)
- [ ] Unit tests: Config validation (invalid SMTP config)
- [ ] Unit tests: Config defaults and optional fields

### Phase 3: Email Providers (15 tasks)
- [ ] Add Resend and SMTP dependencies to `Cargo.toml` with features
- [ ] Create `apps/zopp-server/src/email/mod.rs` with `EmailProvider` trait
- [ ] Create `apps/zopp-server/src/email/templates.rs` with email templates
- [ ] Implement Resend provider (`email/resend.rs`)
- [ ] Implement SMTP provider (`email/smtp.rs`)
- [ ] Add provider factory function with validation
- [ ] Create code generation utility (cryptographically secure 6-digit)
- [ ] Unit tests: Email templates text generation
- [ ] Unit tests: Email templates HTML generation
- [ ] Unit tests: Code generation format validation (6 digits)
- [ ] Unit tests: Code generation randomness (no duplicates in sample)
- [ ] Unit tests: Resend provider with mocked API
- [ ] Unit tests: SMTP provider with mocked transport
- [ ] Unit tests: Provider factory selection logic
- [ ] Unit tests: Provider factory error on invalid config

### Phase 4: Proto Changes (4 tasks)
- [ ] Update `zopp.proto` with `VerifyEmailRequest/Response`
- [ ] Update `zopp.proto` with `ResendVerificationRequest/Response`
- [ ] Add `verification_required` field to `JoinResponse`
- [ ] Regenerate proto code (`cargo build`)

### Phase 5: Server Handlers (14 tasks)
- [ ] Modify join handler to support verification flow
- [ ] Implement `verify_email` handler with rate limiting
- [ ] Implement `resend_verification` handler with rate limiting
- [ ] Add background cleanup task for expired verifications
- [ ] Add authentication bypass for `verify_email` RPC
- [ ] Unit tests: Rate limiting logic (5 attempts per code)
- [ ] Unit tests: Rate limiting (3 codes per hour per email)
- [ ] Unit tests: Verification code validation (constant-time comparison)
- [ ] Unit tests: Background cleanup task removes expired verifications
- [ ] Unit tests: Join handler with verification enabled
- [ ] Unit tests: Join handler with verification disabled
- [ ] Unit tests: VerifyEmail handler success case
- [ ] Unit tests: VerifyEmail handler wrong code
- [ ] Unit tests: ResendVerification handler

### Phase 6: CLI Changes (3 tasks)
- [ ] Modify CLI `cmd_join` to handle verification flow
- [ ] Add code input prompt and retry logic
- [ ] Add resend option during verification

### Phase 7: E2E Tests (8 tasks)
- [ ] E2E test: Join with verification enabled (happy path)
- [ ] E2E test: Join with verification disabled
- [ ] E2E test: Failed verification (wrong code)
- [ ] E2E test: Expired verification code
- [ ] E2E test: Too many attempts (rate limiting)
- [ ] E2E test: Resend verification code
- [ ] E2E test: Workspace invite with verification
- [ ] E2E test: Bootstrap invite (should bypass verification)

### Phase 8: Documentation (4 tasks)
- [ ] Update `CLAUDE.md` with email configuration
- [ ] Create `docs/docs/guides/email-verification.md`
- [ ] Update `docs/docs/reference/cli/join.md`
- [ ] Add troubleshooting guide for email delivery issues

### Phase 9: PR & Review (4 tasks)
- [ ] Run full test suite
- [ ] Run clippy and fmt
- [ ] Create PR and monitor CI
- [ ] Address Cubic review comments

---

## 10. Backwards Compatibility

- **Verification can be disabled**: `ZOPP_EMAIL_VERIFICATION_REQUIRED=false`
- **Existing principals automatically marked as verified** in migration
- **Bootstrap invites work without verification** (server setup unchanged)
- **No breaking changes to existing APIs**

---

## 11. Files Created/Modified So Far

### Created
- `crates/zopp-store-sqlite/migrations/20260121000001_add_email_verification.sql`
- `crates/zopp-store-sqlite/migrations/20260121000002_add_principal_verified.sql`
- `crates/zopp-store-postgres/migrations/20260121000001_add_email_verification.sql`
- `crates/zopp-store-postgres/migrations/20260121000002_add_principal_verified.sql`

### Modified
- `crates/zopp-storage/src/lib.rs` - Added `EmailVerification`, `EmailVerificationId`, `CreateEmailVerificationParams`, and new trait methods
- `crates/zopp-store-sqlite/src/lib.rs` - Implemented email verification methods, updated `Principal` queries to include `verified`
- `crates/zopp-store-postgres/src/lib.rs` - Implemented email verification methods, updated `Principal` queries to include `verified`

---

## 12. Next Steps

1. **Run `sqlx prepare`** for PostgreSQL (requires Docker container)
2. **Create server configuration module** (`apps/zopp-server/src/config.rs`)
3. **Add email provider dependencies** to `Cargo.toml`
4. **Implement email provider trait and implementations**
5. **Update proto definitions**
6. **Implement server handlers**
7. **Update CLI join command**
8. **Write tests**
9. **Write documentation**
10. **Create PR**

---

## 13. Related Issues

- Issue #46: Feature: Implement email verification for new principals
- ListWorkspaces exposes workspaces without principal KEK access (mentioned as related in issue)

---

## 14. Test Philosophy

Per `TESTING.md`:
- **Use real implementations** - Tests use real SQLite/PostgreSQL, not mocks
- **Mock only for external services** - Mock Resend API and SMTP transport
- **100% coverage goal** - Every new function has unit tests
- **E2E for user-facing features** - Full join flow with verification
- **Security-critical code** - Constant-time comparison, rate limiting well-tested
