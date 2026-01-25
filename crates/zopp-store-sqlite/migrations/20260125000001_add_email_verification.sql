-- Email verification with pending join data
-- Verification is per-user (email), not per-principal
-- Principal is created only after successful verification

-- Add verified flag to users table
-- Existing users are grandfathered in as verified (1=TRUE) since they joined before verification was required
-- New users joining with verification enabled will have verified=0 until email is verified
ALTER TABLE users ADD COLUMN verified INTEGER NOT NULL DEFAULT 1;

-- Add consumed flag to invites table (tracks whether invite has been used)
ALTER TABLE invites ADD COLUMN consumed INTEGER NOT NULL DEFAULT 0;

-- Email verification / pending join table
-- One record per email, upserted on each join attempt
CREATE TABLE IF NOT EXISTS email_verifications (
  id TEXT PRIMARY KEY NOT NULL,              -- UUID string
  email TEXT NOT NULL UNIQUE,                -- Email being verified (lowercased, unique)
  code TEXT NOT NULL,                        -- 6-digit verification code
  invite_token TEXT NOT NULL,                -- Invite token to consume on success
  attempts INTEGER NOT NULL DEFAULT 0,       -- Failed verification attempts
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now')),
  expires_at TEXT NOT NULL                   -- 15 minutes from created_at
);

-- Index for cleanup of expired verifications
CREATE INDEX idx_email_verifications_expires_at ON email_verifications(expires_at);
