-- Email verification with pending join data
-- Verification is per-user (email), not per-principal
-- Principal is created only after successful verification

-- Add verified flag to users table
-- Step 1: Add column with DEFAULT TRUE to grandfather existing users as verified
ALTER TABLE users ADD COLUMN verified BOOLEAN NOT NULL DEFAULT TRUE;
-- Step 2: Change default to FALSE for new users (verification flow creates unverified users)
ALTER TABLE users ALTER COLUMN verified SET DEFAULT FALSE;

-- Add consumed flag to invites table (tracks whether invite has been used)
ALTER TABLE invites ADD COLUMN consumed BOOLEAN NOT NULL DEFAULT FALSE;

-- Email verification / pending join table
-- One record per email, upserted on each join attempt
CREATE TABLE IF NOT EXISTS email_verifications (
  id UUID PRIMARY KEY NOT NULL,
  email TEXT NOT NULL UNIQUE,                -- Email being verified (lowercased, unique)
  code_hash TEXT NOT NULL,                   -- Argon2id hash of verification code (zero-knowledge)
  invite_token TEXT NOT NULL,                -- Invite token to consume on success
  attempts INTEGER NOT NULL DEFAULT 0,       -- Failed verification attempts
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at TIMESTAMPTZ NOT NULL            -- 15 minutes from created_at
);

-- Index for cleanup of expired verifications
CREATE INDEX idx_email_verifications_expires_at ON email_verifications(expires_at);
