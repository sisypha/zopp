-- Add verification_salt column for Argon2id-based passphrase verification
-- This replaces SHA256 verification with Argon2id to prevent fast offline brute-force
-- attacks if the database is compromised.

-- Enable pgcrypto extension for gen_random_bytes
CREATE EXTENSION IF NOT EXISTS pgcrypto;

ALTER TABLE principal_exports ADD COLUMN verification_salt BYTEA;

-- Backfill existing rows with a random salt (16 bytes)
-- Note: Existing exports will need to be re-created since we can't regenerate
-- the Argon2id hash without the original passphrase. The token_hash remains
-- but verification will fail for old exports (they'll expire in 24h anyway).
UPDATE principal_exports SET verification_salt = gen_random_bytes(16) WHERE verification_salt IS NULL;

-- Make it NOT NULL after backfill
ALTER TABLE principal_exports ALTER COLUMN verification_salt SET NOT NULL;
