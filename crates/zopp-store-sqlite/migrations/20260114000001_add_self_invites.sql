-- Add for_user_id column to invites table for self-invites
-- When set, only this user can consume the invite (for adding new devices)
ALTER TABLE invites ADD COLUMN for_user_id TEXT REFERENCES users(id) ON DELETE CASCADE;

-- Partial index for efficient lookup of self-invites (only when for_user_id is set)
CREATE INDEX idx_invites_for_user_id ON invites(for_user_id) WHERE for_user_id IS NOT NULL;
