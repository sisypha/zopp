-- Add for_user_id column to invites table for self-invites
-- When set, only this user can consume the invite (for adding new devices)
ALTER TABLE invites ADD COLUMN for_user_id UUID REFERENCES users(id) ON DELETE CASCADE;
