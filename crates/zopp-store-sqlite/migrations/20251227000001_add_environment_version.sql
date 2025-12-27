-- Add version column to environments table for change tracking
ALTER TABLE environments ADD COLUMN version INTEGER NOT NULL DEFAULT 0;
