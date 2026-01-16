-- Add export_code for public identification and failed_attempts for brute-force protection

ALTER TABLE principal_exports ADD COLUMN export_code TEXT;
ALTER TABLE principal_exports ADD COLUMN failed_attempts INTEGER NOT NULL DEFAULT 0;

-- Backfill existing rows with a generated export_code (if any exist)
UPDATE principal_exports SET export_code = 'exp_' || substr(md5(random()::text), 1, 8) WHERE export_code IS NULL;

-- Now make it NOT NULL and UNIQUE
ALTER TABLE principal_exports ALTER COLUMN export_code SET NOT NULL;
CREATE UNIQUE INDEX idx_principal_exports_export_code ON principal_exports(export_code);
