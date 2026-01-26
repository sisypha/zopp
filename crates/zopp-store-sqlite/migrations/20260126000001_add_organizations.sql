-- Organizations: billing unit and workspace container for SaaS
CREATE TABLE IF NOT EXISTS organizations (
  id TEXT PRIMARY KEY NOT NULL,  -- UUID as TEXT
  name TEXT NOT NULL,
  slug TEXT NOT NULL UNIQUE,  -- URL-friendly identifier (lowercase, alphanumeric, hyphens)
  stripe_customer_id TEXT UNIQUE,  -- Stripe customer ID (nullable until billing setup)
  stripe_subscription_id TEXT UNIQUE,  -- Active Stripe subscription ID
  plan TEXT NOT NULL DEFAULT 'free',  -- 'free', 'pro', 'enterprise'
  seat_limit INTEGER NOT NULL DEFAULT 3,  -- Max users based on plan
  trial_ends_at TEXT,  -- Trial period expiration as ISO8601 (NULL = no trial)
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Organization members with roles
CREATE TABLE IF NOT EXISTS organization_members (
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role TEXT NOT NULL DEFAULT 'member',  -- 'owner', 'admin', 'member'
  invited_by TEXT REFERENCES users(id) ON DELETE SET NULL,
  joined_at TEXT NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (organization_id, user_id)
);

-- Index for looking up user's organizations
CREATE INDEX idx_organization_members_user ON organization_members(user_id);

-- Add organization_id to workspaces (nullable for backward compatibility)
ALTER TABLE workspaces ADD COLUMN organization_id TEXT REFERENCES organizations(id) ON DELETE SET NULL;
CREATE INDEX idx_workspaces_organization ON workspaces(organization_id);

-- Organization invites (pending invitations)
CREATE TABLE IF NOT EXISTS organization_invites (
  id TEXT PRIMARY KEY NOT NULL,  -- UUID as TEXT
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  email TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'member',  -- 'admin', 'member'
  token_hash TEXT NOT NULL UNIQUE,  -- SHA256 of invite token (for secure lookup)
  invited_by TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at TEXT NOT NULL,  -- ISO8601 timestamp
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  UNIQUE(organization_id, email)  -- One pending invite per email per org
);

-- Index for looking up invites by email
CREATE INDEX idx_organization_invites_email ON organization_invites(email);

-- Organization settings (feature flags, SSO config, etc.)
CREATE TABLE IF NOT EXISTS organization_settings (
  organization_id TEXT PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE,
  require_email_verification INTEGER NOT NULL DEFAULT 1,  -- Boolean as INTEGER
  require_2fa INTEGER NOT NULL DEFAULT 0,  -- Boolean as INTEGER
  allowed_email_domains TEXT,  -- JSON array of allowed domains (NULL = any domain)
  sso_config TEXT,  -- JSON object for SAML/OIDC configuration
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Triggers for updated_at (SQLite doesn't have functions, so we use triggers directly)
CREATE TRIGGER organizations_updated_at AFTER UPDATE ON organizations
BEGIN
  UPDATE organizations SET updated_at = datetime('now') WHERE id = NEW.id;
END;

CREATE TRIGGER organization_settings_updated_at AFTER UPDATE ON organization_settings
BEGIN
  UPDATE organization_settings SET updated_at = datetime('now') WHERE organization_id = NEW.organization_id;
END;
