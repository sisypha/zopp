-- Organizations: billing unit and workspace container for SaaS
CREATE TABLE IF NOT EXISTS organizations (
  id UUID PRIMARY KEY NOT NULL,
  name TEXT NOT NULL,
  slug TEXT NOT NULL UNIQUE,  -- URL-friendly identifier (lowercase, alphanumeric, hyphens)
  stripe_customer_id TEXT UNIQUE,  -- Stripe customer ID (nullable until billing setup)
  stripe_subscription_id TEXT UNIQUE,  -- Active Stripe subscription ID
  plan TEXT NOT NULL DEFAULT 'free',  -- 'free', 'pro', 'enterprise'
  seat_limit INTEGER NOT NULL DEFAULT 3,  -- Max users based on plan
  trial_ends_at TIMESTAMPTZ,  -- Trial period expiration (NULL = no trial)
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Organization members with roles
CREATE TABLE IF NOT EXISTS organization_members (
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role TEXT NOT NULL DEFAULT 'member',  -- 'owner', 'admin', 'member'
  invited_by UUID REFERENCES users(id) ON DELETE SET NULL,
  joined_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (organization_id, user_id)
);

-- Index for looking up user's organizations
CREATE INDEX idx_organization_members_user ON organization_members(user_id);

-- Add organization_id to workspaces (nullable for backward compatibility)
ALTER TABLE workspaces ADD COLUMN organization_id UUID REFERENCES organizations(id) ON DELETE SET NULL;
CREATE INDEX idx_workspaces_organization ON workspaces(organization_id);

-- Organization invites (pending invitations)
CREATE TABLE IF NOT EXISTS organization_invites (
  id UUID PRIMARY KEY NOT NULL,
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  email TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'member',  -- 'admin', 'member'
  token_hash TEXT NOT NULL UNIQUE,  -- SHA256 of invite token (for secure lookup)
  invited_by UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(organization_id, email)  -- One pending invite per email per org
);

-- Index for looking up invites by email
CREATE INDEX idx_organization_invites_email ON organization_invites(email);

-- Organization settings (feature flags, SSO config, etc.)
CREATE TABLE IF NOT EXISTS organization_settings (
  organization_id UUID PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE,
  require_email_verification BOOLEAN NOT NULL DEFAULT TRUE,
  require_2fa BOOLEAN NOT NULL DEFAULT FALSE,
  allowed_email_domains TEXT[],  -- Restrict signup to specific domains (NULL = any domain)
  sso_config JSONB,  -- SAML/OIDC configuration for Enterprise tier
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Trigger for organizations updated_at
CREATE TRIGGER organizations_updated_at BEFORE UPDATE ON organizations
  FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Trigger for organization_settings updated_at
CREATE TRIGGER organization_settings_updated_at BEFORE UPDATE ON organization_settings
  FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
