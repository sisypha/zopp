-- Subscription history (tracks Stripe subscription state)
CREATE TABLE IF NOT EXISTS subscriptions (
  id TEXT PRIMARY KEY NOT NULL,  -- UUID as TEXT
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  stripe_subscription_id TEXT NOT NULL,
  stripe_price_id TEXT NOT NULL,
  plan TEXT NOT NULL,  -- 'pro', 'enterprise'
  status TEXT NOT NULL,  -- 'active', 'past_due', 'canceled', 'trialing', 'incomplete'
  current_period_start TEXT NOT NULL,  -- ISO8601 timestamp
  current_period_end TEXT NOT NULL,  -- ISO8601 timestamp
  cancel_at_period_end INTEGER NOT NULL DEFAULT 0,  -- Boolean as INTEGER
  canceled_at TEXT,  -- ISO8601 timestamp
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Index for looking up subscriptions by organization
CREATE INDEX idx_subscriptions_organization ON subscriptions(organization_id);
-- Index for looking up by Stripe subscription ID
CREATE UNIQUE INDEX idx_subscriptions_stripe_id ON subscriptions(stripe_subscription_id);

-- Payment history (from Stripe webhooks)
CREATE TABLE IF NOT EXISTS payments (
  id TEXT PRIMARY KEY NOT NULL,  -- UUID as TEXT
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  stripe_payment_intent_id TEXT UNIQUE,
  stripe_invoice_id TEXT UNIQUE,
  amount_cents INTEGER NOT NULL,
  currency TEXT NOT NULL DEFAULT 'usd',
  status TEXT NOT NULL,  -- 'succeeded', 'pending', 'failed', 'refunded'
  description TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Index for looking up payments by organization
CREATE INDEX idx_payments_organization ON payments(organization_id);
CREATE INDEX idx_payments_created_at ON payments(created_at);

-- Real-time quota counters (for enforcement)
CREATE TABLE IF NOT EXISTS organization_quotas (
  organization_id TEXT PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE,
  current_users INTEGER NOT NULL DEFAULT 0,
  current_workspaces INTEGER NOT NULL DEFAULT 0,
  current_secrets INTEGER NOT NULL DEFAULT 0,
  api_calls_this_month INTEGER NOT NULL DEFAULT 0,  -- SQLite doesn't have BIGINT, but INTEGER is 64-bit
  api_calls_reset_at TEXT NOT NULL DEFAULT (datetime('now', 'start of month', '+1 month')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Usage metrics (aggregated daily for billing/analytics)
CREATE TABLE IF NOT EXISTS usage_metrics (
  id TEXT PRIMARY KEY NOT NULL,  -- UUID as TEXT
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  metric_date TEXT NOT NULL,  -- DATE as TEXT (YYYY-MM-DD)
  users_count INTEGER NOT NULL DEFAULT 0,
  workspaces_count INTEGER NOT NULL DEFAULT 0,
  projects_count INTEGER NOT NULL DEFAULT 0,
  environments_count INTEGER NOT NULL DEFAULT 0,
  secrets_count INTEGER NOT NULL DEFAULT 0,
  api_calls_count INTEGER NOT NULL DEFAULT 0,
  storage_bytes INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  UNIQUE(organization_id, metric_date)
);

-- Index for querying metrics by date range
CREATE INDEX idx_usage_metrics_org_date ON usage_metrics(organization_id, metric_date);

-- Rate limiting buckets (token bucket algorithm state)
CREATE TABLE IF NOT EXISTS rate_limit_buckets (
  id TEXT PRIMARY KEY NOT NULL,  -- UUID as TEXT
  bucket_key TEXT NOT NULL UNIQUE,  -- "org:{org_id}", "user:{user_id}", "ip:{ip}"
  tokens INTEGER NOT NULL,
  max_tokens INTEGER NOT NULL,
  refill_rate INTEGER NOT NULL,  -- tokens per second
  last_refill TEXT NOT NULL DEFAULT (datetime('now')),
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Index for efficient bucket lookup
CREATE INDEX idx_rate_limit_buckets_key ON rate_limit_buckets(bucket_key);

-- Triggers for updated_at
CREATE TRIGGER subscriptions_updated_at AFTER UPDATE ON subscriptions
BEGIN
  UPDATE subscriptions SET updated_at = datetime('now') WHERE id = NEW.id;
END;

CREATE TRIGGER organization_quotas_updated_at AFTER UPDATE ON organization_quotas
BEGIN
  UPDATE organization_quotas SET updated_at = datetime('now') WHERE organization_id = NEW.organization_id;
END;
