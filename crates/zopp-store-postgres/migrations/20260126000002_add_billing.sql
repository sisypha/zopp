-- Subscription history (tracks Stripe subscription state)
CREATE TABLE IF NOT EXISTS subscriptions (
  id UUID PRIMARY KEY NOT NULL,
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  stripe_subscription_id TEXT NOT NULL,
  stripe_price_id TEXT NOT NULL,
  plan TEXT NOT NULL,  -- 'pro', 'enterprise'
  status TEXT NOT NULL,  -- 'active', 'past_due', 'canceled', 'trialing', 'incomplete'
  current_period_start TIMESTAMPTZ NOT NULL,
  current_period_end TIMESTAMPTZ NOT NULL,
  cancel_at_period_end BOOLEAN NOT NULL DEFAULT FALSE,
  canceled_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Index for looking up subscriptions by organization
CREATE INDEX idx_subscriptions_organization ON subscriptions(organization_id);
-- Index for looking up by Stripe subscription ID
CREATE UNIQUE INDEX idx_subscriptions_stripe_id ON subscriptions(stripe_subscription_id);

-- Payment history (from Stripe webhooks)
CREATE TABLE IF NOT EXISTS payments (
  id UUID PRIMARY KEY NOT NULL,
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  stripe_payment_intent_id TEXT UNIQUE,
  stripe_invoice_id TEXT UNIQUE,
  amount_cents INTEGER NOT NULL,
  currency TEXT NOT NULL DEFAULT 'usd',
  status TEXT NOT NULL,  -- 'succeeded', 'pending', 'failed', 'refunded'
  description TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Index for looking up payments by organization
CREATE INDEX idx_payments_organization ON payments(organization_id);
CREATE INDEX idx_payments_created_at ON payments(created_at);

-- Real-time quota counters (for enforcement)
CREATE TABLE IF NOT EXISTS organization_quotas (
  organization_id UUID PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE,
  current_users INTEGER NOT NULL DEFAULT 0,
  current_workspaces INTEGER NOT NULL DEFAULT 0,
  current_secrets INTEGER NOT NULL DEFAULT 0,
  api_calls_this_month BIGINT NOT NULL DEFAULT 0,
  api_calls_reset_at TIMESTAMPTZ NOT NULL DEFAULT date_trunc('month', NOW()) + INTERVAL '1 month',
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Usage metrics (aggregated daily for billing/analytics)
CREATE TABLE IF NOT EXISTS usage_metrics (
  id UUID PRIMARY KEY NOT NULL,
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  metric_date DATE NOT NULL,
  users_count INTEGER NOT NULL DEFAULT 0,
  workspaces_count INTEGER NOT NULL DEFAULT 0,
  projects_count INTEGER NOT NULL DEFAULT 0,
  environments_count INTEGER NOT NULL DEFAULT 0,
  secrets_count INTEGER NOT NULL DEFAULT 0,
  api_calls_count BIGINT NOT NULL DEFAULT 0,
  storage_bytes BIGINT NOT NULL DEFAULT 0,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(organization_id, metric_date)
);

-- Index for querying metrics by date range
CREATE INDEX idx_usage_metrics_org_date ON usage_metrics(organization_id, metric_date);

-- Rate limiting buckets (token bucket algorithm state)
CREATE TABLE IF NOT EXISTS rate_limit_buckets (
  id UUID PRIMARY KEY NOT NULL,
  bucket_key TEXT NOT NULL UNIQUE,  -- "org:{org_id}", "user:{user_id}", "ip:{ip}"
  tokens INTEGER NOT NULL,
  max_tokens INTEGER NOT NULL,
  refill_rate INTEGER NOT NULL,  -- tokens per second
  last_refill TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Index for efficient bucket lookup
CREATE INDEX idx_rate_limit_buckets_key ON rate_limit_buckets(bucket_key);

-- Trigger for subscriptions updated_at
CREATE TRIGGER subscriptions_updated_at BEFORE UPDATE ON subscriptions
  FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Trigger for organization_quotas updated_at
CREATE TRIGGER organization_quotas_updated_at BEFORE UPDATE ON organization_quotas
  FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
