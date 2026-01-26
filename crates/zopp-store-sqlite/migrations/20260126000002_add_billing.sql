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

-- Triggers for updated_at
CREATE TRIGGER subscriptions_updated_at AFTER UPDATE ON subscriptions
BEGIN
  UPDATE subscriptions SET updated_at = datetime('now') WHERE id = NEW.id;
END;
