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

-- Trigger for subscriptions updated_at
CREATE TRIGGER subscriptions_updated_at BEFORE UPDATE ON subscriptions
  FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
