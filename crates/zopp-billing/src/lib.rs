//! zopp-billing - Billing integration for zopp cloud
//!
//! This crate provides billing integration for:
//! - Customer management (organization -> billing customer)
//! - Subscription management (per-seat billing)
//! - Webhook handling for subscription events
//!
//! # Architecture
//!
//! The billing system is designed around seat-based pricing:
//! - Each organization has one billing customer
//! - Subscriptions are based on number of seats (organization members)
//! - Seat count is automatically updated when members join/leave
//!
//! # Feature Flags
//!
//! - `stripe`: Enable Stripe integration (adds async-stripe dependency)

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use std::sync::Arc;
use thiserror::Error;
use zopp_storage::{OrganizationId, Plan, Store, StoreError};

mod webhook;
pub use webhook::{
    parse_webhook_event, BillingWebhookEvent, DefaultWebhookHandler, WebhookHandler,
};

/// Billing service errors
#[derive(Debug, Error)]
pub enum BillingError {
    #[error("Billing provider error: {0}")]
    Provider(String),

    #[error("Customer not found")]
    CustomerNotFound,

    #[error("Subscription not found")]
    SubscriptionNotFound,

    #[error("Invalid webhook signature")]
    InvalidWebhookSignature,

    #[error("Organization not found")]
    OrganizationNotFound,

    #[error("Storage error: {0}")]
    Storage(#[from] StoreError),

    #[error("Configuration error: {0}")]
    Config(String),
}

/// Configuration for the billing service
#[derive(Clone)]
pub struct BillingConfig {
    /// API secret key for the billing provider
    pub api_key: String,

    /// Webhook secret for signature verification
    pub webhook_secret: String,

    /// Price ID for the Pro plan (per seat)
    pub pro_price_id: String,

    /// Price ID for the Enterprise plan (per seat)
    pub enterprise_price_id: String,

    /// Trial period in days (default: 14)
    pub trial_days: u32,
}

impl BillingConfig {
    /// Create a new billing configuration from environment variables
    pub fn from_env() -> Result<Self, BillingError> {
        Ok(Self {
            api_key: std::env::var("BILLING_API_KEY")
                .or_else(|_| std::env::var("STRIPE_SECRET_KEY"))
                .map_err(|_| {
                    BillingError::Config("BILLING_API_KEY or STRIPE_SECRET_KEY not set".into())
                })?,
            webhook_secret: std::env::var("BILLING_WEBHOOK_SECRET")
                .or_else(|_| std::env::var("STRIPE_WEBHOOK_SECRET"))
                .map_err(|_| {
                    BillingError::Config(
                        "BILLING_WEBHOOK_SECRET or STRIPE_WEBHOOK_SECRET not set".into(),
                    )
                })?,
            pro_price_id: std::env::var("BILLING_PRO_PRICE_ID")
                .or_else(|_| std::env::var("STRIPE_PRO_PRICE_ID"))
                .map_err(|_| {
                    BillingError::Config(
                        "BILLING_PRO_PRICE_ID or STRIPE_PRO_PRICE_ID not set".into(),
                    )
                })?,
            enterprise_price_id: std::env::var("BILLING_ENTERPRISE_PRICE_ID")
                .or_else(|_| std::env::var("STRIPE_ENTERPRISE_PRICE_ID"))
                .map_err(|_| {
                    BillingError::Config(
                        "BILLING_ENTERPRISE_PRICE_ID or STRIPE_ENTERPRISE_PRICE_ID not set".into(),
                    )
                })?,
            trial_days: match std::env::var("BILLING_TRIAL_DAYS")
                .or_else(|_| std::env::var("STRIPE_TRIAL_DAYS"))
            {
                Ok(v) => v.parse().map_err(|_| {
                    BillingError::Config(format!(
                        "Invalid BILLING_TRIAL_DAYS value '{}': expected a number",
                        v
                    ))
                })?,
                Err(_) => 14, // Default to 14 days if not set
            },
        })
    }

    /// Create a test configuration (for development/testing)
    pub fn test() -> Self {
        Self {
            api_key: "test_api_key".into(),
            webhook_secret: "test_webhook_secret".into(),
            pro_price_id: "price_pro_test".into(),
            enterprise_price_id: "price_enterprise_test".into(),
            trial_days: 14,
        }
    }
}

/// Result of creating a checkout session
#[derive(Debug, Clone)]
pub struct CheckoutSession {
    /// Session ID
    pub session_id: String,

    /// URL to redirect the user to for payment
    pub checkout_url: String,
}

/// Result of creating a billing portal session
#[derive(Debug, Clone)]
pub struct PortalSession {
    /// URL to redirect the user to the billing portal
    pub portal_url: String,
}

/// Subscription status
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubscriptionStatus {
    /// Trial period (no payment required yet)
    Trialing,

    /// Active subscription
    Active,

    /// Past due (payment failed, but still in grace period)
    PastDue,

    /// Canceled (scheduled to end)
    Canceled,

    /// Unpaid (payment failed, subscription suspended)
    Unpaid,

    /// Incomplete (initial payment incomplete)
    Incomplete,
}

impl std::fmt::Display for SubscriptionStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Trialing => write!(f, "trialing"),
            Self::Active => write!(f, "active"),
            Self::PastDue => write!(f, "past_due"),
            Self::Canceled => write!(f, "canceled"),
            Self::Unpaid => write!(f, "unpaid"),
            Self::Incomplete => write!(f, "incomplete"),
        }
    }
}

impl std::str::FromStr for SubscriptionStatus {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "trialing" => Ok(Self::Trialing),
            "active" => Ok(Self::Active),
            "past_due" => Ok(Self::PastDue),
            "canceled" => Ok(Self::Canceled),
            "unpaid" => Ok(Self::Unpaid),
            "incomplete" => Ok(Self::Incomplete),
            _ => Err(format!("Unknown subscription status: {}", s)),
        }
    }
}

/// Subscription information
#[derive(Debug, Clone)]
pub struct Subscription {
    /// Subscription ID
    pub subscription_id: String,

    /// Current status
    pub status: SubscriptionStatus,

    /// Current plan
    pub plan: Plan,

    /// Number of seats in the subscription
    pub seat_count: i32,

    /// Current period start
    pub current_period_start: DateTime<Utc>,

    /// Current period end
    pub current_period_end: DateTime<Utc>,

    /// Whether subscription will cancel at period end
    pub cancel_at_period_end: bool,

    /// Trial end date if in trial
    pub trial_end: Option<DateTime<Utc>>,
}

/// Billing service trait for dependency injection
#[async_trait]
pub trait BillingService: Send + Sync {
    /// Create or get a billing customer for an organization
    async fn ensure_customer(
        &self,
        org_id: &OrganizationId,
        email: &str,
        name: &str,
    ) -> Result<String, BillingError>;

    /// Create a checkout session for upgrading to a paid plan
    async fn create_checkout_session(
        &self,
        org_id: &OrganizationId,
        plan: Plan,
        seat_count: i32,
        success_url: &str,
        cancel_url: &str,
    ) -> Result<CheckoutSession, BillingError>;

    /// Create a billing portal session for managing subscription
    async fn create_portal_session(
        &self,
        org_id: &OrganizationId,
        return_url: &str,
    ) -> Result<PortalSession, BillingError>;

    /// Get the current subscription for an organization
    async fn get_subscription(
        &self,
        org_id: &OrganizationId,
    ) -> Result<Option<Subscription>, BillingError>;

    /// Update the seat count for a subscription
    async fn update_seat_count(
        &self,
        org_id: &OrganizationId,
        new_seat_count: i32,
    ) -> Result<(), BillingError>;

    /// Cancel a subscription at period end
    async fn cancel_subscription(&self, org_id: &OrganizationId) -> Result<(), BillingError>;

    /// Resume a canceled subscription
    async fn resume_subscription(&self, org_id: &OrganizationId) -> Result<(), BillingError>;
}

/// Mock billing service for development and testing
pub struct MockBillingService<S: Store + Send + Sync> {
    #[allow(dead_code)]
    config: BillingConfig,
    store: Arc<S>,
}

impl<S: Store + Send + Sync> MockBillingService<S> {
    /// Create a new mock billing service
    pub fn new(config: BillingConfig, store: Arc<S>) -> Self {
        Self { config, store }
    }
}

#[async_trait]
impl<S: Store + Send + Sync + 'static> BillingService for MockBillingService<S> {
    async fn ensure_customer(
        &self,
        org_id: &OrganizationId,
        _email: &str,
        _name: &str,
    ) -> Result<String, BillingError> {
        // Check if organization already has a customer ID
        let org = self.store.get_organization(org_id).await?;
        if let Some(customer_id) = org.stripe_customer_id {
            return Ok(customer_id);
        }

        // Generate a mock customer ID
        let customer_id = format!("cus_mock_{}", uuid::Uuid::new_v4());

        // Save the customer ID to the organization
        self.store
            .set_organization_stripe_customer(org_id, &customer_id)
            .await?;

        Ok(customer_id)
    }

    async fn create_checkout_session(
        &self,
        org_id: &OrganizationId,
        plan: Plan,
        seat_count: i32,
        success_url: &str,
        _cancel_url: &str,
    ) -> Result<CheckoutSession, BillingError> {
        // Ensure customer exists
        let org = self.store.get_organization(org_id).await?;
        if org.stripe_customer_id.is_none() {
            return Err(BillingError::CustomerNotFound);
        }

        // Generate mock session
        let session_id = format!("cs_mock_{}", uuid::Uuid::new_v4());

        // In development, just redirect to success URL with session ID
        let checkout_url = format!("{}?session_id={}", success_url, session_id);

        tracing::info!(
            org_id = %org_id.0,
            ?plan,
            seat_count,
            "Mock checkout session created"
        );

        Ok(CheckoutSession {
            session_id,
            checkout_url,
        })
    }

    async fn create_portal_session(
        &self,
        org_id: &OrganizationId,
        return_url: &str,
    ) -> Result<PortalSession, BillingError> {
        // Ensure customer exists
        let org = self.store.get_organization(org_id).await?;
        if org.stripe_customer_id.is_none() {
            return Err(BillingError::CustomerNotFound);
        }

        // In development, just redirect to return URL
        Ok(PortalSession {
            portal_url: return_url.to_string(),
        })
    }

    async fn get_subscription(
        &self,
        org_id: &OrganizationId,
    ) -> Result<Option<Subscription>, BillingError> {
        let org = self.store.get_organization(org_id).await?;

        // If not on free plan, simulate an active subscription
        if org.plan != Plan::Free {
            let now = Utc::now();
            let period_end = now + chrono::Duration::days(30);

            Ok(Some(Subscription {
                subscription_id: format!("sub_mock_{}", org_id.0),
                status: SubscriptionStatus::Active,
                plan: org.plan,
                seat_count: org.seat_limit,
                current_period_start: now,
                current_period_end: period_end,
                cancel_at_period_end: false,
                trial_end: org.trial_ends_at,
            }))
        } else {
            Ok(None)
        }
    }

    async fn update_seat_count(
        &self,
        org_id: &OrganizationId,
        new_seat_count: i32,
    ) -> Result<(), BillingError> {
        let org = self.store.get_organization(org_id).await?;

        // Update the seat count in the organization
        self.store
            .set_organization_plan(org_id, org.plan, new_seat_count)
            .await?;

        tracing::info!(
            org_id = %org_id.0,
            new_seat_count,
            "Mock seat count updated"
        );

        Ok(())
    }

    async fn cancel_subscription(&self, org_id: &OrganizationId) -> Result<(), BillingError> {
        let org = self.store.get_organization(org_id).await?;

        if org.plan == Plan::Free {
            return Err(BillingError::SubscriptionNotFound);
        }

        tracing::info!(
            org_id = %org_id.0,
            "Mock subscription canceled"
        );

        Ok(())
    }

    async fn resume_subscription(&self, org_id: &OrganizationId) -> Result<(), BillingError> {
        let org = self.store.get_organization(org_id).await?;

        if org.plan == Plan::Free {
            return Err(BillingError::SubscriptionNotFound);
        }

        tracing::info!(
            org_id = %org_id.0,
            "Mock subscription resumed"
        );

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_subscription_status_display() {
        assert_eq!(SubscriptionStatus::Trialing.to_string(), "trialing");
        assert_eq!(SubscriptionStatus::Active.to_string(), "active");
        assert_eq!(SubscriptionStatus::PastDue.to_string(), "past_due");
    }

    #[test]
    fn test_subscription_status_from_str() {
        assert_eq!(
            "trialing".parse::<SubscriptionStatus>().unwrap(),
            SubscriptionStatus::Trialing
        );
        assert_eq!(
            "active".parse::<SubscriptionStatus>().unwrap(),
            SubscriptionStatus::Active
        );
    }

    #[test]
    fn test_billing_config_test() {
        let config = BillingConfig::test();
        assert_eq!(config.trial_days, 14);
    }
}
