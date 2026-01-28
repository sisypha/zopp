//! Organization types for billing and team management.

use chrono::{DateTime, Utc};

use super::{
    OrganizationId, OrganizationInviteId, OrganizationRole, Plan, SubscriptionId,
    SubscriptionStatus, UserId,
};

/// Organization record (billing unit)
#[derive(Clone, Debug)]
pub struct Organization {
    pub id: OrganizationId,
    pub name: String,
    pub slug: String,
    pub stripe_customer_id: Option<String>,
    pub stripe_subscription_id: Option<String>,
    pub plan: Plan,
    pub seat_limit: i32,
    pub trial_ends_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Organization member record
#[derive(Clone, Debug)]
pub struct OrganizationMember {
    pub organization_id: OrganizationId,
    pub user_id: UserId,
    pub role: OrganizationRole,
    pub invited_by: Option<UserId>,
    pub joined_at: DateTime<Utc>,
}

/// Pending organization invite
#[derive(Clone, Debug)]
pub struct OrganizationInvite {
    pub id: OrganizationInviteId,
    pub organization_id: OrganizationId,
    pub email: String,
    pub role: OrganizationRole,
    pub token_hash: String,
    pub invited_by: UserId,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

/// Organization settings
#[derive(Clone, Debug)]
pub struct OrganizationSettings {
    pub organization_id: OrganizationId,
    pub require_email_verification: bool,
    pub require_2fa: bool,
    pub allowed_email_domains: Option<Vec<String>>,
    pub sso_config: Option<String>, // JSON string
    pub updated_at: DateTime<Utc>,
}

/// Subscription record
#[derive(Clone, Debug)]
pub struct Subscription {
    pub id: SubscriptionId,
    pub organization_id: OrganizationId,
    pub stripe_subscription_id: String,
    pub stripe_price_id: String,
    pub plan: Plan,
    pub status: SubscriptionStatus,
    pub current_period_start: DateTime<Utc>,
    pub current_period_end: DateTime<Utc>,
    pub cancel_at_period_end: bool,
    pub canceled_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Parameters for creating an organization
#[derive(Clone, Debug)]
pub struct CreateOrganizationParams {
    pub name: String,
    pub slug: String,
    pub owner_user_id: UserId,
    pub plan: Plan,
}

/// Parameters for creating an organization invite
#[derive(Clone, Debug)]
pub struct CreateOrganizationInviteParams {
    pub organization_id: OrganizationId,
    pub email: String,
    pub role: OrganizationRole,
    pub token_hash: String,
    pub invited_by: UserId,
    pub expires_at: DateTime<Utc>,
}
