//! Billing webhook handling
//!
//! Handles incoming billing provider webhook events to keep billing state in sync.

use crate::{BillingError, SubscriptionStatus};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use std::sync::Arc;
use tracing::{info, warn};
use zopp_storage::{OrganizationId, Plan, Store};

/// Parsed billing webhook event
#[derive(Debug, Clone)]
pub enum BillingWebhookEvent {
    /// Subscription was created
    SubscriptionCreated {
        subscription_id: String,
        customer_id: String,
        plan: Plan,
        seat_count: i32,
        status: SubscriptionStatus,
        trial_end: Option<DateTime<Utc>>,
    },

    /// Subscription was updated (plan change, seat change, etc.)
    SubscriptionUpdated {
        subscription_id: String,
        customer_id: String,
        plan: Plan,
        seat_count: i32,
        status: SubscriptionStatus,
        cancel_at_period_end: bool,
    },

    /// Subscription was deleted/canceled
    SubscriptionDeleted {
        subscription_id: String,
        customer_id: String,
    },

    /// Invoice was paid successfully
    InvoicePaid {
        invoice_id: String,
        customer_id: String,
        amount_paid: i64,
    },

    /// Invoice payment failed
    InvoicePaymentFailed {
        invoice_id: String,
        customer_id: String,
        attempt_count: i32,
    },

    /// Checkout session completed
    CheckoutCompleted {
        session_id: String,
        customer_id: String,
        subscription_id: Option<String>,
    },

    /// Unknown or unhandled event
    Unknown { event_type: String },
}

/// Handler for billing webhook events
#[async_trait]
pub trait WebhookHandler: Send + Sync {
    /// Handle an incoming webhook event
    async fn handle_event(&self, event: BillingWebhookEvent) -> Result<(), BillingError>;
}

/// Default webhook handler implementation
pub struct DefaultWebhookHandler<S: Store + Send + Sync> {
    store: Arc<S>,
}

impl<S: Store + Send + Sync> DefaultWebhookHandler<S> {
    /// Create a new webhook handler
    pub fn new(store: Arc<S>) -> Self {
        Self { store }
    }

    /// Find organization by billing customer ID
    ///
    /// Note: In production, you'd want a lookup table/index for this
    async fn find_org_by_customer(
        &self,
        _customer_id: &str,
    ) -> Result<OrganizationId, BillingError> {
        // TODO: Implement customer_id -> org_id lookup
        // For now, this would need to scan organizations
        Err(BillingError::OrganizationNotFound)
    }
}

#[async_trait]
impl<S: Store + Send + Sync + 'static> WebhookHandler for DefaultWebhookHandler<S> {
    async fn handle_event(&self, event: BillingWebhookEvent) -> Result<(), BillingError> {
        match event {
            BillingWebhookEvent::SubscriptionCreated {
                subscription_id,
                customer_id,
                plan,
                seat_count,
                status,
                trial_end: _,
            } => {
                info!(
                    %subscription_id,
                    %customer_id,
                    ?plan,
                    seat_count,
                    ?status,
                    "Subscription created"
                );

                // Find organization by customer ID and update plan
                match self.find_org_by_customer(&customer_id).await {
                    Ok(org_id) => {
                        self.store
                            .set_organization_plan(&org_id, plan, seat_count)
                            .await?;
                        info!(?org_id, ?plan, "Organization plan updated");
                    }
                    Err(BillingError::OrganizationNotFound) => {
                        warn!(
                            %customer_id,
                            "Could not find organization for customer"
                        );
                    }
                    Err(e) => return Err(e),
                }

                Ok(())
            }

            BillingWebhookEvent::SubscriptionUpdated {
                subscription_id,
                customer_id,
                plan,
                seat_count,
                status,
                cancel_at_period_end,
            } => {
                info!(
                    %subscription_id,
                    %customer_id,
                    ?plan,
                    seat_count,
                    ?status,
                    cancel_at_period_end,
                    "Subscription updated"
                );

                // Update organization plan if subscription is active
                if status == SubscriptionStatus::Active || status == SubscriptionStatus::Trialing {
                    match self.find_org_by_customer(&customer_id).await {
                        Ok(org_id) => {
                            self.store
                                .set_organization_plan(&org_id, plan, seat_count)
                                .await?;
                        }
                        Err(BillingError::OrganizationNotFound) => {
                            warn!(
                                %customer_id,
                                "Could not find organization for customer"
                            );
                        }
                        Err(e) => return Err(e),
                    }
                }

                Ok(())
            }

            BillingWebhookEvent::SubscriptionDeleted {
                subscription_id,
                customer_id,
            } => {
                info!(
                    %subscription_id,
                    %customer_id,
                    "Subscription deleted"
                );

                // Downgrade organization to free plan
                match self.find_org_by_customer(&customer_id).await {
                    Ok(org_id) => {
                        // Default to 5 seats for free plan
                        self.store
                            .set_organization_plan(&org_id, Plan::Free, 5)
                            .await?;
                        info!(?org_id, "Organization downgraded to free plan");
                    }
                    Err(BillingError::OrganizationNotFound) => {
                        warn!(
                            %customer_id,
                            "Could not find organization for customer"
                        );
                    }
                    Err(e) => return Err(e),
                }

                Ok(())
            }

            BillingWebhookEvent::InvoicePaid {
                invoice_id,
                customer_id,
                amount_paid,
            } => {
                info!(
                    %invoice_id,
                    %customer_id,
                    amount_paid,
                    "Invoice paid"
                );
                // Could record payment for audit purposes
                Ok(())
            }

            BillingWebhookEvent::InvoicePaymentFailed {
                invoice_id,
                customer_id,
                attempt_count,
            } => {
                warn!(
                    %invoice_id,
                    %customer_id,
                    attempt_count,
                    "Invoice payment failed"
                );
                // Could notify organization admins
                Ok(())
            }

            BillingWebhookEvent::CheckoutCompleted {
                session_id,
                customer_id,
                subscription_id,
            } => {
                info!(
                    %session_id,
                    %customer_id,
                    ?subscription_id,
                    "Checkout completed"
                );
                // Subscription events will handle plan updates
                Ok(())
            }

            BillingWebhookEvent::Unknown { event_type } => {
                info!(%event_type, "Unhandled webhook event type");
                Ok(())
            }
        }
    }
}

/// Parse a raw webhook payload into an event
///
/// # Arguments
/// * `payload` - Raw webhook body
/// * `signature` - Webhook signature header value (e.g., Stripe-Signature header)
/// * `webhook_secret` - Your webhook endpoint secret (empty string to disable verification)
///
/// # Returns
/// Parsed event or error
///
/// # Security
/// When `webhook_secret` is configured, this function REQUIRES a valid signature.
/// Signature verification is not yet implemented, so providing a webhook_secret
/// will cause all requests to fail (fail-closed behavior for security).
///
/// For development/testing, pass an empty `webhook_secret` to skip verification.
pub fn parse_webhook_event(
    payload: &str,
    signature: &str,
    webhook_secret: &str,
) -> Result<BillingWebhookEvent, BillingError> {
    // SECURITY: When webhook_secret is configured, we MUST verify signatures.
    // This prevents attackers from forging billing events.
    if !webhook_secret.is_empty() {
        // Webhook secret is configured - signature verification is REQUIRED
        if signature.is_empty() {
            // CRITICAL: Reject requests with missing signature when secret is configured.
            // An attacker could bypass verification by omitting the signature header.
            return Err(BillingError::Provider(
                "Missing webhook signature. Signature verification is required when \
                 webhook_secret is configured."
                    .into(),
            ));
        }

        // TODO: Implement proper HMAC-SHA256 signature verification
        // For Stripe: verify using stripe-rust or manual HMAC verification
        //
        // Fail closed: reject events when signature verification is not implemented
        // but credentials are provided (indicates production use)
        return Err(BillingError::Provider(
            "Webhook signature verification not implemented. \
             Remove webhook_secret for development, \
             or implement HMAC verification for production."
                .into(),
        ));
    }

    // Parse JSON payload
    let value: serde_json::Value =
        serde_json::from_str(payload).map_err(|e| BillingError::Provider(e.to_string()))?;

    let event_type = value["type"]
        .as_str()
        .ok_or_else(|| BillingError::Provider("Missing event type".into()))?;

    match event_type {
        "customer.subscription.created" => {
            let sub = &value["data"]["object"];
            Ok(BillingWebhookEvent::SubscriptionCreated {
                subscription_id: sub["id"].as_str().unwrap_or("").to_string(),
                customer_id: sub["customer"].as_str().unwrap_or("").to_string(),
                plan: parse_plan_from_price(
                    sub["items"]["data"][0]["price"]["id"]
                        .as_str()
                        .unwrap_or(""),
                ),
                seat_count: sub["items"]["data"][0]["quantity"].as_i64().unwrap_or(1) as i32,
                status: parse_subscription_status(sub["status"].as_str().unwrap_or("active")),
                trial_end: sub["trial_end"]
                    .as_i64()
                    .and_then(|ts| DateTime::from_timestamp(ts, 0)),
            })
        }

        "customer.subscription.updated" => {
            let sub = &value["data"]["object"];
            Ok(BillingWebhookEvent::SubscriptionUpdated {
                subscription_id: sub["id"].as_str().unwrap_or("").to_string(),
                customer_id: sub["customer"].as_str().unwrap_or("").to_string(),
                plan: parse_plan_from_price(
                    sub["items"]["data"][0]["price"]["id"]
                        .as_str()
                        .unwrap_or(""),
                ),
                seat_count: sub["items"]["data"][0]["quantity"].as_i64().unwrap_or(1) as i32,
                status: parse_subscription_status(sub["status"].as_str().unwrap_or("active")),
                cancel_at_period_end: sub["cancel_at_period_end"].as_bool().unwrap_or(false),
            })
        }

        "customer.subscription.deleted" => {
            let sub = &value["data"]["object"];
            Ok(BillingWebhookEvent::SubscriptionDeleted {
                subscription_id: sub["id"].as_str().unwrap_or("").to_string(),
                customer_id: sub["customer"].as_str().unwrap_or("").to_string(),
            })
        }

        "invoice.paid" => {
            let invoice = &value["data"]["object"];
            Ok(BillingWebhookEvent::InvoicePaid {
                invoice_id: invoice["id"].as_str().unwrap_or("").to_string(),
                customer_id: invoice["customer"].as_str().unwrap_or("").to_string(),
                amount_paid: invoice["amount_paid"].as_i64().unwrap_or(0),
            })
        }

        "invoice.payment_failed" => {
            let invoice = &value["data"]["object"];
            Ok(BillingWebhookEvent::InvoicePaymentFailed {
                invoice_id: invoice["id"].as_str().unwrap_or("").to_string(),
                customer_id: invoice["customer"].as_str().unwrap_or("").to_string(),
                attempt_count: invoice["attempt_count"].as_i64().unwrap_or(0) as i32,
            })
        }

        "checkout.session.completed" => {
            let session = &value["data"]["object"];
            Ok(BillingWebhookEvent::CheckoutCompleted {
                session_id: session["id"].as_str().unwrap_or("").to_string(),
                customer_id: session["customer"].as_str().unwrap_or("").to_string(),
                subscription_id: session["subscription"].as_str().map(|s| s.to_string()),
            })
        }

        _ => Ok(BillingWebhookEvent::Unknown {
            event_type: event_type.to_string(),
        }),
    }
}

fn parse_subscription_status(status: &str) -> SubscriptionStatus {
    match status {
        "trialing" => SubscriptionStatus::Trialing,
        "active" => SubscriptionStatus::Active,
        "past_due" => SubscriptionStatus::PastDue,
        "canceled" => SubscriptionStatus::Canceled,
        "unpaid" => SubscriptionStatus::Unpaid,
        "incomplete" => SubscriptionStatus::Incomplete,
        // Default to Incomplete for unknown statuses to avoid granting unintended access
        unknown => {
            warn!(%unknown, "Unknown subscription status, defaulting to Incomplete");
            SubscriptionStatus::Incomplete
        }
    }
}

fn parse_plan_from_price(price_id: &str) -> Plan {
    // TODO: In production, implement proper price ID to Plan mapping using BillingConfig
    // For now, default to Free to avoid granting unintended paid features
    if !price_id.is_empty() {
        warn!(
            %price_id,
            "Price ID to Plan mapping not implemented, defaulting to Free plan"
        );
    }
    Plan::Free
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_subscription_created() {
        let payload = r#"{
            "type": "customer.subscription.created",
            "data": {
                "object": {
                    "id": "sub_123",
                    "customer": "cus_456",
                    "status": "trialing",
                    "trial_end": 1735689600,
                    "items": {
                        "data": [
                            {
                                "price": {"id": "price_pro"},
                                "quantity": 5
                            }
                        ]
                    }
                }
            }
        }"#;

        let event = parse_webhook_event(payload, "", "").unwrap();
        match event {
            BillingWebhookEvent::SubscriptionCreated {
                subscription_id,
                customer_id,
                seat_count,
                status,
                ..
            } => {
                assert_eq!(subscription_id, "sub_123");
                assert_eq!(customer_id, "cus_456");
                assert_eq!(seat_count, 5);
                assert_eq!(status, SubscriptionStatus::Trialing);
            }
            _ => panic!("Expected SubscriptionCreated event"),
        }
    }

    #[test]
    fn test_parse_unknown_event() {
        let payload = r#"{"type": "some.unknown.event", "data": {}}"#;
        let event = parse_webhook_event(payload, "", "").unwrap();
        match event {
            BillingWebhookEvent::Unknown { event_type } => {
                assert_eq!(event_type, "some.unknown.event");
            }
            _ => panic!("Expected Unknown event"),
        }
    }

    #[test]
    fn test_missing_signature_with_secret_configured_is_rejected() {
        // SECURITY: When webhook_secret is configured, missing signature MUST be rejected
        // to prevent attackers from bypassing signature verification
        let payload = r#"{"type": "customer.subscription.created", "data": {"object": {}}}"#;
        let result = parse_webhook_event(payload, "", "whsec_test_secret");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("Missing webhook signature"),
            "Expected 'Missing webhook signature' error, got: {}",
            err
        );
    }

    #[test]
    fn test_signature_verification_not_implemented_error() {
        // When both signature and secret are provided, we should get "not implemented" error
        // (until proper HMAC verification is added)
        let payload = r#"{"type": "customer.subscription.created", "data": {"object": {}}}"#;
        let result = parse_webhook_event(payload, "t=123,v1=abc", "whsec_test_secret");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("not implemented"),
            "Expected 'not implemented' error, got: {}",
            err
        );
    }

    #[test]
    fn test_no_secret_skips_verification() {
        // When no webhook_secret is configured (development mode), verification is skipped
        let payload = r#"{"type": "customer.subscription.created", "data": {"object": {"id": "sub_1", "customer": "cus_1", "status": "active", "items": {"data": [{"price": {"id": "p"}, "quantity": 1}]}}}}"#;
        let result = parse_webhook_event(payload, "", "");
        assert!(
            result.is_ok(),
            "Expected success in dev mode, got: {:?}",
            result
        );
    }
}
