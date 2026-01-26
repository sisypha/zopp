//! Billing handlers: subscription, payments, checkout, portal
//!
//! These handlers manage billing operations for organizations.

use tonic::{Request, Response, Status};
use url::Url;
use uuid::Uuid;
use zopp_proto::{
    BillingPortalSession, CheckoutSession, CreateBillingPortalSessionRequest,
    CreateCheckoutSessionRequest, GetSubscriptionRequest, ListPaymentsRequest, PaymentList, Plan,
    Subscription, SubscriptionStatus,
};
use zopp_storage::{OrganizationId, Store};

use crate::server::{extract_signature, ZoppServer};

/// Validate that a redirect URL belongs to a trusted domain.
///
/// SECURITY: This prevents open redirect attacks where an attacker could
/// redirect users to a malicious site after billing operations.
fn validate_redirect_url(url_str: &str) -> Result<Url, Status> {
    let url = Url::parse(url_str).map_err(|_| Status::invalid_argument("Invalid URL format"))?;

    // Only allow HTTPS URLs (except localhost for development)
    let scheme = url.scheme();
    if scheme != "https" && !(scheme == "http" && is_localhost(&url)) {
        return Err(Status::invalid_argument("Only HTTPS URLs are allowed"));
    }

    // Validate against trusted domains
    // In production, this should be configurable via environment variable
    let trusted_domains = ["app.zopp.dev", "zopp.dev", "localhost", "127.0.0.1"];

    let host = url
        .host_str()
        .ok_or_else(|| Status::invalid_argument("URL must have a host"))?;

    // Check if host matches or is a subdomain of a trusted domain
    let is_trusted = trusted_domains
        .iter()
        .any(|&domain| host == domain || host.ends_with(&format!(".{}", domain)));

    if !is_trusted {
        return Err(Status::invalid_argument(
            "Redirect URL must point to a trusted domain",
        ));
    }

    Ok(url)
}

/// Check if URL points to localhost (for development)
fn is_localhost(url: &Url) -> bool {
    matches!(url.host_str(), Some("localhost") | Some("127.0.0.1"))
}

/// Append a query parameter to a URL, handling existing query strings correctly.
fn append_query_param(url: &Url, key: &str, value: &str) -> String {
    let mut url = url.clone();
    url.query_pairs_mut().append_pair(key, value);
    url.to_string()
}

/// Get subscription for an organization
pub async fn get_subscription(
    server: &ZoppServer,
    request: Request<GetSubscriptionRequest>,
) -> Result<Response<Subscription>, Status> {
    let (principal_id, timestamp, signature, request_hash) = extract_signature(&request)?;
    let req_for_verify = request.get_ref().clone();
    let principal = server
        .verify_signature_and_get_principal(
            &principal_id,
            timestamp,
            &signature,
            "/zopp.ZoppService/GetSubscription",
            &req_for_verify,
            &request_hash,
        )
        .await?;
    let req = request.into_inner();

    // Parse organization ID
    let org_id = OrganizationId(
        Uuid::parse_str(&req.organization_id)
            .map_err(|_| Status::invalid_argument("Invalid organization ID"))?,
    );

    // Get the organization
    let org = server
        .store
        .get_organization(&org_id)
        .await
        .map_err(|e| Status::internal(format!("Failed to get organization: {}", e)))?;

    // Verify the user is a member of the organization
    let user_id = principal
        .user_id
        .ok_or_else(|| Status::permission_denied("Service accounts cannot access billing"))?;

    let _member = server
        .store
        .get_organization_member(&org_id, &user_id)
        .await
        .map_err(|_| Status::permission_denied("Not a member of this organization"))?;

    // Convert plan to proto
    let plan = match org.plan {
        zopp_storage::Plan::Free => Plan::Free,
        zopp_storage::Plan::Pro => Plan::Pro,
        zopp_storage::Plan::Enterprise => Plan::Enterprise,
    };

    // If organization has no subscription, return a "no subscription" response
    let subscription_id = org.stripe_subscription_id.clone().unwrap_or_default();
    if subscription_id.is_empty() && org.plan == zopp_storage::Plan::Free {
        return Err(Status::not_found("No active subscription"));
    }

    // Build subscription response from organization data
    let now = chrono::Utc::now();
    let period_end = now + chrono::Duration::days(30);

    Ok(Response::new(Subscription {
        id: format!("sub_{}", org_id.0),
        organization_id: org_id.0.to_string(),
        stripe_subscription_id: subscription_id,
        stripe_price_id: match org.plan {
            zopp_storage::Plan::Free => String::new(),
            zopp_storage::Plan::Pro => "price_pro".to_string(),
            zopp_storage::Plan::Enterprise => "price_enterprise".to_string(),
        },
        plan: plan.into(),
        status: if org.trial_ends_at.is_some() && org.trial_ends_at.unwrap() > now {
            SubscriptionStatus::SubscriptionTrialing.into()
        } else {
            SubscriptionStatus::SubscriptionActive.into()
        },
        current_period_start: now.to_rfc3339(),
        current_period_end: period_end.to_rfc3339(),
        cancel_at_period_end: false,
        canceled_at: None,
        created_at: org.created_at.to_rfc3339(),
        updated_at: org.updated_at.to_rfc3339(),
    }))
}

/// List payments for an organization
pub async fn list_payments(
    server: &ZoppServer,
    request: Request<ListPaymentsRequest>,
) -> Result<Response<PaymentList>, Status> {
    let (principal_id, timestamp, signature, request_hash) = extract_signature(&request)?;
    let req_for_verify = request.get_ref().clone();
    let principal = server
        .verify_signature_and_get_principal(
            &principal_id,
            timestamp,
            &signature,
            "/zopp.ZoppService/ListPayments",
            &req_for_verify,
            &request_hash,
        )
        .await?;
    let req = request.into_inner();

    // Parse organization ID
    let org_id = OrganizationId(
        Uuid::parse_str(&req.organization_id)
            .map_err(|_| Status::invalid_argument("Invalid organization ID"))?,
    );

    // Verify the user is a member of the organization
    let user_id = principal
        .user_id
        .ok_or_else(|| Status::permission_denied("Service accounts cannot access billing"))?;

    let _member = server
        .store
        .get_organization_member(&org_id, &user_id)
        .await
        .map_err(|_| Status::permission_denied("Not a member of this organization"))?;

    // TODO: Implement payment history storage and retrieval
    // For now, return empty list
    Ok(Response::new(PaymentList { payments: vec![] }))
}

/// Create a checkout session for upgrading to a paid plan
pub async fn create_checkout_session(
    server: &ZoppServer,
    request: Request<CreateCheckoutSessionRequest>,
) -> Result<Response<CheckoutSession>, Status> {
    let (principal_id, timestamp, signature, request_hash) = extract_signature(&request)?;
    let req_for_verify = request.get_ref().clone();
    let principal = server
        .verify_signature_and_get_principal(
            &principal_id,
            timestamp,
            &signature,
            "/zopp.ZoppService/CreateCheckoutSession",
            &req_for_verify,
            &request_hash,
        )
        .await?;
    let req = request.into_inner();

    // Parse organization ID
    let org_id = OrganizationId(
        Uuid::parse_str(&req.organization_id)
            .map_err(|_| Status::invalid_argument("Invalid organization ID"))?,
    );

    // Get the organization
    let org = server
        .store
        .get_organization(&org_id)
        .await
        .map_err(|e| Status::internal(format!("Failed to get organization: {}", e)))?;

    // Verify the user is an admin of the organization
    let user_id = principal
        .user_id
        .ok_or_else(|| Status::permission_denied("Service accounts cannot access billing"))?;

    let member = server
        .store
        .get_organization_member(&org_id, &user_id)
        .await
        .map_err(|_| Status::permission_denied("Not a member of this organization"))?;

    // Only owners and admins can create checkout sessions
    if member.role != zopp_storage::OrganizationRole::Owner
        && member.role != zopp_storage::OrganizationRole::Admin
    {
        return Err(Status::permission_denied(
            "Only organization owners and admins can manage billing",
        ));
    }

    // Check if organization has a Stripe customer
    if org.stripe_customer_id.is_none() {
        return Err(Status::failed_precondition(
            "Organization has no billing customer. Contact support to set up billing.",
        ));
    }

    // SECURITY: Validate success_url to prevent open redirect attacks
    let success_url = validate_redirect_url(&req.success_url)?;

    // TODO: Integrate with billing service to create actual Stripe checkout session
    // For now, return a mock URL for development
    let session_id = format!("cs_mock_{}", uuid::Uuid::new_v4());
    let checkout_url = append_query_param(&success_url, "session_id", &session_id);

    Ok(Response::new(CheckoutSession { url: checkout_url }))
}

/// Create a billing portal session for managing subscription
pub async fn create_billing_portal_session(
    server: &ZoppServer,
    request: Request<CreateBillingPortalSessionRequest>,
) -> Result<Response<BillingPortalSession>, Status> {
    let (principal_id, timestamp, signature, request_hash) = extract_signature(&request)?;
    let req_for_verify = request.get_ref().clone();
    let principal = server
        .verify_signature_and_get_principal(
            &principal_id,
            timestamp,
            &signature,
            "/zopp.ZoppService/CreateBillingPortalSession",
            &req_for_verify,
            &request_hash,
        )
        .await?;
    let req = request.into_inner();

    // Parse organization ID
    let org_id = OrganizationId(
        Uuid::parse_str(&req.organization_id)
            .map_err(|_| Status::invalid_argument("Invalid organization ID"))?,
    );

    // Get the organization
    let org = server
        .store
        .get_organization(&org_id)
        .await
        .map_err(|e| Status::internal(format!("Failed to get organization: {}", e)))?;

    // Verify the user is an admin of the organization
    let user_id = principal
        .user_id
        .ok_or_else(|| Status::permission_denied("Service accounts cannot access billing"))?;

    let member = server
        .store
        .get_organization_member(&org_id, &user_id)
        .await
        .map_err(|_| Status::permission_denied("Not a member of this organization"))?;

    // Only owners and admins can access the billing portal
    if member.role != zopp_storage::OrganizationRole::Owner
        && member.role != zopp_storage::OrganizationRole::Admin
    {
        return Err(Status::permission_denied(
            "Only organization owners and admins can manage billing",
        ));
    }

    // Check if organization has a Stripe customer
    if org.stripe_customer_id.is_none() {
        return Err(Status::failed_precondition(
            "Organization has no billing customer. Contact support to set up billing.",
        ));
    }

    // SECURITY: Validate return_url to prevent open redirect attacks
    let return_url = validate_redirect_url(&req.return_url)?;

    // TODO: Integrate with billing service to create actual Stripe portal session
    // For now, return the validated return URL for development
    Ok(Response::new(BillingPortalSession {
        url: return_url.to_string(),
    }))
}
