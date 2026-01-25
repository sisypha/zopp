//! Email verification handlers.

use chrono::Utc;
use tonic::{Request, Response, Status};
use zopp_storage::{CreateEmailVerificationParams, Store};

use crate::email::generate_verification_code;
use crate::server::ZoppServer;
use zopp_proto::{
    ResendVerificationRequest, ResendVerificationResponse, VerifyEmailRequest, VerifyEmailResponse,
};

/// Maximum verification attempts per code
const MAX_ATTEMPTS: i32 = 5;

/// Handle email verification request.
///
/// This RPC does not require authentication since the user hasn't completed
/// the join flow yet. On success, creates the principal and returns the principal_id.
pub async fn verify_email(
    server: &ZoppServer,
    request: Request<VerifyEmailRequest>,
) -> Result<Response<VerifyEmailResponse>, Status> {
    let req = request.into_inner();

    // Validate inputs
    if req.email.is_empty() {
        return Err(Status::invalid_argument("email is required"));
    }
    if req.code.is_empty() {
        return Err(Status::invalid_argument("code is required"));
    }
    if req.principal_name.is_empty() {
        return Err(Status::invalid_argument("principal_name is required"));
    }
    if req.public_key.is_empty() {
        return Err(Status::invalid_argument("public_key is required"));
    }

    // Normalize email
    let email = req.email.to_lowercase();

    // Get the verification record for this email
    let verification = match server.store.get_email_verification(&email).await {
        Ok(v) => v,
        Err(zopp_storage::StoreError::NotFound) => {
            return Ok(Response::new(VerifyEmailResponse {
                success: false,
                message: "No pending verification found. Please request a new code.".to_string(),
                attempts_remaining: 0,
                user_id: String::new(),
                principal_id: String::new(),
                workspaces: vec![],
            }));
        }
        Err(e) => {
            return Err(Status::internal(format!(
                "Failed to get verification: {}",
                e
            )));
        }
    };

    // Check if expired
    if verification.expires_at < chrono::Utc::now() {
        // Clean up expired verification
        let _ = server
            .store
            .delete_email_verification(&verification.id)
            .await;
        return Ok(Response::new(VerifyEmailResponse {
            success: false,
            message: "Verification code has expired. Please request a new code.".to_string(),
            attempts_remaining: 0,
            user_id: String::new(),
            principal_id: String::new(),
            workspaces: vec![],
        }));
    }

    // Check attempt limit
    if verification.attempts >= MAX_ATTEMPTS {
        // Delete the verification after max attempts
        let _ = server
            .store
            .delete_email_verification(&verification.id)
            .await;
        return Ok(Response::new(VerifyEmailResponse {
            success: false,
            message: "Too many failed attempts. Please request a new code.".to_string(),
            attempts_remaining: 0,
            user_id: String::new(),
            principal_id: String::new(),
            workspaces: vec![],
        }));
    }

    // Verify the code using constant-time comparison
    let code_matches: bool =
        subtle::ConstantTimeEq::ct_eq(req.code.as_bytes(), verification.code.as_bytes()).into();

    if !code_matches {
        // Increment attempts
        let attempts = server
            .store
            .increment_email_verification_attempts(&verification.id)
            .await
            .map_err(|e| Status::internal(format!("Failed to increment attempts: {}", e)))?;

        // Check if we've now reached MAX_ATTEMPTS after incrementing
        if attempts >= MAX_ATTEMPTS {
            // Delete the verification record - user must request a new code
            let _ = server
                .store
                .delete_email_verification(&verification.id)
                .await;

            return Ok(Response::new(VerifyEmailResponse {
                success: false,
                message: "Too many failed attempts. Please request a new verification code."
                    .to_string(),
                attempts_remaining: 0,
                user_id: String::new(),
                principal_id: String::new(),
                workspaces: vec![],
            }));
        }

        let remaining = (MAX_ATTEMPTS - attempts).max(0);
        return Ok(Response::new(VerifyEmailResponse {
            success: false,
            message: format!(
                "Invalid verification code. {} attempts remaining.",
                remaining
            ),
            attempts_remaining: remaining,
            user_id: String::new(),
            principal_id: String::new(),
            workspaces: vec![],
        }));
    }

    // Code is correct! Now create the principal and complete the join flow.

    // Get the invite from the stored token
    let invite = server
        .store
        .get_invite_by_token(&verification.invite_token)
        .await
        .map_err(|e| Status::internal(format!("Failed to get invite: {}", e)))?;

    // Check if invite was consumed (someone else used it while we were verifying)
    if invite.consumed {
        // Clean up
        let _ = server
            .store
            .delete_email_verification(&verification.id)
            .await;
        return Ok(Response::new(VerifyEmailResponse {
            success: false,
            message: "This invite has already been used.".to_string(),
            attempts_remaining: 0,
            user_id: String::new(),
            principal_id: String::new(),
            workspaces: vec![],
        }));
    }

    // Get the user (created during join)
    let user = server
        .store
        .get_user_by_email(&email)
        .await
        .map_err(|e| Status::internal(format!("Failed to get user: {}", e)))?;

    // Create the principal
    let principal_id = server
        .store
        .create_principal(&zopp_storage::CreatePrincipalParams {
            user_id: Some(user.id.clone()),
            name: req.principal_name.clone(),
            public_key: req.public_key.clone(),
            x25519_public_key: if req.x25519_public_key.is_empty() {
                None
            } else {
                Some(req.x25519_public_key.clone())
            },
        })
        .await
        .map_err(|e| Status::internal(format!("Failed to create principal: {}", e)))?;

    // Add user to workspace memberships
    for workspace_id in &invite.workspace_ids {
        if let Err(e) = server
            .store
            .add_user_to_workspace(workspace_id, &user.id)
            .await
        {
            // Ignore AlreadyExists errors - user may already be a member
            if !matches!(e, zopp_storage::StoreError::AlreadyExists) {
                return Err(Status::internal(format!(
                    "Failed to add user to workspace: {}",
                    e
                )));
            }
        }
    }

    // For workspace invites, store the wrapped KEK for this principal
    if !invite.workspace_ids.is_empty() && !req.kek_wrapped.is_empty() {
        for workspace_id in &invite.workspace_ids {
            server
                .store
                .add_workspace_principal(&zopp_storage::AddWorkspacePrincipalParams {
                    workspace_id: workspace_id.clone(),
                    principal_id: principal_id.clone(),
                    ephemeral_pub: req.ephemeral_pub.clone(),
                    kek_wrapped: req.kek_wrapped.clone(),
                    kek_nonce: req.kek_nonce.clone(),
                })
                .await
                .map_err(|e| {
                    Status::internal(format!("Failed to add principal to workspace: {}", e))
                })?;
        }
    }

    // Consume the invite (mark as used)
    server
        .store
        .consume_invite(&verification.invite_token)
        .await
        .map_err(|e| Status::internal(format!("Failed to consume invite: {}", e)))?;

    // Mark user as verified
    server
        .store
        .mark_user_verified(&user.id)
        .await
        .map_err(|e| Status::internal(format!("Failed to mark user verified: {}", e)))?;

    // Delete the verification record
    let _ = server
        .store
        .delete_email_verification(&verification.id)
        .await;

    // Build workspaces response
    let mut workspaces = Vec::new();
    for workspace_id in &invite.workspace_ids {
        let workspace = server
            .store
            .get_workspace(workspace_id)
            .await
            .map_err(|e| Status::internal(format!("Failed to get workspace: {}", e)))?;
        workspaces.push(zopp_proto::Workspace {
            id: workspace.id.0.to_string(),
            name: workspace.name,
            project_count: 0, // Not needed for verification response
        });
    }

    Ok(Response::new(VerifyEmailResponse {
        success: true,
        message: "Email verified successfully.".to_string(),
        attempts_remaining: 0,
        user_id: user.id.0.to_string(),
        principal_id: principal_id.0.to_string(),
        workspaces,
    }))
}

/// Handle resend verification request.
///
/// This RPC does not require authentication since the user hasn't completed
/// the join flow yet. Generates a new code for an existing verification.
pub async fn resend_verification(
    server: &ZoppServer,
    request: Request<ResendVerificationRequest>,
) -> Result<Response<ResendVerificationResponse>, Status> {
    let req = request.into_inner();

    // Validate inputs
    if req.email.is_empty() {
        return Err(Status::invalid_argument("email is required"));
    }

    // Normalize email
    let email = req.email.to_lowercase();

    // Check if email provider is configured
    let Some(ref provider) = server.email_provider else {
        return Ok(Response::new(ResendVerificationResponse {
            success: false,
            message: "Email provider not configured. Contact your administrator.".to_string(),
        }));
    };

    // Get existing verification to get the invite_token
    let existing = match server.store.get_email_verification(&email).await {
        Ok(v) => v,
        Err(zopp_storage::StoreError::NotFound) => {
            return Ok(Response::new(ResendVerificationResponse {
                success: false,
                message: "No pending verification found. Please start the join process again."
                    .to_string(),
            }));
        }
        Err(e) => {
            return Err(Status::internal(format!(
                "Failed to get verification: {}",
                e
            )));
        }
    };

    // Generate new verification code
    let code = generate_verification_code();

    // Update verification record with new code (upsert preserves invite_token)
    let expires_at = Utc::now() + chrono::Duration::minutes(15);
    server
        .store
        .create_email_verification(&CreateEmailVerificationParams {
            email: email.clone(),
            code: code.clone(),
            invite_token: existing.invite_token, // Preserve the original invite token
            expires_at,
        })
        .await
        .map_err(|e| Status::internal(format!("Failed to update verification: {}", e)))?;

    // Send verification email
    let email_config = server.config.email.as_ref().unwrap();
    if let Err(e) = provider
        .send_verification(
            &email,
            &code,
            &email_config.from_address,
            email_config.from_name.as_deref(),
        )
        .await
    {
        eprintln!("Failed to send verification email to {}: {}", email, e);
        return Ok(Response::new(ResendVerificationResponse {
            success: false,
            message: "Failed to send verification email. Please try again later.".to_string(),
        }));
    }

    Ok(Response::new(ResendVerificationResponse {
        success: true,
        message: "Verification code sent. Please check your email.".to_string(),
    }))
}
