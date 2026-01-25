//! Authentication handlers: join, register, login

use chrono::Utc;
use prost::Message;
use sha2::{Digest, Sha256};
use tonic::{Request, Response, Status};
use zopp_crypto::argon2_hash;
use zopp_proto::{
    JoinRequest, JoinResponse, LoginRequest, LoginResponse, RegisterRequest, RegisterResponse,
};
use zopp_storage::{
    CreateEmailVerificationParams, CreatePrincipalData, CreatePrincipalParams, CreateUserParams,
    Store, StoreError,
};

use crate::email::generate_verification_code;
use crate::server::{extract_signature, ZoppServer};

pub async fn join(
    server: &ZoppServer,
    request: Request<JoinRequest>,
) -> Result<Response<JoinResponse>, Status> {
    let req = request.into_inner();

    // Normalize email to lowercase for consistent comparison
    let email = req.email.to_lowercase();

    let invite = server
        .store
        .get_invite_by_token(&req.invite_token)
        .await
        .map_err(|e| Status::not_found(format!("Invalid invite: {}", e)))?;

    // Check if invite is expired
    let now = chrono::Utc::now();
    if now > invite.expires_at {
        return Err(Status::permission_denied(format!(
            "Invite expired at {}",
            invite.expires_at
        )));
    }

    // Check if invite was already consumed
    if invite.consumed {
        return Err(Status::permission_denied(
            "This invite has already been used",
        ));
    }

    // Check if email verification is required
    let verification_required =
        server.config.is_verification_required() && server.email_provider.is_some();

    if verification_required {
        // Verification required: create user only (no principal yet)
        // Principal will be created when email is verified

        // Try to create user (or get existing if this is a retry)
        let user_id = match server
            .store
            .create_user(&CreateUserParams {
                email: email.clone(),
                principal: None,       // No principal yet - created at verification
                workspace_ids: vec![], // Workspace membership added at verification
            })
            .await
        {
            Ok((uid, _)) => uid,
            Err(StoreError::AlreadyExists) => {
                // User exists - check if this is a bootstrap invite
                // Bootstrap invites (no workspace_ids) should not allow existing verified users
                if invite.workspace_ids.is_empty() {
                    let existing_user =
                        server.store.get_user_by_email(&email).await.map_err(|e| {
                            Status::internal(format!("Failed to get existing user: {}", e))
                        })?;

                    // If user is verified, reject bootstrap invite
                    if existing_user.verified {
                        return Err(Status::already_exists("User already exists"));
                    }
                    // If not verified, allow retry (user_id from existing user)
                    existing_user.id
                } else {
                    // Workspace invite for existing user - this is allowed
                    server
                        .store
                        .get_user_by_email(&email)
                        .await
                        .map_err(|e| {
                            Status::internal(format!("Failed to get existing user: {}", e))
                        })?
                        .id
                }
            }
            Err(e) => return Err(Status::internal(format!("Failed to create user: {}", e))),
        };

        // Check if a valid verification record already exists for this email+invite
        // If so, don't regenerate the code (allows retry with same code)
        let existing_verification = match server.store.get_email_verification(&email).await {
            Ok(v) => Some(v),
            Err(zopp_storage::StoreError::NotFound) => None,
            Err(e) => {
                return Err(Status::internal(format!(
                    "Failed to check existing verification: {}",
                    e
                )))
            }
        };
        let should_generate_new_code = match &existing_verification {
            Some(v) if v.invite_token == req.invite_token && v.expires_at > Utc::now() => {
                // Valid verification exists for same invite - don't regenerate
                false
            }
            _ => true,
        };

        if should_generate_new_code {
            // Generate verification code
            let code = generate_verification_code();

            // Send verification email FIRST before storing record
            // This ensures we don't store a record if the email fails to send,
            // which would prevent retries from resending the email
            if let Some(ref provider) = server.email_provider {
                let email_config = server.config.email.as_ref().unwrap();
                provider
                    .send_verification(
                        &email,
                        &code,
                        &email_config.from_address,
                        email_config.from_name.as_deref(),
                    )
                    .await
                    .map_err(|e| {
                        Status::internal(format!("Failed to send verification email: {}", e))
                    })?;
            }

            // Email sent successfully - now store verification record (expires in 15 minutes)
            // Hash the code using Argon2id with email as salt for zero-knowledge storage
            let code_hash = argon2_hash(code.as_bytes(), email.as_bytes()).map_err(|e| {
                Status::internal(format!("Failed to hash verification code: {}", e))
            })?;
            // This upserts - if there's an existing verification for this email, it's replaced
            let expires_at = Utc::now() + chrono::Duration::minutes(15);
            server
                .store
                .create_email_verification(&CreateEmailVerificationParams {
                    email: email.clone(),
                    code_hash,
                    invite_token: req.invite_token.clone(),
                    expires_at,
                })
                .await
                .map_err(|e| Status::internal(format!("Failed to create verification: {}", e)))?;
        }

        // Return without principal_id - it will be created at verification
        return Ok(Response::new(JoinResponse {
            user_id: user_id.0.to_string(),
            principal_id: None,
            workspaces: vec![], // Workspaces returned at verification
            verification_required: true,
        }));
    }

    // No verification required: create user + principal immediately

    // Try to create user with principal
    let result = server
        .store
        .create_user(&CreateUserParams {
            email: email.clone(),
            principal: Some(CreatePrincipalData {
                name: req.principal_name.clone(),
                public_key: req.public_key.clone(),
                x25519_public_key: if req.x25519_public_key.is_empty() {
                    None
                } else {
                    Some(req.x25519_public_key.clone())
                },
                is_service: false,
            }),
            workspace_ids: invite.workspace_ids.clone(),
        })
        .await;

    let (user_id, principal_id) = match result {
        Ok((uid, pid)) => (uid, pid.expect("principal_id should be present")),
        Err(StoreError::AlreadyExists) if !invite.workspace_ids.is_empty() => {
            // User exists - this is a workspace invite for an existing user
            let existing_user = server
                .store
                .get_user_by_email(&email)
                .await
                .map_err(|e| Status::internal(format!("Failed to get existing user: {}", e)))?;

            // Create a new principal for this existing user
            let new_principal_id = server
                .store
                .create_principal(&zopp_storage::CreatePrincipalParams {
                    user_id: Some(existing_user.id.clone()),
                    name: req.principal_name.clone(),
                    public_key: req.public_key.clone(),
                    x25519_public_key: if req.x25519_public_key.is_empty() {
                        None
                    } else {
                        Some(req.x25519_public_key.clone())
                    },
                })
                .await
                .map_err(|e| {
                    Status::internal(format!(
                        "Failed to create principal for existing user: {}",
                        e
                    ))
                })?;

            // Add user to workspace memberships (ignore if already a member)
            for workspace_id in &invite.workspace_ids {
                if let Err(e) = server
                    .store
                    .add_user_to_workspace(workspace_id, &existing_user.id)
                    .await
                {
                    // Ignore AlreadyExists errors - user is already a member
                    if !matches!(e, zopp_storage::StoreError::AlreadyExists) {
                        return Err(Status::internal(format!(
                            "Failed to add user to workspace: {}",
                            e
                        )));
                    }
                }
            }

            (existing_user.id, new_principal_id)
        }
        Err(StoreError::AlreadyExists) => {
            // Bootstrap invite: user already exists
            return Err(Status::already_exists("User already exists"));
        }
        Err(e) => return Err(Status::internal(format!("Failed to create user: {}", e))),
    };

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
        .consume_invite(&req.invite_token)
        .await
        .map_err(|e| Status::internal(format!("Failed to consume invite: {}", e)))?;

    // Mark user as verified (no email verification needed)
    server
        .store
        .mark_user_verified(&user_id)
        .await
        .map_err(|e| Status::internal(format!("Failed to mark user verified: {}", e)))?;

    let mut workspaces = Vec::new();
    for workspace_id in invite.workspace_ids {
        let workspace = server
            .store
            .get_workspace(&workspace_id)
            .await
            .map_err(|e| Status::internal(format!("Failed to get workspace: {}", e)))?;
        workspaces.push(zopp_proto::Workspace {
            id: workspace.id.0.to_string(),
            name: workspace.name,
            project_count: 0, // Not needed for join response
        });
    }

    Ok(Response::new(JoinResponse {
        user_id: user_id.0.to_string(),
        principal_id: Some(principal_id.0.to_string()),
        workspaces,
        verification_required: false,
    }))
}

pub async fn register(
    server: &ZoppServer,
    request: Request<RegisterRequest>,
) -> Result<Response<RegisterResponse>, Status> {
    let method = "/zopp.ZoppService/Register";

    // For service principals with workspace, we need authentication
    if request.get_ref().is_service && request.get_ref().workspace_name.is_some() {
        let (caller_principal_id, timestamp, signature, request_hash) =
            extract_signature(&request)?;

        let _caller = server
            .verify_signature_and_get_principal(
                &caller_principal_id,
                timestamp,
                &signature,
                method,
                request.get_ref(),
                &request_hash,
            )
            .await?;

        let req = request.into_inner();
        let workspace_name = req.workspace_name.as_ref().unwrap();

        // Get workspace (caller must have access)
        let workspace = server
            .store
            .get_workspace_by_name_for_principal(&caller_principal_id, workspace_name)
            .await
            .map_err(|_| Status::not_found(format!("Workspace '{}' not found", workspace_name)))?;

        // Verify caller has admin access to the workspace
        server
            .check_workspace_permission(
                &caller_principal_id,
                &workspace.id,
                zopp_storage::Role::Admin,
            )
            .await?;

        // Create service principal (no user_id)
        let new_principal_id = server
            .store
            .create_principal(&CreatePrincipalParams {
                user_id: None, // Service principal has no user
                name: req.principal_name.clone(),
                public_key: req.public_key.clone(),
                x25519_public_key: if req.x25519_public_key.is_empty() {
                    None
                } else {
                    Some(req.x25519_public_key.clone())
                },
            })
            .await
            .map_err(|e| Status::internal(format!("Failed to create service principal: {}", e)))?;

        // Store wrapped KEK for the new service principal
        if let (Some(ephemeral_pub), Some(kek_wrapped), Some(kek_nonce)) =
            (req.ephemeral_pub, req.kek_wrapped, req.kek_nonce)
        {
            server
                .store
                .add_workspace_principal(&zopp_storage::AddWorkspacePrincipalParams {
                    workspace_id: workspace.id.clone(),
                    principal_id: new_principal_id.clone(),
                    ephemeral_pub,
                    kek_wrapped,
                    kek_nonce,
                })
                .await
                .map_err(|e| {
                    Status::internal(format!(
                        "Failed to add service principal to workspace: {}",
                        e
                    ))
                })?;
        }

        // Return empty user_id for service principals
        return Ok(Response::new(RegisterResponse {
            user_id: String::new(),
            principal_id: new_principal_id.0.to_string(),
        }));
    }

    // Standard register flow (for human principals / new devices)
    let req = request.into_inner();

    // Normalize email to lowercase for consistent comparison
    let email = req.email.to_lowercase();

    let (user_id, principal_id) = server
        .store
        .create_user(&CreateUserParams {
            email,
            principal: Some(CreatePrincipalData {
                name: req.principal_name.clone(),
                public_key: req.public_key.clone(),
                x25519_public_key: if req.x25519_public_key.is_empty() {
                    None
                } else {
                    Some(req.x25519_public_key.clone())
                },
                is_service: req.is_service,
            }),
            workspace_ids: vec![],
        })
        .await
        .map_err(|e| Status::internal(format!("Failed to create user: {}", e)))?;

    let principal_id = principal_id.expect("principal_id should be present");

    Ok(Response::new(RegisterResponse {
        user_id: user_id.0.to_string(),
        principal_id: principal_id.0.to_string(),
    }))
}

pub async fn login(
    server: &ZoppServer,
    request: Request<LoginRequest>,
) -> Result<Response<LoginResponse>, Status> {
    let req = request.into_inner();

    // Normalize email to lowercase for consistent comparison
    let email = req.email.to_lowercase();

    let user = server
        .store
        .get_user_by_email(&email)
        .await
        .map_err(|e| Status::not_found(format!("User not found: {}", e)))?;

    let principals = server
        .store
        .list_principals(&user.id)
        .await
        .map_err(|e| Status::internal(format!("Failed to list principals: {}", e)))?;

    let principal = principals
        .iter()
        .find(|p| p.name == req.principal_name)
        .ok_or_else(|| {
            Status::not_found(format!("Principal '{}' not found", req.principal_name))
        })?;

    // Compute the request hash for signature verification
    let method = "/zopp.ZoppService/Login";
    let body_bytes = req.encode_to_vec();
    let mut hasher = Sha256::new();
    hasher.update(method.as_bytes());
    hasher.update(&body_bytes);
    let request_hash = hasher.finalize().to_vec();

    server
        .verify_signature_and_get_principal(
            &principal.id,
            req.timestamp,
            &req.signature,
            method,
            &req,
            &request_hash,
        )
        .await?;

    Ok(Response::new(LoginResponse {
        user_id: user.id.0.to_string(),
        principal_id: principal.id.0.to_string(),
    }))
}
