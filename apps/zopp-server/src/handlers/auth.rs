//! Authentication handlers: join, register, login

use tonic::{Request, Response, Status};
use zopp_proto::{
    JoinRequest, JoinResponse, LoginRequest, LoginResponse, RegisterRequest, RegisterResponse,
};
use zopp_storage::{CreatePrincipalData, CreateUserParams, Store, StoreError};

use crate::server::ZoppServer;

pub async fn join(
    server: &ZoppServer,
    request: Request<JoinRequest>,
) -> Result<Response<JoinResponse>, Status> {
    let req = request.into_inner();

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

    // Try to create user, but if they already exist, that's okay for workspace invites
    let result = server
        .store
        .create_user(&CreateUserParams {
            email: req.email.clone(),
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
                .get_user_by_email(&req.email)
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
        });
    }

    Ok(Response::new(JoinResponse {
        user_id: user_id.0.to_string(),
        principal_id: principal_id.0.to_string(),
        workspaces,
    }))
}

pub async fn register(
    server: &ZoppServer,
    request: Request<RegisterRequest>,
) -> Result<Response<RegisterResponse>, Status> {
    let req = request.into_inner();

    let (user_id, principal_id) = server
        .store
        .create_user(&CreateUserParams {
            email: req.email,
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

    let user = server
        .store
        .get_user_by_email(&req.email)
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

    server
        .verify_signature_and_get_principal(&principal.id, req.timestamp, &req.signature)
        .await?;

    Ok(Response::new(LoginResponse {
        user_id: user.id.0.to_string(),
        principal_id: principal.id.0.to_string(),
    }))
}
