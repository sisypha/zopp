//! Invite handlers: create, get, list, revoke

use tonic::{Request, Response, Status};
use uuid::Uuid;
use zopp_proto::{
    CreateInviteRequest, Empty, GetInviteRequest, InviteList, InviteToken, RevokeInviteRequest,
};
use zopp_storage::{CreateInviteParams, Store, WorkspaceId};

use crate::server::{extract_signature, ZoppServer};

pub async fn create_invite(
    server: &ZoppServer,
    request: Request<CreateInviteRequest>,
) -> Result<Response<InviteToken>, Status> {
    let (principal_id, timestamp, signature) = extract_signature(&request)?;
    let principal = server
        .verify_signature_and_get_principal(&principal_id, timestamp, &signature)
        .await?;
    let req = request.into_inner();

    let workspace_ids: Result<Vec<WorkspaceId>, _> = req
        .workspace_ids
        .into_iter()
        .map(|id| {
            Uuid::parse_str(&id)
                .map(WorkspaceId)
                .map_err(|_| Status::invalid_argument(format!("Invalid workspace ID: {}", id)))
        })
        .collect();

    let user_id = principal
        .user_id
        .ok_or_else(|| Status::unauthenticated("Service accounts cannot create invites"))?;

    let workspace_ids = workspace_ids?;

    // Check ADMIN permission for each workspace in the invite
    for ws_id in &workspace_ids {
        server
            .check_workspace_permission(&principal_id, ws_id, zopp_storage::Role::Admin)
            .await?;
    }

    let invite = server
        .store
        .create_invite(&CreateInviteParams {
            workspace_ids: workspace_ids.clone(),
            token: req.token,
            kek_encrypted: if req.kek_encrypted.is_empty() {
                None
            } else {
                Some(req.kek_encrypted)
            },
            kek_nonce: if req.kek_nonce.is_empty() {
                None
            } else {
                Some(req.kek_nonce)
            },
            expires_at: chrono::DateTime::from_timestamp(req.expires_at, 0)
                .ok_or_else(|| Status::invalid_argument("Invalid expires_at timestamp"))?,
            created_by_user_id: Some(user_id),
        })
        .await
        .map_err(|e| Status::internal(format!("Failed to create invite: {}", e)))?;

    Ok(Response::new(InviteToken {
        id: invite.id.0.to_string(),
        token: invite.token.clone(),
        workspace_ids: invite
            .workspace_ids
            .into_iter()
            .map(|id| id.0.to_string())
            .collect(),
        created_at: invite.created_at.timestamp(),
        expires_at: invite.expires_at.timestamp(),
        kek_encrypted: invite.kek_encrypted.unwrap_or_default(),
        kek_nonce: invite.kek_nonce.unwrap_or_default(),
        invite_secret: String::new(),
    }))
}

pub async fn get_invite(
    server: &ZoppServer,
    request: Request<GetInviteRequest>,
) -> Result<Response<InviteToken>, Status> {
    // No authentication required - the invite secret itself is the credential
    let req = request.into_inner();

    let invite = server
        .store
        .get_invite_by_token(&req.token)
        .await
        .map_err(|_| Status::not_found("Invite not found or expired"))?;

    Ok(Response::new(InviteToken {
        id: invite.id.0.to_string(),
        token: invite.token,
        workspace_ids: invite
            .workspace_ids
            .into_iter()
            .map(|id| id.0.to_string())
            .collect(),
        created_at: invite.created_at.timestamp(),
        expires_at: invite.expires_at.timestamp(),
        kek_encrypted: invite.kek_encrypted.unwrap_or_default(),
        kek_nonce: invite.kek_nonce.unwrap_or_default(),
        invite_secret: String::new(),
    }))
}

pub async fn list_invites(
    server: &ZoppServer,
    request: Request<Empty>,
) -> Result<Response<InviteList>, Status> {
    let (principal_id, timestamp, signature) = extract_signature(&request)?;
    let principal = server
        .verify_signature_and_get_principal(&principal_id, timestamp, &signature)
        .await?;
    let user_id = principal
        .user_id
        .ok_or_else(|| Status::unauthenticated("Service accounts cannot list invites"))?;

    let invites = server
        .store
        .list_invites(Some(&user_id))
        .await
        .map_err(|e| Status::internal(format!("Failed to list invites: {}", e)))?
        .into_iter()
        .map(|inv| InviteToken {
            id: inv.id.0.to_string(),
            token: inv.token,
            workspace_ids: inv
                .workspace_ids
                .into_iter()
                .map(|id| id.0.to_string())
                .collect(),
            created_at: inv.created_at.timestamp(),
            expires_at: inv.expires_at.timestamp(),
            kek_encrypted: inv.kek_encrypted.unwrap_or_default(),
            kek_nonce: inv.kek_nonce.unwrap_or_default(),
            invite_secret: String::new(),
        })
        .collect();

    Ok(Response::new(InviteList { invites }))
}

pub async fn revoke_invite(
    server: &ZoppServer,
    request: Request<RevokeInviteRequest>,
) -> Result<Response<Empty>, Status> {
    let (principal_id, timestamp, signature) = extract_signature(&request)?;
    let principal = server
        .verify_signature_and_get_principal(&principal_id, timestamp, &signature)
        .await?;
    principal
        .user_id
        .ok_or_else(|| Status::unauthenticated("Service accounts cannot revoke invites"))?;
    let req = request.into_inner();

    // Look up invite by token (which is the hash)
    let invite = server
        .store
        .get_invite_by_token(&req.token)
        .await
        .map_err(|e| Status::not_found(format!("Invite not found: {}", e)))?;

    // Check ADMIN permission on at least one workspace in the invite
    let mut has_admin = false;
    for ws_id in &invite.workspace_ids {
        if server
            .check_workspace_permission(&principal_id, ws_id, zopp_storage::Role::Admin)
            .await
            .is_ok()
        {
            has_admin = true;
            break;
        }
    }
    if !has_admin {
        return Err(Status::permission_denied(
            "Admin permission required on at least one workspace in the invite",
        ));
    }

    server
        .store
        .revoke_invite(&invite.id)
        .await
        .map_err(|e| Status::internal(format!("Failed to revoke invite: {}", e)))?;

    Ok(Response::new(Empty {}))
}
