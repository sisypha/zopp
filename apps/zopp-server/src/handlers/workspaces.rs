//! Workspace handlers: create, list, get_keys

use rand_core::RngCore;
use tonic::{Request, Response, Status};
use uuid::Uuid;
use zopp_proto::{
    CreateWorkspaceRequest, Empty, GetWorkspaceKeysRequest, WorkspaceKeys, WorkspaceList,
};
use zopp_storage::{AddWorkspacePrincipalParams, CreateWorkspaceParams, Store, WorkspaceId};

use crate::server::{extract_signature, ZoppServer};

pub async fn create_workspace(
    server: &ZoppServer,
    request: Request<CreateWorkspaceRequest>,
) -> Result<Response<zopp_proto::Workspace>, Status> {
    let (principal_id, timestamp, signature, request_hash) = extract_signature(&request)?;
    let req_for_verify = request.get_ref().clone();
    let principal = server
        .verify_signature_and_get_principal(&principal_id, timestamp, &signature, "/zopp.ZoppService/CreateWorkspace", &req_for_verify, &request_hash)
        .await?;
    let req = request.into_inner();

    // Generate KDF salt
    let mut salt = vec![0u8; 32];
    rand_core::OsRng.fill_bytes(&mut salt);

    let user_id = principal
        .user_id
        .ok_or_else(|| Status::unauthenticated("Service accounts cannot create workspaces"))?;

    // Parse client-provided workspace ID
    let workspace_id = WorkspaceId(
        Uuid::parse_str(&req.id).map_err(|_| Status::invalid_argument("Invalid workspace ID"))?,
    );

    server
        .store
        .create_workspace(&CreateWorkspaceParams {
            id: workspace_id.clone(),
            name: req.name.clone(),
            owner_user_id: user_id.clone(),
            kdf_salt: salt,
            m_cost_kib: 64 * 1024,
            t_cost: 3,
            p_cost: 1,
        })
        .await
        .map_err(|e| Status::internal(format!("Failed to create workspace: {}", e)))?;

    server
        .store
        .add_user_to_workspace(&workspace_id, &user_id)
        .await
        .map_err(|e| Status::internal(format!("Failed to add user to workspace: {}", e)))?;

    // Store wrapped KEK for the workspace creator
    if !req.ephemeral_pub.is_empty() && !req.kek_wrapped.is_empty() {
        // Validate that kek_nonce is also provided when kek_wrapped is set
        if req.kek_nonce.is_empty() {
            return Err(Status::invalid_argument(
                "kek_nonce is required when kek_wrapped is provided",
            ));
        }
        server
            .store
            .add_workspace_principal(&AddWorkspacePrincipalParams {
                workspace_id: workspace_id.clone(),
                principal_id: principal_id.clone(),
                ephemeral_pub: req.ephemeral_pub,
                kek_wrapped: req.kek_wrapped,
                kek_nonce: req.kek_nonce,
            })
            .await
            .map_err(|e| {
                Status::internal(format!("Failed to add wrapped KEK for principal: {}", e))
            })?;
    }

    Ok(Response::new(zopp_proto::Workspace {
        id: workspace_id.0.to_string(),
        name: req.name,
    }))
}

pub async fn list_workspaces(
    server: &ZoppServer,
    request: Request<Empty>,
) -> Result<Response<WorkspaceList>, Status> {
    let (principal_id, timestamp, signature, request_hash) = extract_signature(&request)?;
    let req_for_verify = request.get_ref().clone();
    let principal = server
        .verify_signature_and_get_principal(&principal_id, timestamp, &signature, "/zopp.ZoppService/ListWorkspaces", &req_for_verify, &request_hash)
        .await?;
    let user_id = principal
        .user_id
        .ok_or_else(|| Status::unauthenticated("Service accounts cannot list workspaces"))?;

    let workspaces = server
        .store
        .list_workspaces(&user_id)
        .await
        .map_err(|e| Status::internal(format!("Failed to list workspaces: {}", e)))?
        .into_iter()
        .map(|w| zopp_proto::Workspace {
            id: w.id.0.to_string(),
            name: w.name,
        })
        .collect();

    Ok(Response::new(WorkspaceList { workspaces }))
}

pub async fn get_workspace_keys(
    server: &ZoppServer,
    request: Request<GetWorkspaceKeysRequest>,
) -> Result<Response<WorkspaceKeys>, Status> {
    let (principal_id, timestamp, signature, request_hash) = extract_signature(&request)?;
    let req_for_verify = request.get_ref().clone();
    let principal = server
        .verify_signature_and_get_principal(&principal_id, timestamp, &signature, "/zopp.ZoppService/GetWorkspaceKeys", &req_for_verify, &request_hash)
        .await?;
    let req = request.into_inner();

    let user_id = principal
        .user_id
        .ok_or_else(|| Status::unauthenticated("Service accounts cannot access workspaces"))?;

    // Get workspace by name
    let workspace = server
        .store
        .get_workspace_by_name(&user_id, &req.workspace_name)
        .await
        .map_err(|e| Status::not_found(format!("Workspace not found: {}", e)))?;

    // Get wrapped KEK for this principal
    let wp = server
        .store
        .get_workspace_principal(&workspace.id, &principal_id)
        .await
        .map_err(|e| Status::not_found(format!("KEK not found for principal: {}", e)))?;

    Ok(Response::new(WorkspaceKeys {
        workspace_id: workspace.id.0.to_string(),
        ephemeral_pub: wp.ephemeral_pub,
        kek_wrapped: wp.kek_wrapped,
        kek_nonce: wp.kek_nonce,
    }))
}
