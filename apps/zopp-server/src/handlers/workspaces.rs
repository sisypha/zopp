//! Workspace handlers: create, list, get_keys, grant_principal_access

use rand_core::RngCore;
use tonic::{Request, Response, Status};
use uuid::Uuid;
use zopp_proto::{
    CreateWorkspaceRequest, Empty, GetWorkspaceKeysRequest, GrantPrincipalWorkspaceAccessRequest,
    WorkspaceKeys, WorkspaceList,
};
use zopp_storage::{
    AddWorkspacePrincipalParams, CreateWorkspaceParams, PrincipalId, Store, WorkspaceId,
};

use crate::server::{extract_signature, ZoppServer};

pub async fn create_workspace(
    server: &ZoppServer,
    request: Request<CreateWorkspaceRequest>,
) -> Result<Response<zopp_proto::Workspace>, Status> {
    let (principal_id, timestamp, signature, request_hash) = extract_signature(&request)?;
    let req_for_verify = request.get_ref().clone();
    let principal = server
        .verify_signature_and_get_principal(
            &principal_id,
            timestamp,
            &signature,
            "/zopp.ZoppService/CreateWorkspace",
            &req_for_verify,
            &request_hash,
        )
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
        project_count: 0, // New workspace has no projects
    }))
}

pub async fn list_workspaces(
    server: &ZoppServer,
    request: Request<Empty>,
) -> Result<Response<WorkspaceList>, Status> {
    let (principal_id, timestamp, signature, request_hash) = extract_signature(&request)?;
    let req_for_verify = *request.get_ref();
    let principal = server
        .verify_signature_and_get_principal(
            &principal_id,
            timestamp,
            &signature,
            "/zopp.ZoppService/ListWorkspaces",
            &req_for_verify,
            &request_hash,
        )
        .await?;
    let user_id = principal
        .user_id
        .ok_or_else(|| Status::unauthenticated("Service accounts cannot list workspaces"))?;

    let workspaces = server
        .store
        .list_workspaces(&user_id)
        .await
        .map_err(|e| Status::internal(format!("Failed to list workspaces: {}", e)))?;

    // Build response with project counts
    let mut result = Vec::with_capacity(workspaces.len());
    for w in workspaces {
        let project_count = server
            .store
            .list_projects(&w.id)
            .await
            .map(|p| p.len() as i32)
            .unwrap_or(0);

        result.push(zopp_proto::Workspace {
            id: w.id.0.to_string(),
            name: w.name,
            project_count,
        });
    }

    Ok(Response::new(WorkspaceList { workspaces: result }))
}

pub async fn get_workspace_keys(
    server: &ZoppServer,
    request: Request<GetWorkspaceKeysRequest>,
) -> Result<Response<WorkspaceKeys>, Status> {
    let (principal_id, timestamp, signature, request_hash) = extract_signature(&request)?;
    let req_for_verify = request.get_ref().clone();
    let principal = server
        .verify_signature_and_get_principal(
            &principal_id,
            timestamp,
            &signature,
            "/zopp.ZoppService/GetWorkspaceKeys",
            &req_for_verify,
            &request_hash,
        )
        .await?;
    let req = request.into_inner();

    // Get workspace by name - use different lookup for service principals
    let workspace = if let Some(user_id) = &principal.user_id {
        server
            .store
            .get_workspace_by_name(user_id, &req.workspace_name)
            .await
            .map_err(|e| Status::not_found(format!("Workspace not found: {}", e)))?
    } else {
        // Service principal - use principal-based lookup
        server
            .store
            .get_workspace_by_name_for_principal(&principal_id, &req.workspace_name)
            .await
            .map_err(|e| Status::not_found(format!("Workspace not found: {}", e)))?
    };

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

pub async fn grant_principal_workspace_access(
    server: &ZoppServer,
    request: Request<GrantPrincipalWorkspaceAccessRequest>,
) -> Result<Response<Empty>, Status> {
    let (caller_principal_id, timestamp, signature, request_hash) = extract_signature(&request)?;
    let req_for_verify = request.get_ref().clone();
    let caller = server
        .verify_signature_and_get_principal(
            &caller_principal_id,
            timestamp,
            &signature,
            "/zopp.ZoppService/GrantPrincipalWorkspaceAccess",
            &req_for_verify,
            &request_hash,
        )
        .await?;
    let req = request.into_inner();

    // Caller must be a user (not service principal) to grant workspace access
    let user_id = caller.user_id.ok_or_else(|| {
        Status::permission_denied("Service principals cannot grant workspace access")
    })?;

    // Get workspace by name (caller must have access)
    let workspace = server
        .store
        .get_workspace_by_name(&user_id, &req.workspace_name)
        .await
        .map_err(|e| Status::not_found(format!("Workspace not found: {}", e)))?;

    // Parse target principal ID
    let target_principal_id = PrincipalId(
        Uuid::parse_str(&req.principal_id)
            .map_err(|_| Status::invalid_argument("Invalid principal ID"))?,
    );

    // Verify the target principal exists
    let target_principal = server
        .store
        .get_principal(&target_principal_id)
        .await
        .map_err(|_| Status::not_found("Principal not found"))?;

    // Check permissions:
    // - If target principal belongs to the same user (device principal), allow without admin
    // - Otherwise, require admin permission on the workspace
    let is_same_user = target_principal.user_id.as_ref() == Some(&user_id);
    if !is_same_user {
        server
            .check_workspace_permission(
                &caller_principal_id,
                &workspace.id,
                zopp_storage::Role::Admin,
            )
            .await?;
    }

    // Store the wrapped KEK for the target principal
    server
        .store
        .add_workspace_principal(&AddWorkspacePrincipalParams {
            workspace_id: workspace.id,
            principal_id: target_principal_id,
            ephemeral_pub: req.ephemeral_pub,
            kek_wrapped: req.kek_wrapped,
            kek_nonce: req.kek_nonce,
        })
        .await
        .map_err(|e| Status::internal(format!("Failed to grant workspace access: {}", e)))?;

    Ok(Response::new(Empty {}))
}
