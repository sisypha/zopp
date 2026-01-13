//! Principal handlers: get, rename, list, service principals, remove, revoke

use tonic::{Request, Response, Status};
use uuid::Uuid;
use zopp_proto::{
    EffectivePermissionsResponse, Empty, GetEffectivePermissionsRequest, GetPrincipalRequest,
    ListWorkspaceServicePrincipalsRequest, PrincipalList, RemovePrincipalFromWorkspaceRequest,
    RenamePrincipalRequest, RevokeAllPrincipalPermissionsRequest,
    RevokeAllPrincipalPermissionsResponse, ServicePrincipalList,
};
use zopp_storage::{PrincipalId, Store};

use crate::server::{extract_signature, ZoppServer};

pub async fn get_principal(
    server: &ZoppServer,
    request: Request<GetPrincipalRequest>,
) -> Result<Response<zopp_proto::Principal>, Status> {
    let (principal_id, timestamp, signature, request_hash) = extract_signature(&request)?;
    let req_for_verify = request.get_ref().clone();
    let _principal = server
        .verify_signature_and_get_principal(
            &principal_id,
            timestamp,
            &signature,
            "/zopp.ZoppService/GetPrincipal",
            &req_for_verify,
            &request_hash,
        )
        .await?;
    let req = request.into_inner();

    let principal_id = Uuid::parse_str(&req.principal_id)
        .map(PrincipalId)
        .map_err(|_| Status::invalid_argument("Invalid principal ID"))?;

    let principal = server
        .store
        .get_principal(&principal_id)
        .await
        .map_err(|e| Status::not_found(format!("Principal not found: {}", e)))?;

    Ok(Response::new(zopp_proto::Principal {
        id: principal.id.0.to_string(),
        name: principal.name,
        public_key: principal.public_key,
        x25519_public_key: principal.x25519_public_key.unwrap_or_default(),
    }))
}

pub async fn rename_principal(
    server: &ZoppServer,
    request: Request<RenamePrincipalRequest>,
) -> Result<Response<Empty>, Status> {
    let (requester_principal_id, timestamp, signature, request_hash) = extract_signature(&request)?;
    let req_for_verify = request.get_ref().clone();
    let requester_principal = server
        .verify_signature_and_get_principal(
            &requester_principal_id,
            timestamp,
            &signature,
            "/zopp.ZoppService/RenamePrincipal",
            &req_for_verify,
            &request_hash,
        )
        .await?;
    let req = request.into_inner();

    let target_principal_id = Uuid::parse_str(&req.principal_id)
        .map(PrincipalId)
        .map_err(|_| Status::invalid_argument("Invalid principal ID"))?;

    // Service accounts cannot rename principals
    let requester_user_id = requester_principal
        .user_id
        .ok_or_else(|| Status::permission_denied("Service accounts cannot rename principals"))?;

    // Get target principal to verify ownership
    let target_principal = server
        .store
        .get_principal(&target_principal_id)
        .await
        .map_err(|e| match e {
            zopp_storage::StoreError::NotFound => Status::not_found("Principal not found"),
            _ => Status::internal(format!("Failed to get principal: {}", e)),
        })?;

    // Users can only rename their own principals
    // Compare user_ids: requester must own the target principal
    if Some(requester_user_id) != target_principal.user_id {
        return Err(Status::permission_denied(
            "Can only rename your own principals",
        ));
    }

    server
        .store
        .rename_principal(&target_principal_id, &req.new_name)
        .await
        .map_err(|e| Status::internal(format!("Failed to rename principal: {}", e)))?;

    Ok(Response::new(Empty {}))
}

pub async fn list_principals(
    server: &ZoppServer,
    request: Request<Empty>,
) -> Result<Response<PrincipalList>, Status> {
    let (principal_id, timestamp, signature, request_hash) = extract_signature(&request)?;
    let req_for_verify = *request.get_ref();
    let principal = server
        .verify_signature_and_get_principal(
            &principal_id,
            timestamp,
            &signature,
            "/zopp.ZoppService/ListPrincipals",
            &req_for_verify,
            &request_hash,
        )
        .await?;
    let user_id = principal
        .user_id
        .ok_or_else(|| Status::unauthenticated("Service accounts cannot list principals"))?;

    let principals = server
        .store
        .list_principals(&user_id)
        .await
        .map_err(|e| Status::internal(format!("Failed to list principals: {}", e)))?
        .into_iter()
        .map(|p| zopp_proto::Principal {
            id: p.id.0.to_string(),
            name: p.name,
            public_key: p.public_key,
            x25519_public_key: p.x25519_public_key.unwrap_or_default(),
        })
        .collect();

    Ok(Response::new(PrincipalList { principals }))
}

pub async fn list_workspace_service_principals(
    server: &ZoppServer,
    request: Request<ListWorkspaceServicePrincipalsRequest>,
) -> Result<Response<ServicePrincipalList>, Status> {
    let (principal_id, timestamp, signature, request_hash) = extract_signature(&request)?;
    let req_for_verify = request.get_ref().clone();
    let principal = server
        .verify_signature_and_get_principal(
            &principal_id,
            timestamp,
            &signature,
            "/zopp.ZoppService/ListWorkspaceServicePrincipals",
            &req_for_verify,
            &request_hash,
        )
        .await?;
    let user_id = principal.user_id.ok_or_else(|| {
        Status::unauthenticated("Service accounts cannot list service principals")
    })?;

    let req = request.into_inner();

    // Look up workspace by name
    let workspace = server
        .store
        .get_workspace_by_name(&user_id, &req.workspace_name)
        .await
        .map_err(|e| match e {
            zopp_storage::StoreError::NotFound => {
                Status::not_found("Workspace not found or access denied")
            }
            _ => Status::internal(format!("Failed to get workspace: {}", e)),
        })?;

    // Get all principals in the workspace
    let workspace_principals = server
        .store
        .list_workspace_principals(&workspace.id)
        .await
        .map_err(|e| Status::internal(format!("Failed to list workspace principals: {}", e)))?;

    // Get all projects in the workspace (for aggregating permissions)
    let projects = server
        .store
        .list_projects(&workspace.id)
        .await
        .map_err(|e| Status::internal(format!("Failed to list projects: {}", e)))?;

    let mut service_principals = Vec::new();

    for wp in workspace_principals {
        // Get the principal details
        let principal_info = match server.store.get_principal(&wp.principal_id).await {
            Ok(p) => p,
            Err(_) => continue,
        };

        // Only include service principals (user_id is None)
        if principal_info.user_id.is_some() {
            continue;
        }

        // Aggregate permissions for this service principal
        let mut permissions = Vec::new();

        // Check project-level permissions
        for project in &projects {
            if let Ok(role) = server
                .store
                .get_project_permission(&project.id, &wp.principal_id)
                .await
            {
                permissions.push(zopp_proto::ServicePrincipalPermission {
                    scope: format!("project:{}", project.name),
                    role: match role {
                        zopp_storage::Role::Admin => zopp_proto::Role::Admin as i32,
                        zopp_storage::Role::Write => zopp_proto::Role::Write as i32,
                        zopp_storage::Role::Read => zopp_proto::Role::Read as i32,
                    },
                });
            }

            // Check environment-level permissions within the project
            if let Ok(environments) = server.store.list_environments(&project.id).await {
                for env in environments {
                    if let Ok(role) = server
                        .store
                        .get_environment_permission(&env.id, &wp.principal_id)
                        .await
                    {
                        permissions.push(zopp_proto::ServicePrincipalPermission {
                            scope: format!("environment:{}/{}", project.name, env.name),
                            role: match role {
                                zopp_storage::Role::Admin => zopp_proto::Role::Admin as i32,
                                zopp_storage::Role::Write => zopp_proto::Role::Write as i32,
                                zopp_storage::Role::Read => zopp_proto::Role::Read as i32,
                            },
                        });
                    }
                }
            }
        }

        service_principals.push(zopp_proto::ServicePrincipal {
            id: principal_info.id.0.to_string(),
            name: principal_info.name,
            created_at: principal_info.created_at.to_rfc3339(),
            permissions,
        });
    }

    Ok(Response::new(ServicePrincipalList { service_principals }))
}

pub async fn remove_principal_from_workspace(
    server: &ZoppServer,
    request: Request<RemovePrincipalFromWorkspaceRequest>,
) -> Result<Response<Empty>, Status> {
    let (principal_id, timestamp, signature, request_hash) = extract_signature(&request)?;
    let req_for_verify = request.get_ref().clone();
    let principal = server
        .verify_signature_and_get_principal(
            &principal_id,
            timestamp,
            &signature,
            "/zopp.ZoppService/RemovePrincipalFromWorkspace",
            &req_for_verify,
            &request_hash,
        )
        .await?;
    let user_id = principal.user_id.ok_or_else(|| {
        Status::unauthenticated("Service accounts cannot remove principals from workspaces")
    })?;

    let req = request.into_inner();

    // Look up workspace by name
    let workspace = server
        .store
        .get_workspace_by_name(&user_id, &req.workspace_name)
        .await
        .map_err(|e| match e {
            zopp_storage::StoreError::NotFound => {
                Status::not_found("Workspace not found or access denied")
            }
            _ => Status::internal(format!("Failed to get workspace: {}", e)),
        })?;

    // Check ADMIN permission (only admins can remove principals)
    server
        .check_workspace_permission(&principal_id, &workspace.id, zopp_storage::Role::Admin)
        .await?;

    // Parse target principal ID
    let target_principal_id = Uuid::parse_str(&req.principal_id)
        .map(PrincipalId)
        .map_err(|_| Status::invalid_argument("Invalid principal ID"))?;

    // Verify principal exists
    server
        .store
        .get_principal(&target_principal_id)
        .await
        .map_err(|e| match e {
            zopp_storage::StoreError::NotFound => Status::not_found("Principal not found"),
            _ => Status::internal(format!("Failed to get principal: {}", e)),
        })?;

    // Prevent removing yourself
    if target_principal_id == principal_id {
        return Err(Status::invalid_argument("Cannot remove your own principal"));
    }

    // First remove all permissions for the principal
    server
        .store
        .remove_all_project_permissions_for_principal(&workspace.id, &target_principal_id)
        .await
        .map_err(|e| Status::internal(format!("Failed to remove project permissions: {}", e)))?;

    server
        .store
        .remove_all_environment_permissions_for_principal(&workspace.id, &target_principal_id)
        .await
        .map_err(|e| {
            Status::internal(format!("Failed to remove environment permissions: {}", e))
        })?;

    // Remove the principal from the workspace
    server
        .store
        .remove_workspace_principal(&workspace.id, &target_principal_id)
        .await
        .map_err(|e| {
            Status::internal(format!("Failed to remove principal from workspace: {}", e))
        })?;

    Ok(Response::new(Empty {}))
}

pub async fn revoke_all_principal_permissions(
    server: &ZoppServer,
    request: Request<RevokeAllPrincipalPermissionsRequest>,
) -> Result<Response<RevokeAllPrincipalPermissionsResponse>, Status> {
    let (principal_id, timestamp, signature, request_hash) = extract_signature(&request)?;
    let req_for_verify = request.get_ref().clone();
    let principal = server
        .verify_signature_and_get_principal(
            &principal_id,
            timestamp,
            &signature,
            "/zopp.ZoppService/RevokeAllPrincipalPermissions",
            &req_for_verify,
            &request_hash,
        )
        .await?;
    let user_id = principal.user_id.ok_or_else(|| {
        Status::unauthenticated("Service accounts cannot revoke principal permissions")
    })?;

    let req = request.into_inner();

    // Look up workspace by name
    let workspace = server
        .store
        .get_workspace_by_name(&user_id, &req.workspace_name)
        .await
        .map_err(|e| match e {
            zopp_storage::StoreError::NotFound => {
                Status::not_found("Workspace not found or access denied")
            }
            _ => Status::internal(format!("Failed to get workspace: {}", e)),
        })?;

    // Check ADMIN permission (only admins can bulk revoke permissions)
    server
        .check_workspace_permission(&principal_id, &workspace.id, zopp_storage::Role::Admin)
        .await?;

    // Parse target principal ID
    let target_principal_id = Uuid::parse_str(&req.principal_id)
        .map(PrincipalId)
        .map_err(|_| Status::invalid_argument("Invalid principal ID"))?;

    // Verify principal exists
    server
        .store
        .get_principal(&target_principal_id)
        .await
        .map_err(|e| match e {
            zopp_storage::StoreError::NotFound => Status::not_found("Principal not found"),
            _ => Status::internal(format!("Failed to get principal: {}", e)),
        })?;

    // Remove all permissions for the principal (workspace, project, environment)
    let mut total_removed = 0;

    // Remove workspace-level permission
    match server
        .store
        .remove_workspace_permission(&workspace.id, &target_principal_id)
        .await
    {
        Ok(()) => total_removed += 1,
        Err(zopp_storage::StoreError::NotFound) => {} // No workspace permission to remove
        Err(e) => {
            return Err(Status::internal(format!(
                "Failed to remove workspace permission: {}",
                e
            )))
        }
    }

    // Remove project-level permissions
    let project_removed = server
        .store
        .remove_all_project_permissions_for_principal(&workspace.id, &target_principal_id)
        .await
        .map_err(|e| Status::internal(format!("Failed to remove project permissions: {}", e)))?;
    total_removed += project_removed;

    // Remove environment-level permissions
    let env_removed = server
        .store
        .remove_all_environment_permissions_for_principal(&workspace.id, &target_principal_id)
        .await
        .map_err(|e| {
            Status::internal(format!("Failed to remove environment permissions: {}", e))
        })?;
    total_removed += env_removed;

    Ok(Response::new(RevokeAllPrincipalPermissionsResponse {
        permissions_revoked: total_removed as i32,
    }))
}

pub async fn get_effective_permissions(
    server: &ZoppServer,
    request: Request<GetEffectivePermissionsRequest>,
) -> Result<Response<EffectivePermissionsResponse>, Status> {
    let (principal_id, timestamp, signature, request_hash) = extract_signature(&request)?;
    let req_for_verify = request.get_ref().clone();
    let principal = server
        .verify_signature_and_get_principal(
            &principal_id,
            timestamp,
            &signature,
            "/zopp.ZoppService/GetEffectivePermissions",
            &req_for_verify,
            &request_hash,
        )
        .await?;
    let user_id = principal.user_id.ok_or_else(|| {
        Status::unauthenticated("Service accounts cannot query effective permissions")
    })?;

    let req = request.into_inner();

    // Look up workspace by name
    let workspace = server
        .store
        .get_workspace_by_name(&user_id, &req.workspace_name)
        .await
        .map_err(|e| match e {
            zopp_storage::StoreError::NotFound => {
                Status::not_found("Workspace not found or access denied")
            }
            _ => Status::internal(format!("Failed to get workspace: {}", e)),
        })?;

    // Parse target principal ID
    let target_principal_id = Uuid::parse_str(&req.principal_id)
        .map(PrincipalId)
        .map_err(|_| Status::invalid_argument("Invalid principal ID"))?;

    // Get target principal info
    let target_principal = server
        .store
        .get_principal(&target_principal_id)
        .await
        .map_err(|e| match e {
            zopp_storage::StoreError::NotFound => Status::not_found("Principal not found"),
            _ => Status::internal(format!("Failed to get principal: {}", e)),
        })?;

    let is_service_principal = target_principal.user_id.is_none();

    // Get workspace-level effective role
    let workspace_role = server
        .get_effective_workspace_role(&target_principal_id, &workspace.id)
        .await?;

    // Get all projects in the workspace
    let projects = server
        .store
        .list_projects(&workspace.id)
        .await
        .map_err(|e| Status::internal(format!("Failed to list projects: {}", e)))?;

    let mut effective_projects = Vec::new();

    for project in projects {
        // Get project-level effective role
        let project_role = server
            .get_effective_project_role(&target_principal_id, &workspace.id, &project.id)
            .await?;

        // Get all environments in this project
        let environments = server
            .store
            .list_environments(&project.id)
            .await
            .map_err(|e| Status::internal(format!("Failed to list environments: {}", e)))?;

        let mut effective_environments = Vec::new();

        for env in environments {
            // Get environment-level effective role
            let env_role = server
                .get_effective_environment_role(
                    &target_principal_id,
                    &workspace.id,
                    &project.id,
                    &env.id,
                )
                .await?;

            if let Some(role) = env_role {
                effective_environments.push(zopp_proto::EffectiveEnvironmentPermission {
                    environment_id: env.id.0.to_string(),
                    environment_name: env.name,
                    effective_role: match role {
                        zopp_storage::Role::Admin => zopp_proto::Role::Admin as i32,
                        zopp_storage::Role::Write => zopp_proto::Role::Write as i32,
                        zopp_storage::Role::Read => zopp_proto::Role::Read as i32,
                    },
                });
            }
        }

        // Only include project if there are permissions at any level
        if project_role.is_some() || !effective_environments.is_empty() {
            effective_projects.push(zopp_proto::EffectiveProjectPermission {
                project_id: project.id.0.to_string(),
                project_name: project.name,
                effective_role: project_role.map(|r| match r {
                    zopp_storage::Role::Admin => zopp_proto::Role::Admin as i32,
                    zopp_storage::Role::Write => zopp_proto::Role::Write as i32,
                    zopp_storage::Role::Read => zopp_proto::Role::Read as i32,
                }),
                environments: effective_environments,
            });
        }
    }

    Ok(Response::new(EffectivePermissionsResponse {
        principal_id: target_principal.id.0.to_string(),
        principal_name: target_principal.name,
        is_service_principal,
        workspace_role: workspace_role.map(|r| match r {
            zopp_storage::Role::Admin => zopp_proto::Role::Admin as i32,
            zopp_storage::Role::Write => zopp_proto::Role::Write as i32,
            zopp_storage::Role::Read => zopp_proto::Role::Read as i32,
        }),
        projects: effective_projects,
    }))
}
