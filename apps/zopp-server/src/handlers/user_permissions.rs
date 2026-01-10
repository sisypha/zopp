//! User permission handlers: set, get, list, remove at workspace/project/environment levels

use tonic::{Request, Response, Status};
use zopp_proto::Empty;
use zopp_storage::Store;

use crate::server::{extract_signature, ZoppServer};

// ───────────────────────────────────── Workspace Level ─────────────────────────────────────

pub async fn set_user_workspace_permission(
    server: &ZoppServer,
    request: Request<zopp_proto::SetUserWorkspacePermissionRequest>,
) -> Result<Response<Empty>, Status> {
    let (principal_id, timestamp, signature, request_hash) = extract_signature(&request)?;
    let req_for_verify = request.get_ref().clone();
    let principal = server
        .verify_signature_and_get_principal(&principal_id, timestamp, &signature, "/zopp.ZoppService/SetUserWorkspacePermission", &req_for_verify, &request_hash)
        .await?;
    let user_id = principal
        .user_id
        .ok_or_else(|| Status::unauthenticated("Service accounts cannot set user permissions"))?;

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

    // Convert proto Role to storage Role first so we can check delegated authority
    let role = match zopp_proto::Role::try_from(req.role) {
        Ok(zopp_proto::Role::Admin) => zopp_storage::Role::Admin,
        Ok(zopp_proto::Role::Write) => zopp_storage::Role::Write,
        Ok(zopp_proto::Role::Read) => zopp_storage::Role::Read,
        _ => return Err(Status::invalid_argument("Invalid role")),
    };

    // Delegated authority: requester can only grant permissions <= their own effective role
    let requester_role = server
        .get_effective_workspace_role(&principal_id, &workspace.id)
        .await?
        .ok_or_else(|| {
            Status::permission_denied("No permission to set user permissions on this workspace")
        })?;

    // Check if requester's role is sufficient to grant the requested role
    if !requester_role.includes(&role) {
        return Err(Status::permission_denied(format!(
            "Cannot grant {:?} permission (you only have {:?} access)",
            role, requester_role
        )));
    }

    // Look up target user by email
    let target_user = server
        .store
        .get_user_by_email(&req.user_email)
        .await
        .map_err(|e| match e {
            zopp_storage::StoreError::NotFound => Status::not_found("User not found"),
            _ => Status::internal(format!("Failed to get user: {}", e)),
        })?;

    server
        .store
        .set_user_workspace_permission(&workspace.id, &target_user.id, role)
        .await
        .map_err(|e| Status::internal(format!("Failed to set user permission: {}", e)))?;

    Ok(Response::new(Empty {}))
}

pub async fn get_user_workspace_permission(
    server: &ZoppServer,
    request: Request<zopp_proto::GetUserWorkspacePermissionRequest>,
) -> Result<Response<zopp_proto::PermissionResponse>, Status> {
    let (principal_id, timestamp, signature, request_hash) = extract_signature(&request)?;
    let req_for_verify = request.get_ref().clone();
    let principal = server
        .verify_signature_and_get_principal(&principal_id, timestamp, &signature, "/zopp.ZoppService/GetUserWorkspacePermission", &req_for_verify, &request_hash)
        .await?;
    let user_id = principal
        .user_id
        .ok_or_else(|| Status::unauthenticated("Service accounts cannot get user permissions"))?;

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

    // Look up target user by email
    let target_user = server
        .store
        .get_user_by_email(&req.user_email)
        .await
        .map_err(|e| match e {
            zopp_storage::StoreError::NotFound => Status::not_found("User not found"),
            _ => Status::internal(format!("Failed to get user: {}", e)),
        })?;

    let role = server
        .store
        .get_user_workspace_permission(&workspace.id, &target_user.id)
        .await
        .map_err(|e| match e {
            zopp_storage::StoreError::NotFound => Status::not_found("Permission not found"),
            _ => Status::internal(format!("Failed to get user permission: {}", e)),
        })?;

    let proto_role = match role {
        zopp_storage::Role::Admin => zopp_proto::Role::Admin,
        zopp_storage::Role::Write => zopp_proto::Role::Write,
        zopp_storage::Role::Read => zopp_proto::Role::Read,
    };

    Ok(Response::new(zopp_proto::PermissionResponse {
        role: proto_role as i32,
    }))
}

pub async fn list_user_workspace_permissions(
    server: &ZoppServer,
    request: Request<zopp_proto::ListUserWorkspacePermissionsRequest>,
) -> Result<Response<zopp_proto::UserPermissionList>, Status> {
    let (principal_id, timestamp, signature, request_hash) = extract_signature(&request)?;
    let req_for_verify = request.get_ref().clone();
    let principal = server
        .verify_signature_and_get_principal(&principal_id, timestamp, &signature, "/zopp.ZoppService/ListUserWorkspacePermissions", &req_for_verify, &request_hash)
        .await?;
    let user_id = principal
        .user_id
        .ok_or_else(|| Status::unauthenticated("Service accounts cannot list user permissions"))?;

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

    let permissions = server
        .store
        .list_user_workspace_permissions(&workspace.id)
        .await
        .map_err(|e| Status::internal(format!("Failed to list user permissions: {}", e)))?;

    let mut proto_permissions = Vec::with_capacity(permissions.len());
    for perm in permissions {
        let user = server.store.get_user_by_id(&perm.user_id).await.ok();
        let proto_role = match perm.role {
            zopp_storage::Role::Admin => zopp_proto::Role::Admin,
            zopp_storage::Role::Write => zopp_proto::Role::Write,
            zopp_storage::Role::Read => zopp_proto::Role::Read,
        };
        proto_permissions.push(zopp_proto::UserPermission {
            user_id: perm.user_id.0.to_string(),
            user_email: user.map(|u| u.email).unwrap_or_default(),
            role: proto_role as i32,
        });
    }

    Ok(Response::new(zopp_proto::UserPermissionList {
        permissions: proto_permissions,
    }))
}

pub async fn remove_user_workspace_permission(
    server: &ZoppServer,
    request: Request<zopp_proto::RemoveUserWorkspacePermissionRequest>,
) -> Result<Response<Empty>, Status> {
    let (principal_id, timestamp, signature, request_hash) = extract_signature(&request)?;
    let req_for_verify = request.get_ref().clone();
    let principal = server
        .verify_signature_and_get_principal(&principal_id, timestamp, &signature, "/zopp.ZoppService/RemoveUserWorkspacePermission", &req_for_verify, &request_hash)
        .await?;
    let user_id = principal.user_id.ok_or_else(|| {
        Status::unauthenticated("Service accounts cannot remove user permissions")
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

    // Look up target user by email
    let target_user = server
        .store
        .get_user_by_email(&req.user_email)
        .await
        .map_err(|e| match e {
            zopp_storage::StoreError::NotFound => Status::not_found("User not found"),
            _ => Status::internal(format!("Failed to get user: {}", e)),
        })?;

    // Get target user's current permission level
    let target_role = server
        .store
        .get_user_workspace_permission(&workspace.id, &target_user.id)
        .await
        .map_err(|e| match e {
            zopp_storage::StoreError::NotFound => Status::not_found("User permission not found"),
            _ => Status::internal(format!("Failed to get user permission: {}", e)),
        })?;

    // Delegated authority: requester can only remove permissions <= their own effective role
    let requester_role = server
        .get_effective_workspace_role(&principal_id, &workspace.id)
        .await?
        .ok_or_else(|| {
            Status::permission_denied("No permission to remove user permissions on this workspace")
        })?;

    // Check if requester's role is sufficient to remove the target's role
    if !requester_role.includes(&target_role) {
        return Err(Status::permission_denied(format!(
            "Cannot remove {:?} permission (you only have {:?} access)",
            target_role, requester_role
        )));
    }

    server
        .store
        .remove_user_workspace_permission(&workspace.id, &target_user.id)
        .await
        .map_err(|e| Status::internal(format!("Failed to remove user permission: {}", e)))?;

    Ok(Response::new(Empty {}))
}

// ───────────────────────────────────── Project Level ─────────────────────────────────────

pub async fn set_user_project_permission(
    server: &ZoppServer,
    request: Request<zopp_proto::SetUserProjectPermissionRequest>,
) -> Result<Response<Empty>, Status> {
    let (principal_id, timestamp, signature, request_hash) = extract_signature(&request)?;
    let req_for_verify = request.get_ref().clone();
    let principal = server
        .verify_signature_and_get_principal(&principal_id, timestamp, &signature, "/zopp.ZoppService/SetUserProjectPermission", &req_for_verify, &request_hash)
        .await?;
    let user_id = principal
        .user_id
        .ok_or_else(|| Status::unauthenticated("Service accounts cannot set user permissions"))?;

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

    // Look up project by name
    let project = server
        .store
        .get_project_by_name(&workspace.id, &req.project_name)
        .await
        .map_err(|e| match e {
            zopp_storage::StoreError::NotFound => Status::not_found("Project not found"),
            _ => Status::internal(format!("Failed to get project: {}", e)),
        })?;

    // Look up target user by email
    let target_user = server
        .store
        .get_user_by_email(&req.user_email)
        .await
        .map_err(|e| match e {
            zopp_storage::StoreError::NotFound => Status::not_found("User not found"),
            _ => Status::internal(format!("Failed to get user: {}", e)),
        })?;

    // Check ADMIN permission (project-level or higher)
    server
        .check_project_permission(
            &principal_id,
            &workspace.id,
            &project.id,
            zopp_storage::Role::Admin,
        )
        .await?;

    // Convert proto Role to storage Role
    let role = match zopp_proto::Role::try_from(req.role) {
        Ok(zopp_proto::Role::Admin) => zopp_storage::Role::Admin,
        Ok(zopp_proto::Role::Write) => zopp_storage::Role::Write,
        Ok(zopp_proto::Role::Read) => zopp_storage::Role::Read,
        _ => return Err(Status::invalid_argument("Invalid role")),
    };

    server
        .store
        .set_user_project_permission(&project.id, &target_user.id, role)
        .await
        .map_err(|e| Status::internal(format!("Failed to set user permission: {}", e)))?;

    Ok(Response::new(Empty {}))
}

pub async fn get_user_project_permission(
    server: &ZoppServer,
    request: Request<zopp_proto::GetUserProjectPermissionRequest>,
) -> Result<Response<zopp_proto::PermissionResponse>, Status> {
    let (principal_id, timestamp, signature, request_hash) = extract_signature(&request)?;
    let req_for_verify = request.get_ref().clone();
    let principal = server
        .verify_signature_and_get_principal(&principal_id, timestamp, &signature, "/zopp.ZoppService/GetUserProjectPermission", &req_for_verify, &request_hash)
        .await?;
    let user_id = principal
        .user_id
        .ok_or_else(|| Status::unauthenticated("Service accounts cannot get user permissions"))?;

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

    // Look up project by name
    let project = server
        .store
        .get_project_by_name(&workspace.id, &req.project_name)
        .await
        .map_err(|e| match e {
            zopp_storage::StoreError::NotFound => Status::not_found("Project not found"),
            _ => Status::internal(format!("Failed to get project: {}", e)),
        })?;

    // Look up target user by email
    let target_user = server
        .store
        .get_user_by_email(&req.user_email)
        .await
        .map_err(|e| match e {
            zopp_storage::StoreError::NotFound => Status::not_found("User not found"),
            _ => Status::internal(format!("Failed to get user: {}", e)),
        })?;

    let role = server
        .store
        .get_user_project_permission(&project.id, &target_user.id)
        .await
        .map_err(|e| match e {
            zopp_storage::StoreError::NotFound => Status::not_found("Permission not found"),
            _ => Status::internal(format!("Failed to get user permission: {}", e)),
        })?;

    let proto_role = match role {
        zopp_storage::Role::Admin => zopp_proto::Role::Admin,
        zopp_storage::Role::Write => zopp_proto::Role::Write,
        zopp_storage::Role::Read => zopp_proto::Role::Read,
    };

    Ok(Response::new(zopp_proto::PermissionResponse {
        role: proto_role as i32,
    }))
}

pub async fn list_user_project_permissions(
    server: &ZoppServer,
    request: Request<zopp_proto::ListUserProjectPermissionsRequest>,
) -> Result<Response<zopp_proto::UserPermissionList>, Status> {
    let (principal_id, timestamp, signature, request_hash) = extract_signature(&request)?;
    let req_for_verify = request.get_ref().clone();
    let principal = server
        .verify_signature_and_get_principal(&principal_id, timestamp, &signature, "/zopp.ZoppService/ListUserProjectPermissions", &req_for_verify, &request_hash)
        .await?;
    let user_id = principal
        .user_id
        .ok_or_else(|| Status::unauthenticated("Service accounts cannot list user permissions"))?;

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

    // Look up project by name
    let project = server
        .store
        .get_project_by_name(&workspace.id, &req.project_name)
        .await
        .map_err(|e| match e {
            zopp_storage::StoreError::NotFound => Status::not_found("Project not found"),
            _ => Status::internal(format!("Failed to get project: {}", e)),
        })?;

    let permissions = server
        .store
        .list_user_project_permissions(&project.id)
        .await
        .map_err(|e| Status::internal(format!("Failed to list user permissions: {}", e)))?;

    let mut proto_permissions = Vec::with_capacity(permissions.len());
    for perm in permissions {
        let user = server.store.get_user_by_id(&perm.user_id).await.ok();
        let proto_role = match perm.role {
            zopp_storage::Role::Admin => zopp_proto::Role::Admin,
            zopp_storage::Role::Write => zopp_proto::Role::Write,
            zopp_storage::Role::Read => zopp_proto::Role::Read,
        };
        proto_permissions.push(zopp_proto::UserPermission {
            user_id: perm.user_id.0.to_string(),
            user_email: user.map(|u| u.email).unwrap_or_default(),
            role: proto_role as i32,
        });
    }

    Ok(Response::new(zopp_proto::UserPermissionList {
        permissions: proto_permissions,
    }))
}

pub async fn remove_user_project_permission(
    server: &ZoppServer,
    request: Request<zopp_proto::RemoveUserProjectPermissionRequest>,
) -> Result<Response<Empty>, Status> {
    let (principal_id, timestamp, signature, request_hash) = extract_signature(&request)?;
    let req_for_verify = request.get_ref().clone();
    let principal = server
        .verify_signature_and_get_principal(&principal_id, timestamp, &signature, "/zopp.ZoppService/RemoveUserProjectPermission", &req_for_verify, &request_hash)
        .await?;
    let user_id = principal.user_id.ok_or_else(|| {
        Status::unauthenticated("Service accounts cannot remove user permissions")
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

    // Look up project by name
    let project = server
        .store
        .get_project_by_name(&workspace.id, &req.project_name)
        .await
        .map_err(|e| match e {
            zopp_storage::StoreError::NotFound => Status::not_found("Project not found"),
            _ => Status::internal(format!("Failed to get project: {}", e)),
        })?;

    // Look up target user by email
    let target_user = server
        .store
        .get_user_by_email(&req.user_email)
        .await
        .map_err(|e| match e {
            zopp_storage::StoreError::NotFound => Status::not_found("User not found"),
            _ => Status::internal(format!("Failed to get user: {}", e)),
        })?;

    // Check ADMIN permission (project-level or higher)
    server
        .check_project_permission(
            &principal_id,
            &workspace.id,
            &project.id,
            zopp_storage::Role::Admin,
        )
        .await?;

    server
        .store
        .remove_user_project_permission(&project.id, &target_user.id)
        .await
        .map_err(|e| Status::internal(format!("Failed to remove user permission: {}", e)))?;

    Ok(Response::new(Empty {}))
}

// ───────────────────────────────────── Environment Level ─────────────────────────────────────

pub async fn set_user_environment_permission(
    server: &ZoppServer,
    request: Request<zopp_proto::SetUserEnvironmentPermissionRequest>,
) -> Result<Response<Empty>, Status> {
    let (principal_id, timestamp, signature, request_hash) = extract_signature(&request)?;
    let req_for_verify = request.get_ref().clone();
    let principal = server
        .verify_signature_and_get_principal(&principal_id, timestamp, &signature, "/zopp.ZoppService/SetUserEnvironmentPermission", &req_for_verify, &request_hash)
        .await?;
    let user_id = principal
        .user_id
        .ok_or_else(|| Status::unauthenticated("Service accounts cannot set user permissions"))?;

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

    // Look up project by name
    let project = server
        .store
        .get_project_by_name(&workspace.id, &req.project_name)
        .await
        .map_err(|e| match e {
            zopp_storage::StoreError::NotFound => Status::not_found("Project not found"),
            _ => Status::internal(format!("Failed to get project: {}", e)),
        })?;

    // Look up environment by name
    let env = server
        .store
        .get_environment_by_name(&project.id, &req.environment_name)
        .await
        .map_err(|e| match e {
            zopp_storage::StoreError::NotFound => Status::not_found("Environment not found"),
            _ => Status::internal(format!("Failed to get environment: {}", e)),
        })?;

    // Look up target user by email
    let target_user = server
        .store
        .get_user_by_email(&req.user_email)
        .await
        .map_err(|e| match e {
            zopp_storage::StoreError::NotFound => Status::not_found("User not found"),
            _ => Status::internal(format!("Failed to get user: {}", e)),
        })?;

    // Check ADMIN permission (environment-level or higher)
    server
        .check_environment_permission(
            &principal_id,
            &workspace.id,
            &project.id,
            &env.id,
            zopp_storage::Role::Admin,
        )
        .await?;

    // Convert proto Role to storage Role
    let role = match zopp_proto::Role::try_from(req.role) {
        Ok(zopp_proto::Role::Admin) => zopp_storage::Role::Admin,
        Ok(zopp_proto::Role::Write) => zopp_storage::Role::Write,
        Ok(zopp_proto::Role::Read) => zopp_storage::Role::Read,
        _ => return Err(Status::invalid_argument("Invalid role")),
    };

    server
        .store
        .set_user_environment_permission(&env.id, &target_user.id, role)
        .await
        .map_err(|e| Status::internal(format!("Failed to set user permission: {}", e)))?;

    Ok(Response::new(Empty {}))
}

pub async fn get_user_environment_permission(
    server: &ZoppServer,
    request: Request<zopp_proto::GetUserEnvironmentPermissionRequest>,
) -> Result<Response<zopp_proto::PermissionResponse>, Status> {
    let (principal_id, timestamp, signature, request_hash) = extract_signature(&request)?;
    let req_for_verify = request.get_ref().clone();
    let principal = server
        .verify_signature_and_get_principal(&principal_id, timestamp, &signature, "/zopp.ZoppService/GetUserEnvironmentPermission", &req_for_verify, &request_hash)
        .await?;
    let user_id = principal
        .user_id
        .ok_or_else(|| Status::unauthenticated("Service accounts cannot get user permissions"))?;

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

    // Look up project by name
    let project = server
        .store
        .get_project_by_name(&workspace.id, &req.project_name)
        .await
        .map_err(|e| match e {
            zopp_storage::StoreError::NotFound => Status::not_found("Project not found"),
            _ => Status::internal(format!("Failed to get project: {}", e)),
        })?;

    // Look up environment by name
    let env = server
        .store
        .get_environment_by_name(&project.id, &req.environment_name)
        .await
        .map_err(|e| match e {
            zopp_storage::StoreError::NotFound => Status::not_found("Environment not found"),
            _ => Status::internal(format!("Failed to get environment: {}", e)),
        })?;

    // Look up target user by email
    let target_user = server
        .store
        .get_user_by_email(&req.user_email)
        .await
        .map_err(|e| match e {
            zopp_storage::StoreError::NotFound => Status::not_found("User not found"),
            _ => Status::internal(format!("Failed to get user: {}", e)),
        })?;

    let role = server
        .store
        .get_user_environment_permission(&env.id, &target_user.id)
        .await
        .map_err(|e| match e {
            zopp_storage::StoreError::NotFound => Status::not_found("Permission not found"),
            _ => Status::internal(format!("Failed to get user permission: {}", e)),
        })?;

    let proto_role = match role {
        zopp_storage::Role::Admin => zopp_proto::Role::Admin,
        zopp_storage::Role::Write => zopp_proto::Role::Write,
        zopp_storage::Role::Read => zopp_proto::Role::Read,
    };

    Ok(Response::new(zopp_proto::PermissionResponse {
        role: proto_role as i32,
    }))
}

pub async fn list_user_environment_permissions(
    server: &ZoppServer,
    request: Request<zopp_proto::ListUserEnvironmentPermissionsRequest>,
) -> Result<Response<zopp_proto::UserPermissionList>, Status> {
    let (principal_id, timestamp, signature, request_hash) = extract_signature(&request)?;
    let req_for_verify = request.get_ref().clone();
    let principal = server
        .verify_signature_and_get_principal(&principal_id, timestamp, &signature, "/zopp.ZoppService/ListUserEnvironmentPermissions", &req_for_verify, &request_hash)
        .await?;
    let user_id = principal
        .user_id
        .ok_or_else(|| Status::unauthenticated("Service accounts cannot list user permissions"))?;

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

    // Look up project by name
    let project = server
        .store
        .get_project_by_name(&workspace.id, &req.project_name)
        .await
        .map_err(|e| match e {
            zopp_storage::StoreError::NotFound => Status::not_found("Project not found"),
            _ => Status::internal(format!("Failed to get project: {}", e)),
        })?;

    // Look up environment by name
    let env = server
        .store
        .get_environment_by_name(&project.id, &req.environment_name)
        .await
        .map_err(|e| match e {
            zopp_storage::StoreError::NotFound => Status::not_found("Environment not found"),
            _ => Status::internal(format!("Failed to get environment: {}", e)),
        })?;

    let permissions = server
        .store
        .list_user_environment_permissions(&env.id)
        .await
        .map_err(|e| Status::internal(format!("Failed to list user permissions: {}", e)))?;

    let mut proto_permissions = Vec::with_capacity(permissions.len());
    for perm in permissions {
        let user = server.store.get_user_by_id(&perm.user_id).await.ok();
        let proto_role = match perm.role {
            zopp_storage::Role::Admin => zopp_proto::Role::Admin,
            zopp_storage::Role::Write => zopp_proto::Role::Write,
            zopp_storage::Role::Read => zopp_proto::Role::Read,
        };
        proto_permissions.push(zopp_proto::UserPermission {
            user_id: perm.user_id.0.to_string(),
            user_email: user.map(|u| u.email).unwrap_or_default(),
            role: proto_role as i32,
        });
    }

    Ok(Response::new(zopp_proto::UserPermissionList {
        permissions: proto_permissions,
    }))
}

pub async fn remove_user_environment_permission(
    server: &ZoppServer,
    request: Request<zopp_proto::RemoveUserEnvironmentPermissionRequest>,
) -> Result<Response<Empty>, Status> {
    let (principal_id, timestamp, signature, request_hash) = extract_signature(&request)?;
    let req_for_verify = request.get_ref().clone();
    let principal = server
        .verify_signature_and_get_principal(&principal_id, timestamp, &signature, "/zopp.ZoppService/RemoveUserEnvironmentPermission", &req_for_verify, &request_hash)
        .await?;
    let user_id = principal.user_id.ok_or_else(|| {
        Status::unauthenticated("Service accounts cannot remove user permissions")
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

    // Look up project by name
    let project = server
        .store
        .get_project_by_name(&workspace.id, &req.project_name)
        .await
        .map_err(|e| match e {
            zopp_storage::StoreError::NotFound => Status::not_found("Project not found"),
            _ => Status::internal(format!("Failed to get project: {}", e)),
        })?;

    // Look up environment by name
    let env = server
        .store
        .get_environment_by_name(&project.id, &req.environment_name)
        .await
        .map_err(|e| match e {
            zopp_storage::StoreError::NotFound => Status::not_found("Environment not found"),
            _ => Status::internal(format!("Failed to get environment: {}", e)),
        })?;

    // Look up target user by email
    let target_user = server
        .store
        .get_user_by_email(&req.user_email)
        .await
        .map_err(|e| match e {
            zopp_storage::StoreError::NotFound => Status::not_found("User not found"),
            _ => Status::internal(format!("Failed to get user: {}", e)),
        })?;

    // Check ADMIN permission (environment-level or higher)
    server
        .check_environment_permission(
            &principal_id,
            &workspace.id,
            &project.id,
            &env.id,
            zopp_storage::Role::Admin,
        )
        .await?;

    server
        .store
        .remove_user_environment_permission(&env.id, &target_user.id)
        .await
        .map_err(|e| Status::internal(format!("Failed to remove user permission: {}", e)))?;

    Ok(Response::new(Empty {}))
}
