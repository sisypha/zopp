//! Principal permission handlers: set, get, list, remove at workspace/project/environment levels

use tonic::{Request, Response, Status};
use uuid::Uuid;
use zopp_proto::Empty;
use zopp_storage::{PrincipalId, Store};

use crate::server::{extract_signature, ZoppServer};

// ───────────────────────────────────── Workspace Permissions ─────────────────────────────────────

pub async fn set_workspace_permission(
    server: &ZoppServer,
    request: Request<zopp_proto::SetWorkspacePermissionRequest>,
) -> Result<Response<Empty>, Status> {
    let (principal_id, timestamp, signature, request_hash) = extract_signature(&request)?;
    let req_for_verify = request.get_ref().clone();
    let principal = server
        .verify_signature_and_get_principal(&principal_id, timestamp, &signature, "/zopp.ZoppService/SetWorkspacePermission", &req_for_verify, &request_hash)
        .await?;
    let user_id = principal
        .user_id
        .ok_or_else(|| Status::unauthenticated("Service accounts cannot set permissions"))?;

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

    // Parse principal ID
    let target_principal_id = Uuid::parse_str(&req.principal_id)
        .map(PrincipalId)
        .map_err(|_| Status::invalid_argument("Invalid principal ID"))?;

    // Convert proto Role to storage Role
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
            Status::permission_denied("No permission to set permissions on this workspace")
        })?;

    // Check if requester's role is sufficient to grant the requested role
    if !requester_role.includes(&role) {
        return Err(Status::permission_denied(format!(
            "Cannot grant {:?} permission (you only have {:?} access)",
            role, requester_role
        )));
    }

    server
        .store
        .set_workspace_permission(&workspace.id, &target_principal_id, role)
        .await
        .map_err(|e| Status::internal(format!("Failed to set permission: {}", e)))?;

    Ok(Response::new(Empty {}))
}

pub async fn get_workspace_permission(
    server: &ZoppServer,
    request: Request<zopp_proto::GetWorkspacePermissionRequest>,
) -> Result<Response<zopp_proto::PermissionResponse>, Status> {
    let (principal_id, timestamp, signature, request_hash) = extract_signature(&request)?;
    let req_for_verify = request.get_ref().clone();
    let principal = server
        .verify_signature_and_get_principal(&principal_id, timestamp, &signature, "/zopp.ZoppService/GetWorkspacePermission", &req_for_verify, &request_hash)
        .await?;
    let user_id = principal
        .user_id
        .ok_or_else(|| Status::unauthenticated("Service accounts cannot get permissions"))?;

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

    // Parse principal ID
    let target_principal_id = Uuid::parse_str(&req.principal_id)
        .map(PrincipalId)
        .map_err(|_| Status::invalid_argument("Invalid principal ID"))?;

    let role = server
        .store
        .get_workspace_permission(&workspace.id, &target_principal_id)
        .await
        .map_err(|e| match e {
            zopp_storage::StoreError::NotFound => Status::not_found("Permission not found"),
            _ => Status::internal(format!("Failed to get permission: {}", e)),
        })?;

    // Convert storage Role to proto Role
    let proto_role = match role {
        zopp_storage::Role::Admin => zopp_proto::Role::Admin as i32,
        zopp_storage::Role::Write => zopp_proto::Role::Write as i32,
        zopp_storage::Role::Read => zopp_proto::Role::Read as i32,
    };

    Ok(Response::new(zopp_proto::PermissionResponse {
        role: proto_role,
    }))
}

pub async fn list_workspace_permissions(
    server: &ZoppServer,
    request: Request<zopp_proto::ListWorkspacePermissionsRequest>,
) -> Result<Response<zopp_proto::PermissionList>, Status> {
    let (principal_id, timestamp, signature, request_hash) = extract_signature(&request)?;
    let req_for_verify = request.get_ref().clone();
    let principal = server
        .verify_signature_and_get_principal(&principal_id, timestamp, &signature, "/zopp.ZoppService/ListWorkspacePermissions", &req_for_verify, &request_hash)
        .await?;
    let user_id = principal
        .user_id
        .ok_or_else(|| Status::unauthenticated("Service accounts cannot list permissions"))?;

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
        .list_workspace_permissions(&workspace.id)
        .await
        .map_err(|e| Status::internal(format!("Failed to list permissions: {}", e)))?;

    let mut proto_permissions = Vec::with_capacity(permissions.len());
    for p in permissions {
        let principal_name = match server.store.get_principal(&p.principal_id).await {
            Ok(principal) => principal.name,
            Err(_) => String::new(), // Principal might have been deleted
        };
        proto_permissions.push(zopp_proto::Permission {
            principal_id: p.principal_id.0.to_string(),
            principal_name,
            role: match p.role {
                zopp_storage::Role::Admin => zopp_proto::Role::Admin as i32,
                zopp_storage::Role::Write => zopp_proto::Role::Write as i32,
                zopp_storage::Role::Read => zopp_proto::Role::Read as i32,
            },
        });
    }

    Ok(Response::new(zopp_proto::PermissionList {
        permissions: proto_permissions,
    }))
}

pub async fn remove_workspace_permission(
    server: &ZoppServer,
    request: Request<zopp_proto::RemoveWorkspacePermissionRequest>,
) -> Result<Response<Empty>, Status> {
    let (principal_id, timestamp, signature, request_hash) = extract_signature(&request)?;
    let req_for_verify = request.get_ref().clone();
    let principal = server
        .verify_signature_and_get_principal(&principal_id, timestamp, &signature, "/zopp.ZoppService/RemoveWorkspacePermission", &req_for_verify, &request_hash)
        .await?;
    let user_id = principal
        .user_id
        .ok_or_else(|| Status::unauthenticated("Service accounts cannot remove permissions"))?;

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

    // Parse principal ID
    let target_principal_id = Uuid::parse_str(&req.principal_id)
        .map(PrincipalId)
        .map_err(|_| Status::invalid_argument("Invalid principal ID"))?;

    // Get the target's current role
    let target_role = server
        .store
        .get_workspace_permission(&workspace.id, &target_principal_id)
        .await
        .map_err(|e| match e {
            zopp_storage::StoreError::NotFound => Status::not_found("Permission not found"),
            _ => Status::internal(format!("Failed to get permission: {}", e)),
        })?;

    // Delegated authority: requester can only remove permissions <= their own effective role
    let requester_role = server
        .get_effective_workspace_role(&principal_id, &workspace.id)
        .await?
        .ok_or_else(|| {
            Status::permission_denied("No permission to remove permissions on this workspace")
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
        .remove_workspace_permission(&workspace.id, &target_principal_id)
        .await
        .map_err(|e| Status::internal(format!("Failed to remove permission: {}", e)))?;

    Ok(Response::new(Empty {}))
}

// ───────────────────────────────────── Project Permissions ─────────────────────────────────────

pub async fn set_project_permission(
    server: &ZoppServer,
    request: Request<zopp_proto::SetProjectPermissionRequest>,
) -> Result<Response<Empty>, Status> {
    let (principal_id, timestamp, signature, request_hash) = extract_signature(&request)?;
    let req_for_verify = request.get_ref().clone();
    server
        .verify_signature_and_get_principal(&principal_id, timestamp, &signature, "/zopp.ZoppService/SetProjectPermission", &req_for_verify, &request_hash)
        .await?;

    let req = request.into_inner();

    // Look up workspace by name for this principal
    let workspace = server
        .store
        .get_workspace_by_name_for_principal(&principal_id, &req.workspace_name)
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

    // Parse target principal ID
    let target_principal_id = Uuid::parse_str(&req.principal_id)
        .map(PrincipalId)
        .map_err(|_| Status::invalid_argument("Invalid principal ID"))?;

    // Convert proto Role to storage Role
    let role = match zopp_proto::Role::try_from(req.role) {
        Ok(zopp_proto::Role::Admin) => zopp_storage::Role::Admin,
        Ok(zopp_proto::Role::Write) => zopp_storage::Role::Write,
        Ok(zopp_proto::Role::Read) => zopp_storage::Role::Read,
        _ => return Err(Status::invalid_argument("Invalid role")),
    };

    // Delegated authority: requester can only grant permissions <= their own effective role
    let requester_role = server
        .get_effective_project_role(&principal_id, &workspace.id, &project.id)
        .await?
        .ok_or_else(|| {
            Status::permission_denied("No permission to set permissions on this project")
        })?;

    // Check if requester's role is sufficient to grant the requested role
    if !requester_role.includes(&role) {
        return Err(Status::permission_denied(format!(
            "Cannot grant {:?} permission (you only have {:?} access)",
            role, requester_role
        )));
    }

    server
        .store
        .set_project_permission(&project.id, &target_principal_id, role)
        .await
        .map_err(|e| Status::internal(format!("Failed to set permission: {}", e)))?;

    Ok(Response::new(Empty {}))
}

pub async fn get_project_permission(
    server: &ZoppServer,
    request: Request<zopp_proto::GetProjectPermissionRequest>,
) -> Result<Response<zopp_proto::PermissionResponse>, Status> {
    let (principal_id, timestamp, signature, request_hash) = extract_signature(&request)?;
    let req_for_verify = request.get_ref().clone();
    let principal = server
        .verify_signature_and_get_principal(&principal_id, timestamp, &signature, "/zopp.ZoppService/GetProjectPermission", &req_for_verify, &request_hash)
        .await?;
    let user_id = principal
        .user_id
        .ok_or_else(|| Status::unauthenticated("Service accounts cannot get permissions"))?;

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

    // Parse principal ID
    let target_principal_id = Uuid::parse_str(&req.principal_id)
        .map(PrincipalId)
        .map_err(|_| Status::invalid_argument("Invalid principal ID"))?;

    let role = server
        .store
        .get_project_permission(&project.id, &target_principal_id)
        .await
        .map_err(|e| match e {
            zopp_storage::StoreError::NotFound => Status::not_found("Permission not found"),
            _ => Status::internal(format!("Failed to get permission: {}", e)),
        })?;

    // Convert storage Role to proto Role
    let proto_role = match role {
        zopp_storage::Role::Admin => zopp_proto::Role::Admin as i32,
        zopp_storage::Role::Write => zopp_proto::Role::Write as i32,
        zopp_storage::Role::Read => zopp_proto::Role::Read as i32,
    };

    Ok(Response::new(zopp_proto::PermissionResponse {
        role: proto_role,
    }))
}

pub async fn list_project_permissions(
    server: &ZoppServer,
    request: Request<zopp_proto::ListProjectPermissionsRequest>,
) -> Result<Response<zopp_proto::PermissionList>, Status> {
    let (principal_id, timestamp, signature, request_hash) = extract_signature(&request)?;
    let req_for_verify = request.get_ref().clone();
    let principal = server
        .verify_signature_and_get_principal(&principal_id, timestamp, &signature, "/zopp.ZoppService/ListProjectPermissions", &req_for_verify, &request_hash)
        .await?;
    let user_id = principal
        .user_id
        .ok_or_else(|| Status::unauthenticated("Service accounts cannot list permissions"))?;

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
        .list_project_permissions(&project.id)
        .await
        .map_err(|e| Status::internal(format!("Failed to list permissions: {}", e)))?;

    let mut proto_permissions = Vec::with_capacity(permissions.len());
    for p in permissions {
        let principal_name = match server.store.get_principal(&p.principal_id).await {
            Ok(principal) => principal.name,
            Err(_) => String::new(), // Principal might have been deleted
        };
        proto_permissions.push(zopp_proto::Permission {
            principal_id: p.principal_id.0.to_string(),
            principal_name,
            role: match p.role {
                zopp_storage::Role::Admin => zopp_proto::Role::Admin as i32,
                zopp_storage::Role::Write => zopp_proto::Role::Write as i32,
                zopp_storage::Role::Read => zopp_proto::Role::Read as i32,
            },
        });
    }

    Ok(Response::new(zopp_proto::PermissionList {
        permissions: proto_permissions,
    }))
}

pub async fn remove_project_permission(
    server: &ZoppServer,
    request: Request<zopp_proto::RemoveProjectPermissionRequest>,
) -> Result<Response<Empty>, Status> {
    let (principal_id, timestamp, signature, request_hash) = extract_signature(&request)?;
    let req_for_verify = request.get_ref().clone();
    server
        .verify_signature_and_get_principal(&principal_id, timestamp, &signature, "/zopp.ZoppService/RemoveProjectPermission", &req_for_verify, &request_hash)
        .await?;

    let req = request.into_inner();

    // Look up workspace by name for this principal
    let workspace = server
        .store
        .get_workspace_by_name_for_principal(&principal_id, &req.workspace_name)
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

    // Parse target principal ID
    let target_principal_id = Uuid::parse_str(&req.principal_id)
        .map(PrincipalId)
        .map_err(|_| Status::invalid_argument("Invalid principal ID"))?;

    // Get target's current permission level
    let target_role = server
        .store
        .get_project_permission(&project.id, &target_principal_id)
        .await
        .map_err(|e| match e {
            zopp_storage::StoreError::NotFound => {
                Status::not_found("Permission not found for target principal")
            }
            _ => Status::internal(format!("Failed to get target permission: {}", e)),
        })?;

    // Delegated authority: requester can only remove permissions <= their own effective role
    let requester_role = server
        .get_effective_project_role(&principal_id, &workspace.id, &project.id)
        .await?
        .ok_or_else(|| {
            Status::permission_denied("No permission to remove permissions on this project")
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
        .remove_project_permission(&project.id, &target_principal_id)
        .await
        .map_err(|e| Status::internal(format!("Failed to remove permission: {}", e)))?;

    Ok(Response::new(Empty {}))
}

// ───────────────────────────────────── Environment Permissions ─────────────────────────────────────

pub async fn set_environment_permission(
    server: &ZoppServer,
    request: Request<zopp_proto::SetEnvironmentPermissionRequest>,
) -> Result<Response<Empty>, Status> {
    let (principal_id, timestamp, signature, request_hash) = extract_signature(&request)?;
    let req_for_verify = request.get_ref().clone();
    server
        .verify_signature_and_get_principal(&principal_id, timestamp, &signature, "/zopp.ZoppService/SetEnvironmentPermission", &req_for_verify, &request_hash)
        .await?;

    let req = request.into_inner();

    // Look up workspace by name for this principal
    let workspace = server
        .store
        .get_workspace_by_name_for_principal(&principal_id, &req.workspace_name)
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

    // Parse target principal ID
    let target_principal_id = Uuid::parse_str(&req.principal_id)
        .map(PrincipalId)
        .map_err(|_| Status::invalid_argument("Invalid principal ID"))?;

    // Convert proto Role to storage Role
    let role = match zopp_proto::Role::try_from(req.role) {
        Ok(zopp_proto::Role::Admin) => zopp_storage::Role::Admin,
        Ok(zopp_proto::Role::Write) => zopp_storage::Role::Write,
        Ok(zopp_proto::Role::Read) => zopp_storage::Role::Read,
        _ => return Err(Status::invalid_argument("Invalid role")),
    };

    // Delegated authority: requester can only grant permissions <= their own effective role
    let requester_role = server
        .get_effective_environment_role(&principal_id, &workspace.id, &project.id, &env.id)
        .await?
        .ok_or_else(|| {
            Status::permission_denied("No permission to set permissions on this environment")
        })?;

    // Check if requester's role is sufficient to grant the requested role
    if !requester_role.includes(&role) {
        return Err(Status::permission_denied(format!(
            "Cannot grant {:?} permission (you only have {:?} access)",
            role, requester_role
        )));
    }

    server
        .store
        .set_environment_permission(&env.id, &target_principal_id, role)
        .await
        .map_err(|e| Status::internal(format!("Failed to set permission: {}", e)))?;

    Ok(Response::new(Empty {}))
}

pub async fn get_environment_permission(
    server: &ZoppServer,
    request: Request<zopp_proto::GetEnvironmentPermissionRequest>,
) -> Result<Response<zopp_proto::PermissionResponse>, Status> {
    let (principal_id, timestamp, signature, request_hash) = extract_signature(&request)?;
    let req_for_verify = request.get_ref().clone();
    let principal = server
        .verify_signature_and_get_principal(&principal_id, timestamp, &signature, "/zopp.ZoppService/GetEnvironmentPermission", &req_for_verify, &request_hash)
        .await?;
    let user_id = principal
        .user_id
        .ok_or_else(|| Status::unauthenticated("Service accounts cannot get permissions"))?;

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

    // Parse principal ID
    let target_principal_id = Uuid::parse_str(&req.principal_id)
        .map(PrincipalId)
        .map_err(|_| Status::invalid_argument("Invalid principal ID"))?;

    let role = server
        .store
        .get_environment_permission(&env.id, &target_principal_id)
        .await
        .map_err(|e| match e {
            zopp_storage::StoreError::NotFound => Status::not_found("Permission not found"),
            _ => Status::internal(format!("Failed to get permission: {}", e)),
        })?;

    // Convert storage Role to proto Role
    let proto_role = match role {
        zopp_storage::Role::Admin => zopp_proto::Role::Admin as i32,
        zopp_storage::Role::Write => zopp_proto::Role::Write as i32,
        zopp_storage::Role::Read => zopp_proto::Role::Read as i32,
    };

    Ok(Response::new(zopp_proto::PermissionResponse {
        role: proto_role,
    }))
}

pub async fn list_environment_permissions(
    server: &ZoppServer,
    request: Request<zopp_proto::ListEnvironmentPermissionsRequest>,
) -> Result<Response<zopp_proto::PermissionList>, Status> {
    let (principal_id, timestamp, signature, request_hash) = extract_signature(&request)?;
    let req_for_verify = request.get_ref().clone();
    let principal = server
        .verify_signature_and_get_principal(&principal_id, timestamp, &signature, "/zopp.ZoppService/ListEnvironmentPermissions", &req_for_verify, &request_hash)
        .await?;
    let user_id = principal
        .user_id
        .ok_or_else(|| Status::unauthenticated("Service accounts cannot list permissions"))?;

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
        .list_environment_permissions(&env.id)
        .await
        .map_err(|e| Status::internal(format!("Failed to list permissions: {}", e)))?;

    let mut proto_permissions = Vec::with_capacity(permissions.len());
    for p in permissions {
        let principal_name = match server.store.get_principal(&p.principal_id).await {
            Ok(principal) => principal.name,
            Err(_) => String::new(), // Principal might have been deleted
        };
        proto_permissions.push(zopp_proto::Permission {
            principal_id: p.principal_id.0.to_string(),
            principal_name,
            role: match p.role {
                zopp_storage::Role::Admin => zopp_proto::Role::Admin as i32,
                zopp_storage::Role::Write => zopp_proto::Role::Write as i32,
                zopp_storage::Role::Read => zopp_proto::Role::Read as i32,
            },
        });
    }

    Ok(Response::new(zopp_proto::PermissionList {
        permissions: proto_permissions,
    }))
}

pub async fn remove_environment_permission(
    server: &ZoppServer,
    request: Request<zopp_proto::RemoveEnvironmentPermissionRequest>,
) -> Result<Response<Empty>, Status> {
    let (principal_id, timestamp, signature, request_hash) = extract_signature(&request)?;
    let req_for_verify = request.get_ref().clone();
    server
        .verify_signature_and_get_principal(&principal_id, timestamp, &signature, "/zopp.ZoppService/RemoveEnvironmentPermission", &req_for_verify, &request_hash)
        .await?;

    let req = request.into_inner();

    // Look up workspace by name for this principal
    let workspace = server
        .store
        .get_workspace_by_name_for_principal(&principal_id, &req.workspace_name)
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

    // Parse target principal ID
    let target_principal_id = Uuid::parse_str(&req.principal_id)
        .map(PrincipalId)
        .map_err(|_| Status::invalid_argument("Invalid principal ID"))?;

    // Get target's current permission level
    let target_role = server
        .store
        .get_environment_permission(&env.id, &target_principal_id)
        .await
        .map_err(|e| match e {
            zopp_storage::StoreError::NotFound => {
                Status::not_found("Permission not found for target principal")
            }
            _ => Status::internal(format!("Failed to get target permission: {}", e)),
        })?;

    // Delegated authority: requester can only remove permissions <= their own effective role
    let requester_role = server
        .get_effective_environment_role(&principal_id, &workspace.id, &project.id, &env.id)
        .await?
        .ok_or_else(|| {
            Status::permission_denied("No permission to remove permissions on this environment")
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
        .remove_environment_permission(&env.id, &target_principal_id)
        .await
        .map_err(|e| Status::internal(format!("Failed to remove permission: {}", e)))?;

    Ok(Response::new(Empty {}))
}
