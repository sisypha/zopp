//! Group permission handlers: set, get, list, remove at workspace/project/environment levels

use tonic::{Request, Response, Status};
use zopp_proto::Empty;
use zopp_storage::Store;

use crate::server::{extract_signature, ZoppServer};

// ───────────────────────────────────── Workspace Level ─────────────────────────────────────

pub async fn set_group_workspace_permission(
    server: &ZoppServer,
    request: Request<zopp_proto::SetGroupWorkspacePermissionRequest>,
) -> Result<Response<Empty>, Status> {
    let (principal_id, timestamp, signature) = extract_signature(&request)?;
    let principal = server
        .verify_signature_and_get_principal(&principal_id, timestamp, &signature)
        .await?;
    let user_id = principal.user_id.ok_or_else(|| {
        Status::unauthenticated("Service accounts cannot set group permissions")
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

    // Check ADMIN permission for setting group permissions
    server
        .check_workspace_permission(&principal_id, &workspace.id, zopp_storage::Role::Admin)
        .await?;

    let group = server
        .store
        .get_group_by_name(&workspace.id, &req.group_name)
        .await
        .map_err(|e| match e {
            zopp_storage::StoreError::NotFound => Status::not_found("Group not found"),
            _ => Status::internal(format!("Failed to get group: {}", e)),
        })?;

    // Convert proto Role to storage Role
    let role = match zopp_proto::Role::try_from(req.role) {
        Ok(zopp_proto::Role::Admin) => zopp_storage::Role::Admin,
        Ok(zopp_proto::Role::Write) => zopp_storage::Role::Write,
        Ok(zopp_proto::Role::Read) => zopp_storage::Role::Read,
        _ => return Err(Status::invalid_argument("Invalid role")),
    };

    server
        .store
        .set_group_workspace_permission(&workspace.id, &group.id, role)
        .await
        .map_err(|e| Status::internal(format!("Failed to set group permission: {}", e)))?;

    Ok(Response::new(Empty {}))
}

pub async fn get_group_workspace_permission(
    server: &ZoppServer,
    request: Request<zopp_proto::GetGroupWorkspacePermissionRequest>,
) -> Result<Response<zopp_proto::PermissionResponse>, Status> {
    let (principal_id, timestamp, signature) = extract_signature(&request)?;
    let principal = server
        .verify_signature_and_get_principal(&principal_id, timestamp, &signature)
        .await?;
    let user_id = principal.user_id.ok_or_else(|| {
        Status::unauthenticated("Service accounts cannot get group permissions")
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

    let group = server
        .store
        .get_group_by_name(&workspace.id, &req.group_name)
        .await
        .map_err(|e| match e {
            zopp_storage::StoreError::NotFound => Status::not_found("Group not found"),
            _ => Status::internal(format!("Failed to get group: {}", e)),
        })?;

    let role = server
        .store
        .get_group_workspace_permission(&workspace.id, &group.id)
        .await
        .map_err(|e| match e {
            zopp_storage::StoreError::NotFound => Status::not_found("Permission not found"),
            _ => Status::internal(format!("Failed to get group permission: {}", e)),
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

pub async fn list_group_workspace_permissions(
    server: &ZoppServer,
    request: Request<zopp_proto::ListGroupWorkspacePermissionsRequest>,
) -> Result<Response<zopp_proto::GroupPermissionList>, Status> {
    let (principal_id, timestamp, signature) = extract_signature(&request)?;
    let principal = server
        .verify_signature_and_get_principal(&principal_id, timestamp, &signature)
        .await?;
    let user_id = principal.user_id.ok_or_else(|| {
        Status::unauthenticated("Service accounts cannot list group permissions")
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

    let permissions = server
        .store
        .list_group_workspace_permissions(&workspace.id)
        .await
        .map_err(|e| Status::internal(format!("Failed to list group permissions: {}", e)))?;

    let mut proto_permissions = Vec::new();
    for perm in permissions {
        // Look up group to get name
        let group = server
            .store
            .get_group(&perm.group_id)
            .await
            .map_err(|e| Status::internal(format!("Failed to get group: {}", e)))?;

        proto_permissions.push(zopp_proto::GroupPermission {
            group_id: perm.group_id.0.to_string(),
            group_name: group.name,
            role: match perm.role {
                zopp_storage::Role::Admin => zopp_proto::Role::Admin as i32,
                zopp_storage::Role::Write => zopp_proto::Role::Write as i32,
                zopp_storage::Role::Read => zopp_proto::Role::Read as i32,
            },
        });
    }

    Ok(Response::new(zopp_proto::GroupPermissionList {
        permissions: proto_permissions,
    }))
}

pub async fn remove_group_workspace_permission(
    server: &ZoppServer,
    request: Request<zopp_proto::RemoveGroupWorkspacePermissionRequest>,
) -> Result<Response<Empty>, Status> {
    let (principal_id, timestamp, signature) = extract_signature(&request)?;
    let principal = server
        .verify_signature_and_get_principal(&principal_id, timestamp, &signature)
        .await?;
    let user_id = principal.user_id.ok_or_else(|| {
        Status::unauthenticated("Service accounts cannot remove group permissions")
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

    let group = server
        .store
        .get_group_by_name(&workspace.id, &req.group_name)
        .await
        .map_err(|e| match e {
            zopp_storage::StoreError::NotFound => Status::not_found("Group not found"),
            _ => Status::internal(format!("Failed to get group: {}", e)),
        })?;

    server
        .store
        .remove_group_workspace_permission(&workspace.id, &group.id)
        .await
        .map_err(|e| Status::internal(format!("Failed to remove group permission: {}", e)))?;

    Ok(Response::new(Empty {}))
}

// ───────────────────────────────────── Project Level ─────────────────────────────────────

pub async fn set_group_project_permission(
    server: &ZoppServer,
    request: Request<zopp_proto::SetGroupProjectPermissionRequest>,
) -> Result<Response<Empty>, Status> {
    let (principal_id, timestamp, signature) = extract_signature(&request)?;
    let principal = server
        .verify_signature_and_get_principal(&principal_id, timestamp, &signature)
        .await?;
    let user_id = principal.user_id.ok_or_else(|| {
        Status::unauthenticated("Service accounts cannot set group permissions")
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

    let group = server
        .store
        .get_group_by_name(&workspace.id, &req.group_name)
        .await
        .map_err(|e| match e {
            zopp_storage::StoreError::NotFound => Status::not_found("Group not found"),
            _ => Status::internal(format!("Failed to get group: {}", e)),
        })?;

    // Convert proto Role to storage Role
    let role = match zopp_proto::Role::try_from(req.role) {
        Ok(zopp_proto::Role::Admin) => zopp_storage::Role::Admin,
        Ok(zopp_proto::Role::Write) => zopp_storage::Role::Write,
        Ok(zopp_proto::Role::Read) => zopp_storage::Role::Read,
        _ => return Err(Status::invalid_argument("Invalid role")),
    };

    server
        .store
        .set_group_project_permission(&project.id, &group.id, role)
        .await
        .map_err(|e| Status::internal(format!("Failed to set group permission: {}", e)))?;

    Ok(Response::new(Empty {}))
}

pub async fn get_group_project_permission(
    server: &ZoppServer,
    request: Request<zopp_proto::GetGroupProjectPermissionRequest>,
) -> Result<Response<zopp_proto::PermissionResponse>, Status> {
    let (principal_id, timestamp, signature) = extract_signature(&request)?;
    let principal = server
        .verify_signature_and_get_principal(&principal_id, timestamp, &signature)
        .await?;
    let user_id = principal.user_id.ok_or_else(|| {
        Status::unauthenticated("Service accounts cannot get group permissions")
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

    let group = server
        .store
        .get_group_by_name(&workspace.id, &req.group_name)
        .await
        .map_err(|e| match e {
            zopp_storage::StoreError::NotFound => Status::not_found("Group not found"),
            _ => Status::internal(format!("Failed to get group: {}", e)),
        })?;

    let role = server
        .store
        .get_group_project_permission(&project.id, &group.id)
        .await
        .map_err(|e| match e {
            zopp_storage::StoreError::NotFound => Status::not_found("Permission not found"),
            _ => Status::internal(format!("Failed to get group permission: {}", e)),
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

pub async fn list_group_project_permissions(
    server: &ZoppServer,
    request: Request<zopp_proto::ListGroupProjectPermissionsRequest>,
) -> Result<Response<zopp_proto::GroupPermissionList>, Status> {
    let (principal_id, timestamp, signature) = extract_signature(&request)?;
    let principal = server
        .verify_signature_and_get_principal(&principal_id, timestamp, &signature)
        .await?;
    let user_id = principal.user_id.ok_or_else(|| {
        Status::unauthenticated("Service accounts cannot list group permissions")
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

    let permissions = server
        .store
        .list_group_project_permissions(&project.id)
        .await
        .map_err(|e| Status::internal(format!("Failed to list group permissions: {}", e)))?;

    let mut proto_permissions = Vec::new();
    for perm in permissions {
        // Look up group to get name
        let group = server
            .store
            .get_group(&perm.group_id)
            .await
            .map_err(|e| Status::internal(format!("Failed to get group: {}", e)))?;

        proto_permissions.push(zopp_proto::GroupPermission {
            group_id: perm.group_id.0.to_string(),
            group_name: group.name,
            role: match perm.role {
                zopp_storage::Role::Admin => zopp_proto::Role::Admin as i32,
                zopp_storage::Role::Write => zopp_proto::Role::Write as i32,
                zopp_storage::Role::Read => zopp_proto::Role::Read as i32,
            },
        });
    }

    Ok(Response::new(zopp_proto::GroupPermissionList {
        permissions: proto_permissions,
    }))
}

pub async fn remove_group_project_permission(
    server: &ZoppServer,
    request: Request<zopp_proto::RemoveGroupProjectPermissionRequest>,
) -> Result<Response<Empty>, Status> {
    let (principal_id, timestamp, signature) = extract_signature(&request)?;
    let principal = server
        .verify_signature_and_get_principal(&principal_id, timestamp, &signature)
        .await?;
    let user_id = principal.user_id.ok_or_else(|| {
        Status::unauthenticated("Service accounts cannot remove group permissions")
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

    let group = server
        .store
        .get_group_by_name(&workspace.id, &req.group_name)
        .await
        .map_err(|e| match e {
            zopp_storage::StoreError::NotFound => Status::not_found("Group not found"),
            _ => Status::internal(format!("Failed to get group: {}", e)),
        })?;

    server
        .store
        .remove_group_project_permission(&project.id, &group.id)
        .await
        .map_err(|e| Status::internal(format!("Failed to remove group permission: {}", e)))?;

    Ok(Response::new(Empty {}))
}

// ───────────────────────────────────── Environment Level ─────────────────────────────────────

pub async fn set_group_environment_permission(
    server: &ZoppServer,
    request: Request<zopp_proto::SetGroupEnvironmentPermissionRequest>,
) -> Result<Response<Empty>, Status> {
    let (principal_id, timestamp, signature) = extract_signature(&request)?;
    let principal = server
        .verify_signature_and_get_principal(&principal_id, timestamp, &signature)
        .await?;
    let user_id = principal.user_id.ok_or_else(|| {
        Status::unauthenticated("Service accounts cannot set group permissions")
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

    let group = server
        .store
        .get_group_by_name(&workspace.id, &req.group_name)
        .await
        .map_err(|e| match e {
            zopp_storage::StoreError::NotFound => Status::not_found("Group not found"),
            _ => Status::internal(format!("Failed to get group: {}", e)),
        })?;

    // Convert proto Role to storage Role
    let role = match zopp_proto::Role::try_from(req.role) {
        Ok(zopp_proto::Role::Admin) => zopp_storage::Role::Admin,
        Ok(zopp_proto::Role::Write) => zopp_storage::Role::Write,
        Ok(zopp_proto::Role::Read) => zopp_storage::Role::Read,
        _ => return Err(Status::invalid_argument("Invalid role")),
    };

    server
        .store
        .set_group_environment_permission(&env.id, &group.id, role)
        .await
        .map_err(|e| Status::internal(format!("Failed to set group permission: {}", e)))?;

    Ok(Response::new(Empty {}))
}

pub async fn get_group_environment_permission(
    server: &ZoppServer,
    request: Request<zopp_proto::GetGroupEnvironmentPermissionRequest>,
) -> Result<Response<zopp_proto::PermissionResponse>, Status> {
    let (principal_id, timestamp, signature) = extract_signature(&request)?;
    let principal = server
        .verify_signature_and_get_principal(&principal_id, timestamp, &signature)
        .await?;
    let user_id = principal.user_id.ok_or_else(|| {
        Status::unauthenticated("Service accounts cannot get group permissions")
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

    let group = server
        .store
        .get_group_by_name(&workspace.id, &req.group_name)
        .await
        .map_err(|e| match e {
            zopp_storage::StoreError::NotFound => Status::not_found("Group not found"),
            _ => Status::internal(format!("Failed to get group: {}", e)),
        })?;

    let role = server
        .store
        .get_group_environment_permission(&env.id, &group.id)
        .await
        .map_err(|e| match e {
            zopp_storage::StoreError::NotFound => Status::not_found("Permission not found"),
            _ => Status::internal(format!("Failed to get group permission: {}", e)),
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

pub async fn list_group_environment_permissions(
    server: &ZoppServer,
    request: Request<zopp_proto::ListGroupEnvironmentPermissionsRequest>,
) -> Result<Response<zopp_proto::GroupPermissionList>, Status> {
    let (principal_id, timestamp, signature) = extract_signature(&request)?;
    let principal = server
        .verify_signature_and_get_principal(&principal_id, timestamp, &signature)
        .await?;
    let user_id = principal.user_id.ok_or_else(|| {
        Status::unauthenticated("Service accounts cannot list group permissions")
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

    let permissions = server
        .store
        .list_group_environment_permissions(&env.id)
        .await
        .map_err(|e| Status::internal(format!("Failed to list group permissions: {}", e)))?;

    let mut proto_permissions = Vec::new();
    for perm in permissions {
        // Look up group to get name
        let group = server
            .store
            .get_group(&perm.group_id)
            .await
            .map_err(|e| Status::internal(format!("Failed to get group: {}", e)))?;

        proto_permissions.push(zopp_proto::GroupPermission {
            group_id: perm.group_id.0.to_string(),
            group_name: group.name,
            role: match perm.role {
                zopp_storage::Role::Admin => zopp_proto::Role::Admin as i32,
                zopp_storage::Role::Write => zopp_proto::Role::Write as i32,
                zopp_storage::Role::Read => zopp_proto::Role::Read as i32,
            },
        });
    }

    Ok(Response::new(zopp_proto::GroupPermissionList {
        permissions: proto_permissions,
    }))
}

pub async fn remove_group_environment_permission(
    server: &ZoppServer,
    request: Request<zopp_proto::RemoveGroupEnvironmentPermissionRequest>,
) -> Result<Response<Empty>, Status> {
    let (principal_id, timestamp, signature) = extract_signature(&request)?;
    let principal = server
        .verify_signature_and_get_principal(&principal_id, timestamp, &signature)
        .await?;
    let user_id = principal.user_id.ok_or_else(|| {
        Status::unauthenticated("Service accounts cannot remove group permissions")
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

    let group = server
        .store
        .get_group_by_name(&workspace.id, &req.group_name)
        .await
        .map_err(|e| match e {
            zopp_storage::StoreError::NotFound => Status::not_found("Group not found"),
            _ => Status::internal(format!("Failed to get group: {}", e)),
        })?;

    server
        .store
        .remove_group_environment_permission(&env.id, &group.id)
        .await
        .map_err(|e| Status::internal(format!("Failed to remove group permission: {}", e)))?;

    Ok(Response::new(Empty {}))
}
