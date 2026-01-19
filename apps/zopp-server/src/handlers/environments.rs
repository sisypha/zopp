//! Environment handlers: create, list, get, delete

use tonic::{Request, Response, Status};
use zopp_proto::{
    CreateEnvironmentRequest, DeleteEnvironmentRequest, Empty, Environment, EnvironmentList,
    GetEnvironmentRequest, ListEnvironmentsRequest,
};
use zopp_storage::Store;

use crate::server::{extract_signature, ZoppServer};

pub async fn create_environment(
    server: &ZoppServer,
    request: Request<CreateEnvironmentRequest>,
) -> Result<Response<Environment>, Status> {
    let (principal_id, timestamp, signature, request_hash) = extract_signature(&request)?;
    let req_for_verify = request.get_ref().clone();
    let principal = server
        .verify_signature_and_get_principal(
            &principal_id,
            timestamp,
            &signature,
            "/zopp.ZoppService/CreateEnvironment",
            &req_for_verify,
            &request_hash,
        )
        .await?;
    let user_id = principal
        .user_id
        .ok_or_else(|| Status::unauthenticated("Service accounts cannot create environments"))?;

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

    // Look up project by name in workspace
    let project = server
        .store
        .get_project_by_name(&workspace.id, &req.project_name)
        .await
        .map_err(|e| match e {
            zopp_storage::StoreError::NotFound => Status::not_found("Project not found"),
            _ => Status::internal(format!("Failed to get project: {}", e)),
        })?;

    // Check ADMIN permission for creating environments (project-level or higher)
    server
        .check_project_permission(
            &principal_id,
            &workspace.id,
            &project.id,
            zopp_storage::Role::Admin,
        )
        .await?;

    let env_id = server
        .store
        .create_env(&zopp_storage::CreateEnvParams {
            project_id: project.id.clone(),
            name: req.name,
            dek_wrapped: req.dek_wrapped,
            dek_nonce: req.dek_nonce,
        })
        .await
        .map_err(|e| match e {
            zopp_storage::StoreError::AlreadyExists => {
                Status::already_exists("Environment with this name already exists in project")
            }
            _ => Status::internal(format!("Failed to create environment: {}", e)),
        })?;

    let env = server
        .store
        .get_environment(&env_id)
        .await
        .map_err(|e| Status::internal(format!("Failed to get environment: {}", e)))?;

    Ok(Response::new(Environment {
        id: env.id.0.to_string(),
        project_id: env.project_id.0.to_string(),
        name: env.name,
        dek_wrapped: env.dek_wrapped,
        dek_nonce: env.dek_nonce,
        created_at: env.created_at.timestamp(),
        updated_at: env.updated_at.timestamp(),
        secret_count: 0, // New environment has no secrets
    }))
}

pub async fn list_environments(
    server: &ZoppServer,
    request: Request<ListEnvironmentsRequest>,
) -> Result<Response<EnvironmentList>, Status> {
    let (principal_id, timestamp, signature, request_hash) = extract_signature(&request)?;
    let req_for_verify = request.get_ref().clone();
    let principal = server
        .verify_signature_and_get_principal(
            &principal_id,
            timestamp,
            &signature,
            "/zopp.ZoppService/ListEnvironments",
            &req_for_verify,
            &request_hash,
        )
        .await?;
    let user_id = principal
        .user_id
        .ok_or_else(|| Status::unauthenticated("Service accounts cannot list environments"))?;

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

    // Look up project by name in workspace
    let project = server
        .store
        .get_project_by_name(&workspace.id, &req.project_name)
        .await
        .map_err(|e| match e {
            zopp_storage::StoreError::NotFound => Status::not_found("Project not found"),
            _ => Status::internal(format!("Failed to get project: {}", e)),
        })?;

    // Check READ permission for listing environments
    server
        .check_project_permission(
            &principal_id,
            &workspace.id,
            &project.id,
            zopp_storage::Role::Read,
        )
        .await?;

    let environments = server
        .store
        .list_environments(&project.id)
        .await
        .map_err(|e| Status::internal(format!("Failed to list environments: {}", e)))?;

    // Build response with secret counts
    let mut result = Vec::with_capacity(environments.len());
    for e in environments {
        let secret_count = server
            .store
            .list_secret_keys(&e.id)
            .await
            .map(|s| s.len() as i32)
            .unwrap_or(0);

        result.push(Environment {
            id: e.id.0.to_string(),
            project_id: e.project_id.0.to_string(),
            name: e.name,
            dek_wrapped: e.dek_wrapped,
            dek_nonce: e.dek_nonce,
            created_at: e.created_at.timestamp(),
            updated_at: e.updated_at.timestamp(),
            secret_count,
        });
    }

    Ok(Response::new(EnvironmentList {
        environments: result,
    }))
}

pub async fn get_environment(
    server: &ZoppServer,
    request: Request<GetEnvironmentRequest>,
) -> Result<Response<Environment>, Status> {
    let (principal_id, timestamp, signature, request_hash) = extract_signature(&request)?;
    let req_for_verify = request.get_ref().clone();
    let principal = server
        .verify_signature_and_get_principal(
            &principal_id,
            timestamp,
            &signature,
            "/zopp.ZoppService/GetEnvironment",
            &req_for_verify,
            &request_hash,
        )
        .await?;
    let req = request.into_inner();

    // Look up workspace by name - use different lookup for service principals
    let workspace = if let Some(user_id) = &principal.user_id {
        server
            .store
            .get_workspace_by_name(user_id, &req.workspace_name)
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::NotFound => {
                    Status::not_found("Workspace not found or access denied")
                }
                _ => Status::internal(format!("Failed to get workspace: {}", e)),
            })?
    } else {
        // Service principal - use principal-based lookup
        server
            .store
            .get_workspace_by_name_for_principal(&principal_id, &req.workspace_name)
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::NotFound => {
                    Status::not_found("Workspace not found or access denied")
                }
                _ => Status::internal(format!("Failed to get workspace: {}", e)),
            })?
    };

    // Look up project by name in workspace
    let project = server
        .store
        .get_project_by_name(&workspace.id, &req.project_name)
        .await
        .map_err(|e| match e {
            zopp_storage::StoreError::NotFound => Status::not_found("Project not found"),
            _ => Status::internal(format!("Failed to get project: {}", e)),
        })?;

    // Look up environment by name in project
    let env = server
        .store
        .get_environment_by_name(&project.id, &req.environment_name)
        .await
        .map_err(|e| match e {
            zopp_storage::StoreError::NotFound => Status::not_found("Environment not found"),
            _ => Status::internal(format!("Failed to get environment: {}", e)),
        })?;

    // Check READ permission for getting environment
    server
        .check_environment_permission(
            &principal_id,
            &workspace.id,
            &project.id,
            &env.id,
            zopp_storage::Role::Read,
        )
        .await?;

    // Get secret count for this environment
    let secret_count = server
        .store
        .list_secret_keys(&env.id)
        .await
        .map(|s| s.len() as i32)
        .unwrap_or(0);

    Ok(Response::new(Environment {
        id: env.id.0.to_string(),
        project_id: env.project_id.0.to_string(),
        name: env.name,
        dek_wrapped: env.dek_wrapped,
        dek_nonce: env.dek_nonce,
        created_at: env.created_at.timestamp(),
        updated_at: env.updated_at.timestamp(),
        secret_count,
    }))
}

pub async fn delete_environment(
    server: &ZoppServer,
    request: Request<DeleteEnvironmentRequest>,
) -> Result<Response<Empty>, Status> {
    let (principal_id, timestamp, signature, request_hash) = extract_signature(&request)?;
    let req_for_verify = request.get_ref().clone();
    let principal = server
        .verify_signature_and_get_principal(
            &principal_id,
            timestamp,
            &signature,
            "/zopp.ZoppService/DeleteEnvironment",
            &req_for_verify,
            &request_hash,
        )
        .await?;
    let user_id = principal
        .user_id
        .ok_or_else(|| Status::unauthenticated("Service accounts cannot delete environments"))?;

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

    // Look up project by name in workspace
    let project = server
        .store
        .get_project_by_name(&workspace.id, &req.project_name)
        .await
        .map_err(|e| match e {
            zopp_storage::StoreError::NotFound => Status::not_found("Project not found"),
            _ => Status::internal(format!("Failed to get project: {}", e)),
        })?;

    // Check ADMIN permission for deleting environments (project-level or higher)
    server
        .check_project_permission(
            &principal_id,
            &workspace.id,
            &project.id,
            zopp_storage::Role::Admin,
        )
        .await?;

    // Look up environment by name in project
    let env = server
        .store
        .get_environment_by_name(&project.id, &req.environment_name)
        .await
        .map_err(|e| match e {
            zopp_storage::StoreError::NotFound => Status::not_found("Environment not found"),
            _ => Status::internal(format!("Failed to get environment: {}", e)),
        })?;

    server
        .store
        .delete_environment(&env.id)
        .await
        .map_err(|e| match e {
            zopp_storage::StoreError::NotFound => Status::not_found("Environment not found"),
            _ => Status::internal(format!("Failed to delete environment: {}", e)),
        })?;

    Ok(Response::new(Empty {}))
}
