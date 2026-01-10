//! Project handlers: create, list, get, delete

use tonic::{Request, Response, Status};
use zopp_proto::{
    CreateProjectRequest, DeleteProjectRequest, Empty, GetProjectRequest, ListProjectsRequest,
    Project, ProjectList,
};
use zopp_storage::Store;

use crate::server::{extract_signature, ZoppServer};

pub async fn create_project(
    server: &ZoppServer,
    request: Request<CreateProjectRequest>,
) -> Result<Response<Project>, Status> {
    let (principal_id, timestamp, signature, request_hash) = extract_signature(&request)?;
    let req_for_verify = request.get_ref().clone();
    let principal = server
        .verify_signature_and_get_principal(&principal_id, timestamp, &signature, "/zopp.ZoppService/CreateProject", &req_for_verify, &request_hash)
        .await?;
    let user_id = principal
        .user_id
        .ok_or_else(|| Status::unauthenticated("Service accounts cannot create projects"))?;

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

    // Check ADMIN permission for creating projects
    server
        .check_workspace_permission(&principal_id, &workspace.id, zopp_storage::Role::Admin)
        .await?;

    let project_id = server
        .store
        .create_project(&zopp_storage::CreateProjectParams {
            workspace_id: workspace.id.clone(),
            name: req.name,
        })
        .await
        .map_err(|e| match e {
            zopp_storage::StoreError::AlreadyExists => {
                Status::already_exists("Project with this name already exists in workspace")
            }
            _ => Status::internal(format!("Failed to create project: {}", e)),
        })?;

    let project = server
        .store
        .get_project(&project_id)
        .await
        .map_err(|e| Status::internal(format!("Failed to get project: {}", e)))?;

    Ok(Response::new(Project {
        id: project.id.0.to_string(),
        workspace_id: project.workspace_id.0.to_string(),
        name: project.name,
        created_at: project.created_at.timestamp(),
        updated_at: project.updated_at.timestamp(),
    }))
}

pub async fn list_projects(
    server: &ZoppServer,
    request: Request<ListProjectsRequest>,
) -> Result<Response<ProjectList>, Status> {
    let (principal_id, timestamp, signature, request_hash) = extract_signature(&request)?;
    let req_for_verify = request.get_ref().clone();
    let principal = server
        .verify_signature_and_get_principal(&principal_id, timestamp, &signature, "/zopp.ZoppService/ListProjects", &req_for_verify, &request_hash)
        .await?;
    let user_id = principal
        .user_id
        .ok_or_else(|| Status::unauthenticated("Service accounts cannot list projects"))?;

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

    // Check READ permission for listing projects
    server
        .check_workspace_permission(&principal_id, &workspace.id, zopp_storage::Role::Read)
        .await?;

    let projects = server
        .store
        .list_projects(&workspace.id)
        .await
        .map_err(|e| Status::internal(format!("Failed to list projects: {}", e)))?
        .into_iter()
        .map(|p| Project {
            id: p.id.0.to_string(),
            workspace_id: p.workspace_id.0.to_string(),
            name: p.name,
            created_at: p.created_at.timestamp(),
            updated_at: p.updated_at.timestamp(),
        })
        .collect();

    Ok(Response::new(ProjectList { projects }))
}

pub async fn get_project(
    server: &ZoppServer,
    request: Request<GetProjectRequest>,
) -> Result<Response<Project>, Status> {
    let (principal_id, timestamp, signature, request_hash) = extract_signature(&request)?;
    let req_for_verify = request.get_ref().clone();
    let principal = server
        .verify_signature_and_get_principal(&principal_id, timestamp, &signature, "/zopp.ZoppService/GetProject", &req_for_verify, &request_hash)
        .await?;
    let user_id = principal
        .user_id
        .ok_or_else(|| Status::unauthenticated("Service accounts cannot get projects"))?;

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

    // Check READ permission for getting project
    server
        .check_project_permission(
            &principal_id,
            &workspace.id,
            &project.id,
            zopp_storage::Role::Read,
        )
        .await?;

    Ok(Response::new(Project {
        id: project.id.0.to_string(),
        workspace_id: project.workspace_id.0.to_string(),
        name: project.name,
        created_at: project.created_at.timestamp(),
        updated_at: project.updated_at.timestamp(),
    }))
}

pub async fn delete_project(
    server: &ZoppServer,
    request: Request<DeleteProjectRequest>,
) -> Result<Response<Empty>, Status> {
    let (principal_id, timestamp, signature, request_hash) = extract_signature(&request)?;
    let req_for_verify = request.get_ref().clone();
    let principal = server
        .verify_signature_and_get_principal(&principal_id, timestamp, &signature, "/zopp.ZoppService/DeleteProject", &req_for_verify, &request_hash)
        .await?;
    let user_id = principal
        .user_id
        .ok_or_else(|| Status::unauthenticated("Service accounts cannot delete projects"))?;

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

    // Check ADMIN permission for deleting projects
    server
        .check_workspace_permission(&principal_id, &workspace.id, zopp_storage::Role::Admin)
        .await?;

    // Look up project by name in workspace
    let project = server
        .store
        .get_project_by_name(&workspace.id, &req.project_name)
        .await
        .map_err(|e| match e {
            zopp_storage::StoreError::NotFound => Status::not_found("Project not found"),
            _ => Status::internal(format!("Failed to get project: {}", e)),
        })?;

    server
        .store
        .delete_project(&project.id)
        .await
        .map_err(|e| match e {
            zopp_storage::StoreError::NotFound => Status::not_found("Project not found"),
            _ => Status::internal(format!("Failed to delete project: {}", e)),
        })?;

    Ok(Response::new(Empty {}))
}
