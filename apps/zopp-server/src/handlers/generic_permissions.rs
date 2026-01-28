//! Generic permission handlers: set, get, list, remove permissions using ResourceType/ActorType
//!
//! This module provides a unified API for all permission operations, replacing the 36 specific
//! permission methods with 4 generic ones. The deprecated methods still work but internally
//! delegate to these generic handlers.

use tonic::{Request, Response, Status};
use uuid::Uuid;
use zopp_proto::{
    actor_ref::Actor, ActorRef, ActorType, Empty, GetPermissionRequest, ListPermissionsRequest,
    PermissionEntry, PermissionListResponse, PermissionResponse, RemovePermissionRequest,
    ResourceRef, ResourceType, SetPermissionRequest,
};
use zopp_storage::{PrincipalId, Store};

use crate::server::{extract_signature, ZoppServer};

// ───────────────────────────────────── Helper Functions ─────────────────────────────────────

fn validate_resource_ref(resource: &ResourceRef) -> Result<(), Status> {
    let resource_type =
        ResourceType::try_from(resource.r#type).unwrap_or(ResourceType::Unspecified);

    match resource_type {
        ResourceType::Unspecified => Err(Status::invalid_argument("Resource type is required")),
        ResourceType::ResourceWorkspace => {
            if resource.workspace_name.is_empty() {
                return Err(Status::invalid_argument(
                    "workspace_name is required for WORKSPACE resource",
                ));
            }
            Ok(())
        }
        ResourceType::ResourceProject => {
            if resource.workspace_name.is_empty() {
                return Err(Status::invalid_argument(
                    "workspace_name is required for PROJECT resource",
                ));
            }
            if resource.project_name.is_none() || resource.project_name.as_ref().unwrap().is_empty()
            {
                return Err(Status::invalid_argument(
                    "project_name is required for PROJECT resource",
                ));
            }
            Ok(())
        }
        ResourceType::ResourceEnvironment => {
            if resource.workspace_name.is_empty() {
                return Err(Status::invalid_argument(
                    "workspace_name is required for ENVIRONMENT resource",
                ));
            }
            if resource.project_name.is_none() || resource.project_name.as_ref().unwrap().is_empty()
            {
                return Err(Status::invalid_argument(
                    "project_name is required for ENVIRONMENT resource",
                ));
            }
            if resource.environment_name.is_none()
                || resource.environment_name.as_ref().unwrap().is_empty()
            {
                return Err(Status::invalid_argument(
                    "environment_name is required for ENVIRONMENT resource",
                ));
            }
            Ok(())
        }
    }
}

fn validate_actor_ref(actor: &ActorRef) -> Result<(), Status> {
    let actor_type = ActorType::try_from(actor.r#type).unwrap_or(ActorType::Unspecified);

    match actor_type {
        ActorType::Unspecified => Err(Status::invalid_argument("Actor type is required")),
        ActorType::ActorPrincipal => match &actor.actor {
            Some(Actor::PrincipalId(id)) if !id.is_empty() => Ok(()),
            _ => Err(Status::invalid_argument(
                "principal_id is required for PRINCIPAL actor",
            )),
        },
        ActorType::ActorGroup => match &actor.actor {
            Some(Actor::GroupName(name)) if !name.is_empty() => Ok(()),
            _ => Err(Status::invalid_argument(
                "group_name is required for GROUP actor",
            )),
        },
        ActorType::ActorUser => match &actor.actor {
            Some(Actor::UserEmail(email)) if !email.is_empty() => Ok(()),
            _ => Err(Status::invalid_argument(
                "user_email is required for USER actor",
            )),
        },
    }
}

fn proto_role_to_storage(role: i32) -> Result<zopp_storage::Role, Status> {
    match zopp_proto::Role::try_from(role) {
        Ok(zopp_proto::Role::Admin) => Ok(zopp_storage::Role::Admin),
        Ok(zopp_proto::Role::Write) => Ok(zopp_storage::Role::Write),
        Ok(zopp_proto::Role::Read) => Ok(zopp_storage::Role::Read),
        _ => Err(Status::invalid_argument("Invalid role")),
    }
}

fn storage_role_to_proto(role: zopp_storage::Role) -> i32 {
    match role {
        zopp_storage::Role::Admin => zopp_proto::Role::Admin as i32,
        zopp_storage::Role::Write => zopp_proto::Role::Write as i32,
        zopp_storage::Role::Read => zopp_proto::Role::Read as i32,
    }
}

// ───────────────────────────────────── SetPermission ─────────────────────────────────────

pub async fn set_permission(
    server: &ZoppServer,
    request: Request<SetPermissionRequest>,
) -> Result<Response<Empty>, Status> {
    let (principal_id, timestamp, signature, request_hash) = extract_signature(&request)?;
    let req_for_verify = request.get_ref().clone();
    let principal = server
        .verify_signature_and_get_principal(
            &principal_id,
            timestamp,
            &signature,
            "/zopp.ZoppService/SetPermission",
            &req_for_verify,
            &request_hash,
        )
        .await?;
    let user_id = principal
        .user_id
        .ok_or_else(|| Status::unauthenticated("Service accounts cannot set permissions"))?;

    let req = request.into_inner();
    let resource = req
        .resource
        .ok_or_else(|| Status::invalid_argument("resource is required"))?;
    let actor = req
        .actor
        .ok_or_else(|| Status::invalid_argument("actor is required"))?;

    validate_resource_ref(&resource)?;
    validate_actor_ref(&actor)?;

    let role = proto_role_to_storage(req.role)?;
    let resource_type =
        ResourceType::try_from(resource.r#type).unwrap_or(ResourceType::Unspecified);
    let actor_type = ActorType::try_from(actor.r#type).unwrap_or(ActorType::Unspecified);

    // Look up workspace
    let workspace = server
        .store
        .get_workspace_by_name(&user_id, &resource.workspace_name)
        .await
        .map_err(|e| match e {
            zopp_storage::StoreError::NotFound => {
                Status::not_found("Workspace not found or access denied")
            }
            _ => Status::internal(format!("Failed to get workspace: {}", e)),
        })?;

    // Get requester's effective role for delegated authority check
    let requester_role = match resource_type {
        ResourceType::ResourceWorkspace => {
            server
                .get_effective_workspace_role(&principal_id, &workspace.id)
                .await?
        }
        ResourceType::ResourceProject => {
            let project = server
                .store
                .get_project_by_name(&workspace.id, resource.project_name.as_ref().unwrap())
                .await
                .map_err(|e| match e {
                    zopp_storage::StoreError::NotFound => Status::not_found("Project not found"),
                    _ => Status::internal(format!("Failed to get project: {}", e)),
                })?;
            server
                .get_effective_project_role(&principal_id, &workspace.id, &project.id)
                .await?
        }
        ResourceType::ResourceEnvironment => {
            let project = server
                .store
                .get_project_by_name(&workspace.id, resource.project_name.as_ref().unwrap())
                .await
                .map_err(|e| match e {
                    zopp_storage::StoreError::NotFound => Status::not_found("Project not found"),
                    _ => Status::internal(format!("Failed to get project: {}", e)),
                })?;
            let environment = server
                .store
                .get_environment_by_name(&project.id, resource.environment_name.as_ref().unwrap())
                .await
                .map_err(|e| match e {
                    zopp_storage::StoreError::NotFound => {
                        Status::not_found("Environment not found")
                    }
                    _ => Status::internal(format!("Failed to get environment: {}", e)),
                })?;
            server
                .get_effective_environment_role(
                    &principal_id,
                    &workspace.id,
                    &project.id,
                    &environment.id,
                )
                .await?
        }
        _ => return Err(Status::invalid_argument("Invalid resource type")),
    };

    let requester_role = requester_role.ok_or_else(|| {
        Status::permission_denied("No permission to set permissions on this resource")
    })?;

    // Delegated authority check
    if !requester_role.includes(&role) {
        return Err(Status::permission_denied(format!(
            "Cannot grant {:?} permission (you only have {:?} access)",
            role, requester_role
        )));
    }

    // Dispatch based on resource type and actor type
    match (resource_type, actor_type) {
        // Principal permissions
        (ResourceType::ResourceWorkspace, ActorType::ActorPrincipal) => {
            let target_principal_id =
                parse_principal_id(actor.actor.as_ref().unwrap().principal_id_ref())?;
            server
                .store
                .set_workspace_permission(&workspace.id, &target_principal_id, role)
                .await
                .map_err(|e| Status::internal(format!("Failed to set permission: {}", e)))?;
        }
        (ResourceType::ResourceProject, ActorType::ActorPrincipal) => {
            let target_principal_id =
                parse_principal_id(actor.actor.as_ref().unwrap().principal_id_ref())?;
            let project = server
                .store
                .get_project_by_name(&workspace.id, resource.project_name.as_ref().unwrap())
                .await
                .map_err(|e| match e {
                    zopp_storage::StoreError::NotFound => Status::not_found("Project not found"),
                    _ => Status::internal(format!("Failed to get project: {}", e)),
                })?;
            server
                .store
                .set_project_permission(&project.id, &target_principal_id, role)
                .await
                .map_err(|e| Status::internal(format!("Failed to set permission: {}", e)))?;
        }
        (ResourceType::ResourceEnvironment, ActorType::ActorPrincipal) => {
            let target_principal_id =
                parse_principal_id(actor.actor.as_ref().unwrap().principal_id_ref())?;
            let project = server
                .store
                .get_project_by_name(&workspace.id, resource.project_name.as_ref().unwrap())
                .await
                .map_err(|e| match e {
                    zopp_storage::StoreError::NotFound => Status::not_found("Project not found"),
                    _ => Status::internal(format!("Failed to get project: {}", e)),
                })?;
            let environment = server
                .store
                .get_environment_by_name(&project.id, resource.environment_name.as_ref().unwrap())
                .await
                .map_err(|e| match e {
                    zopp_storage::StoreError::NotFound => {
                        Status::not_found("Environment not found")
                    }
                    _ => Status::internal(format!("Failed to get environment: {}", e)),
                })?;
            server
                .store
                .set_environment_permission(&environment.id, &target_principal_id, role)
                .await
                .map_err(|e| Status::internal(format!("Failed to set permission: {}", e)))?;
        }
        // Group permissions
        (ResourceType::ResourceWorkspace, ActorType::ActorGroup) => {
            let group_name = actor.actor.as_ref().unwrap().group_name_ref();
            let group = server
                .store
                .get_group_by_name(&workspace.id, group_name)
                .await
                .map_err(|e| match e {
                    zopp_storage::StoreError::NotFound => Status::not_found("Group not found"),
                    _ => Status::internal(format!("Failed to get group: {}", e)),
                })?;
            server
                .store
                .set_group_workspace_permission(&workspace.id, &group.id, role)
                .await
                .map_err(|e| Status::internal(format!("Failed to set permission: {}", e)))?;
        }
        (ResourceType::ResourceProject, ActorType::ActorGroup) => {
            let group_name = actor.actor.as_ref().unwrap().group_name_ref();
            let group = server
                .store
                .get_group_by_name(&workspace.id, group_name)
                .await
                .map_err(|e| match e {
                    zopp_storage::StoreError::NotFound => Status::not_found("Group not found"),
                    _ => Status::internal(format!("Failed to get group: {}", e)),
                })?;
            let project = server
                .store
                .get_project_by_name(&workspace.id, resource.project_name.as_ref().unwrap())
                .await
                .map_err(|e| match e {
                    zopp_storage::StoreError::NotFound => Status::not_found("Project not found"),
                    _ => Status::internal(format!("Failed to get project: {}", e)),
                })?;
            server
                .store
                .set_group_project_permission(&project.id, &group.id, role)
                .await
                .map_err(|e| Status::internal(format!("Failed to set permission: {}", e)))?;
        }
        (ResourceType::ResourceEnvironment, ActorType::ActorGroup) => {
            let group_name = actor.actor.as_ref().unwrap().group_name_ref();
            let group = server
                .store
                .get_group_by_name(&workspace.id, group_name)
                .await
                .map_err(|e| match e {
                    zopp_storage::StoreError::NotFound => Status::not_found("Group not found"),
                    _ => Status::internal(format!("Failed to get group: {}", e)),
                })?;
            let project = server
                .store
                .get_project_by_name(&workspace.id, resource.project_name.as_ref().unwrap())
                .await
                .map_err(|e| match e {
                    zopp_storage::StoreError::NotFound => Status::not_found("Project not found"),
                    _ => Status::internal(format!("Failed to get project: {}", e)),
                })?;
            let environment = server
                .store
                .get_environment_by_name(&project.id, resource.environment_name.as_ref().unwrap())
                .await
                .map_err(|e| match e {
                    zopp_storage::StoreError::NotFound => {
                        Status::not_found("Environment not found")
                    }
                    _ => Status::internal(format!("Failed to get environment: {}", e)),
                })?;
            server
                .store
                .set_group_environment_permission(&environment.id, &group.id, role)
                .await
                .map_err(|e| Status::internal(format!("Failed to set permission: {}", e)))?;
        }
        // User permissions
        (ResourceType::ResourceWorkspace, ActorType::ActorUser) => {
            let user_email = actor.actor.as_ref().unwrap().user_email_ref();
            let target_user =
                server
                    .store
                    .get_user_by_email(user_email)
                    .await
                    .map_err(|e| match e {
                        zopp_storage::StoreError::NotFound => Status::not_found("User not found"),
                        _ => Status::internal(format!("Failed to get user: {}", e)),
                    })?;
            server
                .store
                .set_user_workspace_permission(&workspace.id, &target_user.id, role)
                .await
                .map_err(|e| Status::internal(format!("Failed to set permission: {}", e)))?;
        }
        (ResourceType::ResourceProject, ActorType::ActorUser) => {
            let user_email = actor.actor.as_ref().unwrap().user_email_ref();
            let target_user =
                server
                    .store
                    .get_user_by_email(user_email)
                    .await
                    .map_err(|e| match e {
                        zopp_storage::StoreError::NotFound => Status::not_found("User not found"),
                        _ => Status::internal(format!("Failed to get user: {}", e)),
                    })?;
            let project = server
                .store
                .get_project_by_name(&workspace.id, resource.project_name.as_ref().unwrap())
                .await
                .map_err(|e| match e {
                    zopp_storage::StoreError::NotFound => Status::not_found("Project not found"),
                    _ => Status::internal(format!("Failed to get project: {}", e)),
                })?;
            server
                .store
                .set_user_project_permission(&project.id, &target_user.id, role)
                .await
                .map_err(|e| Status::internal(format!("Failed to set permission: {}", e)))?;
        }
        (ResourceType::ResourceEnvironment, ActorType::ActorUser) => {
            let user_email = actor.actor.as_ref().unwrap().user_email_ref();
            let target_user =
                server
                    .store
                    .get_user_by_email(user_email)
                    .await
                    .map_err(|e| match e {
                        zopp_storage::StoreError::NotFound => Status::not_found("User not found"),
                        _ => Status::internal(format!("Failed to get user: {}", e)),
                    })?;
            let project = server
                .store
                .get_project_by_name(&workspace.id, resource.project_name.as_ref().unwrap())
                .await
                .map_err(|e| match e {
                    zopp_storage::StoreError::NotFound => Status::not_found("Project not found"),
                    _ => Status::internal(format!("Failed to get project: {}", e)),
                })?;
            let environment = server
                .store
                .get_environment_by_name(&project.id, resource.environment_name.as_ref().unwrap())
                .await
                .map_err(|e| match e {
                    zopp_storage::StoreError::NotFound => {
                        Status::not_found("Environment not found")
                    }
                    _ => Status::internal(format!("Failed to get environment: {}", e)),
                })?;
            server
                .store
                .set_user_environment_permission(&environment.id, &target_user.id, role)
                .await
                .map_err(|e| Status::internal(format!("Failed to set permission: {}", e)))?;
        }
        _ => {
            return Err(Status::invalid_argument(
                "Invalid resource type / actor type combination",
            ))
        }
    }

    Ok(Response::new(Empty {}))
}

// ───────────────────────────────────── GetPermission ─────────────────────────────────────

pub async fn get_permission(
    server: &ZoppServer,
    request: Request<GetPermissionRequest>,
) -> Result<Response<PermissionResponse>, Status> {
    let (principal_id, timestamp, signature, request_hash) = extract_signature(&request)?;
    let req_for_verify = request.get_ref().clone();
    let principal = server
        .verify_signature_and_get_principal(
            &principal_id,
            timestamp,
            &signature,
            "/zopp.ZoppService/GetPermission",
            &req_for_verify,
            &request_hash,
        )
        .await?;
    let user_id = principal
        .user_id
        .ok_or_else(|| Status::unauthenticated("Service accounts cannot get permissions"))?;

    let req = request.into_inner();
    let resource = req
        .resource
        .ok_or_else(|| Status::invalid_argument("resource is required"))?;
    let actor = req
        .actor
        .ok_or_else(|| Status::invalid_argument("actor is required"))?;

    validate_resource_ref(&resource)?;
    validate_actor_ref(&actor)?;

    let resource_type =
        ResourceType::try_from(resource.r#type).unwrap_or(ResourceType::Unspecified);
    let actor_type = ActorType::try_from(actor.r#type).unwrap_or(ActorType::Unspecified);

    // Look up workspace
    let workspace = server
        .store
        .get_workspace_by_name(&user_id, &resource.workspace_name)
        .await
        .map_err(|e| match e {
            zopp_storage::StoreError::NotFound => {
                Status::not_found("Workspace not found or access denied")
            }
            _ => Status::internal(format!("Failed to get workspace: {}", e)),
        })?;

    // Dispatch based on resource type and actor type
    let role = match (resource_type, actor_type) {
        // Principal permissions
        (ResourceType::ResourceWorkspace, ActorType::ActorPrincipal) => {
            let target_principal_id =
                parse_principal_id(actor.actor.as_ref().unwrap().principal_id_ref())?;
            server
                .store
                .get_workspace_permission(&workspace.id, &target_principal_id)
                .await
                .map_err(|e| match e {
                    zopp_storage::StoreError::NotFound => Status::not_found("Permission not found"),
                    _ => Status::internal(format!("Failed to get permission: {}", e)),
                })?
        }
        (ResourceType::ResourceProject, ActorType::ActorPrincipal) => {
            let target_principal_id =
                parse_principal_id(actor.actor.as_ref().unwrap().principal_id_ref())?;
            let project = server
                .store
                .get_project_by_name(&workspace.id, resource.project_name.as_ref().unwrap())
                .await
                .map_err(|e| match e {
                    zopp_storage::StoreError::NotFound => Status::not_found("Project not found"),
                    _ => Status::internal(format!("Failed to get project: {}", e)),
                })?;
            server
                .store
                .get_project_permission(&project.id, &target_principal_id)
                .await
                .map_err(|e| match e {
                    zopp_storage::StoreError::NotFound => Status::not_found("Permission not found"),
                    _ => Status::internal(format!("Failed to get permission: {}", e)),
                })?
        }
        (ResourceType::ResourceEnvironment, ActorType::ActorPrincipal) => {
            let target_principal_id =
                parse_principal_id(actor.actor.as_ref().unwrap().principal_id_ref())?;
            let project = server
                .store
                .get_project_by_name(&workspace.id, resource.project_name.as_ref().unwrap())
                .await
                .map_err(|e| match e {
                    zopp_storage::StoreError::NotFound => Status::not_found("Project not found"),
                    _ => Status::internal(format!("Failed to get project: {}", e)),
                })?;
            let environment = server
                .store
                .get_environment_by_name(&project.id, resource.environment_name.as_ref().unwrap())
                .await
                .map_err(|e| match e {
                    zopp_storage::StoreError::NotFound => {
                        Status::not_found("Environment not found")
                    }
                    _ => Status::internal(format!("Failed to get environment: {}", e)),
                })?;
            server
                .store
                .get_environment_permission(&environment.id, &target_principal_id)
                .await
                .map_err(|e| match e {
                    zopp_storage::StoreError::NotFound => Status::not_found("Permission not found"),
                    _ => Status::internal(format!("Failed to get permission: {}", e)),
                })?
        }
        // Group permissions
        (ResourceType::ResourceWorkspace, ActorType::ActorGroup) => {
            let group_name = actor.actor.as_ref().unwrap().group_name_ref();
            let group = server
                .store
                .get_group_by_name(&workspace.id, group_name)
                .await
                .map_err(|e| match e {
                    zopp_storage::StoreError::NotFound => Status::not_found("Group not found"),
                    _ => Status::internal(format!("Failed to get group: {}", e)),
                })?;
            server
                .store
                .get_group_workspace_permission(&workspace.id, &group.id)
                .await
                .map_err(|e| match e {
                    zopp_storage::StoreError::NotFound => Status::not_found("Permission not found"),
                    _ => Status::internal(format!("Failed to get permission: {}", e)),
                })?
        }
        (ResourceType::ResourceProject, ActorType::ActorGroup) => {
            let group_name = actor.actor.as_ref().unwrap().group_name_ref();
            let group = server
                .store
                .get_group_by_name(&workspace.id, group_name)
                .await
                .map_err(|e| match e {
                    zopp_storage::StoreError::NotFound => Status::not_found("Group not found"),
                    _ => Status::internal(format!("Failed to get group: {}", e)),
                })?;
            let project = server
                .store
                .get_project_by_name(&workspace.id, resource.project_name.as_ref().unwrap())
                .await
                .map_err(|e| match e {
                    zopp_storage::StoreError::NotFound => Status::not_found("Project not found"),
                    _ => Status::internal(format!("Failed to get project: {}", e)),
                })?;
            server
                .store
                .get_group_project_permission(&project.id, &group.id)
                .await
                .map_err(|e| match e {
                    zopp_storage::StoreError::NotFound => Status::not_found("Permission not found"),
                    _ => Status::internal(format!("Failed to get permission: {}", e)),
                })?
        }
        (ResourceType::ResourceEnvironment, ActorType::ActorGroup) => {
            let group_name = actor.actor.as_ref().unwrap().group_name_ref();
            let group = server
                .store
                .get_group_by_name(&workspace.id, group_name)
                .await
                .map_err(|e| match e {
                    zopp_storage::StoreError::NotFound => Status::not_found("Group not found"),
                    _ => Status::internal(format!("Failed to get group: {}", e)),
                })?;
            let project = server
                .store
                .get_project_by_name(&workspace.id, resource.project_name.as_ref().unwrap())
                .await
                .map_err(|e| match e {
                    zopp_storage::StoreError::NotFound => Status::not_found("Project not found"),
                    _ => Status::internal(format!("Failed to get project: {}", e)),
                })?;
            let environment = server
                .store
                .get_environment_by_name(&project.id, resource.environment_name.as_ref().unwrap())
                .await
                .map_err(|e| match e {
                    zopp_storage::StoreError::NotFound => {
                        Status::not_found("Environment not found")
                    }
                    _ => Status::internal(format!("Failed to get environment: {}", e)),
                })?;
            server
                .store
                .get_group_environment_permission(&environment.id, &group.id)
                .await
                .map_err(|e| match e {
                    zopp_storage::StoreError::NotFound => Status::not_found("Permission not found"),
                    _ => Status::internal(format!("Failed to get permission: {}", e)),
                })?
        }
        // User permissions
        (ResourceType::ResourceWorkspace, ActorType::ActorUser) => {
            let user_email = actor.actor.as_ref().unwrap().user_email_ref();
            let target_user =
                server
                    .store
                    .get_user_by_email(user_email)
                    .await
                    .map_err(|e| match e {
                        zopp_storage::StoreError::NotFound => Status::not_found("User not found"),
                        _ => Status::internal(format!("Failed to get user: {}", e)),
                    })?;
            server
                .store
                .get_user_workspace_permission(&workspace.id, &target_user.id)
                .await
                .map_err(|e| match e {
                    zopp_storage::StoreError::NotFound => Status::not_found("Permission not found"),
                    _ => Status::internal(format!("Failed to get permission: {}", e)),
                })?
        }
        (ResourceType::ResourceProject, ActorType::ActorUser) => {
            let user_email = actor.actor.as_ref().unwrap().user_email_ref();
            let target_user =
                server
                    .store
                    .get_user_by_email(user_email)
                    .await
                    .map_err(|e| match e {
                        zopp_storage::StoreError::NotFound => Status::not_found("User not found"),
                        _ => Status::internal(format!("Failed to get user: {}", e)),
                    })?;
            let project = server
                .store
                .get_project_by_name(&workspace.id, resource.project_name.as_ref().unwrap())
                .await
                .map_err(|e| match e {
                    zopp_storage::StoreError::NotFound => Status::not_found("Project not found"),
                    _ => Status::internal(format!("Failed to get project: {}", e)),
                })?;
            server
                .store
                .get_user_project_permission(&project.id, &target_user.id)
                .await
                .map_err(|e| match e {
                    zopp_storage::StoreError::NotFound => Status::not_found("Permission not found"),
                    _ => Status::internal(format!("Failed to get permission: {}", e)),
                })?
        }
        (ResourceType::ResourceEnvironment, ActorType::ActorUser) => {
            let user_email = actor.actor.as_ref().unwrap().user_email_ref();
            let target_user =
                server
                    .store
                    .get_user_by_email(user_email)
                    .await
                    .map_err(|e| match e {
                        zopp_storage::StoreError::NotFound => Status::not_found("User not found"),
                        _ => Status::internal(format!("Failed to get user: {}", e)),
                    })?;
            let project = server
                .store
                .get_project_by_name(&workspace.id, resource.project_name.as_ref().unwrap())
                .await
                .map_err(|e| match e {
                    zopp_storage::StoreError::NotFound => Status::not_found("Project not found"),
                    _ => Status::internal(format!("Failed to get project: {}", e)),
                })?;
            let environment = server
                .store
                .get_environment_by_name(&project.id, resource.environment_name.as_ref().unwrap())
                .await
                .map_err(|e| match e {
                    zopp_storage::StoreError::NotFound => {
                        Status::not_found("Environment not found")
                    }
                    _ => Status::internal(format!("Failed to get environment: {}", e)),
                })?;
            server
                .store
                .get_user_environment_permission(&environment.id, &target_user.id)
                .await
                .map_err(|e| match e {
                    zopp_storage::StoreError::NotFound => Status::not_found("Permission not found"),
                    _ => Status::internal(format!("Failed to get permission: {}", e)),
                })?
        }
        _ => {
            return Err(Status::invalid_argument(
                "Invalid resource type / actor type combination",
            ))
        }
    };

    Ok(Response::new(PermissionResponse {
        role: storage_role_to_proto(role),
    }))
}

// ───────────────────────────────────── ListPermissions ─────────────────────────────────────

pub async fn list_permissions(
    server: &ZoppServer,
    request: Request<ListPermissionsRequest>,
) -> Result<Response<PermissionListResponse>, Status> {
    let (principal_id, timestamp, signature, request_hash) = extract_signature(&request)?;
    let req_for_verify = request.get_ref().clone();
    let principal = server
        .verify_signature_and_get_principal(
            &principal_id,
            timestamp,
            &signature,
            "/zopp.ZoppService/ListPermissions",
            &req_for_verify,
            &request_hash,
        )
        .await?;
    let user_id = principal
        .user_id
        .ok_or_else(|| Status::unauthenticated("Service accounts cannot list permissions"))?;

    let req = request.into_inner();
    let resource = req
        .resource
        .ok_or_else(|| Status::invalid_argument("resource is required"))?;

    validate_resource_ref(&resource)?;

    let resource_type =
        ResourceType::try_from(resource.r#type).unwrap_or(ResourceType::Unspecified);
    let actor_type_filter = req
        .actor_type_filter
        .and_then(|t| ActorType::try_from(t).ok())
        .filter(|t| *t != ActorType::Unspecified);

    // Look up workspace
    let workspace = server
        .store
        .get_workspace_by_name(&user_id, &resource.workspace_name)
        .await
        .map_err(|e| match e {
            zopp_storage::StoreError::NotFound => {
                Status::not_found("Workspace not found or access denied")
            }
            _ => Status::internal(format!("Failed to get workspace: {}", e)),
        })?;

    let mut permissions = Vec::new();

    // Get project and environment IDs if needed
    let project = if resource_type == ResourceType::ResourceProject
        || resource_type == ResourceType::ResourceEnvironment
    {
        Some(
            server
                .store
                .get_project_by_name(&workspace.id, resource.project_name.as_ref().unwrap())
                .await
                .map_err(|e| match e {
                    zopp_storage::StoreError::NotFound => Status::not_found("Project not found"),
                    _ => Status::internal(format!("Failed to get project: {}", e)),
                })?,
        )
    } else {
        None
    };

    let environment = if resource_type == ResourceType::ResourceEnvironment {
        Some(
            server
                .store
                .get_environment_by_name(
                    &project.as_ref().unwrap().id,
                    resource.environment_name.as_ref().unwrap(),
                )
                .await
                .map_err(|e| match e {
                    zopp_storage::StoreError::NotFound => {
                        Status::not_found("Environment not found")
                    }
                    _ => Status::internal(format!("Failed to get environment: {}", e)),
                })?,
        )
    } else {
        None
    };

    // Helper to get principal display name
    async fn get_principal_display_name(server: &ZoppServer, principal_id: &PrincipalId) -> String {
        match server.store.get_principal(principal_id).await {
            Ok(principal) => principal.name,
            Err(_) => principal_id.0.to_string(),
        }
    }

    // Helper to get group display name
    async fn get_group_display_name(
        server: &ZoppServer,
        group_id: &zopp_storage::GroupId,
    ) -> String {
        match server.store.get_group(group_id).await {
            Ok(group) => group.name,
            Err(_) => group_id.0.to_string(),
        }
    }

    // Helper to get user display name (email)
    async fn get_user_display_name(server: &ZoppServer, user_id: &zopp_storage::UserId) -> String {
        match server.store.get_user_by_id(user_id).await {
            Ok(user) => user.email,
            Err(_) => user_id.0.to_string(),
        }
    }

    // Collect principal permissions if not filtered out
    if actor_type_filter.is_none() || actor_type_filter == Some(ActorType::ActorPrincipal) {
        match resource_type {
            ResourceType::ResourceWorkspace => {
                let perms = server
                    .store
                    .list_workspace_permissions(&workspace.id)
                    .await
                    .map_err(|e| Status::internal(format!("Failed to list permissions: {}", e)))?;
                for perm in perms {
                    let display_name = get_principal_display_name(server, &perm.principal_id).await;
                    permissions.push(PermissionEntry {
                        actor: Some(ActorRef {
                            r#type: ActorType::ActorPrincipal as i32,
                            actor: Some(Actor::PrincipalId(perm.principal_id.0.to_string())),
                        }),
                        role: storage_role_to_proto(perm.role),
                        actor_display_name: display_name,
                    });
                }
            }
            ResourceType::ResourceProject => {
                let perms = server
                    .store
                    .list_project_permissions(&project.as_ref().unwrap().id)
                    .await
                    .map_err(|e| Status::internal(format!("Failed to list permissions: {}", e)))?;
                for perm in perms {
                    let display_name = get_principal_display_name(server, &perm.principal_id).await;
                    permissions.push(PermissionEntry {
                        actor: Some(ActorRef {
                            r#type: ActorType::ActorPrincipal as i32,
                            actor: Some(Actor::PrincipalId(perm.principal_id.0.to_string())),
                        }),
                        role: storage_role_to_proto(perm.role),
                        actor_display_name: display_name,
                    });
                }
            }
            ResourceType::ResourceEnvironment => {
                let perms = server
                    .store
                    .list_environment_permissions(&environment.as_ref().unwrap().id)
                    .await
                    .map_err(|e| Status::internal(format!("Failed to list permissions: {}", e)))?;
                for perm in perms {
                    let display_name = get_principal_display_name(server, &perm.principal_id).await;
                    permissions.push(PermissionEntry {
                        actor: Some(ActorRef {
                            r#type: ActorType::ActorPrincipal as i32,
                            actor: Some(Actor::PrincipalId(perm.principal_id.0.to_string())),
                        }),
                        role: storage_role_to_proto(perm.role),
                        actor_display_name: display_name,
                    });
                }
            }
            _ => return Err(Status::invalid_argument("Invalid resource type")),
        }
    }

    // Collect group permissions if not filtered out
    if actor_type_filter.is_none() || actor_type_filter == Some(ActorType::ActorGroup) {
        match resource_type {
            ResourceType::ResourceWorkspace => {
                let perms = server
                    .store
                    .list_group_workspace_permissions(&workspace.id)
                    .await
                    .map_err(|e| Status::internal(format!("Failed to list permissions: {}", e)))?;
                for perm in perms {
                    let display_name = get_group_display_name(server, &perm.group_id).await;
                    permissions.push(PermissionEntry {
                        actor: Some(ActorRef {
                            r#type: ActorType::ActorGroup as i32,
                            actor: Some(Actor::GroupName(display_name.clone())),
                        }),
                        role: storage_role_to_proto(perm.role),
                        actor_display_name: display_name,
                    });
                }
            }
            ResourceType::ResourceProject => {
                let perms = server
                    .store
                    .list_group_project_permissions(&project.as_ref().unwrap().id)
                    .await
                    .map_err(|e| Status::internal(format!("Failed to list permissions: {}", e)))?;
                for perm in perms {
                    let display_name = get_group_display_name(server, &perm.group_id).await;
                    permissions.push(PermissionEntry {
                        actor: Some(ActorRef {
                            r#type: ActorType::ActorGroup as i32,
                            actor: Some(Actor::GroupName(display_name.clone())),
                        }),
                        role: storage_role_to_proto(perm.role),
                        actor_display_name: display_name,
                    });
                }
            }
            ResourceType::ResourceEnvironment => {
                let perms = server
                    .store
                    .list_group_environment_permissions(&environment.as_ref().unwrap().id)
                    .await
                    .map_err(|e| Status::internal(format!("Failed to list permissions: {}", e)))?;
                for perm in perms {
                    let display_name = get_group_display_name(server, &perm.group_id).await;
                    permissions.push(PermissionEntry {
                        actor: Some(ActorRef {
                            r#type: ActorType::ActorGroup as i32,
                            actor: Some(Actor::GroupName(display_name.clone())),
                        }),
                        role: storage_role_to_proto(perm.role),
                        actor_display_name: display_name,
                    });
                }
            }
            _ => return Err(Status::invalid_argument("Invalid resource type")),
        }
    }

    // Collect user permissions if not filtered out
    if actor_type_filter.is_none() || actor_type_filter == Some(ActorType::ActorUser) {
        match resource_type {
            ResourceType::ResourceWorkspace => {
                let perms = server
                    .store
                    .list_user_workspace_permissions(&workspace.id)
                    .await
                    .map_err(|e| Status::internal(format!("Failed to list permissions: {}", e)))?;
                for perm in perms {
                    let display_name = get_user_display_name(server, &perm.user_id).await;
                    permissions.push(PermissionEntry {
                        actor: Some(ActorRef {
                            r#type: ActorType::ActorUser as i32,
                            actor: Some(Actor::UserEmail(display_name.clone())),
                        }),
                        role: storage_role_to_proto(perm.role),
                        actor_display_name: display_name,
                    });
                }
            }
            ResourceType::ResourceProject => {
                let perms = server
                    .store
                    .list_user_project_permissions(&project.as_ref().unwrap().id)
                    .await
                    .map_err(|e| Status::internal(format!("Failed to list permissions: {}", e)))?;
                for perm in perms {
                    let display_name = get_user_display_name(server, &perm.user_id).await;
                    permissions.push(PermissionEntry {
                        actor: Some(ActorRef {
                            r#type: ActorType::ActorUser as i32,
                            actor: Some(Actor::UserEmail(display_name.clone())),
                        }),
                        role: storage_role_to_proto(perm.role),
                        actor_display_name: display_name,
                    });
                }
            }
            ResourceType::ResourceEnvironment => {
                let perms = server
                    .store
                    .list_user_environment_permissions(&environment.as_ref().unwrap().id)
                    .await
                    .map_err(|e| Status::internal(format!("Failed to list permissions: {}", e)))?;
                for perm in perms {
                    let display_name = get_user_display_name(server, &perm.user_id).await;
                    permissions.push(PermissionEntry {
                        actor: Some(ActorRef {
                            r#type: ActorType::ActorUser as i32,
                            actor: Some(Actor::UserEmail(display_name.clone())),
                        }),
                        role: storage_role_to_proto(perm.role),
                        actor_display_name: display_name,
                    });
                }
            }
            _ => return Err(Status::invalid_argument("Invalid resource type")),
        }
    }

    Ok(Response::new(PermissionListResponse { permissions }))
}

// ───────────────────────────────────── RemovePermission ─────────────────────────────────────

pub async fn remove_permission(
    server: &ZoppServer,
    request: Request<RemovePermissionRequest>,
) -> Result<Response<Empty>, Status> {
    let (principal_id, timestamp, signature, request_hash) = extract_signature(&request)?;
    let req_for_verify = request.get_ref().clone();
    let principal = server
        .verify_signature_and_get_principal(
            &principal_id,
            timestamp,
            &signature,
            "/zopp.ZoppService/RemovePermission",
            &req_for_verify,
            &request_hash,
        )
        .await?;
    let user_id = principal
        .user_id
        .ok_or_else(|| Status::unauthenticated("Service accounts cannot remove permissions"))?;

    let req = request.into_inner();
    let resource = req
        .resource
        .ok_or_else(|| Status::invalid_argument("resource is required"))?;
    let actor = req
        .actor
        .ok_or_else(|| Status::invalid_argument("actor is required"))?;

    validate_resource_ref(&resource)?;
    validate_actor_ref(&actor)?;

    let resource_type =
        ResourceType::try_from(resource.r#type).unwrap_or(ResourceType::Unspecified);
    let actor_type = ActorType::try_from(actor.r#type).unwrap_or(ActorType::Unspecified);

    // Look up workspace
    let workspace = server
        .store
        .get_workspace_by_name(&user_id, &resource.workspace_name)
        .await
        .map_err(|e| match e {
            zopp_storage::StoreError::NotFound => {
                Status::not_found("Workspace not found or access denied")
            }
            _ => Status::internal(format!("Failed to get workspace: {}", e)),
        })?;

    // Check requester has admin permission on the resource
    let requester_role = match resource_type {
        ResourceType::ResourceWorkspace => {
            server
                .get_effective_workspace_role(&principal_id, &workspace.id)
                .await?
        }
        ResourceType::ResourceProject => {
            let project = server
                .store
                .get_project_by_name(&workspace.id, resource.project_name.as_ref().unwrap())
                .await
                .map_err(|e| match e {
                    zopp_storage::StoreError::NotFound => Status::not_found("Project not found"),
                    _ => Status::internal(format!("Failed to get project: {}", e)),
                })?;
            server
                .get_effective_project_role(&principal_id, &workspace.id, &project.id)
                .await?
        }
        ResourceType::ResourceEnvironment => {
            let project = server
                .store
                .get_project_by_name(&workspace.id, resource.project_name.as_ref().unwrap())
                .await
                .map_err(|e| match e {
                    zopp_storage::StoreError::NotFound => Status::not_found("Project not found"),
                    _ => Status::internal(format!("Failed to get project: {}", e)),
                })?;
            let environment = server
                .store
                .get_environment_by_name(&project.id, resource.environment_name.as_ref().unwrap())
                .await
                .map_err(|e| match e {
                    zopp_storage::StoreError::NotFound => {
                        Status::not_found("Environment not found")
                    }
                    _ => Status::internal(format!("Failed to get environment: {}", e)),
                })?;
            server
                .get_effective_environment_role(
                    &principal_id,
                    &workspace.id,
                    &project.id,
                    &environment.id,
                )
                .await?
        }
        _ => return Err(Status::invalid_argument("Invalid resource type")),
    };

    let requester_role = requester_role.ok_or_else(|| {
        Status::permission_denied("No permission to remove permissions on this resource")
    })?;

    // Must have admin to remove permissions
    if requester_role != zopp_storage::Role::Admin {
        return Err(Status::permission_denied(
            "Admin permission required to remove permissions",
        ));
    }

    // Dispatch based on resource type and actor type
    match (resource_type, actor_type) {
        // Principal permissions
        (ResourceType::ResourceWorkspace, ActorType::ActorPrincipal) => {
            let target_principal_id =
                parse_principal_id(actor.actor.as_ref().unwrap().principal_id_ref())?;
            server
                .store
                .remove_workspace_permission(&workspace.id, &target_principal_id)
                .await
                .map_err(|e| Status::internal(format!("Failed to remove permission: {}", e)))?;
        }
        (ResourceType::ResourceProject, ActorType::ActorPrincipal) => {
            let target_principal_id =
                parse_principal_id(actor.actor.as_ref().unwrap().principal_id_ref())?;
            let project = server
                .store
                .get_project_by_name(&workspace.id, resource.project_name.as_ref().unwrap())
                .await
                .map_err(|e| match e {
                    zopp_storage::StoreError::NotFound => Status::not_found("Project not found"),
                    _ => Status::internal(format!("Failed to get project: {}", e)),
                })?;
            server
                .store
                .remove_project_permission(&project.id, &target_principal_id)
                .await
                .map_err(|e| Status::internal(format!("Failed to remove permission: {}", e)))?;
        }
        (ResourceType::ResourceEnvironment, ActorType::ActorPrincipal) => {
            let target_principal_id =
                parse_principal_id(actor.actor.as_ref().unwrap().principal_id_ref())?;
            let project = server
                .store
                .get_project_by_name(&workspace.id, resource.project_name.as_ref().unwrap())
                .await
                .map_err(|e| match e {
                    zopp_storage::StoreError::NotFound => Status::not_found("Project not found"),
                    _ => Status::internal(format!("Failed to get project: {}", e)),
                })?;
            let environment = server
                .store
                .get_environment_by_name(&project.id, resource.environment_name.as_ref().unwrap())
                .await
                .map_err(|e| match e {
                    zopp_storage::StoreError::NotFound => {
                        Status::not_found("Environment not found")
                    }
                    _ => Status::internal(format!("Failed to get environment: {}", e)),
                })?;
            server
                .store
                .remove_environment_permission(&environment.id, &target_principal_id)
                .await
                .map_err(|e| Status::internal(format!("Failed to remove permission: {}", e)))?;
        }
        // Group permissions
        (ResourceType::ResourceWorkspace, ActorType::ActorGroup) => {
            let group_name = actor.actor.as_ref().unwrap().group_name_ref();
            let group = server
                .store
                .get_group_by_name(&workspace.id, group_name)
                .await
                .map_err(|e| match e {
                    zopp_storage::StoreError::NotFound => Status::not_found("Group not found"),
                    _ => Status::internal(format!("Failed to get group: {}", e)),
                })?;
            server
                .store
                .remove_group_workspace_permission(&workspace.id, &group.id)
                .await
                .map_err(|e| Status::internal(format!("Failed to remove permission: {}", e)))?;
        }
        (ResourceType::ResourceProject, ActorType::ActorGroup) => {
            let group_name = actor.actor.as_ref().unwrap().group_name_ref();
            let group = server
                .store
                .get_group_by_name(&workspace.id, group_name)
                .await
                .map_err(|e| match e {
                    zopp_storage::StoreError::NotFound => Status::not_found("Group not found"),
                    _ => Status::internal(format!("Failed to get group: {}", e)),
                })?;
            let project = server
                .store
                .get_project_by_name(&workspace.id, resource.project_name.as_ref().unwrap())
                .await
                .map_err(|e| match e {
                    zopp_storage::StoreError::NotFound => Status::not_found("Project not found"),
                    _ => Status::internal(format!("Failed to get project: {}", e)),
                })?;
            server
                .store
                .remove_group_project_permission(&project.id, &group.id)
                .await
                .map_err(|e| Status::internal(format!("Failed to remove permission: {}", e)))?;
        }
        (ResourceType::ResourceEnvironment, ActorType::ActorGroup) => {
            let group_name = actor.actor.as_ref().unwrap().group_name_ref();
            let group = server
                .store
                .get_group_by_name(&workspace.id, group_name)
                .await
                .map_err(|e| match e {
                    zopp_storage::StoreError::NotFound => Status::not_found("Group not found"),
                    _ => Status::internal(format!("Failed to get group: {}", e)),
                })?;
            let project = server
                .store
                .get_project_by_name(&workspace.id, resource.project_name.as_ref().unwrap())
                .await
                .map_err(|e| match e {
                    zopp_storage::StoreError::NotFound => Status::not_found("Project not found"),
                    _ => Status::internal(format!("Failed to get project: {}", e)),
                })?;
            let environment = server
                .store
                .get_environment_by_name(&project.id, resource.environment_name.as_ref().unwrap())
                .await
                .map_err(|e| match e {
                    zopp_storage::StoreError::NotFound => {
                        Status::not_found("Environment not found")
                    }
                    _ => Status::internal(format!("Failed to get environment: {}", e)),
                })?;
            server
                .store
                .remove_group_environment_permission(&environment.id, &group.id)
                .await
                .map_err(|e| Status::internal(format!("Failed to remove permission: {}", e)))?;
        }
        // User permissions
        (ResourceType::ResourceWorkspace, ActorType::ActorUser) => {
            let user_email = actor.actor.as_ref().unwrap().user_email_ref();
            let target_user =
                server
                    .store
                    .get_user_by_email(user_email)
                    .await
                    .map_err(|e| match e {
                        zopp_storage::StoreError::NotFound => Status::not_found("User not found"),
                        _ => Status::internal(format!("Failed to get user: {}", e)),
                    })?;
            server
                .store
                .remove_user_workspace_permission(&workspace.id, &target_user.id)
                .await
                .map_err(|e| Status::internal(format!("Failed to remove permission: {}", e)))?;
        }
        (ResourceType::ResourceProject, ActorType::ActorUser) => {
            let user_email = actor.actor.as_ref().unwrap().user_email_ref();
            let target_user =
                server
                    .store
                    .get_user_by_email(user_email)
                    .await
                    .map_err(|e| match e {
                        zopp_storage::StoreError::NotFound => Status::not_found("User not found"),
                        _ => Status::internal(format!("Failed to get user: {}", e)),
                    })?;
            let project = server
                .store
                .get_project_by_name(&workspace.id, resource.project_name.as_ref().unwrap())
                .await
                .map_err(|e| match e {
                    zopp_storage::StoreError::NotFound => Status::not_found("Project not found"),
                    _ => Status::internal(format!("Failed to get project: {}", e)),
                })?;
            server
                .store
                .remove_user_project_permission(&project.id, &target_user.id)
                .await
                .map_err(|e| Status::internal(format!("Failed to remove permission: {}", e)))?;
        }
        (ResourceType::ResourceEnvironment, ActorType::ActorUser) => {
            let user_email = actor.actor.as_ref().unwrap().user_email_ref();
            let target_user =
                server
                    .store
                    .get_user_by_email(user_email)
                    .await
                    .map_err(|e| match e {
                        zopp_storage::StoreError::NotFound => Status::not_found("User not found"),
                        _ => Status::internal(format!("Failed to get user: {}", e)),
                    })?;
            let project = server
                .store
                .get_project_by_name(&workspace.id, resource.project_name.as_ref().unwrap())
                .await
                .map_err(|e| match e {
                    zopp_storage::StoreError::NotFound => Status::not_found("Project not found"),
                    _ => Status::internal(format!("Failed to get project: {}", e)),
                })?;
            let environment = server
                .store
                .get_environment_by_name(&project.id, resource.environment_name.as_ref().unwrap())
                .await
                .map_err(|e| match e {
                    zopp_storage::StoreError::NotFound => {
                        Status::not_found("Environment not found")
                    }
                    _ => Status::internal(format!("Failed to get environment: {}", e)),
                })?;
            server
                .store
                .remove_user_environment_permission(&environment.id, &target_user.id)
                .await
                .map_err(|e| Status::internal(format!("Failed to remove permission: {}", e)))?;
        }
        _ => {
            return Err(Status::invalid_argument(
                "Invalid resource type / actor type combination",
            ))
        }
    }

    Ok(Response::new(Empty {}))
}

// ───────────────────────────────────── Helper Trait Extensions ─────────────────────────────────────

trait ActorRefExt {
    fn principal_id_ref(&self) -> &str;
    fn group_name_ref(&self) -> &str;
    fn user_email_ref(&self) -> &str;
}

impl ActorRefExt for Actor {
    fn principal_id_ref(&self) -> &str {
        match self {
            Actor::PrincipalId(id) => id,
            _ => "",
        }
    }

    fn group_name_ref(&self) -> &str {
        match self {
            Actor::GroupName(name) => name,
            _ => "",
        }
    }

    fn user_email_ref(&self) -> &str {
        match self {
            Actor::UserEmail(email) => email,
            _ => "",
        }
    }
}

fn parse_principal_id(id: &str) -> Result<PrincipalId, Status> {
    Uuid::parse_str(id)
        .map(PrincipalId)
        .map_err(|_| Status::invalid_argument("Invalid principal ID"))
}
