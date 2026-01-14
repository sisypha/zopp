//! Group handlers: create, get, list, update, delete + membership management

use tonic::{Request, Response, Status};
use zopp_proto::Empty;
use zopp_storage::Store;

use crate::server::{extract_signature, ZoppServer};

pub async fn create_group(
    server: &ZoppServer,
    request: Request<zopp_proto::CreateGroupRequest>,
) -> Result<Response<zopp_proto::Group>, Status> {
    let (principal_id, timestamp, signature, request_hash) = extract_signature(&request)?;
    let req_for_verify = request.get_ref().clone();
    let principal = server
        .verify_signature_and_get_principal(
            &principal_id,
            timestamp,
            &signature,
            "/zopp.ZoppService/CreateGroup",
            &req_for_verify,
            &request_hash,
        )
        .await?;
    let user_id = principal
        .user_id
        .ok_or_else(|| Status::unauthenticated("Service accounts cannot create groups"))?;

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

    // Check ADMIN permission for creating groups
    server
        .check_workspace_permission(&principal_id, &workspace.id, zopp_storage::Role::Admin)
        .await?;

    let group_id = server
        .store
        .create_group(&zopp_storage::CreateGroupParams {
            workspace_id: workspace.id.clone(),
            name: req.name,
            description: if req.description.is_empty() {
                None
            } else {
                Some(req.description)
            },
        })
        .await
        .map_err(|e| match e {
            zopp_storage::StoreError::AlreadyExists => {
                Status::already_exists("Group with this name already exists")
            }
            _ => Status::internal(format!("Failed to create group: {}", e)),
        })?;

    let group = server
        .store
        .get_group(&group_id)
        .await
        .map_err(|e| Status::internal(format!("Failed to get group: {}", e)))?;

    Ok(Response::new(zopp_proto::Group {
        id: group.id.0.to_string(),
        workspace_id: group.workspace_id.0.to_string(),
        name: group.name,
        description: group.description.unwrap_or_default(),
        created_at: group.created_at.to_rfc3339(),
        updated_at: group.updated_at.to_rfc3339(),
    }))
}

pub async fn get_group(
    server: &ZoppServer,
    request: Request<zopp_proto::GetGroupRequest>,
) -> Result<Response<zopp_proto::Group>, Status> {
    let (principal_id, timestamp, signature, request_hash) = extract_signature(&request)?;
    let req_for_verify = request.get_ref().clone();
    let principal = server
        .verify_signature_and_get_principal(
            &principal_id,
            timestamp,
            &signature,
            "/zopp.ZoppService/GetGroup",
            &req_for_verify,
            &request_hash,
        )
        .await?;
    let user_id = principal
        .user_id
        .ok_or_else(|| Status::unauthenticated("Service accounts cannot get groups"))?;

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

    Ok(Response::new(zopp_proto::Group {
        id: group.id.0.to_string(),
        workspace_id: group.workspace_id.0.to_string(),
        name: group.name,
        description: group.description.unwrap_or_default(),
        created_at: group.created_at.to_rfc3339(),
        updated_at: group.updated_at.to_rfc3339(),
    }))
}

pub async fn list_groups(
    server: &ZoppServer,
    request: Request<zopp_proto::ListGroupsRequest>,
) -> Result<Response<zopp_proto::GroupList>, Status> {
    let (principal_id, timestamp, signature, request_hash) = extract_signature(&request)?;
    let req_for_verify = request.get_ref().clone();
    let principal = server
        .verify_signature_and_get_principal(
            &principal_id,
            timestamp,
            &signature,
            "/zopp.ZoppService/ListGroups",
            &req_for_verify,
            &request_hash,
        )
        .await?;
    let user_id = principal
        .user_id
        .ok_or_else(|| Status::unauthenticated("Service accounts cannot list groups"))?;

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

    let groups = server
        .store
        .list_groups(&workspace.id)
        .await
        .map_err(|e| Status::internal(format!("Failed to list groups: {}", e)))?;

    let proto_groups = groups
        .into_iter()
        .map(|g| zopp_proto::Group {
            id: g.id.0.to_string(),
            workspace_id: g.workspace_id.0.to_string(),
            name: g.name,
            description: g.description.unwrap_or_default(),
            created_at: g.created_at.to_rfc3339(),
            updated_at: g.updated_at.to_rfc3339(),
        })
        .collect();

    Ok(Response::new(zopp_proto::GroupList {
        groups: proto_groups,
    }))
}

pub async fn update_group(
    server: &ZoppServer,
    request: Request<zopp_proto::UpdateGroupRequest>,
) -> Result<Response<zopp_proto::Group>, Status> {
    let (principal_id, timestamp, signature, request_hash) = extract_signature(&request)?;
    let req_for_verify = request.get_ref().clone();
    let principal = server
        .verify_signature_and_get_principal(
            &principal_id,
            timestamp,
            &signature,
            "/zopp.ZoppService/UpdateGroup",
            &req_for_verify,
            &request_hash,
        )
        .await?;
    let user_id = principal
        .user_id
        .ok_or_else(|| Status::unauthenticated("Service accounts cannot update groups"))?;

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

    // Check ADMIN permission for updating groups
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

    // If new_name is empty, keep the current name
    let name_to_use = if req.new_name.is_empty() {
        &group.name
    } else {
        &req.new_name
    };

    server
        .store
        .update_group(
            &group.id,
            name_to_use,
            if req.new_description.is_empty() {
                None
            } else {
                Some(req.new_description.clone())
            },
        )
        .await
        .map_err(|e| Status::internal(format!("Failed to update group: {}", e)))?;

    let updated_group = server
        .store
        .get_group(&group.id)
        .await
        .map_err(|e| Status::internal(format!("Failed to get updated group: {}", e)))?;

    Ok(Response::new(zopp_proto::Group {
        id: updated_group.id.0.to_string(),
        workspace_id: updated_group.workspace_id.0.to_string(),
        name: updated_group.name,
        description: updated_group.description.unwrap_or_default(),
        created_at: updated_group.created_at.to_rfc3339(),
        updated_at: updated_group.updated_at.to_rfc3339(),
    }))
}

pub async fn delete_group(
    server: &ZoppServer,
    request: Request<zopp_proto::DeleteGroupRequest>,
) -> Result<Response<Empty>, Status> {
    let (principal_id, timestamp, signature, request_hash) = extract_signature(&request)?;
    let req_for_verify = request.get_ref().clone();
    let principal = server
        .verify_signature_and_get_principal(
            &principal_id,
            timestamp,
            &signature,
            "/zopp.ZoppService/DeleteGroup",
            &req_for_verify,
            &request_hash,
        )
        .await?;
    let user_id = principal
        .user_id
        .ok_or_else(|| Status::unauthenticated("Service accounts cannot delete groups"))?;

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

    // Check ADMIN permission for deleting groups
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

    server
        .store
        .delete_group(&group.id)
        .await
        .map_err(|e| Status::internal(format!("Failed to delete group: {}", e)))?;

    Ok(Response::new(Empty {}))
}

// ───────────────────────────────────── Group Membership ─────────────────────────────────────

pub async fn add_group_member(
    server: &ZoppServer,
    request: Request<zopp_proto::AddGroupMemberRequest>,
) -> Result<Response<Empty>, Status> {
    let (principal_id, timestamp, signature, request_hash) = extract_signature(&request)?;
    let req_for_verify = request.get_ref().clone();
    let principal = server
        .verify_signature_and_get_principal(
            &principal_id,
            timestamp,
            &signature,
            "/zopp.ZoppService/AddGroupMember",
            &req_for_verify,
            &request_hash,
        )
        .await?;
    let user_id = principal
        .user_id
        .ok_or_else(|| Status::unauthenticated("Service accounts cannot add group members"))?;

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

    // Check ADMIN permission for managing group members
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

    // Look up user by email
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
        .add_group_member(&group.id, &target_user.id)
        .await
        .map_err(|e| match e {
            zopp_storage::StoreError::AlreadyExists => {
                Status::already_exists("User is already a member of this group")
            }
            _ => Status::internal(format!("Failed to add group member: {}", e)),
        })?;

    Ok(Response::new(Empty {}))
}

pub async fn remove_group_member(
    server: &ZoppServer,
    request: Request<zopp_proto::RemoveGroupMemberRequest>,
) -> Result<Response<Empty>, Status> {
    let (principal_id, timestamp, signature, request_hash) = extract_signature(&request)?;
    let req_for_verify = request.get_ref().clone();
    let principal = server
        .verify_signature_and_get_principal(
            &principal_id,
            timestamp,
            &signature,
            "/zopp.ZoppService/RemoveGroupMember",
            &req_for_verify,
            &request_hash,
        )
        .await?;
    let user_id = principal
        .user_id
        .ok_or_else(|| Status::unauthenticated("Service accounts cannot remove group members"))?;

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

    // Check ADMIN permission for managing group members
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

    // Look up user by email
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
        .remove_group_member(&group.id, &target_user.id)
        .await
        .map_err(|e| Status::internal(format!("Failed to remove group member: {}", e)))?;

    Ok(Response::new(Empty {}))
}

pub async fn list_group_members(
    server: &ZoppServer,
    request: Request<zopp_proto::ListGroupMembersRequest>,
) -> Result<Response<zopp_proto::GroupMemberList>, Status> {
    let (principal_id, timestamp, signature, request_hash) = extract_signature(&request)?;
    let req_for_verify = request.get_ref().clone();
    let principal = server
        .verify_signature_and_get_principal(
            &principal_id,
            timestamp,
            &signature,
            "/zopp.ZoppService/ListGroupMembers",
            &req_for_verify,
            &request_hash,
        )
        .await?;
    let user_id = principal
        .user_id
        .ok_or_else(|| Status::unauthenticated("Service accounts cannot list group members"))?;

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

    let members = server
        .store
        .list_group_members(&group.id)
        .await
        .map_err(|e| Status::internal(format!("Failed to list group members: {}", e)))?;

    let mut proto_members = Vec::new();
    for member in members {
        // Look up user to get email
        let user = server
            .store
            .get_user_by_id(&member.user_id)
            .await
            .map_err(|e| Status::internal(format!("Failed to get user: {}", e)))?;

        proto_members.push(zopp_proto::GroupMember {
            user_id: member.user_id.0.to_string(),
            user_email: user.email,
            created_at: member.created_at.to_rfc3339(),
        });
    }

    Ok(Response::new(zopp_proto::GroupMemberList {
        members: proto_members,
    }))
}

pub async fn list_user_groups(
    server: &ZoppServer,
    request: Request<zopp_proto::ListUserGroupsRequest>,
) -> Result<Response<zopp_proto::GroupList>, Status> {
    let (principal_id, timestamp, signature, request_hash) = extract_signature(&request)?;
    let req_for_verify = request.get_ref().clone();
    let principal = server
        .verify_signature_and_get_principal(
            &principal_id,
            timestamp,
            &signature,
            "/zopp.ZoppService/ListUserGroups",
            &req_for_verify,
            &request_hash,
        )
        .await?;
    let user_id = principal
        .user_id
        .ok_or_else(|| Status::unauthenticated("Service accounts cannot list user groups"))?;

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

    let groups = server
        .store
        .list_user_groups(&target_user.id)
        .await
        .map_err(|e| Status::internal(format!("Failed to list user groups: {}", e)))?;

    // Filter groups by workspace
    let proto_groups = groups
        .into_iter()
        .filter(|g| g.workspace_id == workspace.id)
        .map(|g| zopp_proto::Group {
            id: g.id.0.to_string(),
            workspace_id: g.workspace_id.0.to_string(),
            name: g.name,
            description: g.description.unwrap_or_default(),
            created_at: g.created_at.to_rfc3339(),
            updated_at: g.updated_at.to_rfc3339(),
        })
        .collect();

    Ok(Response::new(zopp_proto::GroupList {
        groups: proto_groups,
    }))
}
