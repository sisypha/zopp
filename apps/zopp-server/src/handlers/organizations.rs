//! Organization handlers for gRPC service implementation
//!
//! Implements organization management RPCs:
//! - create_organization
//! - get_organization
//! - list_user_organizations
//! - update_organization
//! - delete_organization
//! - add_organization_member
//! - get_organization_member
//! - list_organization_members
//! - update_organization_member_role
//! - remove_organization_member
//! - create_organization_invite
//! - get_organization_invite
//! - list_organization_invites
//! - accept_organization_invite
//! - delete_organization_invite
//! - link_workspace_to_organization
//! - unlink_workspace_from_organization
//! - list_organization_workspaces

use chrono::{Duration, Utc};
use rand::Rng;
use sha2::{Digest, Sha256};
use tonic::{Request, Response, Status};
use uuid::Uuid;

use crate::server::{extract_signature, ZoppServer};
use zopp_proto::*;
use zopp_storage::{OrganizationId, OrganizationInviteId, Store, UserId, WorkspaceId};

// ───────────────────────────────────── Organizations ─────────────────────────────────────

pub async fn create_organization(
    server: &ZoppServer,
    request: Request<CreateOrganizationRequest>,
) -> Result<Response<Organization>, Status> {
    let (principal_id, timestamp, signature, request_hash) = extract_signature(&request)?;
    let req_for_verify = request.get_ref().clone();
    let principal = server
        .verify_signature_and_get_principal(
            &principal_id,
            timestamp,
            &signature,
            "/zopp.ZoppService/CreateOrganization",
            &req_for_verify,
            &request_hash,
        )
        .await?;
    let req = request.into_inner();

    let user_id = principal
        .user_id
        .ok_or_else(|| Status::unauthenticated("Service accounts cannot create organizations"))?;

    if req.name.is_empty() {
        return Err(Status::invalid_argument("Organization name is required"));
    }
    if req.slug.is_empty() {
        return Err(Status::invalid_argument("Organization slug is required"));
    }

    // Validate slug format (lowercase alphanumeric and hyphens)
    if !req
        .slug
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        return Err(Status::invalid_argument(
            "Slug must contain only lowercase letters, numbers, and hyphens",
        ));
    }

    let params = zopp_storage::CreateOrganizationParams {
        name: req.name,
        slug: req.slug,
        owner_user_id: user_id.clone(),
        plan: zopp_storage::Plan::Free,
    };

    let org_id = server
        .store
        .create_organization(&params)
        .await
        .map_err(|e| match e {
            zopp_storage::StoreError::AlreadyExists => {
                Status::already_exists("Organization with this slug already exists")
            }
            e => Status::internal(format!("Failed to create organization: {}", e)),
        })?;

    // Fetch the created organization to return full details
    let org = server
        .store
        .get_organization(&org_id)
        .await
        .map_err(|e| Status::internal(format!("Failed to get organization: {}", e)))?;

    let member_count = server
        .store
        .count_organization_members(&org_id)
        .await
        .unwrap_or(1);

    Ok(Response::new(organization_to_proto(&org, member_count)))
}

pub async fn get_organization(
    server: &ZoppServer,
    request: Request<GetOrganizationRequest>,
) -> Result<Response<Organization>, Status> {
    let (principal_id, timestamp, signature, request_hash) = extract_signature(&request)?;
    let req_for_verify = request.get_ref().clone();
    let principal = server
        .verify_signature_and_get_principal(
            &principal_id,
            timestamp,
            &signature,
            "/zopp.ZoppService/GetOrganization",
            &req_for_verify,
            &request_hash,
        )
        .await?;
    let req = request.into_inner();

    let user_id = principal
        .user_id
        .ok_or_else(|| Status::unauthenticated("Service accounts cannot access organizations"))?;

    let org = match req.identifier {
        Some(get_organization_request::Identifier::Id(id)) => {
            let org_id = parse_organization_id(&id)?;
            server.store.get_organization(&org_id).await
        }
        Some(get_organization_request::Identifier::Slug(slug)) => {
            server.store.get_organization_by_slug(&slug).await
        }
        None => return Err(Status::invalid_argument("Organization ID or slug required")),
    }
    .map_err(|e| match e {
        zopp_storage::StoreError::NotFound => Status::not_found("Organization not found"),
        e => Status::internal(format!("Failed to get organization: {}", e)),
    })?;

    // Check if user is a member of the organization
    server
        .store
        .get_organization_member(&org.id, &user_id)
        .await
        .map_err(|e| match e {
            zopp_storage::StoreError::NotFound => {
                Status::permission_denied("Not a member of this organization")
            }
            e => Status::internal(format!("Failed to check membership: {}", e)),
        })?;

    let member_count = server
        .store
        .count_organization_members(&org.id)
        .await
        .unwrap_or(0);

    Ok(Response::new(organization_to_proto(&org, member_count)))
}

pub async fn list_user_organizations(
    server: &ZoppServer,
    request: Request<Empty>,
) -> Result<Response<OrganizationList>, Status> {
    let (principal_id, timestamp, signature, request_hash) = extract_signature(&request)?;
    let req_for_verify = *request.get_ref();
    let principal = server
        .verify_signature_and_get_principal(
            &principal_id,
            timestamp,
            &signature,
            "/zopp.ZoppService/ListUserOrganizations",
            &req_for_verify,
            &request_hash,
        )
        .await?;

    let user_id = principal
        .user_id
        .ok_or_else(|| Status::unauthenticated("Service accounts cannot list organizations"))?;

    let orgs = server
        .store
        .list_user_organizations(&user_id)
        .await
        .map_err(|e| Status::internal(format!("Failed to list organizations: {}", e)))?;

    let mut proto_orgs = Vec::with_capacity(orgs.len());
    for org in orgs {
        let member_count = server
            .store
            .count_organization_members(&org.id)
            .await
            .unwrap_or(0);
        proto_orgs.push(organization_to_proto(&org, member_count));
    }

    Ok(Response::new(OrganizationList {
        organizations: proto_orgs,
    }))
}

pub async fn update_organization(
    server: &ZoppServer,
    request: Request<UpdateOrganizationRequest>,
) -> Result<Response<Organization>, Status> {
    let (principal_id, timestamp, signature, request_hash) = extract_signature(&request)?;
    let req_for_verify = request.get_ref().clone();
    let principal = server
        .verify_signature_and_get_principal(
            &principal_id,
            timestamp,
            &signature,
            "/zopp.ZoppService/UpdateOrganization",
            &req_for_verify,
            &request_hash,
        )
        .await?;
    let req = request.into_inner();

    let user_id = principal
        .user_id
        .ok_or_else(|| Status::unauthenticated("Service accounts cannot update organizations"))?;

    let org_id = parse_organization_id(&req.organization_id)?;

    // Check if user is an admin or owner
    let membership = server
        .store
        .get_organization_member(&org_id, &user_id)
        .await
        .map_err(|e| match e {
            zopp_storage::StoreError::NotFound => {
                Status::permission_denied("Not a member of this organization")
            }
            e => Status::internal(format!("Failed to check membership: {}", e)),
        })?;

    if membership.role != zopp_storage::OrganizationRole::Owner
        && membership.role != zopp_storage::OrganizationRole::Admin
    {
        return Err(Status::permission_denied(
            "Only organization owners and admins can update organization settings",
        ));
    }

    // Validate slug format if provided
    if let Some(ref slug) = req.slug {
        if !slug
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        {
            return Err(Status::invalid_argument(
                "Slug must contain only lowercase letters, numbers, and hyphens",
            ));
        }
    }

    server
        .store
        .update_organization(&org_id, req.name, req.slug)
        .await
        .map_err(|e| match e {
            zopp_storage::StoreError::AlreadyExists => {
                Status::already_exists("Organization with this slug already exists")
            }
            zopp_storage::StoreError::NotFound => Status::not_found("Organization not found"),
            e => Status::internal(format!("Failed to update organization: {}", e)),
        })?;

    let org = server
        .store
        .get_organization(&org_id)
        .await
        .map_err(|e| Status::internal(format!("Failed to get organization: {}", e)))?;

    let member_count = server
        .store
        .count_organization_members(&org_id)
        .await
        .unwrap_or(0);

    Ok(Response::new(organization_to_proto(&org, member_count)))
}

pub async fn delete_organization(
    server: &ZoppServer,
    request: Request<DeleteOrganizationRequest>,
) -> Result<Response<Empty>, Status> {
    let (principal_id, timestamp, signature, request_hash) = extract_signature(&request)?;
    let req_for_verify = request.get_ref().clone();
    let principal = server
        .verify_signature_and_get_principal(
            &principal_id,
            timestamp,
            &signature,
            "/zopp.ZoppService/DeleteOrganization",
            &req_for_verify,
            &request_hash,
        )
        .await?;
    let req = request.into_inner();

    let user_id = principal
        .user_id
        .ok_or_else(|| Status::unauthenticated("Service accounts cannot delete organizations"))?;

    let org_id = parse_organization_id(&req.organization_id)?;

    // Only owner can delete organization
    let membership = server
        .store
        .get_organization_member(&org_id, &user_id)
        .await
        .map_err(|e| match e {
            zopp_storage::StoreError::NotFound => {
                Status::permission_denied("Not a member of this organization")
            }
            e => Status::internal(format!("Failed to check membership: {}", e)),
        })?;

    if membership.role != zopp_storage::OrganizationRole::Owner {
        return Err(Status::permission_denied(
            "Only organization owner can delete the organization",
        ));
    }

    server
        .store
        .delete_organization(&org_id)
        .await
        .map_err(|e| match e {
            zopp_storage::StoreError::NotFound => Status::not_found("Organization not found"),
            e => Status::internal(format!("Failed to delete organization: {}", e)),
        })?;

    Ok(Response::new(Empty {}))
}

// ───────────────────────────────────── Organization Members ─────────────────────────────────────

pub async fn add_organization_member(
    server: &ZoppServer,
    request: Request<AddOrganizationMemberRequest>,
) -> Result<Response<Empty>, Status> {
    let (principal_id, timestamp, signature, request_hash) = extract_signature(&request)?;
    let req_for_verify = request.get_ref().clone();
    let principal = server
        .verify_signature_and_get_principal(
            &principal_id,
            timestamp,
            &signature,
            "/zopp.ZoppService/AddOrganizationMember",
            &req_for_verify,
            &request_hash,
        )
        .await?;
    let req = request.into_inner();

    let caller_user_id = principal
        .user_id
        .ok_or_else(|| Status::unauthenticated("Service accounts cannot manage members"))?;

    let org_id = parse_organization_id(&req.organization_id)?;
    let user_id = parse_user_id(&req.user_id)?;
    let role = proto_role_to_storage(req.role())?;

    // Check if requester is admin or owner
    let membership = server
        .store
        .get_organization_member(&org_id, &caller_user_id)
        .await
        .map_err(|e| match e {
            zopp_storage::StoreError::NotFound => {
                Status::permission_denied("Not a member of this organization")
            }
            e => Status::internal(format!("Failed to check membership: {}", e)),
        })?;

    if membership.role != zopp_storage::OrganizationRole::Owner
        && membership.role != zopp_storage::OrganizationRole::Admin
    {
        return Err(Status::permission_denied(
            "Only organization owners and admins can add members",
        ));
    }

    // Can't add owner role directly (must be set via owner transfer)
    if role == zopp_storage::OrganizationRole::Owner {
        return Err(Status::invalid_argument(
            "Cannot directly add a member as owner",
        ));
    }

    server
        .store
        .add_organization_member(&org_id, &user_id, role, Some(caller_user_id))
        .await
        .map_err(|e| match e {
            zopp_storage::StoreError::AlreadyExists => {
                Status::already_exists("User is already a member of this organization")
            }
            e => Status::internal(format!("Failed to add member: {}", e)),
        })?;

    Ok(Response::new(Empty {}))
}

/// UpsertOrganizationMember: Add a new member or update an existing member's role in one call.
/// This replaces the separate AddOrganizationMember and UpdateOrganizationMemberRole calls.
pub async fn upsert_organization_member(
    server: &ZoppServer,
    request: Request<UpsertOrganizationMemberRequest>,
) -> Result<Response<OrganizationMember>, Status> {
    let (principal_id, timestamp, signature, request_hash) = extract_signature(&request)?;
    let req_for_verify = request.get_ref().clone();
    let principal = server
        .verify_signature_and_get_principal(
            &principal_id,
            timestamp,
            &signature,
            "/zopp.ZoppService/UpsertOrganizationMember",
            &req_for_verify,
            &request_hash,
        )
        .await?;
    let req = request.into_inner();

    let caller_user_id = principal
        .user_id
        .ok_or_else(|| Status::unauthenticated("Service accounts cannot manage members"))?;

    let org_id = parse_organization_id(&req.organization_id)?;
    let user_id = parse_user_id(&req.user_id)?;
    let role = proto_role_to_storage(req.role())?;

    // Check if requester is admin or owner
    let caller_membership = server
        .store
        .get_organization_member(&org_id, &caller_user_id)
        .await
        .map_err(|e| match e {
            zopp_storage::StoreError::NotFound => {
                Status::permission_denied("Not a member of this organization")
            }
            e => Status::internal(format!("Failed to check membership: {}", e)),
        })?;

    // Can't upsert with owner role (must be set via owner transfer)
    if role == zopp_storage::OrganizationRole::Owner {
        return Err(Status::invalid_argument(
            "Cannot set member role to owner directly",
        ));
    }

    // Check if the target user is already a member
    let existing_member = server
        .store
        .get_organization_member(&org_id, &user_id)
        .await;

    match existing_member {
        Ok(member) => {
            // User is already a member - this is an update operation
            // Only owner can change roles
            if caller_membership.role != zopp_storage::OrganizationRole::Owner {
                return Err(Status::permission_denied(
                    "Only organization owner can change member roles",
                ));
            }

            // Can't change own role
            if user_id == caller_user_id {
                return Err(Status::invalid_argument("Cannot change your own role"));
            }

            // Can't change owner's role
            if member.role == zopp_storage::OrganizationRole::Owner {
                return Err(Status::permission_denied("Cannot change owner's role"));
            }

            server
                .store
                .update_organization_member_role(&org_id, &user_id, role)
                .await
                .map_err(|e| Status::internal(format!("Failed to update member role: {}", e)))?;
        }
        Err(zopp_storage::StoreError::NotFound) => {
            // User is not a member - this is an add operation
            // Admin or owner can add members
            if caller_membership.role != zopp_storage::OrganizationRole::Owner
                && caller_membership.role != zopp_storage::OrganizationRole::Admin
            {
                return Err(Status::permission_denied(
                    "Only organization owners and admins can add members",
                ));
            }

            server
                .store
                .add_organization_member(&org_id, &user_id, role, Some(caller_user_id))
                .await
                .map_err(|e| Status::internal(format!("Failed to add member: {}", e)))?;
        }
        Err(e) => {
            return Err(Status::internal(format!(
                "Failed to check existing membership: {}",
                e
            )));
        }
    }

    // Fetch and return the updated/created member
    let member = server
        .store
        .get_organization_member(&org_id, &user_id)
        .await
        .map_err(|e| Status::internal(format!("Failed to get member: {}", e)))?;

    let user = server
        .store
        .get_user_by_id(&member.user_id)
        .await
        .map_err(|e| Status::internal(format!("Failed to get user: {}", e)))?;

    Ok(Response::new(OrganizationMember {
        user_id: member.user_id.0.to_string(),
        email: user.email,
        role: storage_role_to_proto(member.role) as i32,
        invited_by: member.invited_by.map(|id| id.0.to_string()),
        joined_at: member.joined_at.to_rfc3339(),
    }))
}

pub async fn get_organization_member(
    server: &ZoppServer,
    request: Request<GetOrganizationMemberRequest>,
) -> Result<Response<OrganizationMember>, Status> {
    let (principal_id, timestamp, signature, request_hash) = extract_signature(&request)?;
    let req_for_verify = request.get_ref().clone();
    let principal = server
        .verify_signature_and_get_principal(
            &principal_id,
            timestamp,
            &signature,
            "/zopp.ZoppService/GetOrganizationMember",
            &req_for_verify,
            &request_hash,
        )
        .await?;
    let req = request.into_inner();

    let caller_user_id = principal
        .user_id
        .ok_or_else(|| Status::unauthenticated("Service accounts cannot access members"))?;

    let org_id = parse_organization_id(&req.organization_id)?;
    let user_id = parse_user_id(&req.user_id)?;

    // Check if requester is a member
    server
        .store
        .get_organization_member(&org_id, &caller_user_id)
        .await
        .map_err(|e| match e {
            zopp_storage::StoreError::NotFound => {
                Status::permission_denied("Not a member of this organization")
            }
            e => Status::internal(format!("Failed to check membership: {}", e)),
        })?;

    let member = server
        .store
        .get_organization_member(&org_id, &user_id)
        .await
        .map_err(|e| match e {
            zopp_storage::StoreError::NotFound => Status::not_found("Member not found"),
            e => Status::internal(format!("Failed to get member: {}", e)),
        })?;

    let user = server
        .store
        .get_user_by_id(&user_id)
        .await
        .map_err(|e| Status::internal(format!("Failed to get user: {}", e)))?;

    Ok(Response::new(member_to_proto(&member, &user.email)))
}

pub async fn list_organization_members(
    server: &ZoppServer,
    request: Request<ListOrganizationMembersRequest>,
) -> Result<Response<OrganizationMemberList>, Status> {
    let (principal_id, timestamp, signature, request_hash) = extract_signature(&request)?;
    let req_for_verify = request.get_ref().clone();
    let principal = server
        .verify_signature_and_get_principal(
            &principal_id,
            timestamp,
            &signature,
            "/zopp.ZoppService/ListOrganizationMembers",
            &req_for_verify,
            &request_hash,
        )
        .await?;
    let req = request.into_inner();

    let caller_user_id = principal
        .user_id
        .ok_or_else(|| Status::unauthenticated("Service accounts cannot list members"))?;

    let org_id = parse_organization_id(&req.organization_id)?;

    // Check if requester is a member
    server
        .store
        .get_organization_member(&org_id, &caller_user_id)
        .await
        .map_err(|e| match e {
            zopp_storage::StoreError::NotFound => {
                Status::permission_denied("Not a member of this organization")
            }
            e => Status::internal(format!("Failed to check membership: {}", e)),
        })?;

    let members = server
        .store
        .list_organization_members(&org_id)
        .await
        .map_err(|e| Status::internal(format!("Failed to list members: {}", e)))?;

    let mut proto_members = Vec::with_capacity(members.len());
    for member in members {
        let user = server.store.get_user_by_id(&member.user_id).await.ok();
        let email = user.map(|u| u.email).unwrap_or_default();
        proto_members.push(member_to_proto(&member, &email));
    }

    Ok(Response::new(OrganizationMemberList {
        members: proto_members,
    }))
}

pub async fn update_organization_member_role(
    server: &ZoppServer,
    request: Request<UpdateOrganizationMemberRoleRequest>,
) -> Result<Response<Empty>, Status> {
    let (principal_id, timestamp, signature, request_hash) = extract_signature(&request)?;
    let req_for_verify = request.get_ref().clone();
    let principal = server
        .verify_signature_and_get_principal(
            &principal_id,
            timestamp,
            &signature,
            "/zopp.ZoppService/UpdateOrganizationMemberRole",
            &req_for_verify,
            &request_hash,
        )
        .await?;
    let req = request.into_inner();

    let caller_user_id = principal
        .user_id
        .ok_or_else(|| Status::unauthenticated("Service accounts cannot update member roles"))?;

    let org_id = parse_organization_id(&req.organization_id)?;
    let user_id = parse_user_id(&req.user_id)?;
    let new_role = proto_role_to_storage(req.role())?;

    // Check if requester is owner
    let membership = server
        .store
        .get_organization_member(&org_id, &caller_user_id)
        .await
        .map_err(|e| match e {
            zopp_storage::StoreError::NotFound => {
                Status::permission_denied("Not a member of this organization")
            }
            e => Status::internal(format!("Failed to check membership: {}", e)),
        })?;

    // Only owner can change roles
    if membership.role != zopp_storage::OrganizationRole::Owner {
        return Err(Status::permission_denied(
            "Only organization owner can change member roles",
        ));
    }

    // Can't change owner's own role
    if user_id == caller_user_id {
        return Err(Status::invalid_argument("Cannot change your own role"));
    }

    // Can't promote to owner (must use owner transfer)
    if new_role == zopp_storage::OrganizationRole::Owner {
        return Err(Status::invalid_argument(
            "Cannot promote member to owner directly",
        ));
    }

    server
        .store
        .update_organization_member_role(&org_id, &user_id, new_role)
        .await
        .map_err(|e| match e {
            zopp_storage::StoreError::NotFound => Status::not_found("Member not found"),
            e => Status::internal(format!("Failed to update member role: {}", e)),
        })?;

    Ok(Response::new(Empty {}))
}

pub async fn remove_organization_member(
    server: &ZoppServer,
    request: Request<RemoveOrganizationMemberRequest>,
) -> Result<Response<Empty>, Status> {
    let (principal_id, timestamp, signature, request_hash) = extract_signature(&request)?;
    let req_for_verify = request.get_ref().clone();
    let principal = server
        .verify_signature_and_get_principal(
            &principal_id,
            timestamp,
            &signature,
            "/zopp.ZoppService/RemoveOrganizationMember",
            &req_for_verify,
            &request_hash,
        )
        .await?;
    let req = request.into_inner();

    let caller_user_id = principal
        .user_id
        .ok_or_else(|| Status::unauthenticated("Service accounts cannot remove members"))?;

    let org_id = parse_organization_id(&req.organization_id)?;
    let user_id = parse_user_id(&req.user_id)?;

    // Get requester's membership
    let membership = server
        .store
        .get_organization_member(&org_id, &caller_user_id)
        .await
        .map_err(|e| match e {
            zopp_storage::StoreError::NotFound => {
                Status::permission_denied("Not a member of this organization")
            }
            e => Status::internal(format!("Failed to check membership: {}", e)),
        })?;

    // Users can remove themselves, but owner/admin can remove others
    if user_id != caller_user_id
        && membership.role != zopp_storage::OrganizationRole::Owner
        && membership.role != zopp_storage::OrganizationRole::Admin
    {
        return Err(Status::permission_denied(
            "Only organization owners and admins can remove other members",
        ));
    }

    // Get target member's membership
    let target_membership = server
        .store
        .get_organization_member(&org_id, &user_id)
        .await
        .map_err(|e| match e {
            zopp_storage::StoreError::NotFound => Status::not_found("Member not found"),
            e => Status::internal(format!("Failed to get member: {}", e)),
        })?;

    // Can't remove the owner
    if target_membership.role == zopp_storage::OrganizationRole::Owner {
        return Err(Status::invalid_argument(
            "Cannot remove the organization owner",
        ));
    }

    server
        .store
        .remove_organization_member(&org_id, &user_id)
        .await
        .map_err(|e| Status::internal(format!("Failed to remove member: {}", e)))?;

    Ok(Response::new(Empty {}))
}

// ───────────────────────────────────── Organization Invites ─────────────────────────────────────

pub async fn create_organization_invite(
    server: &ZoppServer,
    request: Request<CreateOrganizationInviteRequest>,
) -> Result<Response<OrganizationInvite>, Status> {
    let (principal_id, timestamp, signature, request_hash) = extract_signature(&request)?;
    let req_for_verify = request.get_ref().clone();
    let principal = server
        .verify_signature_and_get_principal(
            &principal_id,
            timestamp,
            &signature,
            "/zopp.ZoppService/CreateOrganizationInvite",
            &req_for_verify,
            &request_hash,
        )
        .await?;
    let req = request.into_inner();

    let caller_user_id = principal
        .user_id
        .ok_or_else(|| Status::unauthenticated("Service accounts cannot create invites"))?;

    let org_id = parse_organization_id(&req.organization_id)?;
    let role = proto_role_to_storage(req.role())?;

    // Check if requester is admin or owner
    let membership = server
        .store
        .get_organization_member(&org_id, &caller_user_id)
        .await
        .map_err(|e| match e {
            zopp_storage::StoreError::NotFound => {
                Status::permission_denied("Not a member of this organization")
            }
            e => Status::internal(format!("Failed to check membership: {}", e)),
        })?;

    if membership.role != zopp_storage::OrganizationRole::Owner
        && membership.role != zopp_storage::OrganizationRole::Admin
    {
        return Err(Status::permission_denied(
            "Only organization owners and admins can create invites",
        ));
    }

    // Can't invite as owner
    if role == zopp_storage::OrganizationRole::Owner {
        return Err(Status::invalid_argument("Cannot invite as owner role"));
    }

    // Validate email
    if req.email.is_empty() || !req.email.contains('@') {
        return Err(Status::invalid_argument("Invalid email address"));
    }

    // Generate secure random token
    let token: String = rand::rng()
        .sample_iter(&rand::distr::Alphanumeric)
        .take(32)
        .map(char::from)
        .collect();

    let token_hash = format!("{:x}", Sha256::digest(token.as_bytes()));

    // Calculate expiration (default 72 hours)
    let expires_in_hours = req.expires_in_hours.unwrap_or(72);
    let expires_at = Utc::now() + Duration::hours(expires_in_hours);

    let params = zopp_storage::CreateOrganizationInviteParams {
        organization_id: org_id,
        email: req.email.clone(),
        role,
        token_hash: token_hash.clone(),
        invited_by: caller_user_id,
        expires_at,
    };

    let invite = server
        .store
        .create_organization_invite(&params)
        .await
        .map_err(|e| match e {
            zopp_storage::StoreError::AlreadyExists => {
                Status::already_exists("An invite for this email already exists")
            }
            e => Status::internal(format!("Failed to create invite: {}", e)),
        })?;

    // Return invite with the plaintext token (only returned once)
    Ok(Response::new(invite_to_proto(&invite, Some(&token))))
}

pub async fn get_organization_invite(
    server: &ZoppServer,
    request: Request<GetOrganizationInviteRequest>,
) -> Result<Response<OrganizationInvite>, Status> {
    // This endpoint doesn't require auth - it's used to look up invites by token
    let req = request.into_inner();

    if req.token.is_empty() {
        return Err(Status::invalid_argument("Token is required"));
    }

    let token_hash = format!("{:x}", Sha256::digest(req.token.as_bytes()));

    let invite = server
        .store
        .get_organization_invite_by_token(&token_hash)
        .await
        .map_err(|e| match e {
            zopp_storage::StoreError::NotFound => Status::not_found("Invite not found"),
            e => Status::internal(format!("Failed to get invite: {}", e)),
        })?;

    // Check if expired
    if invite.expires_at < Utc::now() {
        return Err(Status::not_found("Invite has expired"));
    }

    Ok(Response::new(invite_to_proto(&invite, None)))
}

pub async fn list_organization_invites(
    server: &ZoppServer,
    request: Request<ListOrganizationInvitesRequest>,
) -> Result<Response<OrganizationInviteList>, Status> {
    let (principal_id, timestamp, signature, request_hash) = extract_signature(&request)?;
    let req_for_verify = request.get_ref().clone();
    let principal = server
        .verify_signature_and_get_principal(
            &principal_id,
            timestamp,
            &signature,
            "/zopp.ZoppService/ListOrganizationInvites",
            &req_for_verify,
            &request_hash,
        )
        .await?;
    let req = request.into_inner();

    let caller_user_id = principal
        .user_id
        .ok_or_else(|| Status::unauthenticated("Service accounts cannot list invites"))?;

    let org_id = parse_organization_id(&req.organization_id)?;

    // Check if requester is admin or owner
    let membership = server
        .store
        .get_organization_member(&org_id, &caller_user_id)
        .await
        .map_err(|e| match e {
            zopp_storage::StoreError::NotFound => {
                Status::permission_denied("Not a member of this organization")
            }
            e => Status::internal(format!("Failed to check membership: {}", e)),
        })?;

    if membership.role != zopp_storage::OrganizationRole::Owner
        && membership.role != zopp_storage::OrganizationRole::Admin
    {
        return Err(Status::permission_denied(
            "Only organization owners and admins can view invites",
        ));
    }

    let invites = server
        .store
        .list_organization_invites(&org_id)
        .await
        .map_err(|e| Status::internal(format!("Failed to list invites: {}", e)))?;

    let proto_invites: Vec<_> = invites
        .iter()
        .filter(|i| i.expires_at > Utc::now()) // Filter out expired
        .map(|i| invite_to_proto(i, None))
        .collect();

    Ok(Response::new(OrganizationInviteList {
        invites: proto_invites,
    }))
}

pub async fn accept_organization_invite(
    server: &ZoppServer,
    request: Request<AcceptOrganizationInviteRequest>,
) -> Result<Response<OrganizationMember>, Status> {
    let (principal_id, timestamp, signature, request_hash) = extract_signature(&request)?;
    let req_for_verify = request.get_ref().clone();
    let principal = server
        .verify_signature_and_get_principal(
            &principal_id,
            timestamp,
            &signature,
            "/zopp.ZoppService/AcceptOrganizationInvite",
            &req_for_verify,
            &request_hash,
        )
        .await?;
    let req = request.into_inner();

    let caller_user_id = principal
        .user_id
        .ok_or_else(|| Status::unauthenticated("Service accounts cannot accept invites"))?;

    if req.token.is_empty() {
        return Err(Status::invalid_argument("Token is required"));
    }

    let token_hash = format!("{:x}", Sha256::digest(req.token.as_bytes()));

    let invite = server
        .store
        .get_organization_invite_by_token(&token_hash)
        .await
        .map_err(|e| match e {
            zopp_storage::StoreError::NotFound => Status::not_found("Invite not found"),
            e => Status::internal(format!("Failed to get invite: {}", e)),
        })?;

    // Check if expired
    if invite.expires_at < Utc::now() {
        return Err(Status::not_found("Invite has expired"));
    }

    // Verify email matches (optional - could allow any authenticated user)
    let user = server
        .store
        .get_user_by_id(&caller_user_id)
        .await
        .map_err(|e| Status::internal(format!("Failed to get user: {}", e)))?;

    if user.email.to_lowercase() != invite.email.to_lowercase() {
        return Err(Status::permission_denied(
            "Invite was sent to a different email address",
        ));
    }

    // Add user as member
    server
        .store
        .add_organization_member(
            &invite.organization_id,
            &caller_user_id,
            invite.role,
            Some(invite.invited_by),
        )
        .await
        .map_err(|e| match e {
            zopp_storage::StoreError::AlreadyExists => {
                Status::already_exists("You are already a member of this organization")
            }
            e => Status::internal(format!("Failed to add member: {}", e)),
        })?;

    // Delete the invite (it's been used)
    let _ = server.store.delete_organization_invite(&invite.id).await;

    // Return the new membership
    let member = server
        .store
        .get_organization_member(&invite.organization_id, &caller_user_id)
        .await
        .map_err(|e| Status::internal(format!("Failed to get membership: {}", e)))?;

    Ok(Response::new(member_to_proto(&member, &user.email)))
}

pub async fn delete_organization_invite(
    server: &ZoppServer,
    request: Request<DeleteOrganizationInviteRequest>,
) -> Result<Response<Empty>, Status> {
    let (principal_id, timestamp, signature, request_hash) = extract_signature(&request)?;
    let req_for_verify = request.get_ref().clone();
    let principal = server
        .verify_signature_and_get_principal(
            &principal_id,
            timestamp,
            &signature,
            "/zopp.ZoppService/DeleteOrganizationInvite",
            &req_for_verify,
            &request_hash,
        )
        .await?;
    let req = request.into_inner();

    let caller_user_id = principal
        .user_id
        .ok_or_else(|| Status::unauthenticated("Service accounts cannot delete invites"))?;

    let invite_id = parse_invite_id(&req.invite_id)?;

    // Get the invite to check organization
    let invite = server
        .store
        .get_organization_invite(&invite_id)
        .await
        .map_err(|e| match e {
            zopp_storage::StoreError::NotFound => Status::not_found("Invite not found"),
            e => Status::internal(format!("Failed to get invite: {}", e)),
        })?;

    // Check if requester is admin or owner of the organization
    let membership = server
        .store
        .get_organization_member(&invite.organization_id, &caller_user_id)
        .await
        .map_err(|e| match e {
            zopp_storage::StoreError::NotFound => {
                Status::permission_denied("Not a member of this organization")
            }
            e => Status::internal(format!("Failed to check membership: {}", e)),
        })?;

    if membership.role != zopp_storage::OrganizationRole::Owner
        && membership.role != zopp_storage::OrganizationRole::Admin
    {
        return Err(Status::permission_denied(
            "Only organization owners and admins can delete invites",
        ));
    }

    server
        .store
        .delete_organization_invite(&invite_id)
        .await
        .map_err(|e| match e {
            zopp_storage::StoreError::NotFound => Status::not_found("Invite not found"),
            e => Status::internal(format!("Failed to delete invite: {}", e)),
        })?;

    Ok(Response::new(Empty {}))
}

// ───────────────────────────────────── Organization Workspaces ─────────────────────────────────────

pub async fn link_workspace_to_organization(
    server: &ZoppServer,
    request: Request<LinkWorkspaceToOrganizationRequest>,
) -> Result<Response<Empty>, Status> {
    let (principal_id, timestamp, signature, request_hash) = extract_signature(&request)?;
    let req_for_verify = request.get_ref().clone();
    let principal = server
        .verify_signature_and_get_principal(
            &principal_id,
            timestamp,
            &signature,
            "/zopp.ZoppService/LinkWorkspaceToOrganization",
            &req_for_verify,
            &request_hash,
        )
        .await?;
    let req = request.into_inner();

    let caller_user_id = principal
        .user_id
        .ok_or_else(|| Status::unauthenticated("Service accounts cannot link workspaces"))?;

    let org_id = parse_organization_id(&req.organization_id)?;
    let workspace_id = parse_workspace_id(&req.workspace_id)?;

    // Check if requester is org admin or owner
    let org_membership = server
        .store
        .get_organization_member(&org_id, &caller_user_id)
        .await
        .map_err(|e| match e {
            zopp_storage::StoreError::NotFound => {
                Status::permission_denied("Not a member of this organization")
            }
            e => Status::internal(format!("Failed to check membership: {}", e)),
        })?;

    if org_membership.role != zopp_storage::OrganizationRole::Owner
        && org_membership.role != zopp_storage::OrganizationRole::Admin
    {
        return Err(Status::permission_denied(
            "Only organization owners and admins can link workspaces",
        ));
    }

    // Check if requester owns the workspace
    let workspace = server
        .store
        .get_workspace(&workspace_id)
        .await
        .map_err(|e| match e {
            zopp_storage::StoreError::NotFound => Status::not_found("Workspace not found"),
            e => Status::internal(format!("Failed to get workspace: {}", e)),
        })?;

    if workspace.owner_user_id != caller_user_id {
        return Err(Status::permission_denied(
            "Only workspace owner can link it to an organization",
        ));
    }

    server
        .store
        .set_workspace_organization(&workspace_id, Some(org_id))
        .await
        .map_err(|e| Status::internal(format!("Failed to link workspace: {}", e)))?;

    Ok(Response::new(Empty {}))
}

pub async fn unlink_workspace_from_organization(
    server: &ZoppServer,
    request: Request<UnlinkWorkspaceFromOrganizationRequest>,
) -> Result<Response<Empty>, Status> {
    let (principal_id, timestamp, signature, request_hash) = extract_signature(&request)?;
    let req_for_verify = request.get_ref().clone();
    let principal = server
        .verify_signature_and_get_principal(
            &principal_id,
            timestamp,
            &signature,
            "/zopp.ZoppService/UnlinkWorkspaceFromOrganization",
            &req_for_verify,
            &request_hash,
        )
        .await?;
    let req = request.into_inner();

    let caller_user_id = principal
        .user_id
        .ok_or_else(|| Status::unauthenticated("Service accounts cannot unlink workspaces"))?;

    let workspace_id = parse_workspace_id(&req.workspace_id)?;

    // Check if requester owns the workspace
    let workspace = server
        .store
        .get_workspace(&workspace_id)
        .await
        .map_err(|e| match e {
            zopp_storage::StoreError::NotFound => Status::not_found("Workspace not found"),
            e => Status::internal(format!("Failed to get workspace: {}", e)),
        })?;

    if workspace.owner_user_id != caller_user_id {
        return Err(Status::permission_denied(
            "Only workspace owner can unlink it from an organization",
        ));
    }

    server
        .store
        .set_workspace_organization(&workspace_id, None)
        .await
        .map_err(|e| Status::internal(format!("Failed to unlink workspace: {}", e)))?;

    Ok(Response::new(Empty {}))
}

pub async fn list_organization_workspaces(
    server: &ZoppServer,
    request: Request<ListOrganizationWorkspacesRequest>,
) -> Result<Response<WorkspaceList>, Status> {
    let (principal_id, timestamp, signature, request_hash) = extract_signature(&request)?;
    let req_for_verify = request.get_ref().clone();
    let principal = server
        .verify_signature_and_get_principal(
            &principal_id,
            timestamp,
            &signature,
            "/zopp.ZoppService/ListOrganizationWorkspaces",
            &req_for_verify,
            &request_hash,
        )
        .await?;
    let req = request.into_inner();

    let caller_user_id = principal
        .user_id
        .ok_or_else(|| Status::unauthenticated("Service accounts cannot list workspaces"))?;

    let org_id = parse_organization_id(&req.organization_id)?;

    // Check if requester is a member
    server
        .store
        .get_organization_member(&org_id, &caller_user_id)
        .await
        .map_err(|e| match e {
            zopp_storage::StoreError::NotFound => {
                Status::permission_denied("Not a member of this organization")
            }
            e => Status::internal(format!("Failed to check membership: {}", e)),
        })?;

    let workspaces = server
        .store
        .list_organization_workspaces(&org_id)
        .await
        .map_err(|e| Status::internal(format!("Failed to list workspaces: {}", e)))?;

    let proto_workspaces: Vec<_> = workspaces.iter().map(workspace_to_proto).collect();

    Ok(Response::new(WorkspaceList {
        workspaces: proto_workspaces,
    }))
}

// ───────────────────────────────────── Helper Functions ─────────────────────────────────────

fn parse_organization_id(id: &str) -> Result<OrganizationId, Status> {
    Uuid::parse_str(id)
        .map(OrganizationId)
        .map_err(|_| Status::invalid_argument("Invalid organization ID"))
}

fn parse_user_id(id: &str) -> Result<UserId, Status> {
    Uuid::parse_str(id)
        .map(UserId)
        .map_err(|_| Status::invalid_argument("Invalid user ID"))
}

fn parse_workspace_id(id: &str) -> Result<WorkspaceId, Status> {
    Uuid::parse_str(id)
        .map(WorkspaceId)
        .map_err(|_| Status::invalid_argument("Invalid workspace ID"))
}

fn parse_invite_id(id: &str) -> Result<OrganizationInviteId, Status> {
    Uuid::parse_str(id)
        .map(OrganizationInviteId)
        .map_err(|_| Status::invalid_argument("Invalid invite ID"))
}

fn proto_role_to_storage(role: OrganizationRole) -> Result<zopp_storage::OrganizationRole, Status> {
    match role {
        OrganizationRole::Unspecified => Err(Status::invalid_argument(
            "Organization role must be specified",
        )),
        OrganizationRole::OrganizationOwner => Ok(zopp_storage::OrganizationRole::Owner),
        OrganizationRole::OrganizationAdmin => Ok(zopp_storage::OrganizationRole::Admin),
        OrganizationRole::OrganizationMember => Ok(zopp_storage::OrganizationRole::Member),
    }
}

fn storage_role_to_proto(role: zopp_storage::OrganizationRole) -> OrganizationRole {
    match role {
        zopp_storage::OrganizationRole::Owner => OrganizationRole::OrganizationOwner,
        zopp_storage::OrganizationRole::Admin => OrganizationRole::OrganizationAdmin,
        zopp_storage::OrganizationRole::Member => OrganizationRole::OrganizationMember,
    }
}

fn storage_plan_to_proto(plan: zopp_storage::Plan) -> Plan {
    match plan {
        zopp_storage::Plan::Free => Plan::Free,
        zopp_storage::Plan::Pro => Plan::Pro,
        zopp_storage::Plan::Enterprise => Plan::Enterprise,
    }
}

fn organization_to_proto(org: &zopp_storage::Organization, member_count: i32) -> Organization {
    Organization {
        id: org.id.0.to_string(),
        name: org.name.clone(),
        slug: org.slug.clone(),
        plan: storage_plan_to_proto(org.plan).into(),
        seat_limit: org.seat_limit,
        member_count,
        stripe_customer_id: org.stripe_customer_id.clone(),
        trial_ends_at: org.trial_ends_at.map(|t| t.to_rfc3339()),
        created_at: org.created_at.to_rfc3339(),
        updated_at: org.updated_at.to_rfc3339(),
    }
}

fn member_to_proto(member: &zopp_storage::OrganizationMember, email: &str) -> OrganizationMember {
    OrganizationMember {
        user_id: member.user_id.0.to_string(),
        email: email.to_string(),
        role: storage_role_to_proto(member.role).into(),
        invited_by: member.invited_by.as_ref().map(|u| u.0.to_string()),
        joined_at: member.joined_at.to_rfc3339(),
    }
}

fn invite_to_proto(
    invite: &zopp_storage::OrganizationInvite,
    token: Option<&str>,
) -> OrganizationInvite {
    OrganizationInvite {
        id: invite.id.0.to_string(),
        organization_id: invite.organization_id.0.to_string(),
        email: invite.email.clone(),
        role: storage_role_to_proto(invite.role).into(),
        invited_by: invite.invited_by.0.to_string(),
        expires_at: invite.expires_at.to_rfc3339(),
        created_at: invite.created_at.to_rfc3339(),
        token: token.map(|t| t.to_string()),
    }
}

fn workspace_to_proto(workspace: &zopp_storage::Workspace) -> Workspace {
    Workspace {
        id: workspace.id.0.to_string(),
        name: workspace.name.clone(),
        project_count: 0, // We could count projects but that's expensive
    }
}
