//! Organization commands: list, create, members, invites
//!
//! These commands manage organizations in the cloud offering.

use crate::grpc::{add_auth_metadata, setup_client};
use zopp_proto::{
    get_organization_request, AddOrganizationMemberRequest, CreateOrganizationInviteRequest,
    CreateOrganizationRequest, DeleteOrganizationInviteRequest, Empty, GetOrganizationRequest,
    LinkWorkspaceToOrganizationRequest, ListOrganizationInvitesRequest,
    ListOrganizationMembersRequest, ListOrganizationWorkspacesRequest, OrganizationRole,
    RemoveOrganizationMemberRequest, UnlinkWorkspaceFromOrganizationRequest,
    UpdateOrganizationMemberRoleRequest, UpdateOrganizationRequest,
};

/// Parse organization role from string
fn parse_role(role: &str) -> Result<OrganizationRole, Box<dyn std::error::Error>> {
    match role.to_lowercase().as_str() {
        "owner" => Ok(OrganizationRole::OrganizationOwner),
        "admin" => Ok(OrganizationRole::OrganizationAdmin),
        "member" => Ok(OrganizationRole::OrganizationMember),
        _ => Err(format!("Invalid role: {}. Must be owner, admin, or member", role).into()),
    }
}

/// Format organization role for display
fn format_role(role: i32) -> &'static str {
    match OrganizationRole::try_from(role) {
        Ok(OrganizationRole::OrganizationOwner) => "owner",
        Ok(OrganizationRole::OrganizationAdmin) => "admin",
        Ok(OrganizationRole::OrganizationMember) => "member",
        _ => "unknown",
    }
}

/// Format plan for display
fn format_plan(plan: i32) -> &'static str {
    match zopp_proto::Plan::try_from(plan) {
        Ok(zopp_proto::Plan::Free) => "free",
        Ok(zopp_proto::Plan::Pro) => "pro",
        Ok(zopp_proto::Plan::Enterprise) => "enterprise",
        _ => "unknown",
    }
}

pub async fn cmd_org_list(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, principal, secrets) = setup_client(server, tls_ca_cert).await?;

    let mut request = tonic::Request::new(Empty {});
    add_auth_metadata(
        &mut request,
        &principal,
        &secrets,
        "/zopp.ZoppService/ListUserOrganizations",
    )?;

    let response = client.list_user_organizations(request).await?.into_inner();

    if response.organizations.is_empty() {
        println!("No organizations found.");
    } else {
        println!("Organizations:");
        for org in response.organizations {
            println!(
                "  {} ({}) - {} plan, {} seats",
                org.name,
                org.slug,
                format_plan(org.plan),
                org.seat_limit
            );
        }
    }

    Ok(())
}

pub async fn cmd_org_create(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    name: &str,
    slug: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, principal, secrets) = setup_client(server, tls_ca_cert).await?;

    // Generate slug from name if not provided
    let slug = slug
        .map(|s| s.to_string())
        .unwrap_or_else(|| name.to_lowercase().replace(' ', "-"));

    let mut request = tonic::Request::new(CreateOrganizationRequest {
        name: name.to_string(),
        slug,
    });
    add_auth_metadata(
        &mut request,
        &principal,
        &secrets,
        "/zopp.ZoppService/CreateOrganization",
    )?;

    let response = client.create_organization(request).await?.into_inner();

    println!("Organization created!");
    println!("  Name: {}", response.name);
    println!("  Slug: {}", response.slug);
    println!("  ID:   {}", response.id);

    Ok(())
}

pub async fn cmd_org_get(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    org: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, principal, secrets) = setup_client(server, tls_ca_cert).await?;

    // Determine if input is UUID or slug
    let identifier = if uuid::Uuid::parse_str(org).is_ok() {
        get_organization_request::Identifier::Id(org.to_string())
    } else {
        get_organization_request::Identifier::Slug(org.to_string())
    };

    let mut request = tonic::Request::new(GetOrganizationRequest {
        identifier: Some(identifier),
    });
    add_auth_metadata(
        &mut request,
        &principal,
        &secrets,
        "/zopp.ZoppService/GetOrganization",
    )?;

    let response = client.get_organization(request).await?.into_inner();

    println!("Organization: {}", response.name);
    println!("  ID:       {}", response.id);
    println!("  Slug:     {}", response.slug);
    println!("  Plan:     {}", format_plan(response.plan));
    println!("  Seats:    {}", response.seat_limit);
    println!("  Created:  {}", response.created_at);

    Ok(())
}

pub async fn cmd_org_update(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    org: &str,
    name: Option<&str>,
    slug: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, principal, secrets) = setup_client(server, tls_ca_cert).await?;

    let mut request = tonic::Request::new(UpdateOrganizationRequest {
        organization_id: org.to_string(),
        name: name.map(|s| s.to_string()),
        slug: slug.map(|s| s.to_string()),
    });
    add_auth_metadata(
        &mut request,
        &principal,
        &secrets,
        "/zopp.ZoppService/UpdateOrganization",
    )?;

    let response = client.update_organization(request).await?.into_inner();

    println!("Organization updated!");
    println!("  Name: {}", response.name);
    println!("  Slug: {}", response.slug);

    Ok(())
}

pub async fn cmd_org_members(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    org: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, principal, secrets) = setup_client(server, tls_ca_cert).await?;

    let mut request = tonic::Request::new(ListOrganizationMembersRequest {
        organization_id: org.to_string(),
    });
    add_auth_metadata(
        &mut request,
        &principal,
        &secrets,
        "/zopp.ZoppService/ListOrganizationMembers",
    )?;

    let response = client
        .list_organization_members(request)
        .await?
        .into_inner();

    if response.members.is_empty() {
        println!("No members found.");
    } else {
        println!("Members:");
        for member in response.members {
            println!(
                "  {} ({}) - {}",
                member.email,
                member.user_id,
                format_role(member.role)
            );
        }
    }

    Ok(())
}

pub async fn cmd_org_add_member(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    org: &str,
    user_id: &str,
    role: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, principal, secrets) = setup_client(server, tls_ca_cert).await?;

    let role_enum = parse_role(role)?;

    let mut request = tonic::Request::new(AddOrganizationMemberRequest {
        organization_id: org.to_string(),
        user_id: user_id.to_string(),
        role: role_enum.into(),
    });
    add_auth_metadata(
        &mut request,
        &principal,
        &secrets,
        "/zopp.ZoppService/AddOrganizationMember",
    )?;

    client.add_organization_member(request).await?;

    println!("Member added: {} as {}", user_id, role);

    Ok(())
}

pub async fn cmd_org_remove_member(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    org: &str,
    user_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, principal, secrets) = setup_client(server, tls_ca_cert).await?;

    let mut request = tonic::Request::new(RemoveOrganizationMemberRequest {
        organization_id: org.to_string(),
        user_id: user_id.to_string(),
    });
    add_auth_metadata(
        &mut request,
        &principal,
        &secrets,
        "/zopp.ZoppService/RemoveOrganizationMember",
    )?;

    client.remove_organization_member(request).await?;

    println!("Member removed: {}", user_id);

    Ok(())
}

pub async fn cmd_org_set_role(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    org: &str,
    user_id: &str,
    role: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, principal, secrets) = setup_client(server, tls_ca_cert).await?;

    let role_enum = parse_role(role)?;

    let mut request = tonic::Request::new(UpdateOrganizationMemberRoleRequest {
        organization_id: org.to_string(),
        user_id: user_id.to_string(),
        role: role_enum.into(),
    });
    add_auth_metadata(
        &mut request,
        &principal,
        &secrets,
        "/zopp.ZoppService/UpdateOrganizationMemberRole",
    )?;

    client.update_organization_member_role(request).await?;

    println!("Role updated: {} is now {}", user_id, role);

    Ok(())
}

pub async fn cmd_org_invite(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    org: &str,
    email: &str,
    role: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, principal, secrets) = setup_client(server, tls_ca_cert).await?;

    let role_enum = parse_role(role)?;

    let mut request = tonic::Request::new(CreateOrganizationInviteRequest {
        organization_id: org.to_string(),
        email: email.to_string(),
        role: role_enum.into(),
        expires_in_hours: Some(72), // Default 72 hours
    });
    add_auth_metadata(
        &mut request,
        &principal,
        &secrets,
        "/zopp.ZoppService/CreateOrganizationInvite",
    )?;

    let response = client
        .create_organization_invite(request)
        .await?
        .into_inner();

    println!("Invite created!");
    println!("  ID:      {}", response.id);
    println!("  Email:   {}", response.email);
    println!("  Role:    {}", format_role(response.role));
    println!("  Expires: {}", response.expires_at);

    Ok(())
}

pub async fn cmd_org_invites(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    org: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, principal, secrets) = setup_client(server, tls_ca_cert).await?;

    let mut request = tonic::Request::new(ListOrganizationInvitesRequest {
        organization_id: org.to_string(),
    });
    add_auth_metadata(
        &mut request,
        &principal,
        &secrets,
        "/zopp.ZoppService/ListOrganizationInvites",
    )?;

    let response = client
        .list_organization_invites(request)
        .await?
        .into_inner();

    if response.invites.is_empty() {
        println!("No pending invites.");
    } else {
        println!("Pending invites:");
        for invite in response.invites {
            println!(
                "  {} - {} as {} (expires: {})",
                invite.id,
                invite.email,
                format_role(invite.role),
                invite.expires_at
            );
        }
    }

    Ok(())
}

pub async fn cmd_org_revoke_invite(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    _org: &str,
    invite_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, principal, secrets) = setup_client(server, tls_ca_cert).await?;

    let mut request = tonic::Request::new(DeleteOrganizationInviteRequest {
        invite_id: invite_id.to_string(),
    });
    add_auth_metadata(
        &mut request,
        &principal,
        &secrets,
        "/zopp.ZoppService/DeleteOrganizationInvite",
    )?;

    client.delete_organization_invite(request).await?;

    println!("Invite revoked: {}", invite_id);

    Ok(())
}

pub async fn cmd_org_link_workspace(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    org: &str,
    workspace_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, principal, secrets) = setup_client(server, tls_ca_cert).await?;

    let mut request = tonic::Request::new(LinkWorkspaceToOrganizationRequest {
        organization_id: org.to_string(),
        workspace_id: workspace_id.to_string(),
    });
    add_auth_metadata(
        &mut request,
        &principal,
        &secrets,
        "/zopp.ZoppService/LinkWorkspaceToOrganization",
    )?;

    client.link_workspace_to_organization(request).await?;

    println!("Workspace '{}' linked to organization", workspace_id);

    Ok(())
}

pub async fn cmd_org_unlink_workspace(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    _org: &str,
    workspace_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, principal, secrets) = setup_client(server, tls_ca_cert).await?;

    let mut request = tonic::Request::new(UnlinkWorkspaceFromOrganizationRequest {
        workspace_id: workspace_id.to_string(),
    });
    add_auth_metadata(
        &mut request,
        &principal,
        &secrets,
        "/zopp.ZoppService/UnlinkWorkspaceFromOrganization",
    )?;

    client.unlink_workspace_from_organization(request).await?;

    println!("Workspace '{}' unlinked from organization", workspace_id);

    Ok(())
}

pub async fn cmd_org_workspaces(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    org: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, principal, secrets) = setup_client(server, tls_ca_cert).await?;

    let mut request = tonic::Request::new(ListOrganizationWorkspacesRequest {
        organization_id: org.to_string(),
    });
    add_auth_metadata(
        &mut request,
        &principal,
        &secrets,
        "/zopp.ZoppService/ListOrganizationWorkspaces",
    )?;

    let response = client
        .list_organization_workspaces(request)
        .await?
        .into_inner();

    if response.workspaces.is_empty() {
        println!("No workspaces linked to this organization.");
    } else {
        println!("Workspaces:");
        for ws in response.workspaces {
            let project_text = if ws.project_count == 1 {
                "1 project".to_string()
            } else {
                format!("{} projects", ws.project_count)
            };
            println!("  {} ({})", ws.name, project_text);
        }
    }

    Ok(())
}
