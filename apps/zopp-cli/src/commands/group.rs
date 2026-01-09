use crate::grpc::{add_auth_metadata, setup_client};
use zopp_proto::{
    AddGroupMemberRequest, CreateGroupRequest, DeleteGroupRequest, ListGroupMembersRequest,
    ListGroupsRequest, RemoveGroupEnvironmentPermissionRequest, RemoveGroupMemberRequest,
    RemoveGroupProjectPermissionRequest, RemoveGroupWorkspacePermissionRequest, Role,
    SetGroupEnvironmentPermissionRequest, SetGroupProjectPermissionRequest,
    SetGroupWorkspacePermissionRequest,
};

pub async fn cmd_group_create(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    workspace: Option<&str>,
    name: String,
    description: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, principal) = setup_client(server, tls_ca_cert).await?;

    let workspace_name = workspace
        .map(|s| s.to_string())
        .ok_or("Workspace name required (use -w or --workspace)")?;

    let mut request = tonic::Request::new(CreateGroupRequest {
        workspace_name,
        name,
        description: description.unwrap_or_default(),
    });
    add_auth_metadata(&mut request, &principal)?;

    let response = client.create_group(request).await?.into_inner();

    println!("Created group: {}", response.name);
    println!("  ID: {}", response.id);
    if !response.description.is_empty() {
        println!("  Description: {}", response.description);
    }

    Ok(())
}

pub async fn cmd_group_list(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    workspace: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, principal) = setup_client(server, tls_ca_cert).await?;

    let workspace_name = workspace
        .map(|s| s.to_string())
        .ok_or("Workspace name required (use -w or --workspace)")?;

    let mut request = tonic::Request::new(ListGroupsRequest { workspace_name });
    add_auth_metadata(&mut request, &principal)?;

    let response = client.list_groups(request).await?.into_inner();

    if response.groups.is_empty() {
        println!("No groups found");
        return Ok(());
    }

    println!("Groups:");
    for group in response.groups {
        println!("  {} - {}", group.name, group.description);
    }

    Ok(())
}

pub async fn cmd_group_delete(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    workspace: Option<&str>,
    name: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, principal) = setup_client(server, tls_ca_cert).await?;

    let workspace_name = workspace
        .map(|s| s.to_string())
        .ok_or("Workspace name required (use -w or --workspace)")?;

    let mut request = tonic::Request::new(DeleteGroupRequest {
        workspace_name,
        group_name: name.clone(),
    });
    add_auth_metadata(&mut request, &principal)?;

    client.delete_group(request).await?;
    println!("Deleted group: {}", name);

    Ok(())
}

pub async fn cmd_group_add_member(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    workspace: Option<&str>,
    group_name: String,
    user_email: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, principal) = setup_client(server, tls_ca_cert).await?;

    let workspace_name = workspace
        .map(|s| s.to_string())
        .ok_or("Workspace name required (use -w or --workspace)")?;

    let mut request = tonic::Request::new(AddGroupMemberRequest {
        workspace_name,
        group_name: group_name.clone(),
        user_email: user_email.clone(),
    });
    add_auth_metadata(&mut request, &principal)?;

    client.add_group_member(request).await?;
    println!("Added {} to group {}", user_email, group_name);

    Ok(())
}

pub async fn cmd_group_remove_member(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    workspace: Option<&str>,
    group_name: String,
    user_email: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, principal) = setup_client(server, tls_ca_cert).await?;

    let workspace_name = workspace
        .map(|s| s.to_string())
        .ok_or("Workspace name required (use -w or --workspace)")?;

    let mut request = tonic::Request::new(RemoveGroupMemberRequest {
        workspace_name,
        group_name: group_name.clone(),
        user_email: user_email.clone(),
    });
    add_auth_metadata(&mut request, &principal)?;

    client.remove_group_member(request).await?;
    println!("Removed {} from group {}", user_email, group_name);

    Ok(())
}

pub async fn cmd_group_list_members(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    workspace: Option<&str>,
    group_name: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, principal) = setup_client(server, tls_ca_cert).await?;

    let workspace_name = workspace
        .map(|s| s.to_string())
        .ok_or("Workspace name required (use -w or --workspace)")?;

    let mut request = tonic::Request::new(ListGroupMembersRequest {
        workspace_name,
        group_name: group_name.clone(),
    });
    add_auth_metadata(&mut request, &principal)?;

    let response = client.list_group_members(request).await?.into_inner();

    if response.members.is_empty() {
        println!("No members in group {}", group_name);
        return Ok(());
    }

    println!("Members of group {}:", group_name);
    for member in response.members {
        println!("  {}", member.user_email);
    }

    Ok(())
}

pub async fn cmd_group_set_permission(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    workspace: Option<&str>,
    group_name: String,
    role: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, principal) = setup_client(server, tls_ca_cert).await?;

    let workspace_name = workspace
        .map(|s| s.to_string())
        .ok_or("Workspace name required (use -w or --workspace)")?;

    let role = match role.to_lowercase().as_str() {
        "admin" => Role::Admin as i32,
        "write" => Role::Write as i32,
        "read" => Role::Read as i32,
        _ => return Err("Invalid role: must be admin, write, or read".into()),
    };

    let mut request = tonic::Request::new(SetGroupWorkspacePermissionRequest {
        workspace_name,
        group_name: group_name.clone(),
        role,
    });
    add_auth_metadata(&mut request, &principal)?;

    client.set_group_workspace_permission(request).await?;
    println!("Set permission for group {}", group_name);

    Ok(())
}

pub async fn cmd_group_remove_permission(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    workspace: Option<&str>,
    group_name: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, principal) = setup_client(server, tls_ca_cert).await?;

    let workspace_name = workspace
        .map(|s| s.to_string())
        .ok_or("Workspace name required (use -w or --workspace)")?;

    let mut request = tonic::Request::new(RemoveGroupWorkspacePermissionRequest {
        workspace_name,
        group_name: group_name.clone(),
    });
    add_auth_metadata(&mut request, &principal)?;

    client.remove_group_workspace_permission(request).await?;
    println!("Removed permission for group {}", group_name);

    Ok(())
}

pub async fn cmd_group_set_project_permission(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    workspace: Option<&str>,
    project: &str,
    group_name: String,
    role: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, principal) = setup_client(server, tls_ca_cert).await?;

    let workspace_name = workspace
        .map(|s| s.to_string())
        .ok_or("Workspace name required (use -w or --workspace)")?;

    let role_enum = match role.to_lowercase().as_str() {
        "admin" => Role::Admin as i32,
        "write" => Role::Write as i32,
        "read" => Role::Read as i32,
        _ => return Err("Invalid role: must be admin, write, or read".into()),
    };

    let mut request = tonic::Request::new(SetGroupProjectPermissionRequest {
        workspace_name: workspace_name.clone(),
        project_name: project.to_string(),
        group_name: group_name.clone(),
        role: role_enum,
    });
    add_auth_metadata(&mut request, &principal)?;

    client.set_group_project_permission(request).await?;
    println!(
        "Set {} permission for group {} on project {}/{}",
        role, group_name, workspace_name, project
    );

    Ok(())
}

pub async fn cmd_group_remove_project_permission(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    workspace: Option<&str>,
    project: &str,
    group_name: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, principal) = setup_client(server, tls_ca_cert).await?;

    let workspace_name = workspace
        .map(|s| s.to_string())
        .ok_or("Workspace name required (use -w or --workspace)")?;

    let mut request = tonic::Request::new(RemoveGroupProjectPermissionRequest {
        workspace_name: workspace_name.clone(),
        project_name: project.to_string(),
        group_name: group_name.clone(),
    });
    add_auth_metadata(&mut request, &principal)?;

    client.remove_group_project_permission(request).await?;
    println!(
        "Removed permission for group {} from project {}/{}",
        group_name, workspace_name, project
    );

    Ok(())
}

pub async fn cmd_group_set_environment_permission(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    workspace: Option<&str>,
    project: &str,
    environment: &str,
    group_name: String,
    role: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, principal) = setup_client(server, tls_ca_cert).await?;

    let workspace_name = workspace
        .map(|s| s.to_string())
        .ok_or("Workspace name required (use -w or --workspace)")?;

    let role_enum = match role.to_lowercase().as_str() {
        "admin" => Role::Admin as i32,
        "write" => Role::Write as i32,
        "read" => Role::Read as i32,
        _ => return Err("Invalid role: must be admin, write, or read".into()),
    };

    let mut request = tonic::Request::new(SetGroupEnvironmentPermissionRequest {
        workspace_name: workspace_name.clone(),
        project_name: project.to_string(),
        environment_name: environment.to_string(),
        group_name: group_name.clone(),
        role: role_enum,
    });
    add_auth_metadata(&mut request, &principal)?;

    client.set_group_environment_permission(request).await?;
    println!(
        "Set {} permission for group {} on environment {}/{}/{}",
        role, group_name, workspace_name, project, environment
    );

    Ok(())
}

pub async fn cmd_group_remove_environment_permission(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    workspace: Option<&str>,
    project: &str,
    environment: &str,
    group_name: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, principal) = setup_client(server, tls_ca_cert).await?;

    let workspace_name = workspace
        .map(|s| s.to_string())
        .ok_or("Workspace name required (use -w or --workspace)")?;

    let mut request = tonic::Request::new(RemoveGroupEnvironmentPermissionRequest {
        workspace_name: workspace_name.clone(),
        project_name: project.to_string(),
        environment_name: environment.to_string(),
        group_name: group_name.clone(),
    });
    add_auth_metadata(&mut request, &principal)?;

    client.remove_group_environment_permission(request).await?;
    println!(
        "Removed permission for group {} from environment {}/{}/{}",
        group_name, workspace_name, project, environment
    );

    Ok(())
}

// ────────────────────────────────────── Group Permission Get/List ──────────────────────────────────────

pub async fn cmd_group_get_permission(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    workspace: Option<&str>,
    group_name: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, principal) = setup_client(server, tls_ca_cert).await?;

    let workspace_name = workspace
        .map(|s| s.to_string())
        .ok_or("Workspace name required (use -w or --workspace)")?;

    let mut request = tonic::Request::new(zopp_proto::GetGroupWorkspacePermissionRequest {
        workspace_name: workspace_name.clone(),
        group_name: group_name.clone(),
    });
    add_auth_metadata(&mut request, &principal)?;

    let response = client
        .get_group_workspace_permission(request)
        .await?
        .into_inner();

    let role_str = match Role::try_from(response.role) {
        Ok(Role::Admin) => "admin",
        Ok(Role::Write) => "write",
        Ok(Role::Read) => "read",
        _ => "unknown",
    };

    println!(
        "Group {} has {} permission on workspace {}",
        group_name, role_str, workspace_name
    );

    Ok(())
}

pub async fn cmd_group_list_permissions(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    workspace: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, principal) = setup_client(server, tls_ca_cert).await?;

    let workspace_name = workspace
        .map(|s| s.to_string())
        .ok_or("Workspace name required (use -w or --workspace)")?;

    let mut request = tonic::Request::new(zopp_proto::ListGroupWorkspacePermissionsRequest {
        workspace_name: workspace_name.clone(),
    });
    add_auth_metadata(&mut request, &principal)?;

    let response = client
        .list_group_workspace_permissions(request)
        .await?
        .into_inner();

    if response.permissions.is_empty() {
        println!(
            "No group permissions found on workspace {}",
            workspace_name
        );
        return Ok(());
    }

    println!("Group permissions on workspace {}:", workspace_name);
    for perm in response.permissions {
        let role_str = match Role::try_from(perm.role) {
            Ok(Role::Admin) => "admin",
            Ok(Role::Write) => "write",
            Ok(Role::Read) => "read",
            _ => "unknown",
        };
        println!("  {} - {}", perm.group_name, role_str);
    }

    Ok(())
}

pub async fn cmd_group_get_project_permission(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    workspace: Option<&str>,
    project: &str,
    group_name: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, principal) = setup_client(server, tls_ca_cert).await?;

    let workspace_name = workspace
        .map(|s| s.to_string())
        .ok_or("Workspace name required (use -w or --workspace)")?;

    let mut request = tonic::Request::new(zopp_proto::GetGroupProjectPermissionRequest {
        workspace_name: workspace_name.clone(),
        project_name: project.to_string(),
        group_name: group_name.clone(),
    });
    add_auth_metadata(&mut request, &principal)?;

    let response = client
        .get_group_project_permission(request)
        .await?
        .into_inner();

    let role_str = match Role::try_from(response.role) {
        Ok(Role::Admin) => "admin",
        Ok(Role::Write) => "write",
        Ok(Role::Read) => "read",
        _ => "unknown",
    };

    println!(
        "Group {} has {} permission on project {}/{}",
        group_name, role_str, workspace_name, project
    );

    Ok(())
}

pub async fn cmd_group_list_project_permissions(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    workspace: Option<&str>,
    project: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, principal) = setup_client(server, tls_ca_cert).await?;

    let workspace_name = workspace
        .map(|s| s.to_string())
        .ok_or("Workspace name required (use -w or --workspace)")?;

    let mut request = tonic::Request::new(zopp_proto::ListGroupProjectPermissionsRequest {
        workspace_name: workspace_name.clone(),
        project_name: project.to_string(),
    });
    add_auth_metadata(&mut request, &principal)?;

    let response = client
        .list_group_project_permissions(request)
        .await?
        .into_inner();

    if response.permissions.is_empty() {
        println!(
            "No group permissions found on project {}/{}",
            workspace_name, project
        );
        return Ok(());
    }

    println!(
        "Group permissions on project {}/{}:",
        workspace_name, project
    );
    for perm in response.permissions {
        let role_str = match Role::try_from(perm.role) {
            Ok(Role::Admin) => "admin",
            Ok(Role::Write) => "write",
            Ok(Role::Read) => "read",
            _ => "unknown",
        };
        println!("  {} - {}", perm.group_name, role_str);
    }

    Ok(())
}

pub async fn cmd_group_get_environment_permission(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    workspace: Option<&str>,
    project: &str,
    environment: &str,
    group_name: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, principal) = setup_client(server, tls_ca_cert).await?;

    let workspace_name = workspace
        .map(|s| s.to_string())
        .ok_or("Workspace name required (use -w or --workspace)")?;

    let mut request = tonic::Request::new(zopp_proto::GetGroupEnvironmentPermissionRequest {
        workspace_name: workspace_name.clone(),
        project_name: project.to_string(),
        environment_name: environment.to_string(),
        group_name: group_name.clone(),
    });
    add_auth_metadata(&mut request, &principal)?;

    let response = client
        .get_group_environment_permission(request)
        .await?
        .into_inner();

    let role_str = match Role::try_from(response.role) {
        Ok(Role::Admin) => "admin",
        Ok(Role::Write) => "write",
        Ok(Role::Read) => "read",
        _ => "unknown",
    };

    println!(
        "Group {} has {} permission on environment {}/{}/{}",
        group_name, role_str, workspace_name, project, environment
    );

    Ok(())
}

pub async fn cmd_group_list_environment_permissions(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    workspace: Option<&str>,
    project: &str,
    environment: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, principal) = setup_client(server, tls_ca_cert).await?;

    let workspace_name = workspace
        .map(|s| s.to_string())
        .ok_or("Workspace name required (use -w or --workspace)")?;

    let mut request = tonic::Request::new(zopp_proto::ListGroupEnvironmentPermissionsRequest {
        workspace_name: workspace_name.clone(),
        project_name: project.to_string(),
        environment_name: environment.to_string(),
    });
    add_auth_metadata(&mut request, &principal)?;

    let response = client
        .list_group_environment_permissions(request)
        .await?
        .into_inner();

    if response.permissions.is_empty() {
        println!(
            "No group permissions found on environment {}/{}/{}",
            workspace_name, project, environment
        );
        return Ok(());
    }

    println!(
        "Group permissions on environment {}/{}/{}:",
        workspace_name, project, environment
    );
    for perm in response.permissions {
        let role_str = match Role::try_from(perm.role) {
            Ok(Role::Admin) => "admin",
            Ok(Role::Write) => "write",
            Ok(Role::Read) => "read",
            _ => "unknown",
        };
        println!("  {} - {}", perm.group_name, role_str);
    }

    Ok(())
}
