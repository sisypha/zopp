use crate::grpc::{add_auth_metadata, setup_client};
use zopp_proto::{
    GetEffectivePermissionsRequest, GetUserWorkspacePermissionRequest,
    GetWorkspacePermissionRequest, ListUserWorkspacePermissionsRequest,
    ListWorkspacePermissionsRequest, RemoveUserWorkspacePermissionRequest,
    RemoveWorkspacePermissionRequest, Role, SetUserWorkspacePermissionRequest,
    SetWorkspacePermissionRequest,
};

pub async fn cmd_permission_set(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    workspace: &str,
    principal: &str,
    role: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, auth_principal) = setup_client(server, tls_ca_cert).await?;

    let role_enum = match role.to_lowercase().as_str() {
        "admin" => Role::Admin as i32,
        "write" => Role::Write as i32,
        "read" => Role::Read as i32,
        _ => return Err("Invalid role: must be admin, write, or read".into()),
    };

    let mut request = tonic::Request::new(SetWorkspacePermissionRequest {
        workspace_name: workspace.to_string(),
        principal_id: principal.to_string(),
        role: role_enum,
    });
    add_auth_metadata(&mut request, &auth_principal, "/zopp.ZoppService/SetWorkspacePermission")?;

    client.set_workspace_permission(request).await?;
    println!(
        "Set {} permission for principal {} on workspace {}",
        role, principal, workspace
    );

    Ok(())
}

pub async fn cmd_permission_get(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    workspace: &str,
    principal: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, auth_principal) = setup_client(server, tls_ca_cert).await?;

    let mut request = tonic::Request::new(GetWorkspacePermissionRequest {
        workspace_name: workspace.to_string(),
        principal_id: principal.to_string(),
    });
    add_auth_metadata(&mut request, &auth_principal, "/zopp.ZoppService/GetWorkspacePermission")?;

    let response = client.get_workspace_permission(request).await?.into_inner();

    let role_str = match Role::try_from(response.role) {
        Ok(Role::Admin) => "admin",
        Ok(Role::Write) => "write",
        Ok(Role::Read) => "read",
        _ => "unknown",
    };

    println!(
        "Principal {} has {} permission on workspace {}",
        principal, role_str, workspace
    );

    Ok(())
}

pub async fn cmd_permission_list(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    workspace: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, auth_principal) = setup_client(server, tls_ca_cert).await?;

    let mut request = tonic::Request::new(ListWorkspacePermissionsRequest {
        workspace_name: workspace.to_string(),
    });
    add_auth_metadata(&mut request, &auth_principal, "/zopp.ZoppService/ListWorkspacePermissions")?;

    let response = client
        .list_workspace_permissions(request)
        .await?
        .into_inner();

    if response.permissions.is_empty() {
        println!("No permissions found on workspace {}", workspace);
        return Ok(());
    }

    println!("Permissions on workspace {}:", workspace);
    for perm in response.permissions {
        let role_str = match Role::try_from(perm.role) {
            Ok(Role::Admin) => "admin",
            Ok(Role::Write) => "write",
            Ok(Role::Read) => "read",
            _ => "unknown",
        };
        println!("  {} - {}", perm.principal_id, role_str);
    }

    Ok(())
}

pub async fn cmd_permission_remove(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    workspace: &str,
    principal: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, auth_principal) = setup_client(server, tls_ca_cert).await?;

    let mut request = tonic::Request::new(RemoveWorkspacePermissionRequest {
        workspace_name: workspace.to_string(),
        principal_id: principal.to_string(),
    });
    add_auth_metadata(&mut request, &auth_principal, "/zopp.ZoppService/RemoveWorkspacePermission")?;

    client.remove_workspace_permission(request).await?;
    println!(
        "Removed permission for principal {} from workspace {}",
        principal, workspace
    );

    Ok(())
}

// ────────────────────────────────────── User Permissions ──────────────────────────────────────

pub async fn cmd_user_permission_set(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    workspace: &str,
    email: &str,
    role: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, auth_principal) = setup_client(server, tls_ca_cert).await?;

    let role_enum = match role.to_lowercase().as_str() {
        "admin" => Role::Admin as i32,
        "write" => Role::Write as i32,
        "read" => Role::Read as i32,
        _ => return Err("Invalid role: must be admin, write, or read".into()),
    };

    let mut request = tonic::Request::new(SetUserWorkspacePermissionRequest {
        workspace_name: workspace.to_string(),
        user_email: email.to_string(),
        role: role_enum,
    });
    add_auth_metadata(&mut request, &auth_principal, "/zopp.ZoppService/SetUserWorkspacePermission")?;

    client.set_user_workspace_permission(request).await?;
    println!(
        "Set {} permission for user {} on workspace {}",
        role, email, workspace
    );

    Ok(())
}

pub async fn cmd_user_permission_get(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    workspace: &str,
    email: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, auth_principal) = setup_client(server, tls_ca_cert).await?;

    let mut request = tonic::Request::new(GetUserWorkspacePermissionRequest {
        workspace_name: workspace.to_string(),
        user_email: email.to_string(),
    });
    add_auth_metadata(&mut request, &auth_principal, "/zopp.ZoppService/GetUserWorkspacePermission")?;

    let response = client
        .get_user_workspace_permission(request)
        .await?
        .into_inner();

    let role_str = match Role::try_from(response.role) {
        Ok(Role::Admin) => "admin",
        Ok(Role::Write) => "write",
        Ok(Role::Read) => "read",
        _ => "unknown",
    };

    println!(
        "User {} has {} permission on workspace {}",
        email, role_str, workspace
    );

    Ok(())
}

pub async fn cmd_user_permission_list(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    workspace: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, auth_principal) = setup_client(server, tls_ca_cert).await?;

    let mut request = tonic::Request::new(ListUserWorkspacePermissionsRequest {
        workspace_name: workspace.to_string(),
    });
    add_auth_metadata(&mut request, &auth_principal, "/zopp.ZoppService/ListUserWorkspacePermissions")?;

    let response = client
        .list_user_workspace_permissions(request)
        .await?
        .into_inner();

    if response.permissions.is_empty() {
        println!("No user permissions found on workspace {}", workspace);
        return Ok(());
    }

    println!("User permissions on workspace {}:", workspace);
    for perm in response.permissions {
        let role_str = match Role::try_from(perm.role) {
            Ok(Role::Admin) => "admin",
            Ok(Role::Write) => "write",
            Ok(Role::Read) => "read",
            _ => "unknown",
        };
        println!("  {} - {}", perm.user_email, role_str);
    }

    Ok(())
}

pub async fn cmd_user_permission_remove(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    workspace: &str,
    email: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, auth_principal) = setup_client(server, tls_ca_cert).await?;

    let mut request = tonic::Request::new(RemoveUserWorkspacePermissionRequest {
        workspace_name: workspace.to_string(),
        user_email: email.to_string(),
    });
    add_auth_metadata(&mut request, &auth_principal, "/zopp.ZoppService/RemoveUserWorkspacePermission")?;

    client.remove_user_workspace_permission(request).await?;
    println!(
        "Removed permission for user {} from workspace {}",
        email, workspace
    );

    Ok(())
}

// ────────────────────────────────────── User Project Permissions ──────────────────────────────────────

pub async fn cmd_user_project_permission_set(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    workspace: &str,
    project: &str,
    email: &str,
    role: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, auth_principal) = setup_client(server, tls_ca_cert).await?;

    let role_enum = match role.to_lowercase().as_str() {
        "admin" => Role::Admin as i32,
        "write" => Role::Write as i32,
        "read" => Role::Read as i32,
        _ => return Err("Invalid role: must be admin, write, or read".into()),
    };

    let mut request = tonic::Request::new(zopp_proto::SetUserProjectPermissionRequest {
        workspace_name: workspace.to_string(),
        project_name: project.to_string(),
        user_email: email.to_string(),
        role: role_enum,
    });
    add_auth_metadata(&mut request, &auth_principal, "/zopp.ZoppService/SetUserProjectPermission")?;

    client.set_user_project_permission(request).await?;
    println!(
        "Set {} permission for user {} on project {}/{}",
        role, email, workspace, project
    );

    Ok(())
}

pub async fn cmd_user_project_permission_remove(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    workspace: &str,
    project: &str,
    email: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, auth_principal) = setup_client(server, tls_ca_cert).await?;

    let mut request = tonic::Request::new(zopp_proto::RemoveUserProjectPermissionRequest {
        workspace_name: workspace.to_string(),
        project_name: project.to_string(),
        user_email: email.to_string(),
    });
    add_auth_metadata(&mut request, &auth_principal, "/zopp.ZoppService/RemoveUserProjectPermission")?;

    client.remove_user_project_permission(request).await?;
    println!(
        "Removed permission for user {} from project {}/{}",
        email, workspace, project
    );

    Ok(())
}

// ────────────────────────────────────── User Environment Permissions ──────────────────────────────────────

pub async fn cmd_user_environment_permission_set(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    workspace: &str,
    project: &str,
    environment: &str,
    email: &str,
    role: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, auth_principal) = setup_client(server, tls_ca_cert).await?;

    let role_enum = match role.to_lowercase().as_str() {
        "admin" => Role::Admin as i32,
        "write" => Role::Write as i32,
        "read" => Role::Read as i32,
        _ => return Err("Invalid role: must be admin, write, or read".into()),
    };

    let mut request = tonic::Request::new(zopp_proto::SetUserEnvironmentPermissionRequest {
        workspace_name: workspace.to_string(),
        project_name: project.to_string(),
        environment_name: environment.to_string(),
        user_email: email.to_string(),
        role: role_enum,
    });
    add_auth_metadata(&mut request, &auth_principal, "/zopp.ZoppService/SetUserEnvironmentPermission")?;

    client.set_user_environment_permission(request).await?;
    println!(
        "Set {} permission for user {} on environment {}/{}/{}",
        role, email, workspace, project, environment
    );

    Ok(())
}

pub async fn cmd_user_environment_permission_remove(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    workspace: &str,
    project: &str,
    environment: &str,
    email: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, auth_principal) = setup_client(server, tls_ca_cert).await?;

    let mut request = tonic::Request::new(zopp_proto::RemoveUserEnvironmentPermissionRequest {
        workspace_name: workspace.to_string(),
        project_name: project.to_string(),
        environment_name: environment.to_string(),
        user_email: email.to_string(),
    });
    add_auth_metadata(&mut request, &auth_principal, "/zopp.ZoppService/RemoveUserEnvironmentPermission")?;

    client.remove_user_environment_permission(request).await?;
    println!(
        "Removed permission for user {} from environment {}/{}/{}",
        email, workspace, project, environment
    );

    Ok(())
}

pub async fn cmd_user_project_permission_list(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    workspace: &str,
    project: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, auth_principal) = setup_client(server, tls_ca_cert).await?;

    let mut request = tonic::Request::new(zopp_proto::ListUserProjectPermissionsRequest {
        workspace_name: workspace.to_string(),
        project_name: project.to_string(),
    });
    add_auth_metadata(&mut request, &auth_principal, "/zopp.ZoppService/ListUserProjectPermissions")?;

    let response = client
        .list_user_project_permissions(request)
        .await?
        .into_inner();

    if response.permissions.is_empty() {
        println!(
            "No user permissions found on project {}/{}",
            workspace, project
        );
        return Ok(());
    }

    println!("User permissions on project {}/{}:", workspace, project);
    for perm in response.permissions {
        let role_str = match Role::try_from(perm.role) {
            Ok(Role::Admin) => "admin",
            Ok(Role::Write) => "write",
            Ok(Role::Read) => "read",
            _ => "unknown",
        };
        println!("  {} - {}", perm.user_email, role_str);
    }

    Ok(())
}

pub async fn cmd_user_environment_permission_list(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    workspace: &str,
    project: &str,
    environment: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, auth_principal) = setup_client(server, tls_ca_cert).await?;

    let mut request = tonic::Request::new(zopp_proto::ListUserEnvironmentPermissionsRequest {
        workspace_name: workspace.to_string(),
        project_name: project.to_string(),
        environment_name: environment.to_string(),
    });
    add_auth_metadata(&mut request, &auth_principal, "/zopp.ZoppService/ListUserEnvironmentPermissions")?;

    let response = client
        .list_user_environment_permissions(request)
        .await?
        .into_inner();

    if response.permissions.is_empty() {
        println!(
            "No user permissions found on environment {}/{}/{}",
            workspace, project, environment
        );
        return Ok(());
    }

    println!(
        "User permissions on environment {}/{}/{}:",
        workspace, project, environment
    );
    for perm in response.permissions {
        let role_str = match Role::try_from(perm.role) {
            Ok(Role::Admin) => "admin",
            Ok(Role::Write) => "write",
            Ok(Role::Read) => "read",
            _ => "unknown",
        };
        println!("  {} - {}", perm.user_email, role_str);
    }

    Ok(())
}

pub async fn cmd_user_project_permission_get(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    workspace: &str,
    project: &str,
    email: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, auth_principal) = setup_client(server, tls_ca_cert).await?;

    let mut request = tonic::Request::new(zopp_proto::GetUserProjectPermissionRequest {
        workspace_name: workspace.to_string(),
        project_name: project.to_string(),
        user_email: email.to_string(),
    });
    add_auth_metadata(&mut request, &auth_principal, "/zopp.ZoppService/GetUserProjectPermission")?;

    let response = client
        .get_user_project_permission(request)
        .await?
        .into_inner();

    let role_str = match Role::try_from(response.role) {
        Ok(Role::Admin) => "admin",
        Ok(Role::Write) => "write",
        Ok(Role::Read) => "read",
        _ => "unknown",
    };

    println!(
        "User {} has {} permission on project {}/{}",
        email, role_str, workspace, project
    );

    Ok(())
}

pub async fn cmd_user_environment_permission_get(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    workspace: &str,
    project: &str,
    environment: &str,
    email: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, auth_principal) = setup_client(server, tls_ca_cert).await?;

    let mut request = tonic::Request::new(zopp_proto::GetUserEnvironmentPermissionRequest {
        workspace_name: workspace.to_string(),
        project_name: project.to_string(),
        environment_name: environment.to_string(),
        user_email: email.to_string(),
    });
    add_auth_metadata(&mut request, &auth_principal, "/zopp.ZoppService/GetUserEnvironmentPermission")?;

    let response = client
        .get_user_environment_permission(request)
        .await?
        .into_inner();

    let role_str = match Role::try_from(response.role) {
        Ok(Role::Admin) => "admin",
        Ok(Role::Write) => "write",
        Ok(Role::Read) => "read",
        _ => "unknown",
    };

    println!(
        "User {} has {} permission on environment {}/{}/{}",
        email, role_str, workspace, project, environment
    );

    Ok(())
}

// ────────────────────────────────────── Principal Project Permissions ──────────────────────────────────────

pub async fn cmd_principal_project_permission_set(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    workspace: &str,
    project: &str,
    principal: &str,
    role: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, auth_principal) = setup_client(server, tls_ca_cert).await?;

    let role_enum = match role.to_lowercase().as_str() {
        "admin" => Role::Admin as i32,
        "write" => Role::Write as i32,
        "read" => Role::Read as i32,
        _ => return Err("Invalid role: must be admin, write, or read".into()),
    };

    let mut request = tonic::Request::new(zopp_proto::SetProjectPermissionRequest {
        workspace_name: workspace.to_string(),
        project_name: project.to_string(),
        principal_id: principal.to_string(),
        role: role_enum,
    });
    add_auth_metadata(&mut request, &auth_principal, "/zopp.ZoppService/SetProjectPermission")?;

    client.set_project_permission(request).await?;
    println!(
        "Set {} permission for principal {} on project {}/{}",
        role, principal, workspace, project
    );

    Ok(())
}

pub async fn cmd_principal_project_permission_get(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    workspace: &str,
    project: &str,
    principal: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, auth_principal) = setup_client(server, tls_ca_cert).await?;

    let mut request = tonic::Request::new(zopp_proto::GetProjectPermissionRequest {
        workspace_name: workspace.to_string(),
        project_name: project.to_string(),
        principal_id: principal.to_string(),
    });
    add_auth_metadata(&mut request, &auth_principal, "/zopp.ZoppService/GetProjectPermission")?;

    let response = client.get_project_permission(request).await?.into_inner();

    let role_str = match Role::try_from(response.role) {
        Ok(Role::Admin) => "admin",
        Ok(Role::Write) => "write",
        Ok(Role::Read) => "read",
        _ => "unknown",
    };

    println!(
        "Principal {} has {} permission on project {}/{}",
        principal, role_str, workspace, project
    );

    Ok(())
}

pub async fn cmd_principal_project_permission_list(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    workspace: &str,
    project: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, auth_principal) = setup_client(server, tls_ca_cert).await?;

    let mut request = tonic::Request::new(zopp_proto::ListProjectPermissionsRequest {
        workspace_name: workspace.to_string(),
        project_name: project.to_string(),
    });
    add_auth_metadata(&mut request, &auth_principal, "/zopp.ZoppService/ListProjectPermissions")?;

    let response = client.list_project_permissions(request).await?.into_inner();

    if response.permissions.is_empty() {
        println!(
            "No principal permissions found on project {}/{}",
            workspace, project
        );
        return Ok(());
    }

    println!(
        "Principal permissions on project {}/{}:",
        workspace, project
    );
    for perm in response.permissions {
        let role_str = match Role::try_from(perm.role) {
            Ok(Role::Admin) => "admin",
            Ok(Role::Write) => "write",
            Ok(Role::Read) => "read",
            _ => "unknown",
        };
        println!("  {} - {}", perm.principal_id, role_str);
    }

    Ok(())
}

pub async fn cmd_principal_project_permission_remove(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    workspace: &str,
    project: &str,
    principal: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, auth_principal) = setup_client(server, tls_ca_cert).await?;

    let mut request = tonic::Request::new(zopp_proto::RemoveProjectPermissionRequest {
        workspace_name: workspace.to_string(),
        project_name: project.to_string(),
        principal_id: principal.to_string(),
    });
    add_auth_metadata(&mut request, &auth_principal, "/zopp.ZoppService/RemoveProjectPermission")?;

    client.remove_project_permission(request).await?;
    println!(
        "Removed permission for principal {} from project {}/{}",
        principal, workspace, project
    );

    Ok(())
}

// ────────────────────────────────────── Principal Environment Permissions ──────────────────────────────────────

pub async fn cmd_principal_environment_permission_set(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    workspace: &str,
    project: &str,
    environment: &str,
    principal: &str,
    role: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, auth_principal) = setup_client(server, tls_ca_cert).await?;

    let role_enum = match role.to_lowercase().as_str() {
        "admin" => Role::Admin as i32,
        "write" => Role::Write as i32,
        "read" => Role::Read as i32,
        _ => return Err("Invalid role: must be admin, write, or read".into()),
    };

    let mut request = tonic::Request::new(zopp_proto::SetEnvironmentPermissionRequest {
        workspace_name: workspace.to_string(),
        project_name: project.to_string(),
        environment_name: environment.to_string(),
        principal_id: principal.to_string(),
        role: role_enum,
    });
    add_auth_metadata(&mut request, &auth_principal, "/zopp.ZoppService/SetEnvironmentPermission")?;

    client.set_environment_permission(request).await?;
    println!(
        "Set {} permission for principal {} on environment {}/{}/{}",
        role, principal, workspace, project, environment
    );

    Ok(())
}

pub async fn cmd_principal_environment_permission_get(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    workspace: &str,
    project: &str,
    environment: &str,
    principal: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, auth_principal) = setup_client(server, tls_ca_cert).await?;

    let mut request = tonic::Request::new(zopp_proto::GetEnvironmentPermissionRequest {
        workspace_name: workspace.to_string(),
        project_name: project.to_string(),
        environment_name: environment.to_string(),
        principal_id: principal.to_string(),
    });
    add_auth_metadata(&mut request, &auth_principal, "/zopp.ZoppService/GetEnvironmentPermission")?;

    let response = client
        .get_environment_permission(request)
        .await?
        .into_inner();

    let role_str = match Role::try_from(response.role) {
        Ok(Role::Admin) => "admin",
        Ok(Role::Write) => "write",
        Ok(Role::Read) => "read",
        _ => "unknown",
    };

    println!(
        "Principal {} has {} permission on environment {}/{}/{}",
        principal, role_str, workspace, project, environment
    );

    Ok(())
}

pub async fn cmd_principal_environment_permission_list(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    workspace: &str,
    project: &str,
    environment: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, auth_principal) = setup_client(server, tls_ca_cert).await?;

    let mut request = tonic::Request::new(zopp_proto::ListEnvironmentPermissionsRequest {
        workspace_name: workspace.to_string(),
        project_name: project.to_string(),
        environment_name: environment.to_string(),
    });
    add_auth_metadata(&mut request, &auth_principal, "/zopp.ZoppService/ListEnvironmentPermissions")?;

    let response = client
        .list_environment_permissions(request)
        .await?
        .into_inner();

    if response.permissions.is_empty() {
        println!(
            "No principal permissions found on environment {}/{}/{}",
            workspace, project, environment
        );
        return Ok(());
    }

    println!(
        "Principal permissions on environment {}/{}/{}:",
        workspace, project, environment
    );
    for perm in response.permissions {
        let role_str = match Role::try_from(perm.role) {
            Ok(Role::Admin) => "admin",
            Ok(Role::Write) => "write",
            Ok(Role::Read) => "read",
            _ => "unknown",
        };
        println!("  {} - {}", perm.principal_id, role_str);
    }

    Ok(())
}

pub async fn cmd_principal_environment_permission_remove(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    workspace: &str,
    project: &str,
    environment: &str,
    principal: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, auth_principal) = setup_client(server, tls_ca_cert).await?;

    let mut request = tonic::Request::new(zopp_proto::RemoveEnvironmentPermissionRequest {
        workspace_name: workspace.to_string(),
        project_name: project.to_string(),
        environment_name: environment.to_string(),
        principal_id: principal.to_string(),
    });
    add_auth_metadata(&mut request, &auth_principal, "/zopp.ZoppService/RemoveEnvironmentPermission")?;

    client.remove_environment_permission(request).await?;
    println!(
        "Removed permission for principal {} from environment {}/{}/{}",
        principal, workspace, project, environment
    );

    Ok(())
}

// ────────────────────────────────────── Effective Permissions ──────────────────────────────────────

pub async fn cmd_permission_effective(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    workspace: &str,
    principal: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, auth_principal) = setup_client(server, tls_ca_cert).await?;

    let mut request = tonic::Request::new(GetEffectivePermissionsRequest {
        workspace_name: workspace.to_string(),
        principal_id: principal.to_string(),
    });
    add_auth_metadata(&mut request, &auth_principal, "/zopp.ZoppService/GetEffectivePermissions")?;

    let response = client
        .get_effective_permissions(request)
        .await?
        .into_inner();

    let principal_type = if response.is_service_principal {
        "service"
    } else {
        "user"
    };

    println!(
        "Effective permissions for {} principal '{}' (ID: {}) in workspace '{}':",
        principal_type, response.principal_name, response.principal_id, workspace
    );

    // Show workspace-level permission
    if let Some(role) = response.workspace_role {
        let role_str = match Role::try_from(role) {
            Ok(Role::Admin) => "admin",
            Ok(Role::Write) => "write",
            Ok(Role::Read) => "read",
            _ => "unknown",
        };
        println!("  Workspace: {}", role_str);
    }

    // Show project and environment permissions
    if response.projects.is_empty() && response.workspace_role.is_none() {
        println!("  No permissions found");
    } else {
        for project in response.projects {
            // Project-level permission
            if let Some(role) = project.effective_role {
                let role_str = match Role::try_from(role) {
                    Ok(Role::Admin) => "admin",
                    Ok(Role::Write) => "write",
                    Ok(Role::Read) => "read",
                    _ => "unknown",
                };
                println!("  Project '{}': {}", project.project_name, role_str);
            }

            // Environment-level permissions
            for env in project.environments {
                let role_str = match Role::try_from(env.effective_role) {
                    Ok(Role::Admin) => "admin",
                    Ok(Role::Write) => "write",
                    Ok(Role::Read) => "read",
                    _ => "unknown",
                };
                println!(
                    "    Environment '{}/{}': {}",
                    project.project_name, env.environment_name, role_str
                );
            }
        }
    }

    Ok(())
}
