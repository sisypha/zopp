use clap::Parser;

mod cli;
mod commands;
mod config;
mod crypto;
mod grpc;
mod k8s;

use cli::{
    Cli, Command, DiffCommand, EnvironmentCommand, GroupCommand, InviteCommand, PermissionCommand,
    PrincipalCommand, ProjectCommand, SecretCommand, SyncCommand, WorkspaceCommand,
};
use commands::*;
use config::{resolve_context, resolve_workspace, resolve_workspace_project};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Command::Join {
            token,
            email,
            principal,
        } => {
            cmd_join(
                &cli.server,
                cli.tls_ca_cert.as_deref(),
                &token,
                &email,
                principal.as_deref(),
            )
            .await?;
        }
        Command::Workspace { workspace_cmd } => match workspace_cmd {
            WorkspaceCommand::List => {
                cmd_workspace_list(&cli.server, cli.tls_ca_cert.as_deref()).await?;
            }
            WorkspaceCommand::Create { name } => {
                cmd_workspace_create(&cli.server, cli.tls_ca_cert.as_deref(), &name).await?;
            }
        },
        Command::Principal { principal_cmd } => match principal_cmd {
            PrincipalCommand::List => {
                cmd_principal_list().await?;
            }
            PrincipalCommand::Current => {
                cmd_principal_current().await?;
            }
            PrincipalCommand::Create { name, service } => {
                cmd_principal_create(&cli.server, cli.tls_ca_cert.as_deref(), &name, service)
                    .await?;
            }
            PrincipalCommand::Use { name } => {
                cmd_principal_use(&name).await?;
            }
            PrincipalCommand::Rename { name, new_name } => {
                cmd_principal_rename(&cli.server, cli.tls_ca_cert.as_deref(), &name, &new_name)
                    .await?;
            }
            PrincipalCommand::Delete { name } => {
                cmd_principal_delete(&name).await?;
            }
            PrincipalCommand::ServiceList { workspace } => {
                cmd_principal_service_list(&cli.server, cli.tls_ca_cert.as_deref(), &workspace)
                    .await?;
            }
            PrincipalCommand::WorkspaceRemove {
                workspace,
                principal,
            } => {
                cmd_principal_workspace_remove(
                    &cli.server,
                    cli.tls_ca_cert.as_deref(),
                    &workspace,
                    &principal,
                )
                .await?;
            }
            PrincipalCommand::RevokeAll {
                workspace,
                principal,
            } => {
                cmd_principal_revoke_all(
                    &cli.server,
                    cli.tls_ca_cert.as_deref(),
                    &workspace,
                    &principal,
                )
                .await?;
            }
        },
        Command::Project { project_cmd } => match project_cmd {
            ProjectCommand::List { workspace } => {
                cmd_project_list(&cli.server, cli.tls_ca_cert.as_deref(), &workspace).await?;
            }
            ProjectCommand::Create { workspace, name } => {
                cmd_project_create(&cli.server, cli.tls_ca_cert.as_deref(), &workspace, &name)
                    .await?;
            }
            ProjectCommand::Get { name, workspace } => {
                cmd_project_get(&cli.server, cli.tls_ca_cert.as_deref(), &workspace, &name).await?;
            }
            ProjectCommand::Delete { name, workspace } => {
                cmd_project_delete(&cli.server, cli.tls_ca_cert.as_deref(), &workspace, &name)
                    .await?;
            }
        },
        Command::Environment { environment_cmd } => match environment_cmd {
            EnvironmentCommand::List { workspace, project } => {
                let (workspace, project) =
                    resolve_workspace_project(workspace.as_ref(), project.as_ref())?;
                cmd_environment_list(
                    &cli.server,
                    cli.tls_ca_cert.as_deref(),
                    &workspace,
                    &project,
                )
                .await?;
            }
            EnvironmentCommand::Create {
                workspace,
                project,
                name,
            } => {
                let (workspace, project) =
                    resolve_workspace_project(workspace.as_ref(), project.as_ref())?;
                cmd_environment_create(
                    &cli.server,
                    cli.tls_ca_cert.as_deref(),
                    &workspace,
                    &project,
                    &name,
                )
                .await?;
            }
            EnvironmentCommand::Get {
                name,
                workspace,
                project,
            } => {
                let (workspace, project) =
                    resolve_workspace_project(workspace.as_ref(), project.as_ref())?;
                cmd_environment_get(
                    &cli.server,
                    cli.tls_ca_cert.as_deref(),
                    &workspace,
                    &project,
                    &name,
                )
                .await?;
            }
            EnvironmentCommand::Delete {
                name,
                workspace,
                project,
            } => {
                let (workspace, project) =
                    resolve_workspace_project(workspace.as_ref(), project.as_ref())?;
                cmd_environment_delete(
                    &cli.server,
                    cli.tls_ca_cert.as_deref(),
                    &workspace,
                    &project,
                    &name,
                )
                .await?;
            }
        },
        Command::Secret { secret_cmd } => match secret_cmd {
            SecretCommand::Set {
                workspace,
                project,
                environment,
                key,
                value,
            } => {
                let (workspace, project, environment) =
                    resolve_context(workspace.as_ref(), project.as_ref(), environment.as_ref())?;
                cmd_secret_set(
                    &cli.server,
                    cli.tls_ca_cert.as_deref(),
                    &workspace,
                    &project,
                    &environment,
                    &key,
                    &value,
                )
                .await?;
            }
            SecretCommand::Get {
                workspace,
                project,
                environment,
                key,
            } => {
                let (workspace, project, environment) =
                    resolve_context(workspace.as_ref(), project.as_ref(), environment.as_ref())?;
                cmd_secret_get(
                    &cli.server,
                    cli.tls_ca_cert.as_deref(),
                    &workspace,
                    &project,
                    &environment,
                    &key,
                )
                .await?;
            }
            SecretCommand::List {
                workspace,
                project,
                environment,
            } => {
                let (workspace, project, environment) =
                    resolve_context(workspace.as_ref(), project.as_ref(), environment.as_ref())?;
                cmd_secret_list(
                    &cli.server,
                    cli.tls_ca_cert.as_deref(),
                    &workspace,
                    &project,
                    &environment,
                )
                .await?;
            }
            SecretCommand::Delete {
                workspace,
                project,
                environment,
                key,
            } => {
                let (workspace, project, environment) =
                    resolve_context(workspace.as_ref(), project.as_ref(), environment.as_ref())?;
                cmd_secret_delete(
                    &cli.server,
                    cli.tls_ca_cert.as_deref(),
                    &workspace,
                    &project,
                    &environment,
                    &key,
                )
                .await?;
            }
            SecretCommand::Export {
                workspace,
                project,
                environment,
                output,
            } => {
                let (workspace, project, environment) =
                    resolve_context(workspace.as_ref(), project.as_ref(), environment.as_ref())?;
                cmd_secret_export(
                    &cli.server,
                    cli.tls_ca_cert.as_deref(),
                    &workspace,
                    &project,
                    &environment,
                    output.as_deref(),
                )
                .await?;
            }
            SecretCommand::Import {
                workspace,
                project,
                environment,
                input,
            } => {
                let (workspace, project, environment) =
                    resolve_context(workspace.as_ref(), project.as_ref(), environment.as_ref())?;
                cmd_secret_import(
                    &cli.server,
                    cli.tls_ca_cert.as_deref(),
                    &workspace,
                    &project,
                    &environment,
                    input.as_deref(),
                )
                .await?;
            }
        },
        Command::Invite { invite_cmd } => match invite_cmd {
            InviteCommand::Create {
                workspace,
                expires_hours,
                plain,
            } => {
                let workspace = resolve_workspace(workspace.as_ref())?;
                cmd_invite_create(
                    &cli.server,
                    cli.tls_ca_cert.as_deref(),
                    &workspace,
                    expires_hours,
                    plain,
                )
                .await?;
            }
            InviteCommand::List => {
                cmd_invite_list(&cli.server, cli.tls_ca_cert.as_deref()).await?;
            }
            InviteCommand::Revoke { invite_code } => {
                cmd_invite_revoke(&cli.server, cli.tls_ca_cert.as_deref(), &invite_code).await?;
            }
        },
        Command::Sync { sync_cmd } => match sync_cmd {
            SyncCommand::K8s {
                namespace,
                secret,
                workspace,
                project,
                environment,
                kubeconfig,
                context,
                force,
                dry_run,
            } => {
                let (workspace, project, environment) =
                    resolve_context(workspace.as_ref(), project.as_ref(), environment.as_ref())?;
                cmd_sync_k8s(
                    &cli.server,
                    cli.tls_ca_cert.as_deref(),
                    &workspace,
                    &project,
                    &environment,
                    &namespace,
                    &secret,
                    kubeconfig.as_deref(),
                    context.as_deref(),
                    force,
                    dry_run,
                )
                .await?;
            }
        },
        Command::Permission { permission_cmd } => match permission_cmd {
            PermissionCommand::Set {
                workspace,
                principal,
                role,
            } => {
                cmd_permission_set(
                    &cli.server,
                    cli.tls_ca_cert.as_deref(),
                    &workspace,
                    &principal,
                    &role,
                )
                .await?;
            }
            PermissionCommand::Get {
                workspace,
                principal,
            } => {
                cmd_permission_get(
                    &cli.server,
                    cli.tls_ca_cert.as_deref(),
                    &workspace,
                    &principal,
                )
                .await?;
            }
            PermissionCommand::List { workspace } => {
                cmd_permission_list(&cli.server, cli.tls_ca_cert.as_deref(), &workspace).await?;
            }
            PermissionCommand::Remove {
                workspace,
                principal,
            } => {
                cmd_permission_remove(
                    &cli.server,
                    cli.tls_ca_cert.as_deref(),
                    &workspace,
                    &principal,
                )
                .await?;
            }
            PermissionCommand::ProjectSet {
                workspace,
                project,
                principal,
                role,
            } => {
                commands::permission::cmd_principal_project_permission_set(
                    &cli.server,
                    cli.tls_ca_cert.as_deref(),
                    &workspace,
                    &project,
                    &principal,
                    &role,
                )
                .await?;
            }
            PermissionCommand::ProjectGet {
                workspace,
                project,
                principal,
            } => {
                commands::permission::cmd_principal_project_permission_get(
                    &cli.server,
                    cli.tls_ca_cert.as_deref(),
                    &workspace,
                    &project,
                    &principal,
                )
                .await?;
            }
            PermissionCommand::ProjectList { workspace, project } => {
                commands::permission::cmd_principal_project_permission_list(
                    &cli.server,
                    cli.tls_ca_cert.as_deref(),
                    &workspace,
                    &project,
                )
                .await?;
            }
            PermissionCommand::ProjectRemove {
                workspace,
                project,
                principal,
            } => {
                commands::permission::cmd_principal_project_permission_remove(
                    &cli.server,
                    cli.tls_ca_cert.as_deref(),
                    &workspace,
                    &project,
                    &principal,
                )
                .await?;
            }
            PermissionCommand::EnvSet {
                workspace,
                project,
                environment,
                principal,
                role,
            } => {
                commands::permission::cmd_principal_environment_permission_set(
                    &cli.server,
                    cli.tls_ca_cert.as_deref(),
                    &workspace,
                    &project,
                    &environment,
                    &principal,
                    &role,
                )
                .await?;
            }
            PermissionCommand::EnvGet {
                workspace,
                project,
                environment,
                principal,
            } => {
                commands::permission::cmd_principal_environment_permission_get(
                    &cli.server,
                    cli.tls_ca_cert.as_deref(),
                    &workspace,
                    &project,
                    &environment,
                    &principal,
                )
                .await?;
            }
            PermissionCommand::EnvList {
                workspace,
                project,
                environment,
            } => {
                commands::permission::cmd_principal_environment_permission_list(
                    &cli.server,
                    cli.tls_ca_cert.as_deref(),
                    &workspace,
                    &project,
                    &environment,
                )
                .await?;
            }
            PermissionCommand::EnvRemove {
                workspace,
                project,
                environment,
                principal,
            } => {
                commands::permission::cmd_principal_environment_permission_remove(
                    &cli.server,
                    cli.tls_ca_cert.as_deref(),
                    &workspace,
                    &project,
                    &environment,
                    &principal,
                )
                .await?;
            }
            PermissionCommand::UserSet {
                workspace,
                email,
                role,
            } => {
                cmd_user_permission_set(
                    &cli.server,
                    cli.tls_ca_cert.as_deref(),
                    &workspace,
                    &email,
                    &role,
                )
                .await?;
            }
            PermissionCommand::UserGet { workspace, email } => {
                cmd_user_permission_get(
                    &cli.server,
                    cli.tls_ca_cert.as_deref(),
                    &workspace,
                    &email,
                )
                .await?;
            }
            PermissionCommand::UserList { workspace } => {
                cmd_user_permission_list(&cli.server, cli.tls_ca_cert.as_deref(), &workspace)
                    .await?;
            }
            PermissionCommand::UserRemove { workspace, email } => {
                cmd_user_permission_remove(
                    &cli.server,
                    cli.tls_ca_cert.as_deref(),
                    &workspace,
                    &email,
                )
                .await?;
            }
            PermissionCommand::UserProjectSet {
                workspace,
                project,
                email,
                role,
            } => {
                commands::permission::cmd_user_project_permission_set(
                    &cli.server,
                    cli.tls_ca_cert.as_deref(),
                    &workspace,
                    &project,
                    &email,
                    &role,
                )
                .await?;
            }
            PermissionCommand::UserProjectRemove {
                workspace,
                project,
                email,
            } => {
                commands::permission::cmd_user_project_permission_remove(
                    &cli.server,
                    cli.tls_ca_cert.as_deref(),
                    &workspace,
                    &project,
                    &email,
                )
                .await?;
            }
            PermissionCommand::UserProjectGet {
                workspace,
                project,
                email,
            } => {
                commands::permission::cmd_user_project_permission_get(
                    &cli.server,
                    cli.tls_ca_cert.as_deref(),
                    &workspace,
                    &project,
                    &email,
                )
                .await?;
            }
            PermissionCommand::UserEnvSet {
                workspace,
                project,
                environment,
                email,
                role,
            } => {
                commands::permission::cmd_user_environment_permission_set(
                    &cli.server,
                    cli.tls_ca_cert.as_deref(),
                    &workspace,
                    &project,
                    &environment,
                    &email,
                    &role,
                )
                .await?;
            }
            PermissionCommand::UserEnvRemove {
                workspace,
                project,
                environment,
                email,
            } => {
                commands::permission::cmd_user_environment_permission_remove(
                    &cli.server,
                    cli.tls_ca_cert.as_deref(),
                    &workspace,
                    &project,
                    &environment,
                    &email,
                )
                .await?;
            }
            PermissionCommand::UserEnvGet {
                workspace,
                project,
                environment,
                email,
            } => {
                commands::permission::cmd_user_environment_permission_get(
                    &cli.server,
                    cli.tls_ca_cert.as_deref(),
                    &workspace,
                    &project,
                    &environment,
                    &email,
                )
                .await?;
            }
            PermissionCommand::UserProjectList { workspace, project } => {
                commands::permission::cmd_user_project_permission_list(
                    &cli.server,
                    cli.tls_ca_cert.as_deref(),
                    &workspace,
                    &project,
                )
                .await?;
            }
            PermissionCommand::UserEnvList {
                workspace,
                project,
                environment,
            } => {
                commands::permission::cmd_user_environment_permission_list(
                    &cli.server,
                    cli.tls_ca_cert.as_deref(),
                    &workspace,
                    &project,
                    &environment,
                )
                .await?;
            }
            PermissionCommand::Effective {
                workspace,
                principal,
            } => {
                commands::cmd_permission_effective(
                    &cli.server,
                    cli.tls_ca_cert.as_deref(),
                    &workspace,
                    &principal,
                )
                .await?;
            }
        },
        Command::Group { group_cmd } => match group_cmd {
            GroupCommand::Create {
                workspace,
                name,
                description,
            } => {
                commands::cmd_group_create(
                    &cli.server,
                    cli.tls_ca_cert.as_deref(),
                    workspace.as_deref(),
                    name.clone(),
                    description.clone(),
                )
                .await?;
            }
            GroupCommand::List { workspace } => {
                commands::cmd_group_list(
                    &cli.server,
                    cli.tls_ca_cert.as_deref(),
                    workspace.as_deref(),
                )
                .await?;
            }
            GroupCommand::Delete { workspace, name } => {
                commands::cmd_group_delete(
                    &cli.server,
                    cli.tls_ca_cert.as_deref(),
                    workspace.as_deref(),
                    name.clone(),
                )
                .await?;
            }
            GroupCommand::AddMember {
                workspace,
                group,
                email,
            } => {
                commands::cmd_group_add_member(
                    &cli.server,
                    cli.tls_ca_cert.as_deref(),
                    workspace.as_deref(),
                    group.clone(),
                    email.clone(),
                )
                .await?;
            }
            GroupCommand::RemoveMember {
                workspace,
                group,
                email,
            } => {
                commands::cmd_group_remove_member(
                    &cli.server,
                    cli.tls_ca_cert.as_deref(),
                    workspace.as_deref(),
                    group.clone(),
                    email.clone(),
                )
                .await?;
            }
            GroupCommand::ListMembers { workspace, group } => {
                commands::cmd_group_list_members(
                    &cli.server,
                    cli.tls_ca_cert.as_deref(),
                    workspace.as_deref(),
                    group.clone(),
                )
                .await?;
            }
            GroupCommand::SetPermission {
                workspace,
                group,
                role,
            } => {
                commands::cmd_group_set_permission(
                    &cli.server,
                    cli.tls_ca_cert.as_deref(),
                    workspace.as_deref(),
                    group.clone(),
                    role.clone(),
                )
                .await?;
            }
            GroupCommand::RemovePermission { workspace, group } => {
                commands::cmd_group_remove_permission(
                    &cli.server,
                    cli.tls_ca_cert.as_deref(),
                    workspace.as_deref(),
                    group.clone(),
                )
                .await?;
            }
            GroupCommand::GetPermission { workspace, group } => {
                commands::cmd_group_get_permission(
                    &cli.server,
                    cli.tls_ca_cert.as_deref(),
                    workspace.as_deref(),
                    group.clone(),
                )
                .await?;
            }
            GroupCommand::ListPermissions { workspace } => {
                commands::cmd_group_list_permissions(
                    &cli.server,
                    cli.tls_ca_cert.as_deref(),
                    workspace.as_deref(),
                )
                .await?;
            }
            GroupCommand::SetProjectPermission {
                workspace,
                project,
                group,
                role,
            } => {
                commands::cmd_group_set_project_permission(
                    &cli.server,
                    cli.tls_ca_cert.as_deref(),
                    workspace.as_deref(),
                    &project,
                    group.clone(),
                    role.clone(),
                )
                .await?;
            }
            GroupCommand::RemoveProjectPermission {
                workspace,
                project,
                group,
            } => {
                commands::cmd_group_remove_project_permission(
                    &cli.server,
                    cli.tls_ca_cert.as_deref(),
                    workspace.as_deref(),
                    &project,
                    group.clone(),
                )
                .await?;
            }
            GroupCommand::GetProjectPermission {
                workspace,
                project,
                group,
            } => {
                commands::cmd_group_get_project_permission(
                    &cli.server,
                    cli.tls_ca_cert.as_deref(),
                    workspace.as_deref(),
                    &project,
                    group.clone(),
                )
                .await?;
            }
            GroupCommand::ListProjectPermissions { workspace, project } => {
                commands::cmd_group_list_project_permissions(
                    &cli.server,
                    cli.tls_ca_cert.as_deref(),
                    workspace.as_deref(),
                    &project,
                )
                .await?;
            }
            GroupCommand::SetEnvPermission {
                workspace,
                project,
                environment,
                group,
                role,
            } => {
                commands::cmd_group_set_environment_permission(
                    &cli.server,
                    cli.tls_ca_cert.as_deref(),
                    workspace.as_deref(),
                    &project,
                    &environment,
                    group.clone(),
                    role.clone(),
                )
                .await?;
            }
            GroupCommand::RemoveEnvPermission {
                workspace,
                project,
                environment,
                group,
            } => {
                commands::cmd_group_remove_environment_permission(
                    &cli.server,
                    cli.tls_ca_cert.as_deref(),
                    workspace.as_deref(),
                    &project,
                    &environment,
                    group.clone(),
                )
                .await?;
            }
            GroupCommand::GetEnvPermission {
                workspace,
                project,
                environment,
                group,
            } => {
                commands::cmd_group_get_environment_permission(
                    &cli.server,
                    cli.tls_ca_cert.as_deref(),
                    workspace.as_deref(),
                    &project,
                    &environment,
                    group.clone(),
                )
                .await?;
            }
            GroupCommand::ListEnvPermissions {
                workspace,
                project,
                environment,
            } => {
                commands::cmd_group_list_environment_permissions(
                    &cli.server,
                    cli.tls_ca_cert.as_deref(),
                    workspace.as_deref(),
                    &project,
                    &environment,
                )
                .await?;
            }
        },
        Command::Diff { diff_cmd } => match diff_cmd {
            DiffCommand::K8s {
                namespace,
                secret,
                workspace,
                project,
                environment,
                kubeconfig,
                context,
            } => {
                let (workspace, project, environment) =
                    resolve_context(workspace.as_ref(), project.as_ref(), environment.as_ref())?;
                cmd_diff_k8s(
                    &cli.server,
                    cli.tls_ca_cert.as_deref(),
                    &workspace,
                    &project,
                    &environment,
                    &namespace,
                    &secret,
                    kubeconfig.as_deref(),
                    context.as_deref(),
                )
                .await?;
            }
        },
        Command::Run {
            workspace,
            project,
            environment,
            command,
        } => {
            let (workspace, project, environment) =
                resolve_context(workspace.as_ref(), project.as_ref(), environment.as_ref())?;
            cmd_secret_run(
                &cli.server,
                cli.tls_ca_cert.as_deref(),
                &workspace,
                &project,
                &environment,
                &command,
            )
            .await?;
        }
    }

    Ok(())
}
