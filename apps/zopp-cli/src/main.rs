use clap::Parser;

mod cli;
mod commands;
mod config;
mod crypto;
mod grpc;
mod k8s;

use cli::{
    Cli, Command, DiffCommand, EnvironmentCommand, InviteCommand, PrincipalCommand, ProjectCommand,
    SecretCommand, SyncCommand, WorkspaceCommand,
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
            cmd_join(&cli.server, &token, &email, principal.as_deref()).await?;
        }
        Command::Workspace { workspace_cmd } => match workspace_cmd {
            WorkspaceCommand::List => {
                cmd_workspace_list(&cli.server).await?;
            }
            WorkspaceCommand::Create { name } => {
                cmd_workspace_create(&cli.server, &name).await?;
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
                cmd_principal_create(&cli.server, &name, service).await?;
            }
            PrincipalCommand::Use { name } => {
                cmd_principal_use(&name).await?;
            }
            PrincipalCommand::Rename { name, new_name } => {
                cmd_principal_rename(&cli.server, &name, &new_name).await?;
            }
            PrincipalCommand::Delete { name } => {
                cmd_principal_delete(&name).await?;
            }
        },
        Command::Project { project_cmd } => match project_cmd {
            ProjectCommand::List { workspace } => {
                cmd_project_list(&cli.server, &workspace).await?;
            }
            ProjectCommand::Create { workspace, name } => {
                cmd_project_create(&cli.server, &workspace, &name).await?;
            }
            ProjectCommand::Get { name, workspace } => {
                cmd_project_get(&cli.server, &workspace, &name).await?;
            }
            ProjectCommand::Delete { name, workspace } => {
                cmd_project_delete(&cli.server, &workspace, &name).await?;
            }
        },
        Command::Environment { environment_cmd } => match environment_cmd {
            EnvironmentCommand::List { workspace, project } => {
                let (workspace, project) =
                    resolve_workspace_project(workspace.as_ref(), project.as_ref())?;
                cmd_environment_list(&cli.server, &workspace, &project).await?;
            }
            EnvironmentCommand::Create {
                workspace,
                project,
                name,
            } => {
                let (workspace, project) =
                    resolve_workspace_project(workspace.as_ref(), project.as_ref())?;
                cmd_environment_create(&cli.server, &workspace, &project, &name).await?;
            }
            EnvironmentCommand::Get {
                name,
                workspace,
                project,
            } => {
                let (workspace, project) =
                    resolve_workspace_project(workspace.as_ref(), project.as_ref())?;
                cmd_environment_get(&cli.server, &workspace, &project, &name).await?;
            }
            EnvironmentCommand::Delete {
                name,
                workspace,
                project,
            } => {
                let (workspace, project) =
                    resolve_workspace_project(workspace.as_ref(), project.as_ref())?;
                cmd_environment_delete(&cli.server, &workspace, &project, &name).await?;
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
                cmd_secret_get(&cli.server, &workspace, &project, &environment, &key).await?;
            }
            SecretCommand::List {
                workspace,
                project,
                environment,
            } => {
                let (workspace, project, environment) =
                    resolve_context(workspace.as_ref(), project.as_ref(), environment.as_ref())?;
                cmd_secret_list(&cli.server, &workspace, &project, &environment).await?;
            }
            SecretCommand::Delete {
                workspace,
                project,
                environment,
                key,
            } => {
                let (workspace, project, environment) =
                    resolve_context(workspace.as_ref(), project.as_ref(), environment.as_ref())?;
                cmd_secret_delete(&cli.server, &workspace, &project, &environment, &key).await?;
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
                cmd_invite_create(&cli.server, &workspace, expires_hours, plain).await?;
            }
            InviteCommand::List => {
                cmd_invite_list(&cli.server).await?;
            }
            InviteCommand::Revoke { invite_code } => {
                cmd_invite_revoke(&cli.server, &invite_code).await?;
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
            cmd_secret_run(&cli.server, &workspace, &project, &environment, &command).await?;
        }
    }

    Ok(())
}
