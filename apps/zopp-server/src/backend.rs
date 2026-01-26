use std::sync::Arc;
use zopp_audit::{AuditEvent, AuditLog, AuditLogError, AuditLogFilter, AuditLogId};
use zopp_storage::*;
use zopp_store_postgres::PostgresStore;
use zopp_store_sqlite::SqliteStore;

/// StoreBackend abstracts over SQLite and PostgreSQL implementations
#[derive(Clone)]
pub enum StoreBackend {
    Sqlite(Arc<SqliteStore>),
    Postgres(Arc<PostgresStore>),
}

#[async_trait::async_trait]
impl Store for StoreBackend {
    async fn create_user(
        &self,
        params: &CreateUserParams,
    ) -> Result<(UserId, Option<PrincipalId>), StoreError> {
        match self {
            StoreBackend::Sqlite(s) => s.create_user(params).await,
            StoreBackend::Postgres(s) => s.create_user(params).await,
        }
    }

    async fn get_user_by_email(&self, email: &str) -> Result<User, StoreError> {
        match self {
            StoreBackend::Sqlite(s) => s.get_user_by_email(email).await,
            StoreBackend::Postgres(s) => s.get_user_by_email(email).await,
        }
    }

    async fn get_user_by_id(&self, user_id: &UserId) -> Result<User, StoreError> {
        match self {
            StoreBackend::Sqlite(s) => s.get_user_by_id(user_id).await,
            StoreBackend::Postgres(s) => s.get_user_by_id(user_id).await,
        }
    }

    async fn create_principal(
        &self,
        params: &CreatePrincipalParams,
    ) -> Result<PrincipalId, StoreError> {
        match self {
            StoreBackend::Sqlite(s) => s.create_principal(params).await,
            StoreBackend::Postgres(s) => s.create_principal(params).await,
        }
    }

    async fn get_principal(&self, principal_id: &PrincipalId) -> Result<Principal, StoreError> {
        match self {
            StoreBackend::Sqlite(s) => s.get_principal(principal_id).await,
            StoreBackend::Postgres(s) => s.get_principal(principal_id).await,
        }
    }

    async fn rename_principal(
        &self,
        principal_id: &PrincipalId,
        new_name: &str,
    ) -> Result<(), StoreError> {
        match self {
            StoreBackend::Sqlite(s) => s.rename_principal(principal_id, new_name).await,
            StoreBackend::Postgres(s) => s.rename_principal(principal_id, new_name).await,
        }
    }

    async fn list_principals(&self, user_id: &UserId) -> Result<Vec<Principal>, StoreError> {
        match self {
            StoreBackend::Sqlite(s) => s.list_principals(user_id).await,
            StoreBackend::Postgres(s) => s.list_principals(user_id).await,
        }
    }

    async fn create_invite(&self, params: &CreateInviteParams) -> Result<Invite, StoreError> {
        match self {
            StoreBackend::Sqlite(s) => s.create_invite(params).await,
            StoreBackend::Postgres(s) => s.create_invite(params).await,
        }
    }

    async fn get_invite_by_token(&self, token: &str) -> Result<Invite, StoreError> {
        match self {
            StoreBackend::Sqlite(s) => s.get_invite_by_token(token).await,
            StoreBackend::Postgres(s) => s.get_invite_by_token(token).await,
        }
    }

    async fn list_invites(&self, user_id: Option<UserId>) -> Result<Vec<Invite>, StoreError> {
        match self {
            StoreBackend::Sqlite(s) => s.list_invites(user_id.clone()).await,
            StoreBackend::Postgres(s) => s.list_invites(user_id).await,
        }
    }

    async fn revoke_invite(&self, invite_id: &InviteId) -> Result<(), StoreError> {
        match self {
            StoreBackend::Sqlite(s) => s.revoke_invite(invite_id).await,
            StoreBackend::Postgres(s) => s.revoke_invite(invite_id).await,
        }
    }

    async fn consume_invite(&self, token: &str) -> Result<(), StoreError> {
        match self {
            StoreBackend::Sqlite(s) => s.consume_invite(token).await,
            StoreBackend::Postgres(s) => s.consume_invite(token).await,
        }
    }

    async fn create_principal_export(
        &self,
        params: &CreatePrincipalExportParams,
    ) -> Result<PrincipalExport, StoreError> {
        match self {
            StoreBackend::Sqlite(s) => s.create_principal_export(params).await,
            StoreBackend::Postgres(s) => s.create_principal_export(params).await,
        }
    }

    async fn get_principal_export_by_code(
        &self,
        export_code: &str,
    ) -> Result<PrincipalExport, StoreError> {
        match self {
            StoreBackend::Sqlite(s) => s.get_principal_export_by_code(export_code).await,
            StoreBackend::Postgres(s) => s.get_principal_export_by_code(export_code).await,
        }
    }

    async fn consume_principal_export(
        &self,
        export_id: &PrincipalExportId,
    ) -> Result<(), StoreError> {
        match self {
            StoreBackend::Sqlite(s) => s.consume_principal_export(export_id).await,
            StoreBackend::Postgres(s) => s.consume_principal_export(export_id).await,
        }
    }

    async fn increment_export_failed_attempts(
        &self,
        export_id: &PrincipalExportId,
    ) -> Result<i32, StoreError> {
        match self {
            StoreBackend::Sqlite(s) => s.increment_export_failed_attempts(export_id).await,
            StoreBackend::Postgres(s) => s.increment_export_failed_attempts(export_id).await,
        }
    }

    async fn delete_principal_export(
        &self,
        export_id: &PrincipalExportId,
    ) -> Result<(), StoreError> {
        match self {
            StoreBackend::Sqlite(s) => s.delete_principal_export(export_id).await,
            StoreBackend::Postgres(s) => s.delete_principal_export(export_id).await,
        }
    }

    async fn create_workspace(
        &self,
        params: &CreateWorkspaceParams,
    ) -> Result<WorkspaceId, StoreError> {
        match self {
            StoreBackend::Sqlite(s) => s.create_workspace(params).await,
            StoreBackend::Postgres(s) => s.create_workspace(params).await,
        }
    }

    async fn list_workspaces(
        &self,
        principal_id: &PrincipalId,
    ) -> Result<Vec<Workspace>, StoreError> {
        match self {
            StoreBackend::Sqlite(s) => s.list_workspaces(principal_id).await,
            StoreBackend::Postgres(s) => s.list_workspaces(principal_id).await,
        }
    }

    async fn get_workspace(&self, ws: &WorkspaceId) -> Result<Workspace, StoreError> {
        match self {
            StoreBackend::Sqlite(s) => s.get_workspace(ws).await,
            StoreBackend::Postgres(s) => s.get_workspace(ws).await,
        }
    }

    async fn get_workspace_by_name(
        &self,
        user_id: &UserId,
        name: &str,
    ) -> Result<Workspace, StoreError> {
        match self {
            StoreBackend::Sqlite(s) => s.get_workspace_by_name(user_id, name).await,
            StoreBackend::Postgres(s) => s.get_workspace_by_name(user_id, name).await,
        }
    }

    async fn get_workspace_by_name_for_principal(
        &self,
        principal_id: &PrincipalId,
        name: &str,
    ) -> Result<Workspace, StoreError> {
        match self {
            StoreBackend::Sqlite(s) => {
                s.get_workspace_by_name_for_principal(principal_id, name)
                    .await
            }
            StoreBackend::Postgres(s) => {
                s.get_workspace_by_name_for_principal(principal_id, name)
                    .await
            }
        }
    }

    async fn add_workspace_principal(
        &self,
        params: &AddWorkspacePrincipalParams,
    ) -> Result<(), StoreError> {
        match self {
            StoreBackend::Sqlite(s) => s.add_workspace_principal(params).await,
            StoreBackend::Postgres(s) => s.add_workspace_principal(params).await,
        }
    }

    async fn get_workspace_principal(
        &self,
        workspace_id: &WorkspaceId,
        principal_id: &PrincipalId,
    ) -> Result<WorkspacePrincipal, StoreError> {
        match self {
            StoreBackend::Sqlite(s) => s.get_workspace_principal(workspace_id, principal_id).await,
            StoreBackend::Postgres(s) => {
                s.get_workspace_principal(workspace_id, principal_id).await
            }
        }
    }

    async fn list_workspace_principals(
        &self,
        workspace_id: &WorkspaceId,
    ) -> Result<Vec<WorkspacePrincipal>, StoreError> {
        match self {
            StoreBackend::Sqlite(s) => s.list_workspace_principals(workspace_id).await,
            StoreBackend::Postgres(s) => s.list_workspace_principals(workspace_id).await,
        }
    }

    async fn remove_workspace_principal(
        &self,
        workspace_id: &WorkspaceId,
        principal_id: &PrincipalId,
    ) -> Result<(), StoreError> {
        match self {
            StoreBackend::Sqlite(s) => {
                s.remove_workspace_principal(workspace_id, principal_id)
                    .await
            }
            StoreBackend::Postgres(s) => {
                s.remove_workspace_principal(workspace_id, principal_id)
                    .await
            }
        }
    }

    async fn remove_all_project_permissions_for_principal(
        &self,
        workspace_id: &WorkspaceId,
        principal_id: &PrincipalId,
    ) -> Result<u32, StoreError> {
        match self {
            StoreBackend::Sqlite(s) => {
                s.remove_all_project_permissions_for_principal(workspace_id, principal_id)
                    .await
            }
            StoreBackend::Postgres(s) => {
                s.remove_all_project_permissions_for_principal(workspace_id, principal_id)
                    .await
            }
        }
    }

    async fn remove_all_environment_permissions_for_principal(
        &self,
        workspace_id: &WorkspaceId,
        principal_id: &PrincipalId,
    ) -> Result<u32, StoreError> {
        match self {
            StoreBackend::Sqlite(s) => {
                s.remove_all_environment_permissions_for_principal(workspace_id, principal_id)
                    .await
            }
            StoreBackend::Postgres(s) => {
                s.remove_all_environment_permissions_for_principal(workspace_id, principal_id)
                    .await
            }
        }
    }

    async fn add_user_to_workspace(
        &self,
        workspace_id: &WorkspaceId,
        user_id: &UserId,
    ) -> Result<(), StoreError> {
        match self {
            StoreBackend::Sqlite(s) => s.add_user_to_workspace(workspace_id, user_id).await,
            StoreBackend::Postgres(s) => s.add_user_to_workspace(workspace_id, user_id).await,
        }
    }

    async fn create_project(&self, params: &CreateProjectParams) -> Result<ProjectId, StoreError> {
        match self {
            StoreBackend::Sqlite(s) => s.create_project(params).await,
            StoreBackend::Postgres(s) => s.create_project(params).await,
        }
    }

    async fn list_projects(&self, workspace_id: &WorkspaceId) -> Result<Vec<Project>, StoreError> {
        match self {
            StoreBackend::Sqlite(s) => s.list_projects(workspace_id).await,
            StoreBackend::Postgres(s) => s.list_projects(workspace_id).await,
        }
    }

    async fn get_project(&self, project_id: &ProjectId) -> Result<Project, StoreError> {
        match self {
            StoreBackend::Sqlite(s) => s.get_project(project_id).await,
            StoreBackend::Postgres(s) => s.get_project(project_id).await,
        }
    }

    async fn get_project_by_name(
        &self,
        workspace_id: &WorkspaceId,
        name: &str,
    ) -> Result<Project, StoreError> {
        match self {
            StoreBackend::Sqlite(s) => s.get_project_by_name(workspace_id, name).await,
            StoreBackend::Postgres(s) => s.get_project_by_name(workspace_id, name).await,
        }
    }

    async fn delete_project(&self, project_id: &ProjectId) -> Result<(), StoreError> {
        match self {
            StoreBackend::Sqlite(s) => s.delete_project(project_id).await,
            StoreBackend::Postgres(s) => s.delete_project(project_id).await,
        }
    }

    async fn create_env(&self, params: &CreateEnvParams) -> Result<EnvironmentId, StoreError> {
        match self {
            StoreBackend::Sqlite(s) => s.create_env(params).await,
            StoreBackend::Postgres(s) => s.create_env(params).await,
        }
    }

    async fn list_environments(
        &self,
        project_id: &ProjectId,
    ) -> Result<Vec<Environment>, StoreError> {
        match self {
            StoreBackend::Sqlite(s) => s.list_environments(project_id).await,
            StoreBackend::Postgres(s) => s.list_environments(project_id).await,
        }
    }

    async fn get_environment(&self, env_id: &EnvironmentId) -> Result<Environment, StoreError> {
        match self {
            StoreBackend::Sqlite(s) => s.get_environment(env_id).await,
            StoreBackend::Postgres(s) => s.get_environment(env_id).await,
        }
    }

    async fn get_environment_by_name(
        &self,
        project_id: &ProjectId,
        name: &str,
    ) -> Result<Environment, StoreError> {
        match self {
            StoreBackend::Sqlite(s) => s.get_environment_by_name(project_id, name).await,
            StoreBackend::Postgres(s) => s.get_environment_by_name(project_id, name).await,
        }
    }

    async fn delete_environment(&self, env_id: &EnvironmentId) -> Result<(), StoreError> {
        match self {
            StoreBackend::Sqlite(s) => s.delete_environment(env_id).await,
            StoreBackend::Postgres(s) => s.delete_environment(env_id).await,
        }
    }

    async fn get_env_wrap(
        &self,
        ws: &WorkspaceId,
        project: &ProjectName,
        env: &EnvName,
    ) -> Result<(Vec<u8>, Vec<u8>), StoreError> {
        match self {
            StoreBackend::Sqlite(s) => s.get_env_wrap(ws, project, env).await,
            StoreBackend::Postgres(s) => s.get_env_wrap(ws, project, env).await,
        }
    }

    async fn upsert_secret(
        &self,
        env_id: &EnvironmentId,
        key: &str,
        nonce: &[u8],
        ciphertext: &[u8],
    ) -> Result<i64, StoreError> {
        match self {
            StoreBackend::Sqlite(s) => s.upsert_secret(env_id, key, nonce, ciphertext).await,
            StoreBackend::Postgres(s) => s.upsert_secret(env_id, key, nonce, ciphertext).await,
        }
    }

    async fn get_secret(&self, env_id: &EnvironmentId, key: &str) -> Result<SecretRow, StoreError> {
        match self {
            StoreBackend::Sqlite(s) => s.get_secret(env_id, key).await,
            StoreBackend::Postgres(s) => s.get_secret(env_id, key).await,
        }
    }

    async fn list_secret_keys(&self, env_id: &EnvironmentId) -> Result<Vec<String>, StoreError> {
        match self {
            StoreBackend::Sqlite(s) => s.list_secret_keys(env_id).await,
            StoreBackend::Postgres(s) => s.list_secret_keys(env_id).await,
        }
    }

    async fn delete_secret(&self, env_id: &EnvironmentId, key: &str) -> Result<i64, StoreError> {
        match self {
            StoreBackend::Sqlite(s) => s.delete_secret(env_id, key).await,
            StoreBackend::Postgres(s) => s.delete_secret(env_id, key).await,
        }
    }

    async fn set_workspace_permission(
        &self,
        workspace_id: &WorkspaceId,
        principal_id: &PrincipalId,
        role: Role,
    ) -> Result<(), StoreError> {
        match self {
            StoreBackend::Sqlite(s) => {
                s.set_workspace_permission(workspace_id, principal_id, role)
                    .await
            }
            StoreBackend::Postgres(s) => {
                s.set_workspace_permission(workspace_id, principal_id, role)
                    .await
            }
        }
    }

    async fn get_workspace_permission(
        &self,
        workspace_id: &WorkspaceId,
        principal_id: &PrincipalId,
    ) -> Result<Role, StoreError> {
        match self {
            StoreBackend::Sqlite(s) => s.get_workspace_permission(workspace_id, principal_id).await,
            StoreBackend::Postgres(s) => {
                s.get_workspace_permission(workspace_id, principal_id).await
            }
        }
    }

    async fn list_workspace_permissions_for_principal(
        &self,
        principal_id: &PrincipalId,
    ) -> Result<Vec<WorkspacePermission>, StoreError> {
        match self {
            StoreBackend::Sqlite(s) => {
                s.list_workspace_permissions_for_principal(principal_id)
                    .await
            }
            StoreBackend::Postgres(s) => {
                s.list_workspace_permissions_for_principal(principal_id)
                    .await
            }
        }
    }

    async fn list_workspace_permissions(
        &self,
        workspace_id: &WorkspaceId,
    ) -> Result<Vec<WorkspacePermission>, StoreError> {
        match self {
            StoreBackend::Sqlite(s) => s.list_workspace_permissions(workspace_id).await,
            StoreBackend::Postgres(s) => s.list_workspace_permissions(workspace_id).await,
        }
    }

    async fn remove_workspace_permission(
        &self,
        workspace_id: &WorkspaceId,
        principal_id: &PrincipalId,
    ) -> Result<(), StoreError> {
        match self {
            StoreBackend::Sqlite(s) => {
                s.remove_workspace_permission(workspace_id, principal_id)
                    .await
            }
            StoreBackend::Postgres(s) => {
                s.remove_workspace_permission(workspace_id, principal_id)
                    .await
            }
        }
    }

    async fn set_project_permission(
        &self,
        project_id: &ProjectId,
        principal_id: &PrincipalId,
        role: Role,
    ) -> Result<(), StoreError> {
        match self {
            StoreBackend::Sqlite(s) => {
                s.set_project_permission(project_id, principal_id, role)
                    .await
            }
            StoreBackend::Postgres(s) => {
                s.set_project_permission(project_id, principal_id, role)
                    .await
            }
        }
    }

    async fn get_project_permission(
        &self,
        project_id: &ProjectId,
        principal_id: &PrincipalId,
    ) -> Result<Role, StoreError> {
        match self {
            StoreBackend::Sqlite(s) => s.get_project_permission(project_id, principal_id).await,
            StoreBackend::Postgres(s) => s.get_project_permission(project_id, principal_id).await,
        }
    }

    async fn list_project_permissions_for_principal(
        &self,
        principal_id: &PrincipalId,
    ) -> Result<Vec<ProjectPermission>, StoreError> {
        match self {
            StoreBackend::Sqlite(s) => s.list_project_permissions_for_principal(principal_id).await,
            StoreBackend::Postgres(s) => {
                s.list_project_permissions_for_principal(principal_id).await
            }
        }
    }

    async fn list_project_permissions(
        &self,
        project_id: &ProjectId,
    ) -> Result<Vec<ProjectPermission>, StoreError> {
        match self {
            StoreBackend::Sqlite(s) => s.list_project_permissions(project_id).await,
            StoreBackend::Postgres(s) => s.list_project_permissions(project_id).await,
        }
    }

    async fn remove_project_permission(
        &self,
        project_id: &ProjectId,
        principal_id: &PrincipalId,
    ) -> Result<(), StoreError> {
        match self {
            StoreBackend::Sqlite(s) => s.remove_project_permission(project_id, principal_id).await,
            StoreBackend::Postgres(s) => {
                s.remove_project_permission(project_id, principal_id).await
            }
        }
    }

    async fn set_environment_permission(
        &self,
        environment_id: &EnvironmentId,
        principal_id: &PrincipalId,
        role: Role,
    ) -> Result<(), StoreError> {
        match self {
            StoreBackend::Sqlite(s) => {
                s.set_environment_permission(environment_id, principal_id, role)
                    .await
            }
            StoreBackend::Postgres(s) => {
                s.set_environment_permission(environment_id, principal_id, role)
                    .await
            }
        }
    }

    async fn get_environment_permission(
        &self,
        environment_id: &EnvironmentId,
        principal_id: &PrincipalId,
    ) -> Result<Role, StoreError> {
        match self {
            StoreBackend::Sqlite(s) => {
                s.get_environment_permission(environment_id, principal_id)
                    .await
            }
            StoreBackend::Postgres(s) => {
                s.get_environment_permission(environment_id, principal_id)
                    .await
            }
        }
    }

    async fn list_environment_permissions_for_principal(
        &self,
        principal_id: &PrincipalId,
    ) -> Result<Vec<EnvironmentPermission>, StoreError> {
        match self {
            StoreBackend::Sqlite(s) => {
                s.list_environment_permissions_for_principal(principal_id)
                    .await
            }
            StoreBackend::Postgres(s) => {
                s.list_environment_permissions_for_principal(principal_id)
                    .await
            }
        }
    }

    async fn list_environment_permissions(
        &self,
        environment_id: &EnvironmentId,
    ) -> Result<Vec<EnvironmentPermission>, StoreError> {
        match self {
            StoreBackend::Sqlite(s) => s.list_environment_permissions(environment_id).await,
            StoreBackend::Postgres(s) => s.list_environment_permissions(environment_id).await,
        }
    }

    async fn remove_environment_permission(
        &self,
        environment_id: &EnvironmentId,
        principal_id: &PrincipalId,
    ) -> Result<(), StoreError> {
        match self {
            StoreBackend::Sqlite(s) => {
                s.remove_environment_permission(environment_id, principal_id)
                    .await
            }
            StoreBackend::Postgres(s) => {
                s.remove_environment_permission(environment_id, principal_id)
                    .await
            }
        }
    }

    async fn create_group(&self, params: &CreateGroupParams) -> Result<GroupId, StoreError> {
        match self {
            StoreBackend::Sqlite(s) => s.create_group(params).await,
            StoreBackend::Postgres(s) => s.create_group(params).await,
        }
    }

    async fn get_group(&self, group_id: &GroupId) -> Result<Group, StoreError> {
        match self {
            StoreBackend::Sqlite(s) => s.get_group(group_id).await,
            StoreBackend::Postgres(s) => s.get_group(group_id).await,
        }
    }

    async fn get_group_by_name(
        &self,
        workspace_id: &WorkspaceId,
        name: &str,
    ) -> Result<Group, StoreError> {
        match self {
            StoreBackend::Sqlite(s) => s.get_group_by_name(workspace_id, name).await,
            StoreBackend::Postgres(s) => s.get_group_by_name(workspace_id, name).await,
        }
    }

    async fn list_groups(&self, workspace_id: &WorkspaceId) -> Result<Vec<Group>, StoreError> {
        match self {
            StoreBackend::Sqlite(s) => s.list_groups(workspace_id).await,
            StoreBackend::Postgres(s) => s.list_groups(workspace_id).await,
        }
    }

    async fn update_group(
        &self,
        group_id: &GroupId,
        name: &str,
        description: Option<String>,
    ) -> Result<(), StoreError> {
        match self {
            StoreBackend::Sqlite(s) => s.update_group(group_id, name, description.clone()).await,
            StoreBackend::Postgres(s) => s.update_group(group_id, name, description).await,
        }
    }

    async fn delete_group(&self, group_id: &GroupId) -> Result<(), StoreError> {
        match self {
            StoreBackend::Sqlite(s) => s.delete_group(group_id).await,
            StoreBackend::Postgres(s) => s.delete_group(group_id).await,
        }
    }

    async fn add_group_member(
        &self,
        group_id: &GroupId,
        user_id: &UserId,
    ) -> Result<(), StoreError> {
        match self {
            StoreBackend::Sqlite(s) => s.add_group_member(group_id, user_id).await,
            StoreBackend::Postgres(s) => s.add_group_member(group_id, user_id).await,
        }
    }

    async fn remove_group_member(
        &self,
        group_id: &GroupId,
        user_id: &UserId,
    ) -> Result<(), StoreError> {
        match self {
            StoreBackend::Sqlite(s) => s.remove_group_member(group_id, user_id).await,
            StoreBackend::Postgres(s) => s.remove_group_member(group_id, user_id).await,
        }
    }

    async fn list_group_members(&self, group_id: &GroupId) -> Result<Vec<GroupMember>, StoreError> {
        match self {
            StoreBackend::Sqlite(s) => s.list_group_members(group_id).await,
            StoreBackend::Postgres(s) => s.list_group_members(group_id).await,
        }
    }

    async fn list_user_groups(&self, user_id: &UserId) -> Result<Vec<Group>, StoreError> {
        match self {
            StoreBackend::Sqlite(s) => s.list_user_groups(user_id).await,
            StoreBackend::Postgres(s) => s.list_user_groups(user_id).await,
        }
    }

    async fn set_group_workspace_permission(
        &self,
        workspace_id: &WorkspaceId,
        group_id: &GroupId,
        role: Role,
    ) -> Result<(), StoreError> {
        match self {
            StoreBackend::Sqlite(s) => {
                s.set_group_workspace_permission(workspace_id, group_id, role)
                    .await
            }
            StoreBackend::Postgres(s) => {
                s.set_group_workspace_permission(workspace_id, group_id, role)
                    .await
            }
        }
    }

    async fn get_group_workspace_permission(
        &self,
        workspace_id: &WorkspaceId,
        group_id: &GroupId,
    ) -> Result<Role, StoreError> {
        match self {
            StoreBackend::Sqlite(s) => {
                s.get_group_workspace_permission(workspace_id, group_id)
                    .await
            }
            StoreBackend::Postgres(s) => {
                s.get_group_workspace_permission(workspace_id, group_id)
                    .await
            }
        }
    }

    async fn list_group_workspace_permissions(
        &self,
        workspace_id: &WorkspaceId,
    ) -> Result<Vec<GroupWorkspacePermission>, StoreError> {
        match self {
            StoreBackend::Sqlite(s) => s.list_group_workspace_permissions(workspace_id).await,
            StoreBackend::Postgres(s) => s.list_group_workspace_permissions(workspace_id).await,
        }
    }

    async fn remove_group_workspace_permission(
        &self,
        workspace_id: &WorkspaceId,
        group_id: &GroupId,
    ) -> Result<(), StoreError> {
        match self {
            StoreBackend::Sqlite(s) => {
                s.remove_group_workspace_permission(workspace_id, group_id)
                    .await
            }
            StoreBackend::Postgres(s) => {
                s.remove_group_workspace_permission(workspace_id, group_id)
                    .await
            }
        }
    }

    async fn set_group_project_permission(
        &self,
        project_id: &ProjectId,
        group_id: &GroupId,
        role: Role,
    ) -> Result<(), StoreError> {
        match self {
            StoreBackend::Sqlite(s) => {
                s.set_group_project_permission(project_id, group_id, role)
                    .await
            }
            StoreBackend::Postgres(s) => {
                s.set_group_project_permission(project_id, group_id, role)
                    .await
            }
        }
    }

    async fn get_group_project_permission(
        &self,
        project_id: &ProjectId,
        group_id: &GroupId,
    ) -> Result<Role, StoreError> {
        match self {
            StoreBackend::Sqlite(s) => s.get_group_project_permission(project_id, group_id).await,
            StoreBackend::Postgres(s) => s.get_group_project_permission(project_id, group_id).await,
        }
    }

    async fn list_group_project_permissions(
        &self,
        project_id: &ProjectId,
    ) -> Result<Vec<GroupProjectPermission>, StoreError> {
        match self {
            StoreBackend::Sqlite(s) => s.list_group_project_permissions(project_id).await,
            StoreBackend::Postgres(s) => s.list_group_project_permissions(project_id).await,
        }
    }

    async fn remove_group_project_permission(
        &self,
        project_id: &ProjectId,
        group_id: &GroupId,
    ) -> Result<(), StoreError> {
        match self {
            StoreBackend::Sqlite(s) => {
                s.remove_group_project_permission(project_id, group_id)
                    .await
            }
            StoreBackend::Postgres(s) => {
                s.remove_group_project_permission(project_id, group_id)
                    .await
            }
        }
    }

    async fn set_group_environment_permission(
        &self,
        environment_id: &EnvironmentId,
        group_id: &GroupId,
        role: Role,
    ) -> Result<(), StoreError> {
        match self {
            StoreBackend::Sqlite(s) => {
                s.set_group_environment_permission(environment_id, group_id, role)
                    .await
            }
            StoreBackend::Postgres(s) => {
                s.set_group_environment_permission(environment_id, group_id, role)
                    .await
            }
        }
    }

    async fn get_group_environment_permission(
        &self,
        environment_id: &EnvironmentId,
        group_id: &GroupId,
    ) -> Result<Role, StoreError> {
        match self {
            StoreBackend::Sqlite(s) => {
                s.get_group_environment_permission(environment_id, group_id)
                    .await
            }
            StoreBackend::Postgres(s) => {
                s.get_group_environment_permission(environment_id, group_id)
                    .await
            }
        }
    }

    async fn list_group_environment_permissions(
        &self,
        environment_id: &EnvironmentId,
    ) -> Result<Vec<GroupEnvironmentPermission>, StoreError> {
        match self {
            StoreBackend::Sqlite(s) => s.list_group_environment_permissions(environment_id).await,
            StoreBackend::Postgres(s) => s.list_group_environment_permissions(environment_id).await,
        }
    }

    async fn remove_group_environment_permission(
        &self,
        environment_id: &EnvironmentId,
        group_id: &GroupId,
    ) -> Result<(), StoreError> {
        match self {
            StoreBackend::Sqlite(s) => {
                s.remove_group_environment_permission(environment_id, group_id)
                    .await
            }
            StoreBackend::Postgres(s) => {
                s.remove_group_environment_permission(environment_id, group_id)
                    .await
            }
        }
    }

    // User permissions
    async fn set_user_workspace_permission(
        &self,
        workspace_id: &WorkspaceId,
        user_id: &UserId,
        role: Role,
    ) -> Result<(), StoreError> {
        match self {
            StoreBackend::Sqlite(s) => {
                s.set_user_workspace_permission(workspace_id, user_id, role)
                    .await
            }
            StoreBackend::Postgres(s) => {
                s.set_user_workspace_permission(workspace_id, user_id, role)
                    .await
            }
        }
    }

    async fn get_user_workspace_permission(
        &self,
        workspace_id: &WorkspaceId,
        user_id: &UserId,
    ) -> Result<Role, StoreError> {
        match self {
            StoreBackend::Sqlite(s) => s.get_user_workspace_permission(workspace_id, user_id).await,
            StoreBackend::Postgres(s) => {
                s.get_user_workspace_permission(workspace_id, user_id).await
            }
        }
    }

    async fn list_user_workspace_permissions(
        &self,
        workspace_id: &WorkspaceId,
    ) -> Result<Vec<UserWorkspacePermission>, StoreError> {
        match self {
            StoreBackend::Sqlite(s) => s.list_user_workspace_permissions(workspace_id).await,
            StoreBackend::Postgres(s) => s.list_user_workspace_permissions(workspace_id).await,
        }
    }

    async fn remove_user_workspace_permission(
        &self,
        workspace_id: &WorkspaceId,
        user_id: &UserId,
    ) -> Result<(), StoreError> {
        match self {
            StoreBackend::Sqlite(s) => {
                s.remove_user_workspace_permission(workspace_id, user_id)
                    .await
            }
            StoreBackend::Postgres(s) => {
                s.remove_user_workspace_permission(workspace_id, user_id)
                    .await
            }
        }
    }

    async fn set_user_project_permission(
        &self,
        project_id: &ProjectId,
        user_id: &UserId,
        role: Role,
    ) -> Result<(), StoreError> {
        match self {
            StoreBackend::Sqlite(s) => {
                s.set_user_project_permission(project_id, user_id, role)
                    .await
            }
            StoreBackend::Postgres(s) => {
                s.set_user_project_permission(project_id, user_id, role)
                    .await
            }
        }
    }

    async fn get_user_project_permission(
        &self,
        project_id: &ProjectId,
        user_id: &UserId,
    ) -> Result<Role, StoreError> {
        match self {
            StoreBackend::Sqlite(s) => s.get_user_project_permission(project_id, user_id).await,
            StoreBackend::Postgres(s) => s.get_user_project_permission(project_id, user_id).await,
        }
    }

    async fn list_user_project_permissions(
        &self,
        project_id: &ProjectId,
    ) -> Result<Vec<UserProjectPermission>, StoreError> {
        match self {
            StoreBackend::Sqlite(s) => s.list_user_project_permissions(project_id).await,
            StoreBackend::Postgres(s) => s.list_user_project_permissions(project_id).await,
        }
    }

    async fn remove_user_project_permission(
        &self,
        project_id: &ProjectId,
        user_id: &UserId,
    ) -> Result<(), StoreError> {
        match self {
            StoreBackend::Sqlite(s) => s.remove_user_project_permission(project_id, user_id).await,
            StoreBackend::Postgres(s) => {
                s.remove_user_project_permission(project_id, user_id).await
            }
        }
    }

    async fn set_user_environment_permission(
        &self,
        environment_id: &EnvironmentId,
        user_id: &UserId,
        role: Role,
    ) -> Result<(), StoreError> {
        match self {
            StoreBackend::Sqlite(s) => {
                s.set_user_environment_permission(environment_id, user_id, role)
                    .await
            }
            StoreBackend::Postgres(s) => {
                s.set_user_environment_permission(environment_id, user_id, role)
                    .await
            }
        }
    }

    async fn get_user_environment_permission(
        &self,
        environment_id: &EnvironmentId,
        user_id: &UserId,
    ) -> Result<Role, StoreError> {
        match self {
            StoreBackend::Sqlite(s) => {
                s.get_user_environment_permission(environment_id, user_id)
                    .await
            }
            StoreBackend::Postgres(s) => {
                s.get_user_environment_permission(environment_id, user_id)
                    .await
            }
        }
    }

    async fn list_user_environment_permissions(
        &self,
        environment_id: &EnvironmentId,
    ) -> Result<Vec<UserEnvironmentPermission>, StoreError> {
        match self {
            StoreBackend::Sqlite(s) => s.list_user_environment_permissions(environment_id).await,
            StoreBackend::Postgres(s) => s.list_user_environment_permissions(environment_id).await,
        }
    }

    async fn remove_user_environment_permission(
        &self,
        environment_id: &EnvironmentId,
        user_id: &UserId,
    ) -> Result<(), StoreError> {
        match self {
            StoreBackend::Sqlite(s) => {
                s.remove_user_environment_permission(environment_id, user_id)
                    .await
            }
            StoreBackend::Postgres(s) => {
                s.remove_user_environment_permission(environment_id, user_id)
                    .await
            }
        }
    }

    // Email verification
    async fn create_email_verification(
        &self,
        params: &CreateEmailVerificationParams,
    ) -> Result<EmailVerification, StoreError> {
        match self {
            StoreBackend::Sqlite(s) => s.create_email_verification(params).await,
            StoreBackend::Postgres(s) => s.create_email_verification(params).await,
        }
    }

    async fn get_email_verification(&self, email: &str) -> Result<EmailVerification, StoreError> {
        match self {
            StoreBackend::Sqlite(s) => s.get_email_verification(email).await,
            StoreBackend::Postgres(s) => s.get_email_verification(email).await,
        }
    }

    async fn increment_email_verification_attempts(
        &self,
        id: &EmailVerificationId,
    ) -> Result<i32, StoreError> {
        match self {
            StoreBackend::Sqlite(s) => s.increment_email_verification_attempts(id).await,
            StoreBackend::Postgres(s) => s.increment_email_verification_attempts(id).await,
        }
    }

    async fn delete_email_verification(&self, id: &EmailVerificationId) -> Result<(), StoreError> {
        match self {
            StoreBackend::Sqlite(s) => s.delete_email_verification(id).await,
            StoreBackend::Postgres(s) => s.delete_email_verification(id).await,
        }
    }

    async fn cleanup_expired_email_verifications(&self) -> Result<u64, StoreError> {
        match self {
            StoreBackend::Sqlite(s) => s.cleanup_expired_email_verifications().await,
            StoreBackend::Postgres(s) => s.cleanup_expired_email_verifications().await,
        }
    }

    async fn mark_user_verified(&self, user_id: &UserId) -> Result<(), StoreError> {
        match self {
            StoreBackend::Sqlite(s) => s.mark_user_verified(user_id).await,
            StoreBackend::Postgres(s) => s.mark_user_verified(user_id).await,
        }
    }

    // Organization methods - delegate to underlying store
    async fn create_organization(
        &self,
        params: &CreateOrganizationParams,
    ) -> Result<OrganizationId, StoreError> {
        match self {
            StoreBackend::Sqlite(s) => s.create_organization(params).await,
            StoreBackend::Postgres(s) => s.create_organization(params).await,
        }
    }

    async fn get_organization(&self, org_id: &OrganizationId) -> Result<Organization, StoreError> {
        match self {
            StoreBackend::Sqlite(s) => s.get_organization(org_id).await,
            StoreBackend::Postgres(s) => s.get_organization(org_id).await,
        }
    }

    async fn get_organization_by_slug(&self, slug: &str) -> Result<Organization, StoreError> {
        match self {
            StoreBackend::Sqlite(s) => s.get_organization_by_slug(slug).await,
            StoreBackend::Postgres(s) => s.get_organization_by_slug(slug).await,
        }
    }

    async fn list_user_organizations(
        &self,
        user_id: &UserId,
    ) -> Result<Vec<Organization>, StoreError> {
        match self {
            StoreBackend::Sqlite(s) => s.list_user_organizations(user_id).await,
            StoreBackend::Postgres(s) => s.list_user_organizations(user_id).await,
        }
    }

    async fn update_organization(
        &self,
        org_id: &OrganizationId,
        name: Option<String>,
        slug: Option<String>,
    ) -> Result<(), StoreError> {
        match self {
            StoreBackend::Sqlite(s) => {
                s.update_organization(org_id, name.clone(), slug.clone())
                    .await
            }
            StoreBackend::Postgres(s) => s.update_organization(org_id, name, slug).await,
        }
    }

    async fn set_organization_stripe_customer(
        &self,
        org_id: &OrganizationId,
        stripe_customer_id: &str,
    ) -> Result<(), StoreError> {
        match self {
            StoreBackend::Sqlite(s) => {
                s.set_organization_stripe_customer(org_id, stripe_customer_id)
                    .await
            }
            StoreBackend::Postgres(s) => {
                s.set_organization_stripe_customer(org_id, stripe_customer_id)
                    .await
            }
        }
    }

    async fn set_organization_plan(
        &self,
        org_id: &OrganizationId,
        plan: Plan,
        seat_limit: i32,
    ) -> Result<(), StoreError> {
        match self {
            StoreBackend::Sqlite(s) => s.set_organization_plan(org_id, plan, seat_limit).await,
            StoreBackend::Postgres(s) => s.set_organization_plan(org_id, plan, seat_limit).await,
        }
    }

    async fn delete_organization(&self, org_id: &OrganizationId) -> Result<(), StoreError> {
        match self {
            StoreBackend::Sqlite(s) => s.delete_organization(org_id).await,
            StoreBackend::Postgres(s) => s.delete_organization(org_id).await,
        }
    }

    async fn add_organization_member(
        &self,
        org_id: &OrganizationId,
        user_id: &UserId,
        role: OrganizationRole,
        invited_by: Option<UserId>,
    ) -> Result<(), StoreError> {
        match self {
            StoreBackend::Sqlite(s) => {
                s.add_organization_member(org_id, user_id, role, invited_by.clone())
                    .await
            }
            StoreBackend::Postgres(s) => {
                s.add_organization_member(org_id, user_id, role, invited_by)
                    .await
            }
        }
    }

    async fn get_organization_member(
        &self,
        org_id: &OrganizationId,
        user_id: &UserId,
    ) -> Result<OrganizationMember, StoreError> {
        match self {
            StoreBackend::Sqlite(s) => s.get_organization_member(org_id, user_id).await,
            StoreBackend::Postgres(s) => s.get_organization_member(org_id, user_id).await,
        }
    }

    async fn list_organization_members(
        &self,
        org_id: &OrganizationId,
    ) -> Result<Vec<OrganizationMember>, StoreError> {
        match self {
            StoreBackend::Sqlite(s) => s.list_organization_members(org_id).await,
            StoreBackend::Postgres(s) => s.list_organization_members(org_id).await,
        }
    }

    async fn update_organization_member_role(
        &self,
        org_id: &OrganizationId,
        user_id: &UserId,
        role: OrganizationRole,
    ) -> Result<(), StoreError> {
        match self {
            StoreBackend::Sqlite(s) => {
                s.update_organization_member_role(org_id, user_id, role)
                    .await
            }
            StoreBackend::Postgres(s) => {
                s.update_organization_member_role(org_id, user_id, role)
                    .await
            }
        }
    }

    async fn remove_organization_member(
        &self,
        org_id: &OrganizationId,
        user_id: &UserId,
    ) -> Result<(), StoreError> {
        match self {
            StoreBackend::Sqlite(s) => s.remove_organization_member(org_id, user_id).await,
            StoreBackend::Postgres(s) => s.remove_organization_member(org_id, user_id).await,
        }
    }

    async fn count_organization_members(&self, org_id: &OrganizationId) -> Result<i32, StoreError> {
        match self {
            StoreBackend::Sqlite(s) => s.count_organization_members(org_id).await,
            StoreBackend::Postgres(s) => s.count_organization_members(org_id).await,
        }
    }

    async fn create_organization_invite(
        &self,
        params: &CreateOrganizationInviteParams,
    ) -> Result<OrganizationInvite, StoreError> {
        match self {
            StoreBackend::Sqlite(s) => s.create_organization_invite(params).await,
            StoreBackend::Postgres(s) => s.create_organization_invite(params).await,
        }
    }

    async fn get_organization_invite_by_token(
        &self,
        token_hash: &str,
    ) -> Result<OrganizationInvite, StoreError> {
        match self {
            StoreBackend::Sqlite(s) => s.get_organization_invite_by_token(token_hash).await,
            StoreBackend::Postgres(s) => s.get_organization_invite_by_token(token_hash).await,
        }
    }

    async fn list_organization_invites(
        &self,
        org_id: &OrganizationId,
    ) -> Result<Vec<OrganizationInvite>, StoreError> {
        match self {
            StoreBackend::Sqlite(s) => s.list_organization_invites(org_id).await,
            StoreBackend::Postgres(s) => s.list_organization_invites(org_id).await,
        }
    }

    async fn delete_organization_invite(
        &self,
        invite_id: &OrganizationInviteId,
    ) -> Result<(), StoreError> {
        match self {
            StoreBackend::Sqlite(s) => s.delete_organization_invite(invite_id).await,
            StoreBackend::Postgres(s) => s.delete_organization_invite(invite_id).await,
        }
    }

    async fn set_workspace_organization(
        &self,
        workspace_id: &WorkspaceId,
        org_id: Option<OrganizationId>,
    ) -> Result<(), StoreError> {
        match self {
            StoreBackend::Sqlite(s) => {
                s.set_workspace_organization(workspace_id, org_id.clone())
                    .await
            }
            StoreBackend::Postgres(s) => s.set_workspace_organization(workspace_id, org_id).await,
        }
    }

    async fn list_organization_workspaces(
        &self,
        org_id: &OrganizationId,
    ) -> Result<Vec<Workspace>, StoreError> {
        match self {
            StoreBackend::Sqlite(s) => s.list_organization_workspaces(org_id).await,
            StoreBackend::Postgres(s) => s.list_organization_workspaces(org_id).await,
        }
    }
}

#[async_trait::async_trait]
impl AuditLog for StoreBackend {
    async fn record(&self, event: AuditEvent) -> Result<(), AuditLogError> {
        match self {
            StoreBackend::Sqlite(s) => s.record(event).await,
            StoreBackend::Postgres(s) => s.record(event).await,
        }
    }

    async fn query(&self, filter: AuditLogFilter) -> Result<Vec<AuditEvent>, AuditLogError> {
        match self {
            StoreBackend::Sqlite(s) => s.query(filter).await,
            StoreBackend::Postgres(s) => s.query(filter).await,
        }
    }

    async fn get(&self, id: AuditLogId) -> Result<AuditEvent, AuditLogError> {
        match self {
            StoreBackend::Sqlite(s) => s.get(id).await,
            StoreBackend::Postgres(s) => s.get(id).await,
        }
    }

    async fn count(&self, filter: AuditLogFilter) -> Result<u64, AuditLogError> {
        match self {
            StoreBackend::Sqlite(s) => s.count(filter).await,
            StoreBackend::Postgres(s) => s.count(filter).await,
        }
    }
}
