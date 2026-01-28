//! Storage abstraction for zopp.
//!
//! Backend crates (e.g., zopp-store-sqlite, zopp-store-postgres) implement this trait so
//! `zopp-core` doesn't depend on any specific database engine or schema details.

use thiserror::Error;

pub mod store;
pub mod types;

// Re-export the Store trait from the store module
pub use store::Store;

// Re-export all types from the types module
pub use types::*;

/// Uniform error type for all storage backends.
#[derive(Debug, Error)]
pub enum StoreError {
    #[error("not found")]
    NotFound,
    #[error("already exists")]
    AlreadyExists,
    #[error("conflict")]
    Conflict,
    #[error("backend error: {0}")]
    Backend(String),
}

/// Encrypted secret row (nonce + ciphertext); no plaintext in storage.
#[derive(Clone, Debug)]
pub struct SecretRow {
    pub nonce: Vec<u8>,      // 24 bytes (XChaCha20 nonce)
    pub ciphertext: Vec<u8>, // AEAD ciphertext
}

// Re-export mockall's MockStore when test-support feature is enabled
#[cfg(feature = "test-support")]
pub use store::MockStore;

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use uuid::Uuid;

    // Tiny compile-time smoke test for trait object usage.
    struct NoopStore;

    #[async_trait::async_trait]
    impl Store for NoopStore {
        async fn create_user(
            &self,
            params: &CreateUserParams,
        ) -> Result<(UserId, Option<PrincipalId>), StoreError> {
            let user_id = UserId(Uuid::new_v4());
            let principal_id = params
                .principal
                .as_ref()
                .map(|_| PrincipalId(Uuid::new_v4()));
            Ok((user_id, principal_id))
        }

        async fn get_user_by_email(&self, _email: &str) -> Result<User, StoreError> {
            Err(StoreError::NotFound)
        }

        async fn get_user_by_id(&self, _user_id: &UserId) -> Result<User, StoreError> {
            Err(StoreError::NotFound)
        }

        async fn create_principal(
            &self,
            _params: &CreatePrincipalParams,
        ) -> Result<PrincipalId, StoreError> {
            Ok(PrincipalId(Uuid::new_v4()))
        }

        async fn get_principal(
            &self,
            _principal_id: &PrincipalId,
        ) -> Result<Principal, StoreError> {
            Err(StoreError::NotFound)
        }

        async fn rename_principal(
            &self,
            _principal_id: &PrincipalId,
            _new_name: &str,
        ) -> Result<(), StoreError> {
            Ok(())
        }

        async fn list_principals(&self, _user_id: &UserId) -> Result<Vec<Principal>, StoreError> {
            Ok(vec![])
        }

        async fn create_invite(&self, params: &CreateInviteParams) -> Result<Invite, StoreError> {
            Ok(Invite {
                id: InviteId(Uuid::new_v4()),
                token: "test-token".to_string(),
                workspace_ids: vec![],
                kek_encrypted: None,
                kek_nonce: None,
                created_at: Utc::now(),
                updated_at: Utc::now(),
                expires_at: Utc::now(),
                created_by_user_id: params.created_by_user_id.clone(),
                consumed: false,
            })
        }

        async fn get_invite_by_token(&self, _token: &str) -> Result<Invite, StoreError> {
            Err(StoreError::NotFound)
        }

        async fn list_invites(&self, _user_id: Option<UserId>) -> Result<Vec<Invite>, StoreError> {
            Ok(vec![])
        }

        async fn revoke_invite(&self, _invite_id: &InviteId) -> Result<(), StoreError> {
            Ok(())
        }

        async fn consume_invite(&self, _token: &str) -> Result<(), StoreError> {
            Ok(())
        }

        async fn create_principal_export(
            &self,
            params: &CreatePrincipalExportParams,
        ) -> Result<PrincipalExport, StoreError> {
            Ok(PrincipalExport {
                id: PrincipalExportId(Uuid::new_v4()),
                export_code: params.export_code.clone(),
                token_hash: params.token_hash.clone(),
                verification_salt: params.verification_salt.clone(),
                user_id: params.user_id.clone(),
                principal_id: params.principal_id.clone(),
                encrypted_data: params.encrypted_data.clone(),
                salt: params.salt.clone(),
                nonce: params.nonce.clone(),
                expires_at: params.expires_at,
                created_at: Utc::now(),
                consumed: false,
                failed_attempts: 0,
            })
        }

        async fn get_principal_export_by_code(
            &self,
            _export_code: &str,
        ) -> Result<PrincipalExport, StoreError> {
            Err(StoreError::NotFound)
        }

        async fn consume_principal_export(
            &self,
            _export_id: &PrincipalExportId,
        ) -> Result<(), StoreError> {
            Ok(())
        }

        async fn increment_export_failed_attempts(
            &self,
            _export_id: &PrincipalExportId,
        ) -> Result<i32, StoreError> {
            Ok(1)
        }

        async fn delete_principal_export(
            &self,
            _export_id: &PrincipalExportId,
        ) -> Result<(), StoreError> {
            Ok(())
        }

        async fn create_email_verification(
            &self,
            params: &CreateEmailVerificationParams,
        ) -> Result<EmailVerification, StoreError> {
            Ok(EmailVerification {
                id: EmailVerificationId(Uuid::new_v4()),
                email: params.email.clone(),
                code_hash: params.code_hash.clone(),
                invite_token: params.invite_token.clone(),
                attempts: 0,
                created_at: Utc::now(),
                expires_at: params.expires_at,
            })
        }

        async fn get_email_verification(
            &self,
            _email: &str,
        ) -> Result<EmailVerification, StoreError> {
            Err(StoreError::NotFound)
        }

        async fn increment_email_verification_attempts(
            &self,
            _id: &EmailVerificationId,
        ) -> Result<i32, StoreError> {
            Ok(1)
        }

        async fn delete_email_verification(
            &self,
            _id: &EmailVerificationId,
        ) -> Result<(), StoreError> {
            Ok(())
        }

        async fn cleanup_expired_email_verifications(&self) -> Result<u64, StoreError> {
            Ok(0)
        }

        async fn mark_user_verified(&self, _user_id: &UserId) -> Result<(), StoreError> {
            Ok(())
        }

        async fn create_workspace(
            &self,
            params: &CreateWorkspaceParams,
        ) -> Result<WorkspaceId, StoreError> {
            Ok(params.id.clone())
        }

        async fn list_workspaces(
            &self,
            _principal_id: &PrincipalId,
        ) -> Result<Vec<Workspace>, StoreError> {
            Ok(vec![])
        }

        async fn get_workspace(&self, _ws: &WorkspaceId) -> Result<Workspace, StoreError> {
            Err(StoreError::NotFound)
        }

        async fn get_workspace_by_name(
            &self,
            _user_id: &UserId,
            _name: &str,
        ) -> Result<Workspace, StoreError> {
            Err(StoreError::NotFound)
        }

        async fn get_workspace_by_name_for_principal(
            &self,
            _principal_id: &PrincipalId,
            _name: &str,
        ) -> Result<Workspace, StoreError> {
            Err(StoreError::NotFound)
        }

        async fn add_workspace_principal(
            &self,
            _params: &AddWorkspacePrincipalParams,
        ) -> Result<(), StoreError> {
            Ok(())
        }

        async fn get_workspace_principal(
            &self,
            _workspace_id: &WorkspaceId,
            _principal_id: &PrincipalId,
        ) -> Result<WorkspacePrincipal, StoreError> {
            Err(StoreError::NotFound)
        }

        async fn list_workspace_principals(
            &self,
            _workspace_id: &WorkspaceId,
        ) -> Result<Vec<WorkspacePrincipal>, StoreError> {
            Ok(vec![])
        }

        async fn remove_workspace_principal(
            &self,
            _workspace_id: &WorkspaceId,
            _principal_id: &PrincipalId,
        ) -> Result<(), StoreError> {
            Ok(())
        }

        async fn remove_all_project_permissions_for_principal(
            &self,
            _workspace_id: &WorkspaceId,
            _principal_id: &PrincipalId,
        ) -> Result<u32, StoreError> {
            Ok(0)
        }

        async fn remove_all_environment_permissions_for_principal(
            &self,
            _workspace_id: &WorkspaceId,
            _principal_id: &PrincipalId,
        ) -> Result<u32, StoreError> {
            Ok(0)
        }

        async fn add_user_to_workspace(
            &self,
            _workspace_id: &WorkspaceId,
            _user_id: &UserId,
        ) -> Result<(), StoreError> {
            Ok(())
        }

        async fn create_project(
            &self,
            _params: &CreateProjectParams,
        ) -> Result<ProjectId, StoreError> {
            Ok(ProjectId(Uuid::new_v4()))
        }

        async fn list_projects(
            &self,
            _workspace_id: &WorkspaceId,
        ) -> Result<Vec<Project>, StoreError> {
            Ok(vec![])
        }

        async fn get_project(&self, _project_id: &ProjectId) -> Result<Project, StoreError> {
            Err(StoreError::NotFound)
        }

        async fn get_project_by_name(
            &self,
            _workspace_id: &WorkspaceId,
            _name: &str,
        ) -> Result<Project, StoreError> {
            Err(StoreError::NotFound)
        }

        async fn delete_project(&self, _project_id: &ProjectId) -> Result<(), StoreError> {
            Ok(())
        }

        async fn create_env(&self, _params: &CreateEnvParams) -> Result<EnvironmentId, StoreError> {
            Ok(EnvironmentId(Uuid::new_v4()))
        }

        async fn list_environments(
            &self,
            _project_id: &ProjectId,
        ) -> Result<Vec<Environment>, StoreError> {
            Ok(vec![])
        }

        async fn get_environment(
            &self,
            _env_id: &EnvironmentId,
        ) -> Result<Environment, StoreError> {
            Err(StoreError::NotFound)
        }

        async fn get_environment_by_name(
            &self,
            _project_id: &ProjectId,
            _name: &str,
        ) -> Result<Environment, StoreError> {
            Err(StoreError::NotFound)
        }

        async fn delete_environment(&self, _env_id: &EnvironmentId) -> Result<(), StoreError> {
            Ok(())
        }

        async fn upsert_secret(
            &self,
            _env_id: &EnvironmentId,
            _key: &str,
            _nonce: &[u8],
            _ciphertext: &[u8],
        ) -> Result<i64, StoreError> {
            Ok(1)
        }

        async fn get_secret(
            &self,
            _env_id: &EnvironmentId,
            _key: &str,
        ) -> Result<SecretRow, StoreError> {
            Err(StoreError::NotFound)
        }

        async fn list_secret_keys(
            &self,
            _env_id: &EnvironmentId,
        ) -> Result<Vec<String>, StoreError> {
            Ok(vec![])
        }

        async fn delete_secret(
            &self,
            _env_id: &EnvironmentId,
            _key: &str,
        ) -> Result<i64, StoreError> {
            Ok(1)
        }

        async fn get_env_wrap(
            &self,
            _ws: &WorkspaceId,
            _project: &ProjectName,
            _env: &EnvName,
        ) -> Result<(Vec<u8>, Vec<u8>), StoreError> {
            Err(StoreError::NotFound)
        }

        async fn set_workspace_permission(
            &self,
            _workspace_id: &WorkspaceId,
            _principal_id: &PrincipalId,
            _role: Role,
        ) -> Result<(), StoreError> {
            Ok(())
        }

        async fn get_workspace_permission(
            &self,
            _workspace_id: &WorkspaceId,
            _principal_id: &PrincipalId,
        ) -> Result<Role, StoreError> {
            Err(StoreError::NotFound)
        }

        async fn list_workspace_permissions_for_principal(
            &self,
            _principal_id: &PrincipalId,
        ) -> Result<Vec<WorkspacePermission>, StoreError> {
            Ok(vec![])
        }

        async fn list_workspace_permissions(
            &self,
            _workspace_id: &WorkspaceId,
        ) -> Result<Vec<WorkspacePermission>, StoreError> {
            Ok(vec![])
        }

        async fn remove_workspace_permission(
            &self,
            _workspace_id: &WorkspaceId,
            _principal_id: &PrincipalId,
        ) -> Result<(), StoreError> {
            Ok(())
        }

        async fn set_project_permission(
            &self,
            _project_id: &ProjectId,
            _principal_id: &PrincipalId,
            _role: Role,
        ) -> Result<(), StoreError> {
            Ok(())
        }

        async fn get_project_permission(
            &self,
            _project_id: &ProjectId,
            _principal_id: &PrincipalId,
        ) -> Result<Role, StoreError> {
            Err(StoreError::NotFound)
        }

        async fn list_project_permissions_for_principal(
            &self,
            _principal_id: &PrincipalId,
        ) -> Result<Vec<ProjectPermission>, StoreError> {
            Ok(vec![])
        }

        async fn list_project_permissions(
            &self,
            _project_id: &ProjectId,
        ) -> Result<Vec<ProjectPermission>, StoreError> {
            Ok(vec![])
        }

        async fn remove_project_permission(
            &self,
            _project_id: &ProjectId,
            _principal_id: &PrincipalId,
        ) -> Result<(), StoreError> {
            Ok(())
        }

        async fn set_environment_permission(
            &self,
            _environment_id: &EnvironmentId,
            _principal_id: &PrincipalId,
            _role: Role,
        ) -> Result<(), StoreError> {
            Ok(())
        }

        async fn get_environment_permission(
            &self,
            _environment_id: &EnvironmentId,
            _principal_id: &PrincipalId,
        ) -> Result<Role, StoreError> {
            Err(StoreError::NotFound)
        }

        async fn list_environment_permissions_for_principal(
            &self,
            _principal_id: &PrincipalId,
        ) -> Result<Vec<EnvironmentPermission>, StoreError> {
            Ok(vec![])
        }

        async fn list_environment_permissions(
            &self,
            _environment_id: &EnvironmentId,
        ) -> Result<Vec<EnvironmentPermission>, StoreError> {
            Ok(vec![])
        }

        async fn remove_environment_permission(
            &self,
            _environment_id: &EnvironmentId,
            _principal_id: &PrincipalId,
        ) -> Result<(), StoreError> {
            Ok(())
        }

        async fn set_user_workspace_permission(
            &self,
            _workspace_id: &WorkspaceId,
            _user_id: &UserId,
            _role: Role,
        ) -> Result<(), StoreError> {
            Ok(())
        }

        async fn get_user_workspace_permission(
            &self,
            _workspace_id: &WorkspaceId,
            _user_id: &UserId,
        ) -> Result<Role, StoreError> {
            Err(StoreError::NotFound)
        }

        async fn list_user_workspace_permissions(
            &self,
            _workspace_id: &WorkspaceId,
        ) -> Result<Vec<UserWorkspacePermission>, StoreError> {
            Ok(vec![])
        }

        async fn remove_user_workspace_permission(
            &self,
            _workspace_id: &WorkspaceId,
            _user_id: &UserId,
        ) -> Result<(), StoreError> {
            Ok(())
        }

        async fn set_user_project_permission(
            &self,
            _project_id: &ProjectId,
            _user_id: &UserId,
            _role: Role,
        ) -> Result<(), StoreError> {
            Ok(())
        }

        async fn get_user_project_permission(
            &self,
            _project_id: &ProjectId,
            _user_id: &UserId,
        ) -> Result<Role, StoreError> {
            Err(StoreError::NotFound)
        }

        async fn list_user_project_permissions(
            &self,
            _project_id: &ProjectId,
        ) -> Result<Vec<UserProjectPermission>, StoreError> {
            Ok(vec![])
        }

        async fn remove_user_project_permission(
            &self,
            _project_id: &ProjectId,
            _user_id: &UserId,
        ) -> Result<(), StoreError> {
            Ok(())
        }

        async fn set_user_environment_permission(
            &self,
            _environment_id: &EnvironmentId,
            _user_id: &UserId,
            _role: Role,
        ) -> Result<(), StoreError> {
            Ok(())
        }

        async fn get_user_environment_permission(
            &self,
            _environment_id: &EnvironmentId,
            _user_id: &UserId,
        ) -> Result<Role, StoreError> {
            Err(StoreError::NotFound)
        }

        async fn list_user_environment_permissions(
            &self,
            _environment_id: &EnvironmentId,
        ) -> Result<Vec<UserEnvironmentPermission>, StoreError> {
            Ok(vec![])
        }

        async fn remove_user_environment_permission(
            &self,
            _environment_id: &EnvironmentId,
            _user_id: &UserId,
        ) -> Result<(), StoreError> {
            Ok(())
        }

        async fn create_group(&self, _params: &CreateGroupParams) -> Result<GroupId, StoreError> {
            Ok(GroupId(Uuid::new_v4()))
        }

        async fn get_group(&self, _group_id: &GroupId) -> Result<Group, StoreError> {
            Err(StoreError::NotFound)
        }

        async fn get_group_by_name(
            &self,
            _workspace_id: &WorkspaceId,
            _name: &str,
        ) -> Result<Group, StoreError> {
            Err(StoreError::NotFound)
        }

        async fn list_groups(&self, _workspace_id: &WorkspaceId) -> Result<Vec<Group>, StoreError> {
            Ok(vec![])
        }

        async fn update_group(
            &self,
            _group_id: &GroupId,
            _name: &str,
            _description: Option<String>,
        ) -> Result<(), StoreError> {
            Ok(())
        }

        async fn delete_group(&self, _group_id: &GroupId) -> Result<(), StoreError> {
            Ok(())
        }

        async fn add_group_member(
            &self,
            _group_id: &GroupId,
            _user_id: &UserId,
        ) -> Result<(), StoreError> {
            Ok(())
        }

        async fn remove_group_member(
            &self,
            _group_id: &GroupId,
            _user_id: &UserId,
        ) -> Result<(), StoreError> {
            Ok(())
        }

        async fn list_group_members(
            &self,
            _group_id: &GroupId,
        ) -> Result<Vec<GroupMember>, StoreError> {
            Ok(vec![])
        }

        async fn list_user_groups(&self, _user_id: &UserId) -> Result<Vec<Group>, StoreError> {
            Ok(vec![])
        }

        async fn set_group_workspace_permission(
            &self,
            _workspace_id: &WorkspaceId,
            _group_id: &GroupId,
            _role: Role,
        ) -> Result<(), StoreError> {
            Ok(())
        }

        async fn get_group_workspace_permission(
            &self,
            _workspace_id: &WorkspaceId,
            _group_id: &GroupId,
        ) -> Result<Role, StoreError> {
            Err(StoreError::NotFound)
        }

        async fn list_group_workspace_permissions(
            &self,
            _workspace_id: &WorkspaceId,
        ) -> Result<Vec<GroupWorkspacePermission>, StoreError> {
            Ok(vec![])
        }

        async fn remove_group_workspace_permission(
            &self,
            _workspace_id: &WorkspaceId,
            _group_id: &GroupId,
        ) -> Result<(), StoreError> {
            Ok(())
        }

        async fn set_group_project_permission(
            &self,
            _project_id: &ProjectId,
            _group_id: &GroupId,
            _role: Role,
        ) -> Result<(), StoreError> {
            Ok(())
        }

        async fn get_group_project_permission(
            &self,
            _project_id: &ProjectId,
            _group_id: &GroupId,
        ) -> Result<Role, StoreError> {
            Err(StoreError::NotFound)
        }

        async fn list_group_project_permissions(
            &self,
            _project_id: &ProjectId,
        ) -> Result<Vec<GroupProjectPermission>, StoreError> {
            Ok(vec![])
        }

        async fn remove_group_project_permission(
            &self,
            _project_id: &ProjectId,
            _group_id: &GroupId,
        ) -> Result<(), StoreError> {
            Ok(())
        }

        async fn set_group_environment_permission(
            &self,
            _environment_id: &EnvironmentId,
            _group_id: &GroupId,
            _role: Role,
        ) -> Result<(), StoreError> {
            Ok(())
        }

        async fn get_group_environment_permission(
            &self,
            _environment_id: &EnvironmentId,
            _group_id: &GroupId,
        ) -> Result<Role, StoreError> {
            Err(StoreError::NotFound)
        }

        async fn list_group_environment_permissions(
            &self,
            _environment_id: &EnvironmentId,
        ) -> Result<Vec<GroupEnvironmentPermission>, StoreError> {
            Ok(vec![])
        }

        async fn remove_group_environment_permission(
            &self,
            _environment_id: &EnvironmentId,
            _group_id: &GroupId,
        ) -> Result<(), StoreError> {
            Ok(())
        }

        async fn create_organization(
            &self,
            _params: &CreateOrganizationParams,
        ) -> Result<OrganizationId, StoreError> {
            Ok(OrganizationId(Uuid::new_v4()))
        }

        async fn get_organization(
            &self,
            _org_id: &OrganizationId,
        ) -> Result<Organization, StoreError> {
            Err(StoreError::NotFound)
        }

        async fn get_organization_by_slug(&self, _slug: &str) -> Result<Organization, StoreError> {
            Err(StoreError::NotFound)
        }

        async fn list_user_organizations(
            &self,
            _user_id: &UserId,
        ) -> Result<Vec<Organization>, StoreError> {
            Ok(vec![])
        }

        async fn update_organization(
            &self,
            _org_id: &OrganizationId,
            _name: Option<String>,
            _slug: Option<String>,
        ) -> Result<(), StoreError> {
            Ok(())
        }

        async fn set_organization_stripe_customer(
            &self,
            _org_id: &OrganizationId,
            _stripe_customer_id: &str,
        ) -> Result<(), StoreError> {
            Ok(())
        }

        async fn set_organization_plan(
            &self,
            _org_id: &OrganizationId,
            _plan: Plan,
            _seat_limit: i32,
        ) -> Result<(), StoreError> {
            Ok(())
        }

        async fn delete_organization(&self, _org_id: &OrganizationId) -> Result<(), StoreError> {
            Ok(())
        }

        async fn add_organization_member(
            &self,
            _org_id: &OrganizationId,
            _user_id: &UserId,
            _role: OrganizationRole,
            _invited_by: Option<UserId>,
        ) -> Result<(), StoreError> {
            Ok(())
        }

        async fn get_organization_member(
            &self,
            _org_id: &OrganizationId,
            _user_id: &UserId,
        ) -> Result<OrganizationMember, StoreError> {
            Err(StoreError::NotFound)
        }

        async fn list_organization_members(
            &self,
            _org_id: &OrganizationId,
        ) -> Result<Vec<OrganizationMember>, StoreError> {
            Ok(vec![])
        }

        async fn update_organization_member_role(
            &self,
            _org_id: &OrganizationId,
            _user_id: &UserId,
            _role: OrganizationRole,
        ) -> Result<(), StoreError> {
            Ok(())
        }

        async fn remove_organization_member(
            &self,
            _org_id: &OrganizationId,
            _user_id: &UserId,
        ) -> Result<(), StoreError> {
            Ok(())
        }

        async fn count_organization_members(
            &self,
            _org_id: &OrganizationId,
        ) -> Result<i32, StoreError> {
            Ok(0)
        }

        async fn create_organization_invite(
            &self,
            params: &CreateOrganizationInviteParams,
        ) -> Result<OrganizationInvite, StoreError> {
            Ok(OrganizationInvite {
                id: OrganizationInviteId(Uuid::new_v4()),
                organization_id: params.organization_id.clone(),
                email: params.email.clone(),
                role: params.role,
                token_hash: params.token_hash.clone(),
                invited_by: params.invited_by.clone(),
                expires_at: params.expires_at,
                created_at: Utc::now(),
            })
        }

        async fn get_organization_invite(
            &self,
            _invite_id: &OrganizationInviteId,
        ) -> Result<OrganizationInvite, StoreError> {
            Err(StoreError::NotFound)
        }

        async fn get_organization_invite_by_token(
            &self,
            _token_hash: &str,
        ) -> Result<OrganizationInvite, StoreError> {
            Err(StoreError::NotFound)
        }

        async fn list_organization_invites(
            &self,
            _org_id: &OrganizationId,
        ) -> Result<Vec<OrganizationInvite>, StoreError> {
            Ok(vec![])
        }

        async fn delete_organization_invite(
            &self,
            _invite_id: &OrganizationInviteId,
        ) -> Result<(), StoreError> {
            Ok(())
        }

        async fn set_workspace_organization(
            &self,
            _workspace_id: &WorkspaceId,
            _org_id: Option<OrganizationId>,
        ) -> Result<(), StoreError> {
            Ok(())
        }

        async fn list_organization_workspaces(
            &self,
            _org_id: &OrganizationId,
        ) -> Result<Vec<Workspace>, StoreError> {
            Ok(vec![])
        }
    }

    #[tokio::test]
    async fn noop_store_compiles_and_runs() {
        let store: &dyn Store = &NoopStore;
        let result = store.get_user_by_email("test@example.com").await;
        assert!(matches!(result, Err(StoreError::NotFound)));
    }
}
