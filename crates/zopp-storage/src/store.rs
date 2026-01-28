//! The Store trait that backends implement.

use crate::types::*;
use crate::SecretRow;
use crate::StoreError;

/// The storage trait `zopp-core` depends on.
///
/// All methods that act on project/env/secrets are **scoped by workspace**.
#[cfg_attr(feature = "test-support", mockall::automock)]
#[async_trait::async_trait]
pub trait Store: Send + Sync {
    // ───────────────────────────────────── Users ──────────────────────────────────────────

    /// Create a new user (returns generated ID, and optional principal ID if principal was provided).
    /// If params.principal is provided, atomically creates the user, principal, and adds principal to workspaces.
    async fn create_user(
        &self,
        params: &CreateUserParams,
    ) -> Result<(UserId, Option<PrincipalId>), StoreError>;

    /// Get user by email.
    async fn get_user_by_email(&self, email: &str) -> Result<User, StoreError>;

    /// Get user by ID.
    async fn get_user_by_id(&self, user_id: &UserId) -> Result<User, StoreError>;

    // ───────────────────────────────────── Principals ─────────────────────────────────────

    /// Create a new principal (device) for a user.
    async fn create_principal(
        &self,
        params: &CreatePrincipalParams,
    ) -> Result<PrincipalId, StoreError>;

    /// Get principal by ID.
    async fn get_principal(&self, principal_id: &PrincipalId) -> Result<Principal, StoreError>;

    /// Rename a principal.
    async fn rename_principal(
        &self,
        principal_id: &PrincipalId,
        new_name: &str,
    ) -> Result<(), StoreError>;

    /// List all principals for a user.
    async fn list_principals(&self, user_id: &UserId) -> Result<Vec<Principal>, StoreError>;

    // ───────────────────────────────────── Invites ────────────────────────────────────────

    /// Create an invite token (returns generated ID and token).
    async fn create_invite(&self, params: &CreateInviteParams) -> Result<Invite, StoreError>;

    /// Get invite by token.
    async fn get_invite_by_token(&self, token: &str) -> Result<Invite, StoreError>;

    /// List all active invites for a user (None = server invites).
    async fn list_invites(&self, user_id: Option<UserId>) -> Result<Vec<Invite>, StoreError>;

    /// Revoke an invite.
    async fn revoke_invite(&self, invite_id: &InviteId) -> Result<(), StoreError>;

    /// Mark an invite as consumed (used).
    async fn consume_invite(&self, token: &str) -> Result<(), StoreError>;

    // ───────────────────────────────────── Principal Exports ──────────────────────────────

    /// Create a principal export for multi-device transfer.
    async fn create_principal_export(
        &self,
        params: &CreatePrincipalExportParams,
    ) -> Result<PrincipalExport, StoreError>;

    /// Get principal export by export code.
    async fn get_principal_export_by_code(
        &self,
        export_code: &str,
    ) -> Result<PrincipalExport, StoreError>;

    /// Mark a principal export as consumed (can only be used once).
    async fn consume_principal_export(
        &self,
        export_id: &PrincipalExportId,
    ) -> Result<(), StoreError>;

    /// Increment failed attempts counter for a principal export.
    /// Returns the new failed_attempts count.
    async fn increment_export_failed_attempts(
        &self,
        export_id: &PrincipalExportId,
    ) -> Result<i32, StoreError>;

    /// Delete a principal export (used after 3 failed attempts or manual cleanup).
    async fn delete_principal_export(
        &self,
        export_id: &PrincipalExportId,
    ) -> Result<(), StoreError>;

    // ───────────────────────────────────── Email Verification ──────────────────────────────

    /// Create an email verification record.
    async fn create_email_verification(
        &self,
        params: &CreateEmailVerificationParams,
    ) -> Result<EmailVerification, StoreError>;

    /// Get the latest pending email verification for an email address.
    async fn get_email_verification(&self, email: &str) -> Result<EmailVerification, StoreError>;

    /// Increment the failed attempts counter for an email verification.
    /// Returns the new attempts count.
    async fn increment_email_verification_attempts(
        &self,
        id: &EmailVerificationId,
    ) -> Result<i32, StoreError>;

    /// Delete an email verification (used after successful verification or manual cleanup).
    async fn delete_email_verification(&self, id: &EmailVerificationId) -> Result<(), StoreError>;

    /// Delete all expired email verifications.
    /// Returns the number of deleted records.
    async fn cleanup_expired_email_verifications(&self) -> Result<u64, StoreError>;

    /// Mark a user as verified (email ownership confirmed).
    async fn mark_user_verified(&self, user_id: &UserId) -> Result<(), StoreError>;

    // ───────────────────────────────────── Workspaces ─────────────────────────────────────

    /// Create a new workspace (returns its generated ID).
    async fn create_workspace(
        &self,
        params: &CreateWorkspaceParams,
    ) -> Result<WorkspaceId, StoreError>;

    /// List all workspaces that a principal has KEK access to.
    async fn list_workspaces(
        &self,
        principal_id: &PrincipalId,
    ) -> Result<Vec<Workspace>, StoreError>;

    /// Get workspace by ID.
    async fn get_workspace(&self, ws: &WorkspaceId) -> Result<Workspace, StoreError>;

    /// Get workspace by name for a user (user must have access).
    async fn get_workspace_by_name(
        &self,
        user_id: &UserId,
        name: &str,
    ) -> Result<Workspace, StoreError>;

    /// Get workspace by name for a principal (principal must have access).
    async fn get_workspace_by_name_for_principal(
        &self,
        principal_id: &PrincipalId,
        name: &str,
    ) -> Result<Workspace, StoreError>;

    /// Add a principal to a workspace with wrapped KEK.
    async fn add_workspace_principal(
        &self,
        params: &AddWorkspacePrincipalParams,
    ) -> Result<(), StoreError>;

    /// Get workspace principal (to access wrapped KEK).
    async fn get_workspace_principal(
        &self,
        workspace_id: &WorkspaceId,
        principal_id: &PrincipalId,
    ) -> Result<WorkspacePrincipal, StoreError>;

    /// List all principals in a workspace (with their wrapped KEKs).
    async fn list_workspace_principals(
        &self,
        workspace_id: &WorkspaceId,
    ) -> Result<Vec<WorkspacePrincipal>, StoreError>;

    /// Remove a principal from a workspace.
    async fn remove_workspace_principal(
        &self,
        workspace_id: &WorkspaceId,
        principal_id: &PrincipalId,
    ) -> Result<(), StoreError>;

    /// Remove all project permissions for a principal in a workspace.
    /// Returns the number of permissions removed.
    async fn remove_all_project_permissions_for_principal(
        &self,
        workspace_id: &WorkspaceId,
        principal_id: &PrincipalId,
    ) -> Result<u32, StoreError>;

    /// Remove all environment permissions for a principal in a workspace.
    /// Returns the number of permissions removed.
    async fn remove_all_environment_permissions_for_principal(
        &self,
        workspace_id: &WorkspaceId,
        principal_id: &PrincipalId,
    ) -> Result<u32, StoreError>;

    /// Add a user to a workspace (user-level membership).
    async fn add_user_to_workspace(
        &self,
        workspace_id: &WorkspaceId,
        user_id: &UserId,
    ) -> Result<(), StoreError>;

    // ───────────────────────────────────── Projects ───────────────────────────────────────

    /// Create a project within a workspace (returns generated ID).
    async fn create_project(&self, params: &CreateProjectParams) -> Result<ProjectId, StoreError>;

    /// List all projects in a workspace.
    async fn list_projects(&self, workspace_id: &WorkspaceId) -> Result<Vec<Project>, StoreError>;

    /// Get a project by ID.
    async fn get_project(&self, project_id: &ProjectId) -> Result<Project, StoreError>;

    /// Get a project by name within a workspace.
    async fn get_project_by_name(
        &self,
        workspace_id: &WorkspaceId,
        name: &str,
    ) -> Result<Project, StoreError>;

    /// Delete a project (and all its environments and secrets).
    async fn delete_project(&self, project_id: &ProjectId) -> Result<(), StoreError>;

    // ─────────────────────────────────────── Environments ─────────────────────────────────────

    /// Create an environment within a project (returns generated ID).
    async fn create_env(&self, params: &CreateEnvParams) -> Result<EnvironmentId, StoreError>;

    /// List all environments in a project.
    async fn list_environments(
        &self,
        project_id: &ProjectId,
    ) -> Result<Vec<Environment>, StoreError>;

    /// Get an environment by ID.
    async fn get_environment(&self, env_id: &EnvironmentId) -> Result<Environment, StoreError>;

    /// Get an environment by name within a project.
    async fn get_environment_by_name(
        &self,
        project_id: &ProjectId,
        name: &str,
    ) -> Result<Environment, StoreError>;

    /// Delete an environment (and all its secrets).
    async fn delete_environment(&self, env_id: &EnvironmentId) -> Result<(), StoreError>;

    // ────────────────────────────────────── Secrets ───────────────────────────────────────

    /// Upsert a secret value (AEAD ciphertext + nonce) in an environment.
    /// Returns the new environment version after the update.
    async fn upsert_secret(
        &self,
        env_id: &EnvironmentId,
        key: &str,
        nonce: &[u8],      // per-value 24B nonce
        ciphertext: &[u8], // AEAD ciphertext under DEK
    ) -> Result<i64, StoreError>;

    /// Fetch a secret row (nonce + ciphertext).
    async fn get_secret(&self, env_id: &EnvironmentId, key: &str) -> Result<SecretRow, StoreError>;

    /// List all secret keys in an environment.
    async fn list_secret_keys(&self, env_id: &EnvironmentId) -> Result<Vec<String>, StoreError>;

    /// Delete a secret from an environment.
    /// Returns the new environment version after the deletion.
    async fn delete_secret(&self, env_id: &EnvironmentId, key: &str) -> Result<i64, StoreError>;

    /// Fetch the (wrapped_dek, dek_nonce) pair for an environment so core can unwrap it (legacy name-based).
    async fn get_env_wrap(
        &self,
        ws: &WorkspaceId,
        project: &ProjectName,
        env: &EnvName,
    ) -> Result<(Vec<u8>, Vec<u8>), StoreError>;

    // ────────────────────────────────────── RBAC Permissions ──────────────────────────────────

    /// Set workspace-level permission for a principal
    async fn set_workspace_permission(
        &self,
        workspace_id: &WorkspaceId,
        principal_id: &PrincipalId,
        role: Role,
    ) -> Result<(), StoreError>;

    /// Get workspace-level permission for a principal
    async fn get_workspace_permission(
        &self,
        workspace_id: &WorkspaceId,
        principal_id: &PrincipalId,
    ) -> Result<Role, StoreError>;

    /// List all workspace permissions for a principal
    async fn list_workspace_permissions_for_principal(
        &self,
        principal_id: &PrincipalId,
    ) -> Result<Vec<WorkspacePermission>, StoreError>;

    /// List all principals with permissions on a workspace
    async fn list_workspace_permissions(
        &self,
        workspace_id: &WorkspaceId,
    ) -> Result<Vec<WorkspacePermission>, StoreError>;

    /// Remove workspace-level permission for a principal
    async fn remove_workspace_permission(
        &self,
        workspace_id: &WorkspaceId,
        principal_id: &PrincipalId,
    ) -> Result<(), StoreError>;

    /// Set project-level permission for a principal
    async fn set_project_permission(
        &self,
        project_id: &ProjectId,
        principal_id: &PrincipalId,
        role: Role,
    ) -> Result<(), StoreError>;

    /// Get project-level permission for a principal
    async fn get_project_permission(
        &self,
        project_id: &ProjectId,
        principal_id: &PrincipalId,
    ) -> Result<Role, StoreError>;

    /// List all project permissions for a principal
    async fn list_project_permissions_for_principal(
        &self,
        principal_id: &PrincipalId,
    ) -> Result<Vec<ProjectPermission>, StoreError>;

    /// List all principals with permissions on a project
    async fn list_project_permissions(
        &self,
        project_id: &ProjectId,
    ) -> Result<Vec<ProjectPermission>, StoreError>;

    /// Remove project-level permission for a principal
    async fn remove_project_permission(
        &self,
        project_id: &ProjectId,
        principal_id: &PrincipalId,
    ) -> Result<(), StoreError>;

    /// Set environment-level permission for a principal
    async fn set_environment_permission(
        &self,
        environment_id: &EnvironmentId,
        principal_id: &PrincipalId,
        role: Role,
    ) -> Result<(), StoreError>;

    /// Get environment-level permission for a principal
    async fn get_environment_permission(
        &self,
        environment_id: &EnvironmentId,
        principal_id: &PrincipalId,
    ) -> Result<Role, StoreError>;

    /// List all environment permissions for a principal
    async fn list_environment_permissions_for_principal(
        &self,
        principal_id: &PrincipalId,
    ) -> Result<Vec<EnvironmentPermission>, StoreError>;

    /// List all principals with permissions on an environment
    async fn list_environment_permissions(
        &self,
        environment_id: &EnvironmentId,
    ) -> Result<Vec<EnvironmentPermission>, StoreError>;

    /// Remove environment-level permission for a principal
    async fn remove_environment_permission(
        &self,
        environment_id: &EnvironmentId,
        principal_id: &PrincipalId,
    ) -> Result<(), StoreError>;

    // ────────────────────────────────────── User Permissions ────────────────────────────────────────

    /// Set workspace-level permission for a user
    async fn set_user_workspace_permission(
        &self,
        workspace_id: &WorkspaceId,
        user_id: &UserId,
        role: Role,
    ) -> Result<(), StoreError>;

    /// Get workspace-level permission for a user
    async fn get_user_workspace_permission(
        &self,
        workspace_id: &WorkspaceId,
        user_id: &UserId,
    ) -> Result<Role, StoreError>;

    /// List all user permissions on a workspace
    async fn list_user_workspace_permissions(
        &self,
        workspace_id: &WorkspaceId,
    ) -> Result<Vec<UserWorkspacePermission>, StoreError>;

    /// Remove workspace-level permission for a user
    async fn remove_user_workspace_permission(
        &self,
        workspace_id: &WorkspaceId,
        user_id: &UserId,
    ) -> Result<(), StoreError>;

    /// Set project-level permission for a user
    async fn set_user_project_permission(
        &self,
        project_id: &ProjectId,
        user_id: &UserId,
        role: Role,
    ) -> Result<(), StoreError>;

    /// Get project-level permission for a user
    async fn get_user_project_permission(
        &self,
        project_id: &ProjectId,
        user_id: &UserId,
    ) -> Result<Role, StoreError>;

    /// List all user permissions on a project
    async fn list_user_project_permissions(
        &self,
        project_id: &ProjectId,
    ) -> Result<Vec<UserProjectPermission>, StoreError>;

    /// Remove project-level permission for a user
    async fn remove_user_project_permission(
        &self,
        project_id: &ProjectId,
        user_id: &UserId,
    ) -> Result<(), StoreError>;

    /// Set environment-level permission for a user
    async fn set_user_environment_permission(
        &self,
        environment_id: &EnvironmentId,
        user_id: &UserId,
        role: Role,
    ) -> Result<(), StoreError>;

    /// Get environment-level permission for a user
    async fn get_user_environment_permission(
        &self,
        environment_id: &EnvironmentId,
        user_id: &UserId,
    ) -> Result<Role, StoreError>;

    /// List all user permissions on an environment
    async fn list_user_environment_permissions(
        &self,
        environment_id: &EnvironmentId,
    ) -> Result<Vec<UserEnvironmentPermission>, StoreError>;

    /// Remove environment-level permission for a user
    async fn remove_user_environment_permission(
        &self,
        environment_id: &EnvironmentId,
        user_id: &UserId,
    ) -> Result<(), StoreError>;

    // ────────────────────────────────────── Groups ────────────────────────────────────────

    /// Create a new group within a workspace
    async fn create_group(&self, params: &CreateGroupParams) -> Result<GroupId, StoreError>;

    /// Get group by ID
    async fn get_group(&self, group_id: &GroupId) -> Result<Group, StoreError>;

    /// Get group by name within a workspace
    async fn get_group_by_name(
        &self,
        workspace_id: &WorkspaceId,
        name: &str,
    ) -> Result<Group, StoreError>;

    /// List all groups in a workspace
    async fn list_groups(&self, workspace_id: &WorkspaceId) -> Result<Vec<Group>, StoreError>;

    /// Update group description
    async fn update_group(
        &self,
        group_id: &GroupId,
        name: &str,
        description: Option<String>,
    ) -> Result<(), StoreError>;

    /// Delete a group (and all its memberships and permissions)
    async fn delete_group(&self, group_id: &GroupId) -> Result<(), StoreError>;

    /// Add a user to a group
    async fn add_group_member(
        &self,
        group_id: &GroupId,
        user_id: &UserId,
    ) -> Result<(), StoreError>;

    /// Remove a user from a group
    async fn remove_group_member(
        &self,
        group_id: &GroupId,
        user_id: &UserId,
    ) -> Result<(), StoreError>;

    /// List all members of a group
    async fn list_group_members(&self, group_id: &GroupId) -> Result<Vec<GroupMember>, StoreError>;

    /// List all groups a user belongs to
    async fn list_user_groups(&self, user_id: &UserId) -> Result<Vec<Group>, StoreError>;

    /// Set workspace-level permission for a group
    async fn set_group_workspace_permission(
        &self,
        workspace_id: &WorkspaceId,
        group_id: &GroupId,
        role: Role,
    ) -> Result<(), StoreError>;

    /// Get workspace-level permission for a group
    async fn get_group_workspace_permission(
        &self,
        workspace_id: &WorkspaceId,
        group_id: &GroupId,
    ) -> Result<Role, StoreError>;

    /// List all workspace permissions for a group
    async fn list_group_workspace_permissions(
        &self,
        workspace_id: &WorkspaceId,
    ) -> Result<Vec<GroupWorkspacePermission>, StoreError>;

    /// Remove workspace-level permission for a group
    async fn remove_group_workspace_permission(
        &self,
        workspace_id: &WorkspaceId,
        group_id: &GroupId,
    ) -> Result<(), StoreError>;

    /// Set project-level permission for a group
    async fn set_group_project_permission(
        &self,
        project_id: &ProjectId,
        group_id: &GroupId,
        role: Role,
    ) -> Result<(), StoreError>;

    /// Get project-level permission for a group
    async fn get_group_project_permission(
        &self,
        project_id: &ProjectId,
        group_id: &GroupId,
    ) -> Result<Role, StoreError>;

    /// List all project permissions for a group
    async fn list_group_project_permissions(
        &self,
        project_id: &ProjectId,
    ) -> Result<Vec<GroupProjectPermission>, StoreError>;

    /// Remove project-level permission for a group
    async fn remove_group_project_permission(
        &self,
        project_id: &ProjectId,
        group_id: &GroupId,
    ) -> Result<(), StoreError>;

    /// Set environment-level permission for a group
    async fn set_group_environment_permission(
        &self,
        environment_id: &EnvironmentId,
        group_id: &GroupId,
        role: Role,
    ) -> Result<(), StoreError>;

    /// Get environment-level permission for a group
    async fn get_group_environment_permission(
        &self,
        environment_id: &EnvironmentId,
        group_id: &GroupId,
    ) -> Result<Role, StoreError>;

    /// List all environment permissions for a group
    async fn list_group_environment_permissions(
        &self,
        environment_id: &EnvironmentId,
    ) -> Result<Vec<GroupEnvironmentPermission>, StoreError>;

    /// Remove environment-level permission for a group
    async fn remove_group_environment_permission(
        &self,
        environment_id: &EnvironmentId,
        group_id: &GroupId,
    ) -> Result<(), StoreError>;

    // ────────────────────────────────────── Organizations ────────────────────────────────────────

    /// Create a new organization (returns generated ID).
    async fn create_organization(
        &self,
        params: &CreateOrganizationParams,
    ) -> Result<OrganizationId, StoreError>;

    /// Get organization by ID.
    async fn get_organization(&self, org_id: &OrganizationId) -> Result<Organization, StoreError>;

    /// Get organization by slug.
    async fn get_organization_by_slug(&self, slug: &str) -> Result<Organization, StoreError>;

    /// List all organizations a user is a member of.
    async fn list_user_organizations(
        &self,
        user_id: &UserId,
    ) -> Result<Vec<Organization>, StoreError>;

    /// Update organization details.
    async fn update_organization(
        &self,
        org_id: &OrganizationId,
        name: Option<String>,
        slug: Option<String>,
    ) -> Result<(), StoreError>;

    /// Update organization's Stripe customer ID.
    async fn set_organization_stripe_customer(
        &self,
        org_id: &OrganizationId,
        stripe_customer_id: &str,
    ) -> Result<(), StoreError>;

    /// Update organization's plan and seat limit.
    async fn set_organization_plan(
        &self,
        org_id: &OrganizationId,
        plan: Plan,
        seat_limit: i32,
    ) -> Result<(), StoreError>;

    /// Delete an organization (cascades to members, invites, settings).
    async fn delete_organization(&self, org_id: &OrganizationId) -> Result<(), StoreError>;

    // ────────────────────────────────────── Organization Members ────────────────────────────────────────

    /// Add a user to an organization with a role.
    async fn add_organization_member(
        &self,
        org_id: &OrganizationId,
        user_id: &UserId,
        role: OrganizationRole,
        invited_by: Option<UserId>,
    ) -> Result<(), StoreError>;

    /// Get a user's membership in an organization.
    async fn get_organization_member(
        &self,
        org_id: &OrganizationId,
        user_id: &UserId,
    ) -> Result<OrganizationMember, StoreError>;

    /// List all members of an organization.
    async fn list_organization_members(
        &self,
        org_id: &OrganizationId,
    ) -> Result<Vec<OrganizationMember>, StoreError>;

    /// Update a member's role in an organization.
    async fn update_organization_member_role(
        &self,
        org_id: &OrganizationId,
        user_id: &UserId,
        role: OrganizationRole,
    ) -> Result<(), StoreError>;

    /// Remove a user from an organization.
    async fn remove_organization_member(
        &self,
        org_id: &OrganizationId,
        user_id: &UserId,
    ) -> Result<(), StoreError>;

    /// Count members in an organization.
    async fn count_organization_members(&self, org_id: &OrganizationId) -> Result<i32, StoreError>;

    // ────────────────────────────────────── Organization Invites ────────────────────────────────────────

    /// Create an organization invite.
    async fn create_organization_invite(
        &self,
        params: &CreateOrganizationInviteParams,
    ) -> Result<OrganizationInvite, StoreError>;

    /// Get an organization invite by ID.
    async fn get_organization_invite(
        &self,
        invite_id: &OrganizationInviteId,
    ) -> Result<OrganizationInvite, StoreError>;

    /// Get an organization invite by token hash.
    async fn get_organization_invite_by_token(
        &self,
        token_hash: &str,
    ) -> Result<OrganizationInvite, StoreError>;

    /// List pending invites for an organization.
    async fn list_organization_invites(
        &self,
        org_id: &OrganizationId,
    ) -> Result<Vec<OrganizationInvite>, StoreError>;

    /// Delete an organization invite (revoke or after consumption).
    async fn delete_organization_invite(
        &self,
        invite_id: &OrganizationInviteId,
    ) -> Result<(), StoreError>;

    // ────────────────────────────────────── Workspace-Organization Link ────────────────────────────────────────

    /// Link a workspace to an organization.
    async fn set_workspace_organization(
        &self,
        workspace_id: &WorkspaceId,
        org_id: Option<OrganizationId>,
    ) -> Result<(), StoreError>;

    /// List workspaces belonging to an organization.
    async fn list_organization_workspaces(
        &self,
        org_id: &OrganizationId,
    ) -> Result<Vec<Workspace>, StoreError>;
}
