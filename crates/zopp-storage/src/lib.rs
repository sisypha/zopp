//! Storage abstraction for zopp.
//!
//! Backend crates (e.g., zopp-store-sqlite, zopp-store-postgres) implement this trait so
//! `zopp-core` doesn't depend on any specific database engine or schema details.

use chrono::{DateTime, Utc};
use std::str::FromStr;
use thiserror::Error;
use uuid::Uuid;

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

/// Strongly-typed identifiers & names (avoid mixing strings arbitrarily).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct UserId(pub Uuid);

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PrincipalId(pub Uuid);

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct InviteId(pub Uuid);

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct WorkspaceId(pub Uuid);

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ProjectId(pub Uuid);

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ProjectName(pub String);

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct EnvironmentId(pub Uuid);

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct EnvName(pub String);

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct GroupId(pub Uuid);

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PrincipalExportId(pub Uuid);

/// Role for RBAC permissions
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Role {
    Admin,
    Write,
    Read,
}

/// Error type for parsing Role from string
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseRoleError(pub String);

impl std::fmt::Display for ParseRoleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid role: {}", self.0)
    }
}

impl std::error::Error for ParseRoleError {}

impl FromStr for Role {
    type Err = ParseRoleError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "admin" => Ok(Role::Admin),
            "write" => Ok(Role::Write),
            "read" => Ok(Role::Read),
            _ => Err(ParseRoleError(s.to_string())),
        }
    }
}

impl Role {
    pub fn as_str(&self) -> &'static str {
        match self {
            Role::Admin => "admin",
            Role::Write => "write",
            Role::Read => "read",
        }
    }

    /// Check if this role has at least the permissions of another role
    pub fn includes(&self, other: &Role) -> bool {
        match self {
            Role::Admin => true, // Admin includes all permissions
            Role::Write => matches!(other, Role::Write | Role::Read),
            Role::Read => matches!(other, Role::Read),
        }
    }
}

/// Workspace-level permission
#[derive(Clone, Debug)]
pub struct WorkspacePermission {
    pub workspace_id: WorkspaceId,
    pub principal_id: PrincipalId,
    pub role: Role,
    pub created_at: DateTime<Utc>,
}

/// Project-level permission
#[derive(Clone, Debug)]
pub struct ProjectPermission {
    pub project_id: ProjectId,
    pub principal_id: PrincipalId,
    pub role: Role,
    pub created_at: DateTime<Utc>,
}

/// Environment-level permission (principal)
#[derive(Clone, Debug)]
pub struct EnvironmentPermission {
    pub environment_id: EnvironmentId,
    pub principal_id: PrincipalId,
    pub role: Role,
    pub created_at: DateTime<Utc>,
}

/// User workspace-level permission
#[derive(Clone, Debug)]
pub struct UserWorkspacePermission {
    pub workspace_id: WorkspaceId,
    pub user_id: UserId,
    pub role: Role,
    pub created_at: DateTime<Utc>,
}

/// User project-level permission
#[derive(Clone, Debug)]
pub struct UserProjectPermission {
    pub project_id: ProjectId,
    pub user_id: UserId,
    pub role: Role,
    pub created_at: DateTime<Utc>,
}

/// User environment-level permission
#[derive(Clone, Debug)]
pub struct UserEnvironmentPermission {
    pub environment_id: EnvironmentId,
    pub user_id: UserId,
    pub role: Role,
    pub created_at: DateTime<Utc>,
}

/// Group record
#[derive(Clone, Debug)]
pub struct Group {
    pub id: GroupId,
    pub workspace_id: WorkspaceId,
    pub name: String,
    pub description: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Group membership record
#[derive(Clone, Debug)]
pub struct GroupMember {
    pub group_id: GroupId,
    pub user_id: UserId,
    pub created_at: DateTime<Utc>,
}

/// Group workspace-level permission
#[derive(Clone, Debug)]
pub struct GroupWorkspacePermission {
    pub workspace_id: WorkspaceId,
    pub group_id: GroupId,
    pub role: Role,
    pub created_at: DateTime<Utc>,
}

/// Group project-level permission
#[derive(Clone, Debug)]
pub struct GroupProjectPermission {
    pub project_id: ProjectId,
    pub group_id: GroupId,
    pub role: Role,
    pub created_at: DateTime<Utc>,
}

/// Group environment-level permission
#[derive(Clone, Debug)]
pub struct GroupEnvironmentPermission {
    pub environment_id: EnvironmentId,
    pub group_id: GroupId,
    pub role: Role,
    pub created_at: DateTime<Utc>,
}

/// Parameters for creating a group
#[derive(Clone, Debug)]
pub struct CreateGroupParams {
    pub workspace_id: WorkspaceId,
    pub name: String,
    pub description: Option<String>,
}

/// Encrypted secret row (nonce + ciphertext); no plaintext in storage.
#[derive(Clone, Debug)]
pub struct SecretRow {
    pub nonce: Vec<u8>,      // 24 bytes (XChaCha20 nonce)
    pub ciphertext: Vec<u8>, // AEAD ciphertext
}

/// Parameters for creating a user
#[derive(Clone, Debug)]
pub struct CreateUserParams {
    pub email: String,
    /// Optional principal to create atomically with the user
    pub principal: Option<CreatePrincipalData>,
    /// Workspaces to add this user to (user-level membership)
    pub workspace_ids: Vec<WorkspaceId>,
}

/// Principal data for atomic user creation
#[derive(Clone, Debug)]
pub struct CreatePrincipalData {
    pub name: String,
    pub public_key: Vec<u8>,                // Ed25519 for authentication
    pub x25519_public_key: Option<Vec<u8>>, // X25519 for encryption (ECDH)
    pub is_service: bool,                   // Service principal (user_id will be NULL)
}

/// Parameters for creating a principal
#[derive(Clone, Debug)]
pub struct CreatePrincipalParams {
    pub user_id: Option<UserId>, // None for service accounts
    pub name: String,
    pub public_key: Vec<u8>,                // Ed25519 for authentication
    pub x25519_public_key: Option<Vec<u8>>, // X25519 for encryption (ECDH)
}

/// Parameters for creating a workspace
#[derive(Clone, Debug)]
pub struct CreateWorkspaceParams {
    pub id: WorkspaceId, // Client-generated workspace ID
    pub name: String,
    pub owner_user_id: UserId,
    pub kdf_salt: Vec<u8>, // >= 16 bytes
    pub m_cost_kib: u32,   // memory cost (KiB)
    pub t_cost: u32,       // iterations
    pub p_cost: u32,       // parallelism
}

/// Parameters for creating an invite
#[derive(Clone, Debug)]
pub struct CreateInviteParams {
    pub workspace_ids: Vec<WorkspaceId>,
    pub token: String,                  // Hash of invite secret (for lookup)
    pub kek_encrypted: Option<Vec<u8>>, // Workspace KEK encrypted with invite secret
    pub kek_nonce: Option<Vec<u8>>,     // 24-byte nonce for KEK encryption
    pub expires_at: DateTime<Utc>,
    pub created_by_user_id: Option<UserId>, // None for server-created invites
}

/// Parameters for creating a project
#[derive(Clone, Debug)]
pub struct CreateProjectParams {
    pub workspace_id: WorkspaceId,
    pub name: String,
}

/// Parameters for creating an environment
#[derive(Clone, Debug)]
pub struct CreateEnvParams {
    pub project_id: ProjectId,
    pub name: String,
    pub dek_wrapped: Vec<u8>, // wrapped DEK
    pub dek_nonce: Vec<u8>,   // 24-byte nonce used in wrapping
}

/// User record
#[derive(Clone, Debug)]
pub struct User {
    pub id: UserId,
    pub email: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Principal (device or service account) record
#[derive(Clone, Debug)]
pub struct Principal {
    pub id: PrincipalId,
    pub user_id: Option<UserId>, // None for service accounts
    pub name: String,
    pub public_key: Vec<u8>,                // Ed25519 for authentication
    pub x25519_public_key: Option<Vec<u8>>, // X25519 for encryption (ECDH)
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Invite record
#[derive(Clone, Debug)]
pub struct Invite {
    pub id: InviteId,
    pub token: String,
    pub workspace_ids: Vec<WorkspaceId>,
    pub kek_encrypted: Option<Vec<u8>>, // Workspace KEK encrypted with invite secret
    pub kek_nonce: Option<Vec<u8>>,     // 24-byte nonce for KEK encryption
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub created_by_user_id: Option<UserId>, // None for server-created invites
}

/// Workspace record
#[derive(Clone, Debug)]
pub struct Workspace {
    pub id: WorkspaceId,
    pub name: String,
    pub owner_user_id: UserId,
    pub kdf_salt: Vec<u8>,
    pub m_cost_kib: u32,
    pub t_cost: u32,
    pub p_cost: u32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Workspace-Principal junction with wrapped KEK
#[derive(Clone, Debug)]
pub struct WorkspacePrincipal {
    pub workspace_id: WorkspaceId,
    pub principal_id: PrincipalId,
    pub ephemeral_pub: Vec<u8>, // Ephemeral X25519 public key for wrapping
    pub kek_wrapped: Vec<u8>,   // Workspace KEK wrapped for this principal
    pub kek_nonce: Vec<u8>,     // 24-byte nonce for wrapping
    pub created_at: DateTime<Utc>,
}

/// Parameters for adding a principal to a workspace with wrapped KEK
#[derive(Clone, Debug)]
pub struct AddWorkspacePrincipalParams {
    pub workspace_id: WorkspaceId,
    pub principal_id: PrincipalId,
    pub ephemeral_pub: Vec<u8>,
    pub kek_wrapped: Vec<u8>,
    pub kek_nonce: Vec<u8>,
}

/// Project record
#[derive(Clone, Debug)]
pub struct Project {
    pub id: ProjectId,
    pub workspace_id: WorkspaceId,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Environment record
#[derive(Clone, Debug)]
pub struct Environment {
    pub id: EnvironmentId,
    pub project_id: ProjectId,
    pub name: String,
    pub dek_wrapped: Vec<u8>,
    pub dek_nonce: Vec<u8>,
    pub version: i64, // Monotonic version counter for change tracking
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Principal export record for multi-device transfer
#[derive(Clone, Debug)]
pub struct PrincipalExport {
    pub id: PrincipalExportId,
    pub export_code: String, // Public identifier for lookup (e.g., "exp_a7k9m2x4")
    pub token_hash: String,  // Argon2id(passphrase, verification_salt) for verification
    pub verification_salt: Vec<u8>, // Salt for passphrase verification (separate from encryption)
    pub user_id: UserId,
    pub principal_id: PrincipalId,
    pub encrypted_data: Vec<u8>, // Encrypted principal JSON
    pub salt: Vec<u8>,           // Argon2id salt for encryption key derivation
    pub nonce: Vec<u8>,          // XChaCha20-Poly1305 nonce
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub consumed: bool,
    pub failed_attempts: i32, // Track failed passphrase attempts (delete after 3)
}

/// Parameters for creating a principal export
#[derive(Clone, Debug)]
pub struct CreatePrincipalExportParams {
    pub export_code: String, // Public identifier for lookup (e.g., "exp_a7k9m2x4")
    pub token_hash: String,  // Argon2id(passphrase, verification_salt) for verification
    pub verification_salt: Vec<u8>, // Salt for passphrase verification (separate from encryption)
    pub user_id: UserId,
    pub principal_id: PrincipalId,
    pub encrypted_data: Vec<u8>, // Encrypted principal JSON
    pub salt: Vec<u8>,           // Argon2id salt for encryption key derivation
    pub nonce: Vec<u8>,          // XChaCha20-Poly1305 nonce
    pub expires_at: DateTime<Utc>,
}

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
}

#[cfg(test)]
mod tests {
    use super::*;

    // Tiny compile-time smoke test for trait object usage.
    struct NoopStore;
    #[async_trait::async_trait]
    impl Store for NoopStore {
        async fn create_user(
            &self,
            _params: &CreateUserParams,
        ) -> Result<(UserId, Option<PrincipalId>), StoreError> {
            let user_id = UserId(Uuid::new_v4());
            let principal_id = _params
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

        async fn create_invite(&self, _params: &CreateInviteParams) -> Result<Invite, StoreError> {
            Ok(Invite {
                id: InviteId(Uuid::new_v4()),
                token: "test-token".to_string(),
                workspace_ids: vec![],
                kek_encrypted: None,
                kek_nonce: None,
                created_at: Utc::now(),
                updated_at: Utc::now(),
                expires_at: Utc::now(),
                created_by_user_id: _params.created_by_user_id.clone(),
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

        async fn create_workspace(
            &self,
            _params: &CreateWorkspaceParams,
        ) -> Result<WorkspaceId, StoreError> {
            Ok(WorkspaceId(Uuid::new_v4()))
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

        async fn get_env_wrap(
            &self,
            _ws: &WorkspaceId,
            _project: &ProjectName,
            _env: &EnvName,
        ) -> Result<(Vec<u8>, Vec<u8>), StoreError> {
            Err(StoreError::NotFound)
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

        // User permissions
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
    }

    #[tokio::test]
    async fn trait_smoke() {
        let s = NoopStore;

        let (user_id, _) = s
            .create_user(&CreateUserParams {
                email: "test@example.com".to_string(),
                principal: None,
                workspace_ids: vec![],
            })
            .await
            .unwrap();

        let ws = s
            .create_workspace(&CreateWorkspaceParams {
                id: WorkspaceId(uuid::Uuid::now_v7()),
                name: "test-workspace".to_string(),
                owner_user_id: user_id.clone(),
                kdf_salt: b"0123456789abcdef".to_vec(),
                m_cost_kib: 64 * 1024,
                t_cost: 3,
                p_cost: 1,
            })
            .await
            .unwrap();

        // We can call workspace-scoped methods without compile errors.
        let project_id = s
            .create_project(&CreateProjectParams {
                workspace_id: ws.clone(),
                name: "p1".to_string(),
            })
            .await
            .unwrap();

        let principal_id = PrincipalId(uuid::Uuid::now_v7());
        let _ = s.list_workspaces(&principal_id).await.unwrap();
        let _ = s.list_projects(&ws).await.unwrap();
        let _ = s.get_project(&project_id).await;
    }

    // ───────────────────────────────────── Role Tests ─────────────────────────────────────

    #[test]
    fn test_role_includes_admin() {
        // Admin includes all roles
        assert!(Role::Admin.includes(&Role::Admin));
        assert!(Role::Admin.includes(&Role::Write));
        assert!(Role::Admin.includes(&Role::Read));
    }

    #[test]
    fn test_role_includes_write() {
        // Write includes Write and Read, but not Admin
        assert!(!Role::Write.includes(&Role::Admin));
        assert!(Role::Write.includes(&Role::Write));
        assert!(Role::Write.includes(&Role::Read));
    }

    #[test]
    fn test_role_includes_read() {
        // Read only includes Read
        assert!(!Role::Read.includes(&Role::Admin));
        assert!(!Role::Read.includes(&Role::Write));
        assert!(Role::Read.includes(&Role::Read));
    }

    #[test]
    fn test_role_as_str() {
        assert_eq!(Role::Admin.as_str(), "admin");
        assert_eq!(Role::Write.as_str(), "write");
        assert_eq!(Role::Read.as_str(), "read");
    }

    #[test]
    fn test_role_parse() {
        assert_eq!("admin".parse::<Role>().unwrap(), Role::Admin);
        assert_eq!("write".parse::<Role>().unwrap(), Role::Write);
        assert_eq!("read".parse::<Role>().unwrap(), Role::Read);
    }

    #[test]
    fn test_role_parse_invalid() {
        assert!("invalid".parse::<Role>().is_err());
        assert!("Admin".parse::<Role>().is_err()); // Case sensitive
        assert!("ADMIN".parse::<Role>().is_err());
        assert!("".parse::<Role>().is_err());
    }

    #[test]
    fn test_role_roundtrip() {
        for role in [Role::Admin, Role::Write, Role::Read] {
            let s = role.as_str();
            let parsed: Role = s.parse().unwrap();
            assert_eq!(role, parsed);
        }
    }

    #[test]
    fn test_role_is_copy() {
        let role = Role::Admin;
        let copied = role; // Copy, not move
        assert_eq!(role, copied); // Original still valid
    }

    // ───────────────────────────────────── Typed ID Tests ─────────────────────────────────────

    #[test]
    fn test_user_id_debug() {
        let uuid = Uuid::new_v4();
        let user_id = UserId(uuid);
        assert!(format!("{:?}", user_id).contains(&uuid.to_string()));
    }

    #[test]
    fn test_principal_id_debug() {
        let uuid = Uuid::new_v4();
        let principal_id = PrincipalId(uuid);
        assert!(format!("{:?}", principal_id).contains(&uuid.to_string()));
    }

    #[test]
    fn test_workspace_id_debug() {
        let uuid = Uuid::new_v4();
        let workspace_id = WorkspaceId(uuid);
        assert!(format!("{:?}", workspace_id).contains(&uuid.to_string()));
    }

    #[test]
    fn test_project_id_debug() {
        let uuid = Uuid::new_v4();
        let project_id = ProjectId(uuid);
        assert!(format!("{:?}", project_id).contains(&uuid.to_string()));
    }

    #[test]
    fn test_environment_id_debug() {
        let uuid = Uuid::new_v4();
        let env_id = EnvironmentId(uuid);
        assert!(format!("{:?}", env_id).contains(&uuid.to_string()));
    }

    #[test]
    fn test_group_id_debug() {
        let uuid = Uuid::new_v4();
        let group_id = GroupId(uuid);
        assert!(format!("{:?}", group_id).contains(&uuid.to_string()));
    }

    #[test]
    fn test_typed_ids_equality() {
        let uuid = Uuid::new_v4();
        let user_id1 = UserId(uuid);
        let user_id2 = UserId(uuid);
        assert_eq!(user_id1, user_id2);

        let different_uuid = Uuid::new_v4();
        let user_id3 = UserId(different_uuid);
        assert_ne!(user_id1, user_id3);
    }

    #[test]
    fn test_typed_ids_clone() {
        let uuid = Uuid::new_v4();
        let user_id = UserId(uuid);
        let cloned = user_id.clone();
        assert_eq!(user_id, cloned);
    }

    #[test]
    fn test_typed_ids_inner_access() {
        let uuid = Uuid::new_v4();
        let user_id = UserId(uuid);
        assert_eq!(user_id.0, uuid);

        let principal_id = PrincipalId(uuid);
        assert_eq!(principal_id.0, uuid);

        let workspace_id = WorkspaceId(uuid);
        assert_eq!(workspace_id.0, uuid);

        let project_id = ProjectId(uuid);
        assert_eq!(project_id.0, uuid);

        let env_id = EnvironmentId(uuid);
        assert_eq!(env_id.0, uuid);

        let group_id = GroupId(uuid);
        assert_eq!(group_id.0, uuid);
    }

    #[test]
    fn test_typed_ids_hash() {
        use std::collections::HashSet;

        let uuid = Uuid::new_v4();
        let user_id1 = UserId(uuid);
        let user_id2 = UserId(uuid);

        let mut set = HashSet::new();
        set.insert(user_id1);
        assert!(set.contains(&user_id2));
    }

    // ───────────────────────────────────── StoreError Tests ─────────────────────────────────────

    #[test]
    fn test_store_error_display() {
        let not_found = StoreError::NotFound;
        assert_eq!(not_found.to_string(), "not found");

        let already_exists = StoreError::AlreadyExists;
        assert_eq!(already_exists.to_string(), "already exists");

        let conflict = StoreError::Conflict;
        assert_eq!(conflict.to_string(), "conflict");

        let backend = StoreError::Backend("db failure".to_string());
        assert!(backend.to_string().contains("backend error"));
        assert!(backend.to_string().contains("db failure"));
    }

    #[test]
    fn test_parse_role_error_display() {
        let err = ParseRoleError("unknown".to_string());
        assert!(err.to_string().contains("unknown"));
    }

    // ───────────────────────────────────── Name Wrapper Tests ─────────────────────────────────────

    #[test]
    fn test_env_name_inner_access() {
        let name = EnvName("production".to_string());
        assert_eq!(name.0, "production");
    }

    #[test]
    fn test_project_name_inner_access() {
        let name = ProjectName("backend".to_string());
        assert_eq!(name.0, "backend");
    }

    #[test]
    fn test_env_name_equality() {
        let name1 = EnvName("production".to_string());
        let name2 = EnvName("production".to_string());
        let name3 = EnvName("staging".to_string());
        assert_eq!(name1, name2);
        assert_ne!(name1, name3);
    }

    #[test]
    fn test_project_name_equality() {
        let name1 = ProjectName("backend".to_string());
        let name2 = ProjectName("backend".to_string());
        let name3 = ProjectName("frontend".to_string());
        assert_eq!(name1, name2);
        assert_ne!(name1, name3);
    }

    #[test]
    fn test_invite_id_debug_and_equality() {
        let uuid = Uuid::new_v4();
        let invite_id1 = InviteId(uuid);
        let invite_id2 = InviteId(uuid);
        assert_eq!(invite_id1, invite_id2);
        assert!(format!("{:?}", invite_id1).contains(&uuid.to_string()));
    }
}
