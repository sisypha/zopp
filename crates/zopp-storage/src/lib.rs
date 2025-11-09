//! Storage abstraction for zopp.
//!
//! Backend crates (e.g., zopp-store-sqlite, zopp-store-postgres) implement this trait so
//! `zopp-core` doesn't depend on any specific database engine or schema details.

use chrono::{DateTime, Utc};
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
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Optional explicit transaction interface.
/// For simple backends you can stub this out and let methods be atomic.
pub trait Transaction {
    fn commit(self) -> Result<(), StoreError>;
    fn rollback(self) -> Result<(), StoreError>;
}

/// The storage trait `zopp-core` depends on.
///
/// All methods that act on project/env/secrets are **scoped by workspace**.
#[async_trait::async_trait]
pub trait Store {
    type Txn: Transaction;

    // ─────────────────────────────── Lifecycle  ───────────────────────────────

    /// Optional explicit transaction (backends may ignore if not needed).
    async fn begin_txn(&self) -> Result<Self::Txn, StoreError>;

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
    async fn list_invites(&self, user_id: Option<&UserId>) -> Result<Vec<Invite>, StoreError>;

    /// Revoke an invite.
    async fn revoke_invite(&self, invite_id: &InviteId) -> Result<(), StoreError>;

    // ───────────────────────────────────── Workspaces ─────────────────────────────────────

    /// Create a new workspace (returns its generated ID).
    async fn create_workspace(
        &self,
        params: &CreateWorkspaceParams,
    ) -> Result<WorkspaceId, StoreError>;

    /// List all workspaces for a user (via their principals).
    async fn list_workspaces(&self, user_id: &UserId) -> Result<Vec<Workspace>, StoreError>;

    /// Get workspace by ID.
    async fn get_workspace(&self, ws: &WorkspaceId) -> Result<Workspace, StoreError>;

    /// Get workspace by name for a user (user must have access).
    async fn get_workspace_by_name(
        &self,
        user_id: &UserId,
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
    async fn upsert_secret(
        &self,
        env_id: &EnvironmentId,
        key: &str,
        nonce: &[u8],      // per-value 24B nonce
        ciphertext: &[u8], // AEAD ciphertext under DEK
    ) -> Result<(), StoreError>;

    /// Fetch a secret row (nonce + ciphertext).
    async fn get_secret(&self, env_id: &EnvironmentId, key: &str) -> Result<SecretRow, StoreError>;

    /// List all secret keys in an environment.
    async fn list_secret_keys(&self, env_id: &EnvironmentId) -> Result<Vec<String>, StoreError>;

    /// Delete a secret from an environment.
    async fn delete_secret(&self, env_id: &EnvironmentId, key: &str) -> Result<(), StoreError>;

    /// Fetch the (wrapped_dek, dek_nonce) pair for an environment so core can unwrap it (legacy name-based).
    async fn get_env_wrap(
        &self,
        ws: &WorkspaceId,
        project: &ProjectName,
        env: &EnvName,
    ) -> Result<(Vec<u8>, Vec<u8>), StoreError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    // Tiny compile-time smoke test for trait object usage.
    struct NoopTxn;
    impl Transaction for NoopTxn {
        fn commit(self) -> Result<(), StoreError> {
            Ok(())
        }
        fn rollback(self) -> Result<(), StoreError> {
            Ok(())
        }
    }

    struct NoopStore;
    #[async_trait::async_trait]
    impl Store for NoopStore {
        type Txn = NoopTxn;

        async fn begin_txn(&self) -> Result<Self::Txn, StoreError> {
            Ok(NoopTxn)
        }

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

        async fn list_invites(&self, _user_id: Option<&UserId>) -> Result<Vec<Invite>, StoreError> {
            Ok(vec![])
        }

        async fn revoke_invite(&self, _invite_id: &InviteId) -> Result<(), StoreError> {
            Ok(())
        }

        async fn create_workspace(
            &self,
            _params: &CreateWorkspaceParams,
        ) -> Result<WorkspaceId, StoreError> {
            Ok(WorkspaceId(Uuid::new_v4()))
        }

        async fn list_workspaces(&self, _user_id: &UserId) -> Result<Vec<Workspace>, StoreError> {
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
        ) -> Result<(), StoreError> {
            Ok(())
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
        ) -> Result<(), StoreError> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn trait_smoke() {
        let s = NoopStore;
        let _txn = s.begin_txn().await.unwrap();

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

        let _ = s.list_workspaces(&user_id).await.unwrap();
        let _ = s.list_projects(&ws).await.unwrap();
        let _ = s.get_project(&project_id).await;
    }
}
