use chrono::Utc;
use clap::{Parser, Subcommand};
#[allow(unused_imports)]
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use futures::StreamExt;
#[allow(unused_imports)]
use rand_core::OsRng;
use std::sync::Arc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status, transport::Server};
use uuid::Uuid;

use zopp_events::{EventBus, EventType, SecretChangeEvent};
use zopp_events_memory::MemoryEventBus;
use zopp_proto::zopp_service_server::{ZoppService, ZoppServiceServer};
use zopp_proto::{
    CreateInviteRequest, CreateWorkspaceRequest, Empty, GetInviteRequest, GetPrincipalRequest,
    InviteList, InviteToken, JoinRequest, JoinResponse, LoginRequest, LoginResponse, PrincipalList,
    RegisterRequest, RegisterResponse, RenamePrincipalRequest, RevokeInviteRequest, WorkspaceList,
};
use zopp_storage::{AddWorkspacePrincipalParams, CreatePrincipalData, Principal, Store, *};
use zopp_store_postgres::PostgresStore;
use zopp_store_sqlite::SqliteStore;

// ────────────────────────────────────── CLI Types ──────────────────────────────────────

#[derive(Parser)]
#[command(name = "zopp-server")]
#[command(about = "Zopp server CLI for administration and serving")]
struct Cli {
    /// Database URL (sqlite://path/to/db.db or postgres://user:pass@host/db)
    #[arg(long, global = true, env = "DATABASE_URL")]
    database_url: Option<String>,

    /// Legacy: Path to SQLite database file (deprecated, use --database-url instead)
    #[arg(long, global = true, env = "ZOPP_DB_PATH")]
    db: Option<String>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Start the gRPC server
    Serve {
        /// Server address
        #[arg(long, default_value = "0.0.0.0:50051")]
        addr: String,
    },
    /// Invite management commands
    Invite {
        #[command(subcommand)]
        invite_cmd: InviteCommand,
    },
}

#[derive(Subcommand)]
enum InviteCommand {
    /// Create a new server invite token (for bootstrapping)
    Create {
        /// Expiration duration in hours
        #[arg(long, default_value = "24")]
        expires_hours: i64,
        /// Output only the token (for scripts)
        #[arg(long)]
        plain: bool,
    },
    /// List all server invites
    List,
    /// Revoke an invite
    Revoke {
        /// Invite token to revoke
        token: String,
    },
}

// ────────────────────────────────────── Backend Enum ──────────────────────────────────────

enum StoreBackend {
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

    async fn list_invites(&self, user_id: Option<&UserId>) -> Result<Vec<Invite>, StoreError> {
        match self {
            StoreBackend::Sqlite(s) => s.list_invites(user_id).await,
            StoreBackend::Postgres(s) => s.list_invites(user_id).await,
        }
    }

    async fn revoke_invite(&self, invite_id: &InviteId) -> Result<(), StoreError> {
        match self {
            StoreBackend::Sqlite(s) => s.revoke_invite(invite_id).await,
            StoreBackend::Postgres(s) => s.revoke_invite(invite_id).await,
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

    async fn list_workspaces(&self, user_id: &UserId) -> Result<Vec<Workspace>, StoreError> {
        match self {
            StoreBackend::Sqlite(s) => s.list_workspaces(user_id).await,
            StoreBackend::Postgres(s) => s.list_workspaces(user_id).await,
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
}

// ────────────────────────────────────── gRPC Server ──────────────────────────────────────

pub struct ZoppServer {
    store: StoreBackend,
    events: Arc<dyn EventBus>,
}

impl ZoppServer {
    pub fn new_sqlite(store: Arc<SqliteStore>, events: Arc<dyn EventBus>) -> Self {
        Self {
            store: StoreBackend::Sqlite(store),
            events,
        }
    }

    pub fn new_postgres(store: Arc<PostgresStore>, events: Arc<dyn EventBus>) -> Self {
        Self {
            store: StoreBackend::Postgres(store),
            events,
        }
    }

    async fn verify_signature_and_get_principal(
        &self,
        principal_id: &PrincipalId,
        timestamp: i64,
        signature: &[u8],
    ) -> Result<Principal, Status> {
        // Check timestamp freshness (replay protection)
        let now = Utc::now().timestamp();
        let age = now - timestamp;

        if age > 60 {
            return Err(Status::unauthenticated(
                "Request timestamp too old (>60s), possible replay attack",
            ));
        }
        if age < -30 {
            return Err(Status::unauthenticated(
                "Request timestamp too far in future (>30s), check clock sync",
            ));
        }

        let principal = self
            .store
            .get_principal(principal_id)
            .await
            .map_err(|_| Status::unauthenticated("Invalid principal"))?;

        let verifying_key = VerifyingKey::from_bytes(
            principal
                .public_key
                .as_slice()
                .try_into()
                .map_err(|_| Status::unauthenticated("Invalid public key length"))?,
        )
        .map_err(|_| Status::unauthenticated("Invalid public key"))?;

        let sig = Signature::from_bytes(
            signature
                .try_into()
                .map_err(|_| Status::unauthenticated("Invalid signature length"))?,
        );

        let message = timestamp.to_le_bytes();
        verifying_key
            .verify(&message, &sig)
            .map_err(|_| Status::unauthenticated("Invalid signature"))?;

        Ok(principal)
    }
}

#[tonic::async_trait]
impl ZoppService for ZoppServer {
    async fn join(&self, request: Request<JoinRequest>) -> Result<Response<JoinResponse>, Status> {
        let req = request.into_inner();

        let invite = self
            .store
            .get_invite_by_token(&req.invite_token)
            .await
            .map_err(|e| Status::not_found(format!("Invalid invite: {}", e)))?;

        // Check if invite is expired
        let now = chrono::Utc::now();
        if now > invite.expires_at {
            return Err(Status::permission_denied(format!(
                "Invite expired at {}",
                invite.expires_at
            )));
        }

        // Try to create user, but if they already exist, that's okay for workspace invites
        let result = self
            .store
            .create_user(&CreateUserParams {
                email: req.email.clone(),
                principal: Some(CreatePrincipalData {
                    name: req.principal_name.clone(),
                    public_key: req.public_key.clone(),
                    x25519_public_key: if req.x25519_public_key.is_empty() {
                        None
                    } else {
                        Some(req.x25519_public_key.clone())
                    },
                    is_service: false, // Join always creates user principals
                }),
                workspace_ids: invite.workspace_ids.clone(),
            })
            .await;

        let (user_id, principal_id) = match result {
            Ok((uid, pid)) => (uid, pid.expect("principal_id should be present")),
            Err(StoreError::AlreadyExists) if !invite.workspace_ids.is_empty() => {
                // User exists - this must be a workspace invite for an existing user
                // For now, return error - this needs proper implementation
                return Err(Status::unimplemented(
                    "Workspace invites for existing users not yet fully implemented. \
                     Use the same principal name you used when first joining.",
                ));
            }
            Err(e) => return Err(Status::internal(format!("Failed to create user: {}", e))),
        };

        // For workspace invites, store the wrapped KEK for this principal
        if !invite.workspace_ids.is_empty() && !req.kek_wrapped.is_empty() {
            for workspace_id in &invite.workspace_ids {
                self.store
                    .add_workspace_principal(&AddWorkspacePrincipalParams {
                        workspace_id: workspace_id.clone(),
                        principal_id: principal_id.clone(),
                        ephemeral_pub: req.ephemeral_pub.clone(),
                        kek_wrapped: req.kek_wrapped.clone(),
                        kek_nonce: req.kek_nonce.clone(),
                    })
                    .await
                    .map_err(|e| {
                        Status::internal(format!("Failed to add principal to workspace: {}", e))
                    })?;
            }
        }

        let mut workspaces = Vec::new();
        for workspace_id in invite.workspace_ids {
            let workspace = self
                .store
                .get_workspace(&workspace_id)
                .await
                .map_err(|e| Status::internal(format!("Failed to get workspace: {}", e)))?;
            workspaces.push(zopp_proto::Workspace {
                id: workspace.id.0.to_string(),
                name: workspace.name,
            });
        }

        Ok(Response::new(JoinResponse {
            user_id: user_id.0.to_string(),
            principal_id: principal_id.0.to_string(),
            workspaces,
        }))
    }

    async fn register(
        &self,
        request: Request<RegisterRequest>,
    ) -> Result<Response<RegisterResponse>, Status> {
        let req = request.into_inner();

        let (user_id, principal_id) = self
            .store
            .create_user(&CreateUserParams {
                email: req.email,
                principal: Some(CreatePrincipalData {
                    name: req.principal_name.clone(),
                    public_key: req.public_key.clone(),
                    x25519_public_key: if req.x25519_public_key.is_empty() {
                        None
                    } else {
                        Some(req.x25519_public_key.clone())
                    },
                    is_service: req.is_service,
                }),
                workspace_ids: vec![],
            })
            .await
            .map_err(|e| Status::internal(format!("Failed to create user: {}", e)))?;

        let principal_id = principal_id.expect("principal_id should be present");

        Ok(Response::new(RegisterResponse {
            user_id: user_id.0.to_string(),
            principal_id: principal_id.0.to_string(),
        }))
    }

    async fn login(
        &self,
        request: Request<LoginRequest>,
    ) -> Result<Response<LoginResponse>, Status> {
        let req = request.into_inner();

        let user = self
            .store
            .get_user_by_email(&req.email)
            .await
            .map_err(|e| Status::not_found(format!("User not found: {}", e)))?;

        let principals = self
            .store
            .list_principals(&user.id)
            .await
            .map_err(|e| Status::internal(format!("Failed to list principals: {}", e)))?;

        let principal = principals
            .iter()
            .find(|p| p.name == req.principal_name)
            .ok_or_else(|| {
                Status::not_found(format!("Principal '{}' not found", req.principal_name))
            })?;

        self.verify_signature_and_get_principal(&principal.id, req.timestamp, &req.signature)
            .await?;

        Ok(Response::new(LoginResponse {
            user_id: user.id.0.to_string(),
            principal_id: principal.id.0.to_string(),
        }))
    }

    async fn create_workspace(
        &self,
        request: Request<CreateWorkspaceRequest>,
    ) -> Result<Response<zopp_proto::Workspace>, Status> {
        let (principal_id, timestamp, signature) = extract_signature(&request)?;
        let principal = self
            .verify_signature_and_get_principal(&principal_id, timestamp, &signature)
            .await?;
        let req = request.into_inner();

        // Generate KDF salt
        let mut salt = vec![0u8; 32];
        use rand_core::RngCore;
        rand_core::OsRng.fill_bytes(&mut salt);

        let user_id = principal
            .user_id
            .ok_or_else(|| Status::unauthenticated("Service accounts cannot create workspaces"))?;

        // Parse client-provided workspace ID
        let workspace_id = WorkspaceId(
            Uuid::parse_str(&req.id)
                .map_err(|_| Status::invalid_argument("Invalid workspace ID"))?,
        );

        self.store
            .create_workspace(&CreateWorkspaceParams {
                id: workspace_id.clone(),
                name: req.name.clone(),
                owner_user_id: user_id.clone(),
                kdf_salt: salt,
                m_cost_kib: 64 * 1024,
                t_cost: 3,
                p_cost: 1,
            })
            .await
            .map_err(|e| Status::internal(format!("Failed to create workspace: {}", e)))?;

        self.store
            .add_user_to_workspace(&workspace_id, &user_id)
            .await
            .map_err(|e| Status::internal(format!("Failed to add user to workspace: {}", e)))?;

        // Store wrapped KEK for the workspace creator
        if !req.ephemeral_pub.is_empty() && !req.kek_wrapped.is_empty() {
            self.store
                .add_workspace_principal(&AddWorkspacePrincipalParams {
                    workspace_id: workspace_id.clone(),
                    principal_id: principal_id.clone(),
                    ephemeral_pub: req.ephemeral_pub,
                    kek_wrapped: req.kek_wrapped,
                    kek_nonce: req.kek_nonce,
                })
                .await
                .map_err(|e| {
                    Status::internal(format!("Failed to add wrapped KEK for principal: {}", e))
                })?;
        }

        Ok(Response::new(zopp_proto::Workspace {
            id: workspace_id.0.to_string(),
            name: req.name,
        }))
    }

    async fn list_workspaces(
        &self,
        request: Request<Empty>,
    ) -> Result<Response<WorkspaceList>, Status> {
        let (principal_id, timestamp, signature) = extract_signature(&request)?;
        let principal = self
            .verify_signature_and_get_principal(&principal_id, timestamp, &signature)
            .await?;
        let user_id = principal
            .user_id
            .ok_or_else(|| Status::unauthenticated("Service accounts cannot list workspaces"))?;

        let workspaces = self
            .store
            .list_workspaces(&user_id)
            .await
            .map_err(|e| Status::internal(format!("Failed to list workspaces: {}", e)))?
            .into_iter()
            .map(|w| zopp_proto::Workspace {
                id: w.id.0.to_string(),
                name: w.name,
            })
            .collect();

        Ok(Response::new(WorkspaceList { workspaces }))
    }

    async fn get_workspace_keys(
        &self,
        request: Request<zopp_proto::GetWorkspaceKeysRequest>,
    ) -> Result<Response<zopp_proto::WorkspaceKeys>, Status> {
        let (principal_id, timestamp, signature) = extract_signature(&request)?;
        let principal = self
            .verify_signature_and_get_principal(&principal_id, timestamp, &signature)
            .await?;
        let req = request.into_inner();

        let user_id = principal
            .user_id
            .ok_or_else(|| Status::unauthenticated("Service accounts cannot access workspaces"))?;

        // Get workspace by name
        let workspace = self
            .store
            .get_workspace_by_name(&user_id, &req.workspace_name)
            .await
            .map_err(|e| Status::not_found(format!("Workspace not found: {}", e)))?;

        // Get wrapped KEK for this principal
        let wp = self
            .store
            .get_workspace_principal(&workspace.id, &principal_id)
            .await
            .map_err(|e| Status::not_found(format!("KEK not found for principal: {}", e)))?;

        Ok(Response::new(zopp_proto::WorkspaceKeys {
            workspace_id: workspace.id.0.to_string(),
            ephemeral_pub: wp.ephemeral_pub,
            kek_wrapped: wp.kek_wrapped,
            kek_nonce: wp.kek_nonce,
        }))
    }

    async fn create_invite(
        &self,
        request: Request<CreateInviteRequest>,
    ) -> Result<Response<InviteToken>, Status> {
        let (principal_id, timestamp, signature) = extract_signature(&request)?;
        let principal = self
            .verify_signature_and_get_principal(&principal_id, timestamp, &signature)
            .await?;
        let req = request.into_inner();

        let workspace_ids: Result<Vec<WorkspaceId>, _> = req
            .workspace_ids
            .into_iter()
            .map(|id| {
                Uuid::parse_str(&id)
                    .map(WorkspaceId)
                    .map_err(|_| Status::invalid_argument(format!("Invalid workspace ID: {}", id)))
            })
            .collect();

        let user_id = principal
            .user_id
            .ok_or_else(|| Status::unauthenticated("Service accounts cannot create invites"))?;

        let invite = self
            .store
            .create_invite(&CreateInviteParams {
                workspace_ids: workspace_ids?,
                token: req.token,
                kek_encrypted: if req.kek_encrypted.is_empty() {
                    None
                } else {
                    Some(req.kek_encrypted)
                },
                kek_nonce: if req.kek_nonce.is_empty() {
                    None
                } else {
                    Some(req.kek_nonce)
                },
                expires_at: chrono::DateTime::from_timestamp(req.expires_at, 0)
                    .ok_or_else(|| Status::invalid_argument("Invalid expires_at timestamp"))?,
                created_by_user_id: Some(user_id),
            })
            .await
            .map_err(|e| Status::internal(format!("Failed to create invite: {}", e)))?;

        Ok(Response::new(InviteToken {
            id: invite.id.0.to_string(),
            token: invite.token.clone(),
            workspace_ids: invite
                .workspace_ids
                .into_iter()
                .map(|id| id.0.to_string())
                .collect(),
            created_at: invite.created_at.timestamp(),
            expires_at: invite.expires_at.timestamp(),
            kek_encrypted: invite.kek_encrypted.unwrap_or_default(),
            kek_nonce: invite.kek_nonce.unwrap_or_default(),
            invite_secret: String::new(), // TODO: generate and return invite secret
        }))
    }

    async fn get_invite(
        &self,
        request: Request<GetInviteRequest>,
    ) -> Result<Response<InviteToken>, Status> {
        // No authentication required - the invite secret itself is the credential
        let req = request.into_inner();

        let invite = self
            .store
            .get_invite_by_token(&req.token)
            .await
            .map_err(|_| Status::not_found("Invite not found or expired"))?;

        Ok(Response::new(InviteToken {
            id: invite.id.0.to_string(),
            token: invite.token,
            workspace_ids: invite
                .workspace_ids
                .into_iter()
                .map(|id| id.0.to_string())
                .collect(),
            created_at: invite.created_at.timestamp(),
            expires_at: invite.expires_at.timestamp(),
            kek_encrypted: invite.kek_encrypted.unwrap_or_default(),
            kek_nonce: invite.kek_nonce.unwrap_or_default(),
            invite_secret: String::new(), // Never returned
        }))
    }

    async fn list_invites(&self, request: Request<Empty>) -> Result<Response<InviteList>, Status> {
        let (principal_id, timestamp, signature) = extract_signature(&request)?;
        let principal = self
            .verify_signature_and_get_principal(&principal_id, timestamp, &signature)
            .await?;
        let user_id = principal
            .user_id
            .ok_or_else(|| Status::unauthenticated("Service accounts cannot list invites"))?;

        let invites = self
            .store
            .list_invites(Some(&user_id))
            .await
            .map_err(|e| Status::internal(format!("Failed to list invites: {}", e)))?
            .into_iter()
            .map(|inv| InviteToken {
                id: inv.id.0.to_string(),
                token: inv.token,
                workspace_ids: inv
                    .workspace_ids
                    .into_iter()
                    .map(|id| id.0.to_string())
                    .collect(),
                created_at: inv.created_at.timestamp(),
                expires_at: inv.expires_at.timestamp(),
                kek_encrypted: inv.kek_encrypted.unwrap_or_default(),
                kek_nonce: inv.kek_nonce.unwrap_or_default(),
                invite_secret: String::new(), // Not returned on list
            })
            .collect();

        Ok(Response::new(InviteList { invites }))
    }

    async fn revoke_invite(
        &self,
        request: Request<RevokeInviteRequest>,
    ) -> Result<Response<Empty>, Status> {
        let (principal_id, timestamp, signature) = extract_signature(&request)?;
        let _principal = self
            .verify_signature_and_get_principal(&principal_id, timestamp, &signature)
            .await?;
        let req = request.into_inner();

        // Look up invite by token (which is the hash)
        let invite = self
            .store
            .get_invite_by_token(&req.token)
            .await
            .map_err(|e| Status::not_found(format!("Invite not found: {}", e)))?;

        self.store
            .revoke_invite(&invite.id)
            .await
            .map_err(|e| Status::internal(format!("Failed to revoke invite: {}", e)))?;

        Ok(Response::new(Empty {}))
    }

    async fn get_principal(
        &self,
        request: Request<GetPrincipalRequest>,
    ) -> Result<Response<zopp_proto::Principal>, Status> {
        let (principal_id, timestamp, signature) = extract_signature(&request)?;
        let _principal = self
            .verify_signature_and_get_principal(&principal_id, timestamp, &signature)
            .await?;
        let req = request.into_inner();

        let principal_id = Uuid::parse_str(&req.principal_id)
            .map(PrincipalId)
            .map_err(|_| Status::invalid_argument("Invalid principal ID"))?;

        let principal = self
            .store
            .get_principal(&principal_id)
            .await
            .map_err(|e| Status::not_found(format!("Principal not found: {}", e)))?;

        Ok(Response::new(zopp_proto::Principal {
            id: principal.id.0.to_string(),
            name: principal.name,
            public_key: principal.public_key,
            x25519_public_key: principal.x25519_public_key.unwrap_or_default(),
        }))
    }

    async fn rename_principal(
        &self,
        request: Request<RenamePrincipalRequest>,
    ) -> Result<Response<Empty>, Status> {
        let (principal_id, timestamp, signature) = extract_signature(&request)?;
        let _principal = self
            .verify_signature_and_get_principal(&principal_id, timestamp, &signature)
            .await?;
        let req = request.into_inner();

        let principal_id = Uuid::parse_str(&req.principal_id)
            .map(PrincipalId)
            .map_err(|_| Status::invalid_argument("Invalid principal ID"))?;

        self.store
            .rename_principal(&principal_id, &req.new_name)
            .await
            .map_err(|e| Status::internal(format!("Failed to rename principal: {}", e)))?;

        Ok(Response::new(Empty {}))
    }

    async fn list_principals(
        &self,
        request: Request<Empty>,
    ) -> Result<Response<PrincipalList>, Status> {
        let (principal_id, timestamp, signature) = extract_signature(&request)?;
        let principal = self
            .verify_signature_and_get_principal(&principal_id, timestamp, &signature)
            .await?;
        let user_id = principal
            .user_id
            .ok_or_else(|| Status::unauthenticated("Service accounts cannot list principals"))?;

        let principals = self
            .store
            .list_principals(&user_id)
            .await
            .map_err(|e| Status::internal(format!("Failed to list principals: {}", e)))?
            .into_iter()
            .map(|p| zopp_proto::Principal {
                id: p.id.0.to_string(),
                name: p.name,
                public_key: p.public_key,
                x25519_public_key: p.x25519_public_key.unwrap_or_default(),
            })
            .collect();

        Ok(Response::new(PrincipalList { principals }))
    }

    async fn create_project(
        &self,
        request: Request<zopp_proto::CreateProjectRequest>,
    ) -> Result<Response<zopp_proto::Project>, Status> {
        let (principal_id, timestamp, signature) = extract_signature(&request)?;
        let principal = self
            .verify_signature_and_get_principal(&principal_id, timestamp, &signature)
            .await?;
        let user_id = principal
            .user_id
            .ok_or_else(|| Status::unauthenticated("Service accounts cannot create projects"))?;

        let req = request.into_inner();

        // Look up workspace by name
        let workspace = self
            .store
            .get_workspace_by_name(&user_id, &req.workspace_name)
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::NotFound => {
                    Status::not_found("Workspace not found or access denied")
                }
                _ => Status::internal(format!("Failed to get workspace: {}", e)),
            })?;

        let project_id = self
            .store
            .create_project(&zopp_storage::CreateProjectParams {
                workspace_id: workspace.id.clone(),
                name: req.name,
            })
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::AlreadyExists => {
                    Status::already_exists("Project with this name already exists in workspace")
                }
                _ => Status::internal(format!("Failed to create project: {}", e)),
            })?;

        let project = self
            .store
            .get_project(&project_id)
            .await
            .map_err(|e| Status::internal(format!("Failed to get project: {}", e)))?;

        Ok(Response::new(zopp_proto::Project {
            id: project.id.0.to_string(),
            workspace_id: project.workspace_id.0.to_string(),
            name: project.name,
            created_at: project.created_at.timestamp(),
            updated_at: project.updated_at.timestamp(),
        }))
    }

    async fn list_projects(
        &self,
        request: Request<zopp_proto::ListProjectsRequest>,
    ) -> Result<Response<zopp_proto::ProjectList>, Status> {
        let (principal_id, timestamp, signature) = extract_signature(&request)?;
        let principal = self
            .verify_signature_and_get_principal(&principal_id, timestamp, &signature)
            .await?;
        let user_id = principal
            .user_id
            .ok_or_else(|| Status::unauthenticated("Service accounts cannot list projects"))?;

        let req = request.into_inner();

        // Look up workspace by name
        let workspace = self
            .store
            .get_workspace_by_name(&user_id, &req.workspace_name)
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::NotFound => {
                    Status::not_found("Workspace not found or access denied")
                }
                _ => Status::internal(format!("Failed to get workspace: {}", e)),
            })?;

        let projects = self
            .store
            .list_projects(&workspace.id)
            .await
            .map_err(|e| Status::internal(format!("Failed to list projects: {}", e)))?
            .into_iter()
            .map(|p| zopp_proto::Project {
                id: p.id.0.to_string(),
                workspace_id: p.workspace_id.0.to_string(),
                name: p.name,
                created_at: p.created_at.timestamp(),
                updated_at: p.updated_at.timestamp(),
            })
            .collect();

        Ok(Response::new(zopp_proto::ProjectList { projects }))
    }

    async fn get_project(
        &self,
        request: Request<zopp_proto::GetProjectRequest>,
    ) -> Result<Response<zopp_proto::Project>, Status> {
        let (principal_id, timestamp, signature) = extract_signature(&request)?;
        let principal = self
            .verify_signature_and_get_principal(&principal_id, timestamp, &signature)
            .await?;
        let user_id = principal
            .user_id
            .ok_or_else(|| Status::unauthenticated("Service accounts cannot get projects"))?;

        let req = request.into_inner();

        // Look up workspace by name
        let workspace = self
            .store
            .get_workspace_by_name(&user_id, &req.workspace_name)
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::NotFound => {
                    Status::not_found("Workspace not found or access denied")
                }
                _ => Status::internal(format!("Failed to get workspace: {}", e)),
            })?;

        // Look up project by name in workspace
        let project = self
            .store
            .get_project_by_name(&workspace.id, &req.project_name)
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::NotFound => Status::not_found("Project not found"),
                _ => Status::internal(format!("Failed to get project: {}", e)),
            })?;

        Ok(Response::new(zopp_proto::Project {
            id: project.id.0.to_string(),
            workspace_id: project.workspace_id.0.to_string(),
            name: project.name,
            created_at: project.created_at.timestamp(),
            updated_at: project.updated_at.timestamp(),
        }))
    }

    async fn delete_project(
        &self,
        request: Request<zopp_proto::DeleteProjectRequest>,
    ) -> Result<Response<Empty>, Status> {
        let (principal_id, timestamp, signature) = extract_signature(&request)?;
        let principal = self
            .verify_signature_and_get_principal(&principal_id, timestamp, &signature)
            .await?;
        let user_id = principal
            .user_id
            .ok_or_else(|| Status::unauthenticated("Service accounts cannot delete projects"))?;

        let req = request.into_inner();

        // Look up workspace by name
        let workspace = self
            .store
            .get_workspace_by_name(&user_id, &req.workspace_name)
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::NotFound => {
                    Status::not_found("Workspace not found or access denied")
                }
                _ => Status::internal(format!("Failed to get workspace: {}", e)),
            })?;

        // Look up project by name in workspace
        let project = self
            .store
            .get_project_by_name(&workspace.id, &req.project_name)
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::NotFound => Status::not_found("Project not found"),
                _ => Status::internal(format!("Failed to get project: {}", e)),
            })?;

        self.store
            .delete_project(&project.id)
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::NotFound => Status::not_found("Project not found"),
                _ => Status::internal(format!("Failed to delete project: {}", e)),
            })?;

        Ok(Response::new(Empty {}))
    }

    async fn create_environment(
        &self,
        request: Request<zopp_proto::CreateEnvironmentRequest>,
    ) -> Result<Response<zopp_proto::Environment>, Status> {
        let (principal_id, timestamp, signature) = extract_signature(&request)?;
        let principal = self
            .verify_signature_and_get_principal(&principal_id, timestamp, &signature)
            .await?;
        let user_id = principal.user_id.ok_or_else(|| {
            Status::unauthenticated("Service accounts cannot create environments")
        })?;

        let req = request.into_inner();

        // Look up workspace by name
        let workspace = self
            .store
            .get_workspace_by_name(&user_id, &req.workspace_name)
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::NotFound => {
                    Status::not_found("Workspace not found or access denied")
                }
                _ => Status::internal(format!("Failed to get workspace: {}", e)),
            })?;

        // Look up project by name in workspace
        let project = self
            .store
            .get_project_by_name(&workspace.id, &req.project_name)
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::NotFound => Status::not_found("Project not found"),
                _ => Status::internal(format!("Failed to get project: {}", e)),
            })?;

        let env_id = self
            .store
            .create_env(&zopp_storage::CreateEnvParams {
                project_id: project.id.clone(),
                name: req.name,
                dek_wrapped: req.dek_wrapped,
                dek_nonce: req.dek_nonce,
            })
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::AlreadyExists => {
                    Status::already_exists("Environment with this name already exists in project")
                }
                _ => Status::internal(format!("Failed to create environment: {}", e)),
            })?;

        let env = self
            .store
            .get_environment(&env_id)
            .await
            .map_err(|e| Status::internal(format!("Failed to get environment: {}", e)))?;

        Ok(Response::new(zopp_proto::Environment {
            id: env.id.0.to_string(),
            project_id: env.project_id.0.to_string(),
            name: env.name,
            dek_wrapped: env.dek_wrapped,
            dek_nonce: env.dek_nonce,
            created_at: env.created_at.timestamp(),
            updated_at: env.updated_at.timestamp(),
        }))
    }

    async fn list_environments(
        &self,
        request: Request<zopp_proto::ListEnvironmentsRequest>,
    ) -> Result<Response<zopp_proto::EnvironmentList>, Status> {
        let (principal_id, timestamp, signature) = extract_signature(&request)?;
        let principal = self
            .verify_signature_and_get_principal(&principal_id, timestamp, &signature)
            .await?;
        let user_id = principal
            .user_id
            .ok_or_else(|| Status::unauthenticated("Service accounts cannot list environments"))?;

        let req = request.into_inner();

        // Look up workspace by name
        let workspace = self
            .store
            .get_workspace_by_name(&user_id, &req.workspace_name)
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::NotFound => {
                    Status::not_found("Workspace not found or access denied")
                }
                _ => Status::internal(format!("Failed to get workspace: {}", e)),
            })?;

        // Look up project by name in workspace
        let project = self
            .store
            .get_project_by_name(&workspace.id, &req.project_name)
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::NotFound => Status::not_found("Project not found"),
                _ => Status::internal(format!("Failed to get project: {}", e)),
            })?;

        let environments = self
            .store
            .list_environments(&project.id)
            .await
            .map_err(|e| Status::internal(format!("Failed to list environments: {}", e)))?
            .into_iter()
            .map(|e| zopp_proto::Environment {
                id: e.id.0.to_string(),
                project_id: e.project_id.0.to_string(),
                name: e.name,
                dek_wrapped: e.dek_wrapped,
                dek_nonce: e.dek_nonce,
                created_at: e.created_at.timestamp(),
                updated_at: e.updated_at.timestamp(),
            })
            .collect();

        Ok(Response::new(zopp_proto::EnvironmentList { environments }))
    }

    async fn get_environment(
        &self,
        request: Request<zopp_proto::GetEnvironmentRequest>,
    ) -> Result<Response<zopp_proto::Environment>, Status> {
        let (principal_id, timestamp, signature) = extract_signature(&request)?;
        let principal = self
            .verify_signature_and_get_principal(&principal_id, timestamp, &signature)
            .await?;
        let user_id = principal
            .user_id
            .ok_or_else(|| Status::unauthenticated("Service accounts cannot get environments"))?;

        let req = request.into_inner();

        // Look up workspace by name
        let workspace = self
            .store
            .get_workspace_by_name(&user_id, &req.workspace_name)
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::NotFound => {
                    Status::not_found("Workspace not found or access denied")
                }
                _ => Status::internal(format!("Failed to get workspace: {}", e)),
            })?;

        // Look up project by name in workspace
        let project = self
            .store
            .get_project_by_name(&workspace.id, &req.project_name)
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::NotFound => Status::not_found("Project not found"),
                _ => Status::internal(format!("Failed to get project: {}", e)),
            })?;

        // Look up environment by name in project
        let env = self
            .store
            .get_environment_by_name(&project.id, &req.environment_name)
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::NotFound => Status::not_found("Environment not found"),
                _ => Status::internal(format!("Failed to get environment: {}", e)),
            })?;

        Ok(Response::new(zopp_proto::Environment {
            id: env.id.0.to_string(),
            project_id: env.project_id.0.to_string(),
            name: env.name,
            dek_wrapped: env.dek_wrapped,
            dek_nonce: env.dek_nonce,
            created_at: env.created_at.timestamp(),
            updated_at: env.updated_at.timestamp(),
        }))
    }

    async fn delete_environment(
        &self,
        request: Request<zopp_proto::DeleteEnvironmentRequest>,
    ) -> Result<Response<Empty>, Status> {
        let (principal_id, timestamp, signature) = extract_signature(&request)?;
        let principal = self
            .verify_signature_and_get_principal(&principal_id, timestamp, &signature)
            .await?;
        let user_id = principal.user_id.ok_or_else(|| {
            Status::unauthenticated("Service accounts cannot delete environments")
        })?;

        let req = request.into_inner();

        // Look up workspace by name
        let workspace = self
            .store
            .get_workspace_by_name(&user_id, &req.workspace_name)
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::NotFound => {
                    Status::not_found("Workspace not found or access denied")
                }
                _ => Status::internal(format!("Failed to get workspace: {}", e)),
            })?;

        // Look up project by name in workspace
        let project = self
            .store
            .get_project_by_name(&workspace.id, &req.project_name)
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::NotFound => Status::not_found("Project not found"),
                _ => Status::internal(format!("Failed to get project: {}", e)),
            })?;

        // Look up environment by name in project
        let env = self
            .store
            .get_environment_by_name(&project.id, &req.environment_name)
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::NotFound => Status::not_found("Environment not found"),
                _ => Status::internal(format!("Failed to get environment: {}", e)),
            })?;

        self.store
            .delete_environment(&env.id)
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::NotFound => Status::not_found("Environment not found"),
                _ => Status::internal(format!("Failed to delete environment: {}", e)),
            })?;

        Ok(Response::new(Empty {}))
    }

    async fn upsert_secret(
        &self,
        request: Request<zopp_proto::UpsertSecretRequest>,
    ) -> Result<Response<Empty>, Status> {
        let (principal_id, timestamp, signature) = extract_signature(&request)?;
        let principal = self
            .verify_signature_and_get_principal(&principal_id, timestamp, &signature)
            .await?;
        let user_id = principal
            .user_id
            .ok_or_else(|| Status::unauthenticated("Service accounts cannot upsert secrets"))?;

        let req = request.into_inner();

        // Look up workspace by name
        let workspace = self
            .store
            .get_workspace_by_name(&user_id, &req.workspace_name)
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::NotFound => {
                    Status::not_found("Workspace not found or access denied")
                }
                _ => Status::internal(format!("Failed to get workspace: {}", e)),
            })?;

        // Look up project by name in workspace
        let project = self
            .store
            .get_project_by_name(&workspace.id, &req.project_name)
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::NotFound => Status::not_found("Project not found"),
                _ => Status::internal(format!("Failed to get project: {}", e)),
            })?;

        // Look up environment by name in project
        let env = self
            .store
            .get_environment_by_name(&project.id, &req.environment_name)
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::NotFound => Status::not_found("Environment not found"),
                _ => Status::internal(format!("Failed to get environment: {}", e)),
            })?;

        let new_version = self
            .store
            .upsert_secret(&env.id, &req.key, &req.nonce, &req.ciphertext)
            .await
            .map_err(|e| Status::internal(format!("Failed to upsert secret: {}", e)))?;

        // Broadcast event to watchers
        let event = SecretChangeEvent {
            event_type: EventType::Updated, // Could be Created or Updated, we don't track that
            key: req.key.clone(),
            version: new_version,
            timestamp: Utc::now().timestamp(),
        };
        let _ = self.events.publish(&env.id, event).await; // Ignore error if no watchers

        Ok(Response::new(Empty {}))
    }

    async fn get_secret(
        &self,
        request: Request<zopp_proto::GetSecretRequest>,
    ) -> Result<Response<zopp_proto::Secret>, Status> {
        let (principal_id, timestamp, signature) = extract_signature(&request)?;
        let principal = self
            .verify_signature_and_get_principal(&principal_id, timestamp, &signature)
            .await?;
        let user_id = principal
            .user_id
            .ok_or_else(|| Status::unauthenticated("Service accounts cannot get secrets"))?;

        let req = request.into_inner();

        // Look up workspace by name
        let workspace = self
            .store
            .get_workspace_by_name(&user_id, &req.workspace_name)
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::NotFound => {
                    Status::not_found("Workspace not found or access denied")
                }
                _ => Status::internal(format!("Failed to get workspace: {}", e)),
            })?;

        // Look up project by name in workspace
        let project = self
            .store
            .get_project_by_name(&workspace.id, &req.project_name)
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::NotFound => Status::not_found("Project not found"),
                _ => Status::internal(format!("Failed to get project: {}", e)),
            })?;

        // Look up environment by name in project
        let env = self
            .store
            .get_environment_by_name(&project.id, &req.environment_name)
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::NotFound => Status::not_found("Environment not found"),
                _ => Status::internal(format!("Failed to get environment: {}", e)),
            })?;

        let secret = self
            .store
            .get_secret(&env.id, &req.key)
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::NotFound => Status::not_found("Secret not found"),
                _ => Status::internal(format!("Failed to get secret: {}", e)),
            })?;

        Ok(Response::new(zopp_proto::Secret {
            key: req.key,
            nonce: secret.nonce,
            ciphertext: secret.ciphertext,
        }))
    }

    async fn list_secrets(
        &self,
        request: Request<zopp_proto::ListSecretsRequest>,
    ) -> Result<Response<zopp_proto::SecretList>, Status> {
        let (principal_id, timestamp, signature) = extract_signature(&request)?;
        let principal = self
            .verify_signature_and_get_principal(&principal_id, timestamp, &signature)
            .await?;
        let user_id = principal
            .user_id
            .ok_or_else(|| Status::unauthenticated("Service accounts cannot list secrets"))?;

        let req = request.into_inner();

        // Look up workspace by name
        let workspace = self
            .store
            .get_workspace_by_name(&user_id, &req.workspace_name)
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::NotFound => {
                    Status::not_found("Workspace not found or access denied")
                }
                _ => Status::internal(format!("Failed to get workspace: {}", e)),
            })?;

        // Look up project by name in workspace
        let project = self
            .store
            .get_project_by_name(&workspace.id, &req.project_name)
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::NotFound => Status::not_found("Project not found"),
                _ => Status::internal(format!("Failed to get project: {}", e)),
            })?;

        // Look up environment by name in project
        let env = self
            .store
            .get_environment_by_name(&project.id, &req.environment_name)
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::NotFound => Status::not_found("Environment not found"),
                _ => Status::internal(format!("Failed to get environment: {}", e)),
            })?;

        let keys = self
            .store
            .list_secret_keys(&env.id)
            .await
            .map_err(|e| Status::internal(format!("Failed to list secrets: {}", e)))?;

        // For each key, fetch the secret
        let mut secrets = Vec::new();
        for key in keys {
            let secret = self
                .store
                .get_secret(&env.id, &key)
                .await
                .map_err(|e| Status::internal(format!("Failed to get secret: {}", e)))?;
            secrets.push(zopp_proto::Secret {
                key,
                nonce: secret.nonce,
                ciphertext: secret.ciphertext,
            });
        }

        Ok(Response::new(zopp_proto::SecretList {
            secrets,
            version: env.version,
        }))
    }

    async fn delete_secret(
        &self,
        request: Request<zopp_proto::DeleteSecretRequest>,
    ) -> Result<Response<Empty>, Status> {
        let (principal_id, timestamp, signature) = extract_signature(&request)?;
        let principal = self
            .verify_signature_and_get_principal(&principal_id, timestamp, &signature)
            .await?;
        let user_id = principal
            .user_id
            .ok_or_else(|| Status::unauthenticated("Service accounts cannot delete secrets"))?;

        let req = request.into_inner();

        // Look up workspace by name
        let workspace = self
            .store
            .get_workspace_by_name(&user_id, &req.workspace_name)
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::NotFound => {
                    Status::not_found("Workspace not found or access denied")
                }
                _ => Status::internal(format!("Failed to get workspace: {}", e)),
            })?;

        // Look up project by name in workspace
        let project = self
            .store
            .get_project_by_name(&workspace.id, &req.project_name)
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::NotFound => Status::not_found("Project not found"),
                _ => Status::internal(format!("Failed to get project: {}", e)),
            })?;

        // Look up environment by name in project
        let env = self
            .store
            .get_environment_by_name(&project.id, &req.environment_name)
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::NotFound => Status::not_found("Environment not found"),
                _ => Status::internal(format!("Failed to get environment: {}", e)),
            })?;

        let new_version =
            self.store
                .delete_secret(&env.id, &req.key)
                .await
                .map_err(|e| match e {
                    zopp_storage::StoreError::NotFound => Status::not_found("Secret not found"),
                    _ => Status::internal(format!("Failed to delete secret: {}", e)),
                })?;

        // Broadcast event to watchers
        let event = SecretChangeEvent {
            event_type: EventType::Deleted,
            key: req.key.clone(),
            version: new_version,
            timestamp: Utc::now().timestamp(),
        };
        let _ = self.events.publish(&env.id, event).await; // Ignore error if no watchers

        Ok(Response::new(Empty {}))
    }

    type WatchSecretsStream = ReceiverStream<Result<zopp_proto::WatchSecretsResponse, Status>>;

    async fn watch_secrets(
        &self,
        request: Request<zopp_proto::WatchSecretsRequest>,
    ) -> Result<Response<Self::WatchSecretsStream>, Status> {
        let (principal_id, timestamp, signature) = extract_signature(&request)?;
        let principal = self
            .verify_signature_and_get_principal(&principal_id, timestamp, &signature)
            .await?;

        let req = request.into_inner();

        // Look up workspace by name (use principal-based lookup for service principals)
        let workspace = if let Some(user_id) = &principal.user_id {
            self.store
                .get_workspace_by_name(user_id, &req.workspace_name)
                .await
        } else {
            self.store
                .get_workspace_by_name_for_principal(&principal_id, &req.workspace_name)
                .await
        }
        .map_err(|e| match e {
            zopp_storage::StoreError::NotFound => {
                Status::not_found("Workspace not found or access denied")
            }
            _ => Status::internal(format!("Failed to get workspace: {}", e)),
        })?;

        // Look up project by name in workspace
        let project = self
            .store
            .get_project_by_name(&workspace.id, &req.project_name)
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::NotFound => Status::not_found("Project not found"),
                _ => Status::internal(format!("Failed to get project: {}", e)),
            })?;

        // Look up environment by name in project
        let env = self
            .store
            .get_environment_by_name(&project.id, &req.environment_name)
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::NotFound => Status::not_found("Environment not found"),
                _ => Status::internal(format!("Failed to get environment: {}", e)),
            })?;

        // Check if client is behind (needs resync)
        if let Some(client_version) = req.since_version
            && client_version < env.version
        {
            // Client is behind, send ResyncRequired
            let (tx, rx) = tokio::sync::mpsc::channel(1);
            let response = zopp_proto::WatchSecretsResponse {
                response: Some(zopp_proto::watch_secrets_response::Response::Resync(
                    zopp_proto::ResyncRequired {
                        current_version: env.version,
                    },
                )),
            };
            let _ = tx.send(Ok(response)).await;
            return Ok(Response::new(ReceiverStream::new(rx)));
        }

        // Subscribe to events
        let mut event_stream = self
            .events
            .subscribe(&env.id)
            .await
            .map_err(|e| Status::internal(format!("Failed to subscribe to events: {}", e)))?;

        // Create channel for streaming responses
        let (tx, rx) = tokio::sync::mpsc::channel(100);

        // Spawn task to forward events to client
        tokio::spawn(async move {
            while let Some(event) = event_stream.next().await {
                let response = zopp_proto::WatchSecretsResponse {
                    response: Some(zopp_proto::watch_secrets_response::Response::Event(
                        zopp_proto::SecretChangeEvent {
                            event_type: match event.event_type {
                                EventType::Created => {
                                    zopp_proto::secret_change_event::EventType::Created as i32
                                }
                                EventType::Updated => {
                                    zopp_proto::secret_change_event::EventType::Updated as i32
                                }
                                EventType::Deleted => {
                                    zopp_proto::secret_change_event::EventType::Deleted as i32
                                }
                            },
                            key: event.key,
                            version: event.version,
                            timestamp: event.timestamp,
                        },
                    )),
                };

                if tx.send(Ok(response)).await.is_err() {
                    // Client disconnected or receiver dropped
                    break;
                }
            }
        });

        Ok(Response::new(ReceiverStream::new(rx)))
    }
}

fn extract_signature<T>(request: &Request<T>) -> Result<(PrincipalId, i64, Vec<u8>), Status> {
    let metadata = request.metadata();

    let principal_id_str = metadata
        .get("principal-id")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| Status::unauthenticated("Missing principal-id metadata"))?;

    let principal_id = Uuid::parse_str(principal_id_str)
        .map(PrincipalId)
        .map_err(|_| Status::unauthenticated("Invalid principal-id format"))?;

    let timestamp_str = metadata
        .get("timestamp")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| Status::unauthenticated("Missing timestamp metadata"))?;

    let timestamp = timestamp_str
        .parse::<i64>()
        .map_err(|_| Status::unauthenticated("Invalid timestamp format"))?;

    let signature_str = metadata
        .get("signature")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| Status::unauthenticated("Missing signature metadata"))?;

    let signature = hex::decode(signature_str)
        .map_err(|_| Status::unauthenticated("Invalid signature format"))?;

    Ok((principal_id, timestamp, signature))
}

// ────────────────────────────────────── CLI Commands ──────────────────────────────────────

async fn cmd_invite_create(
    db_url: &str,
    expires_hours: i64,
    plain: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let backend: StoreBackend = if db_url.starts_with("postgres:") {
        StoreBackend::Postgres(Arc::new(PostgresStore::open(db_url).await?))
    } else {
        StoreBackend::Sqlite(Arc::new(SqliteStore::open(db_url).await?))
    };

    // Generate random token for server invite (32 bytes = 256 bits)
    use rand_core::RngCore;
    let mut token_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut token_bytes);
    let token = hex::encode(token_bytes);

    let expires_at = Utc::now() + chrono::Duration::hours(expires_hours);
    let invite = backend
        .create_invite(&CreateInviteParams {
            workspace_ids: vec![],
            token,
            kek_encrypted: None,
            kek_nonce: None,
            expires_at,
            created_by_user_id: None,
        })
        .await?;

    if plain {
        println!("{}", invite.token);
    } else {
        println!("✓ Server invite created!\n");
        println!("Token:   {}", invite.token);
        println!("Expires: {}", invite.expires_at);
        println!("\nUse this token to join this server using zopp join");
    }

    Ok(())
}

async fn cmd_invite_list(db_url: &str) -> Result<(), Box<dyn std::error::Error>> {
    let backend: StoreBackend = if db_url.starts_with("postgres:") {
        StoreBackend::Postgres(Arc::new(PostgresStore::open(db_url).await?))
    } else {
        StoreBackend::Sqlite(Arc::new(SqliteStore::open(db_url).await?))
    };

    let invites = backend.list_invites(None).await?;

    if invites.is_empty() {
        println!("No active server invites found.");
    } else {
        println!("Active server invites:\n");
        for invite in invites {
            println!("Token:   {}", invite.token);
            println!("Expires: {}", invite.expires_at);
            println!();
        }
    }

    Ok(())
}

async fn cmd_invite_revoke(db_url: &str, token: &str) -> Result<(), Box<dyn std::error::Error>> {
    let backend: StoreBackend = if db_url.starts_with("postgres:") {
        StoreBackend::Postgres(Arc::new(PostgresStore::open(db_url).await?))
    } else {
        StoreBackend::Sqlite(Arc::new(SqliteStore::open(db_url).await?))
    };

    let invite = backend.get_invite_by_token(token).await?;

    backend.revoke_invite(&invite.id).await?;

    println!("✓ Invite token {} revoked", token);

    Ok(())
}

async fn cmd_serve(
    database_url: Option<String>,
    legacy_db_path: Option<String>,
    addr: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let addr = addr.parse()?;

    // Determine database URL
    let db_url = if let Some(url) = database_url {
        url
    } else if let Some(path) = legacy_db_path {
        if path.starts_with("sqlite:") || path.starts_with("postgres:") {
            path
        } else {
            format!("sqlite://{}?mode=rwc", path)
        }
    } else {
        "sqlite://zopp.db?mode=rwc".to_string()
    };

    // Create backend based on URL scheme
    let backend = if db_url.starts_with("postgres:") {
        let store = PostgresStore::open(&db_url).await?;
        StoreBackend::Postgres(Arc::new(store))
    } else {
        let store = SqliteStore::open(&db_url).await?;
        StoreBackend::Sqlite(Arc::new(store))
    };

    let events: Arc<dyn EventBus> = Arc::new(MemoryEventBus::new());
    let server = match backend {
        StoreBackend::Sqlite(ref s) => ZoppServer::new_sqlite(s.clone(), events),
        StoreBackend::Postgres(ref s) => ZoppServer::new_postgres(s.clone(), events),
    };

    println!("ZoppServer listening on {}", addr);

    Server::builder()
        .add_service(ZoppServiceServer::new(server))
        .serve(addr)
        .await?;

    Ok(())
}

// ────────────────────────────────────── Main ──────────────────────────────────────

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Command::Serve { addr } => {
            cmd_serve(cli.database_url, cli.db, &addr).await?;
        }
        Command::Invite { invite_cmd } => {
            let db_url = if let Some(url) = cli.database_url {
                url
            } else if let Some(path) = cli.db {
                if path.starts_with("sqlite:") || path.starts_with("postgres:") {
                    path
                } else {
                    format!("sqlite://{}?mode=rwc", path)
                }
            } else {
                "sqlite://zopp.db?mode=rwc".to_string()
            };

            match invite_cmd {
                InviteCommand::Create {
                    expires_hours,
                    plain,
                } => {
                    cmd_invite_create(&db_url, expires_hours, plain).await?;
                }
                InviteCommand::List => {
                    cmd_invite_list(&db_url).await?;
                }
                InviteCommand::Revoke { token } => {
                    cmd_invite_revoke(&db_url, &token).await?;
                }
            }
        }
    }

    Ok(())
}

// ────────────────────────────────────── Tests ──────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand_core::OsRng;

    #[tokio::test]
    async fn test_server_invite_joins_user_without_creating_workspace() {
        let store = Arc::new(SqliteStore::open_in_memory().await.unwrap());
        let events: Arc<dyn EventBus> = Arc::new(MemoryEventBus::new());
        let server = ZoppServer::new_sqlite(store.clone(), events);

        // Create a server invite (no workspaces)
        let mut invite_secret = [0u8; 32];
        rand_core::RngCore::fill_bytes(&mut OsRng, &mut invite_secret);
        let secret_hash = zopp_crypto::hash_sha256(&invite_secret);
        let invite = store
            .create_invite(&CreateInviteParams {
                workspace_ids: vec![],
                token: hex::encode(secret_hash),
                kek_encrypted: None,
                kek_nonce: None,
                expires_at: Utc::now() + chrono::Duration::hours(24),
                created_by_user_id: None,
            })
            .await
            .unwrap();

        // Generate keypair for join
        let signing_key = SigningKey::generate(&mut OsRng);
        let public_key = signing_key.verifying_key().to_bytes().to_vec();

        // Generate X25519 keypair for encryption
        let x25519_keypair = zopp_crypto::Keypair::generate();
        let x25519_public_key = x25519_keypair.public_key_bytes().to_vec();

        // Join using server invite
        let request = tonic::Request::new(JoinRequest {
            invite_token: invite.token.clone(),
            email: "test@example.com".to_string(),
            principal_name: "test-laptop".to_string(),
            public_key,
            x25519_public_key,
            ephemeral_pub: vec![],
            kek_wrapped: vec![],
            kek_nonce: vec![],
        });

        let response = server.join(request).await.unwrap().into_inner();

        assert!(!response.user_id.is_empty());
        assert!(!response.principal_id.is_empty());
        assert_eq!(
            response.workspaces.len(),
            0,
            "No workspaces should be created automatically"
        );

        let user_id = UserId(Uuid::parse_str(&response.user_id).unwrap());

        let workspaces = store.list_workspaces(&user_id).await.unwrap();
        assert_eq!(
            workspaces.len(),
            0,
            "User should not have access to any workspaces yet"
        );
    }

    #[tokio::test]
    async fn test_replay_protection_rejects_old_timestamps() {
        let store = SqliteStore::open_in_memory().await.unwrap();
        let events: Arc<dyn EventBus> = Arc::new(MemoryEventBus::new());
        let server = ZoppServer::new_sqlite(Arc::new(store), events);

        // Create a test keypair
        let signing_key = SigningKey::generate(&mut OsRng);
        let public_key = signing_key.verifying_key().to_bytes().to_vec();

        // Create a test principal
        let principal_id = server
            .store
            .create_principal(&CreatePrincipalParams {
                user_id: None,
                name: "test-principal".to_string(),
                public_key,
                x25519_public_key: None,
            })
            .await
            .unwrap();

        // Create a timestamp 70 seconds in the past
        let old_timestamp = Utc::now().timestamp() - 70;
        let signature = signing_key.sign(&old_timestamp.to_le_bytes());

        // Should reject old timestamp
        let result = server
            .verify_signature_and_get_principal(
                &principal_id,
                old_timestamp,
                signature.to_bytes().as_ref(),
            )
            .await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
        assert!(err.message().contains("too old"));
    }

    #[tokio::test]
    async fn test_replay_protection_rejects_future_timestamps() {
        let store = SqliteStore::open_in_memory().await.unwrap();
        let events: Arc<dyn EventBus> = Arc::new(MemoryEventBus::new());
        let server = ZoppServer::new_sqlite(Arc::new(store), events);

        // Create a test keypair
        let signing_key = SigningKey::generate(&mut OsRng);
        let public_key = signing_key.verifying_key().to_bytes().to_vec();

        // Create a test principal
        let principal_id = server
            .store
            .create_principal(&CreatePrincipalParams {
                user_id: None,
                name: "test-principal".to_string(),
                public_key,
                x25519_public_key: None,
            })
            .await
            .unwrap();

        // Create a timestamp 40 seconds in the future
        let future_timestamp = Utc::now().timestamp() + 40;
        let signature = signing_key.sign(&future_timestamp.to_le_bytes());

        // Should reject future timestamp
        let result = server
            .verify_signature_and_get_principal(
                &principal_id,
                future_timestamp,
                signature.to_bytes().as_ref(),
            )
            .await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
        assert!(err.message().contains("future"));
    }

    #[tokio::test]
    async fn test_replay_protection_accepts_valid_timestamps() {
        let store = SqliteStore::open_in_memory().await.unwrap();
        let events: Arc<dyn EventBus> = Arc::new(MemoryEventBus::new());
        let server = ZoppServer::new_sqlite(Arc::new(store), events);

        // Create a test keypair
        let signing_key = SigningKey::generate(&mut OsRng);
        let public_key = signing_key.verifying_key().to_bytes().to_vec();

        // Create a test principal
        let principal_id = server
            .store
            .create_principal(&CreatePrincipalParams {
                user_id: None,
                name: "test-principal".to_string(),
                public_key,
                x25519_public_key: None,
            })
            .await
            .unwrap();

        // Create a current timestamp
        let now = Utc::now().timestamp();
        let signature = signing_key.sign(&now.to_le_bytes());

        // Should accept valid timestamp
        let result = server
            .verify_signature_and_get_principal(&principal_id, now, signature.to_bytes().as_ref())
            .await;

        assert!(result.is_ok());
        let principal = result.unwrap();
        assert_eq!(principal.id, principal_id);
    }

    #[tokio::test]
    async fn test_replay_protection_rejects_invalid_signature() {
        let store = SqliteStore::open_in_memory().await.unwrap();
        let events: Arc<dyn EventBus> = Arc::new(MemoryEventBus::new());
        let server = ZoppServer::new_sqlite(Arc::new(store), events);

        // Create a test keypair
        let signing_key = SigningKey::generate(&mut OsRng);
        let public_key = signing_key.verifying_key().to_bytes().to_vec();

        // Create a test principal
        let principal_id = server
            .store
            .create_principal(&CreatePrincipalParams {
                user_id: None,
                name: "test-principal".to_string(),
                public_key,
                x25519_public_key: None,
            })
            .await
            .unwrap();

        // Create a current timestamp but sign wrong data
        let now = Utc::now().timestamp();
        let wrong_data = (now + 1).to_le_bytes();
        let signature = signing_key.sign(&wrong_data);

        // Should reject invalid signature
        let result = server
            .verify_signature_and_get_principal(&principal_id, now, signature.to_bytes().as_ref())
            .await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
        assert!(err.message().contains("Invalid signature"));
    }
}
