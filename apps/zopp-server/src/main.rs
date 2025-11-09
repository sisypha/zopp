use chrono::Utc;
use clap::{Parser, Subcommand};
#[allow(unused_imports)]
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
#[allow(unused_imports)]
use rand_core::OsRng;
use std::sync::Arc;
use tonic::{Request, Response, Status, transport::Server};
use uuid::Uuid;

use zopp_proto::zopp_service_server::{ZoppService, ZoppServiceServer};
use zopp_proto::{
    CreateInviteRequest, CreateWorkspaceRequest, Empty, GetPrincipalRequest, InviteList,
    InviteToken, JoinRequest, JoinResponse, LoginRequest, LoginResponse, PrincipalList,
    RegisterRequest, RegisterResponse, RenamePrincipalRequest, RevokeInviteRequest, WorkspaceList,
};
use zopp_storage::{CreatePrincipalData, Principal, *};
use zopp_store_sqlite::SqliteStore;

// ────────────────────────────────────── CLI Types ──────────────────────────────────────

#[derive(Parser)]
#[command(name = "zopp-server")]
#[command(about = "Zopp server CLI for administration and serving")]
struct Cli {
    /// Path to database file
    #[arg(long, global = true, env = "ZOPP_DB_PATH", default_value = "zopp.db")]
    db: String,

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
    },
    /// List all server invites
    List,
    /// Revoke an invite
    Revoke {
        /// Invite token to revoke
        token: String,
    },
}

// ────────────────────────────────────── gRPC Server ──────────────────────────────────────

pub struct ZoppServer {
    store: Arc<SqliteStore>,
}

impl ZoppServer {
    pub fn new(store: Arc<SqliteStore>) -> Self {
        Self { store }
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

        let (user_id, principal_id) = self
            .store
            .create_user(&CreateUserParams {
                email: req.email,
                principal: Some(CreatePrincipalData {
                    name: req.principal_name,
                    public_key: req.public_key,
                }),
                workspace_ids: invite.workspace_ids.clone(),
            })
            .await
            .map_err(|e| Status::internal(format!("Failed to create user: {}", e)))?;

        let principal_id = principal_id.expect("principal_id should be present");

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
                    name: req.principal_name,
                    public_key: req.public_key,
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

        let workspace_id = self
            .store
            .create_workspace(&CreateWorkspaceParams {
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

        self.store
            .add_principal_to_workspace(&workspace_id, &principal_id)
            .await
            .map_err(|e| {
                Status::internal(format!("Failed to add principal to workspace: {}", e))
            })?;

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
                expires_at: chrono::DateTime::from_timestamp(req.expires_at, 0)
                    .ok_or_else(|| Status::invalid_argument("Invalid expires_at timestamp"))?,
                created_by_user_id: Some(user_id),
            })
            .await
            .map_err(|e| Status::internal(format!("Failed to create invite: {}", e)))?;

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

        let invite_id = Uuid::parse_str(&req.invite_id)
            .map(InviteId)
            .map_err(|_| Status::invalid_argument("Invalid invite ID"))?;

        self.store
            .revoke_invite(&invite_id)
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
        let workspace_id = Uuid::parse_str(&req.workspace_id)
            .map(WorkspaceId)
            .map_err(|_| Status::invalid_argument("Invalid workspace ID"))?;

        // Verify user has access to workspace
        let workspaces =
            self.store.list_workspaces(&user_id).await.map_err(|e| {
                Status::internal(format!("Failed to verify workspace access: {}", e))
            })?;

        if !workspaces.iter().any(|w| w.id == workspace_id) {
            return Err(Status::permission_denied("No access to workspace"));
        }

        let project_id = self
            .store
            .create_project(&zopp_storage::CreateProjectParams {
                workspace_id: workspace_id.clone(),
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
        let workspace_id = Uuid::parse_str(&req.workspace_id)
            .map(WorkspaceId)
            .map_err(|_| Status::invalid_argument("Invalid workspace ID"))?;

        // Verify user has access to workspace
        let workspaces =
            self.store.list_workspaces(&user_id).await.map_err(|e| {
                Status::internal(format!("Failed to verify workspace access: {}", e))
            })?;

        if !workspaces.iter().any(|w| w.id == workspace_id) {
            return Err(Status::permission_denied("No access to workspace"));
        }

        let projects = self
            .store
            .list_projects(&workspace_id)
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
        let project_id = Uuid::parse_str(&req.project_id)
            .map(zopp_storage::ProjectId)
            .map_err(|_| Status::invalid_argument("Invalid project ID"))?;

        let project = self
            .store
            .get_project(&project_id)
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::NotFound => Status::not_found("Project not found"),
                _ => Status::internal(format!("Failed to get project: {}", e)),
            })?;

        // Verify user has access to workspace
        let workspaces =
            self.store.list_workspaces(&user_id).await.map_err(|e| {
                Status::internal(format!("Failed to verify workspace access: {}", e))
            })?;

        if !workspaces.iter().any(|w| w.id == project.workspace_id) {
            return Err(Status::permission_denied("No access to workspace"));
        }

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
        let project_id = Uuid::parse_str(&req.project_id)
            .map(zopp_storage::ProjectId)
            .map_err(|_| Status::invalid_argument("Invalid project ID"))?;

        // Get project to verify access
        let project = self
            .store
            .get_project(&project_id)
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::NotFound => Status::not_found("Project not found"),
                _ => Status::internal(format!("Failed to get project: {}", e)),
            })?;

        // Verify user has access to workspace
        let workspaces =
            self.store.list_workspaces(&user_id).await.map_err(|e| {
                Status::internal(format!("Failed to verify workspace access: {}", e))
            })?;

        if !workspaces.iter().any(|w| w.id == project.workspace_id) {
            return Err(Status::permission_denied("No access to workspace"));
        }

        self.store
            .delete_project(&project_id)
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
        let project_id = Uuid::parse_str(&req.project_id)
            .map(zopp_storage::ProjectId)
            .map_err(|_| Status::invalid_argument("Invalid project ID"))?;

        // Get project to verify access
        let project = self
            .store
            .get_project(&project_id)
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::NotFound => Status::not_found("Project not found"),
                _ => Status::internal(format!("Failed to get project: {}", e)),
            })?;

        // Verify user has access to workspace
        let workspaces =
            self.store.list_workspaces(&user_id).await.map_err(|e| {
                Status::internal(format!("Failed to verify workspace access: {}", e))
            })?;

        if !workspaces.iter().any(|w| w.id == project.workspace_id) {
            return Err(Status::permission_denied("No access to workspace"));
        }

        let env_id = self
            .store
            .create_env(&zopp_storage::CreateEnvParams {
                project_id: project_id.clone(),
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
        let project_id = Uuid::parse_str(&req.project_id)
            .map(zopp_storage::ProjectId)
            .map_err(|_| Status::invalid_argument("Invalid project ID"))?;

        // Get project to verify access
        let project = self
            .store
            .get_project(&project_id)
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::NotFound => Status::not_found("Project not found"),
                _ => Status::internal(format!("Failed to get project: {}", e)),
            })?;

        // Verify user has access to workspace
        let workspaces =
            self.store.list_workspaces(&user_id).await.map_err(|e| {
                Status::internal(format!("Failed to verify workspace access: {}", e))
            })?;

        if !workspaces.iter().any(|w| w.id == project.workspace_id) {
            return Err(Status::permission_denied("No access to workspace"));
        }

        let environments = self
            .store
            .list_environments(&project_id)
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
        let env_id = Uuid::parse_str(&req.environment_id)
            .map(zopp_storage::EnvironmentId)
            .map_err(|_| Status::invalid_argument("Invalid environment ID"))?;

        let env = self
            .store
            .get_environment(&env_id)
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::NotFound => Status::not_found("Environment not found"),
                _ => Status::internal(format!("Failed to get environment: {}", e)),
            })?;

        // Get project to verify access
        let project = self
            .store
            .get_project(&env.project_id)
            .await
            .map_err(|e| Status::internal(format!("Failed to get project: {}", e)))?;

        // Verify user has access to workspace
        let workspaces =
            self.store.list_workspaces(&user_id).await.map_err(|e| {
                Status::internal(format!("Failed to verify workspace access: {}", e))
            })?;

        if !workspaces.iter().any(|w| w.id == project.workspace_id) {
            return Err(Status::permission_denied("No access to workspace"));
        }

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
        let env_id = Uuid::parse_str(&req.environment_id)
            .map(zopp_storage::EnvironmentId)
            .map_err(|_| Status::invalid_argument("Invalid environment ID"))?;

        // Get environment to verify access
        let env = self
            .store
            .get_environment(&env_id)
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::NotFound => Status::not_found("Environment not found"),
                _ => Status::internal(format!("Failed to get environment: {}", e)),
            })?;

        // Get project to verify access
        let project = self
            .store
            .get_project(&env.project_id)
            .await
            .map_err(|e| Status::internal(format!("Failed to get project: {}", e)))?;

        // Verify user has access to workspace
        let workspaces =
            self.store.list_workspaces(&user_id).await.map_err(|e| {
                Status::internal(format!("Failed to verify workspace access: {}", e))
            })?;

        if !workspaces.iter().any(|w| w.id == project.workspace_id) {
            return Err(Status::permission_denied("No access to workspace"));
        }

        self.store
            .delete_environment(&env_id)
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
        let env_id = Uuid::parse_str(&req.environment_id)
            .map(zopp_storage::EnvironmentId)
            .map_err(|_| Status::invalid_argument("Invalid environment ID"))?;

        // Get environment to verify access
        let env = self
            .store
            .get_environment(&env_id)
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::NotFound => Status::not_found("Environment not found"),
                _ => Status::internal(format!("Failed to get environment: {}", e)),
            })?;

        // Get project to verify access
        let project = self
            .store
            .get_project(&env.project_id)
            .await
            .map_err(|e| Status::internal(format!("Failed to get project: {}", e)))?;

        // Verify user has access to workspace
        let workspaces =
            self.store.list_workspaces(&user_id).await.map_err(|e| {
                Status::internal(format!("Failed to verify workspace access: {}", e))
            })?;

        if !workspaces.iter().any(|w| w.id == project.workspace_id) {
            return Err(Status::permission_denied("No access to workspace"));
        }

        self.store
            .upsert_secret(&env_id, &req.key, &req.nonce, &req.ciphertext)
            .await
            .map_err(|e| Status::internal(format!("Failed to upsert secret: {}", e)))?;

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
        let env_id = Uuid::parse_str(&req.environment_id)
            .map(zopp_storage::EnvironmentId)
            .map_err(|_| Status::invalid_argument("Invalid environment ID"))?;

        // Get environment to verify access
        let env = self
            .store
            .get_environment(&env_id)
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::NotFound => Status::not_found("Environment not found"),
                _ => Status::internal(format!("Failed to get environment: {}", e)),
            })?;

        // Get project to verify access
        let project = self
            .store
            .get_project(&env.project_id)
            .await
            .map_err(|e| Status::internal(format!("Failed to get project: {}", e)))?;

        // Verify user has access to workspace
        let workspaces =
            self.store.list_workspaces(&user_id).await.map_err(|e| {
                Status::internal(format!("Failed to verify workspace access: {}", e))
            })?;

        if !workspaces.iter().any(|w| w.id == project.workspace_id) {
            return Err(Status::permission_denied("No access to workspace"));
        }

        let secret = self
            .store
            .get_secret(&env_id, &req.key)
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
        let env_id = Uuid::parse_str(&req.environment_id)
            .map(zopp_storage::EnvironmentId)
            .map_err(|_| Status::invalid_argument("Invalid environment ID"))?;

        // Get environment to verify access
        let env = self
            .store
            .get_environment(&env_id)
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::NotFound => Status::not_found("Environment not found"),
                _ => Status::internal(format!("Failed to get environment: {}", e)),
            })?;

        // Get project to verify access
        let project = self
            .store
            .get_project(&env.project_id)
            .await
            .map_err(|e| Status::internal(format!("Failed to get project: {}", e)))?;

        // Verify user has access to workspace
        let workspaces =
            self.store.list_workspaces(&user_id).await.map_err(|e| {
                Status::internal(format!("Failed to verify workspace access: {}", e))
            })?;

        if !workspaces.iter().any(|w| w.id == project.workspace_id) {
            return Err(Status::permission_denied("No access to workspace"));
        }

        let keys = self
            .store
            .list_secret_keys(&env_id)
            .await
            .map_err(|e| Status::internal(format!("Failed to list secrets: {}", e)))?;

        // For each key, fetch the secret
        let mut secrets = Vec::new();
        for key in keys {
            let secret = self
                .store
                .get_secret(&env_id, &key)
                .await
                .map_err(|e| Status::internal(format!("Failed to get secret: {}", e)))?;
            secrets.push(zopp_proto::Secret {
                key,
                nonce: secret.nonce,
                ciphertext: secret.ciphertext,
            });
        }

        Ok(Response::new(zopp_proto::SecretList { secrets }))
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
        let env_id = Uuid::parse_str(&req.environment_id)
            .map(zopp_storage::EnvironmentId)
            .map_err(|_| Status::invalid_argument("Invalid environment ID"))?;

        // Get environment to verify access
        let env = self
            .store
            .get_environment(&env_id)
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::NotFound => Status::not_found("Environment not found"),
                _ => Status::internal(format!("Failed to get environment: {}", e)),
            })?;

        // Get project to verify access
        let project = self
            .store
            .get_project(&env.project_id)
            .await
            .map_err(|e| Status::internal(format!("Failed to get project: {}", e)))?;

        // Verify user has access to workspace
        let workspaces =
            self.store.list_workspaces(&user_id).await.map_err(|e| {
                Status::internal(format!("Failed to verify workspace access: {}", e))
            })?;

        if !workspaces.iter().any(|w| w.id == project.workspace_id) {
            return Err(Status::permission_denied("No access to workspace"));
        }

        self.store
            .delete_secret(&env_id, &req.key)
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::NotFound => Status::not_found("Secret not found"),
                _ => Status::internal(format!("Failed to delete secret: {}", e)),
            })?;

        Ok(Response::new(Empty {}))
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
    db_path: &str,
    expires_hours: i64,
) -> Result<(), Box<dyn std::error::Error>> {
    let db_url = if db_path.starts_with("sqlite:") {
        db_path.to_string()
    } else {
        format!("sqlite://{}?mode=rwc", db_path)
    };
    let store = SqliteStore::open(&db_url).await?;

    let expires_at = Utc::now() + chrono::Duration::hours(expires_hours);
    let invite = store
        .create_invite(&CreateInviteParams {
            workspace_ids: vec![],
            expires_at,
            created_by_user_id: None,
        })
        .await?;

    println!("✓ Server invite created!\n");
    println!("Token:   {}", invite.token);
    println!("Expires: {}", invite.expires_at);
    println!("\nUse this token to join this server using zopp join");

    Ok(())
}

async fn cmd_invite_list(db_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let db_url = if db_path.starts_with("sqlite:") {
        db_path.to_string()
    } else {
        format!("sqlite://{}?mode=rwc", db_path)
    };
    let store = SqliteStore::open(&db_url).await?;

    let invites = store.list_invites(None).await?;

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

async fn cmd_invite_revoke(db_path: &str, token: &str) -> Result<(), Box<dyn std::error::Error>> {
    let db_url = if db_path.starts_with("sqlite:") {
        db_path.to_string()
    } else {
        format!("sqlite://{}?mode=rwc", db_path)
    };
    let store = SqliteStore::open(&db_url).await?;

    let invite = store.get_invite_by_token(token).await?;

    store.revoke_invite(&invite.id).await?;

    println!("✓ Invite token {} revoked", token);

    Ok(())
}

async fn cmd_serve(db_path: &str, addr: &str) -> Result<(), Box<dyn std::error::Error>> {
    let addr = addr.parse()?;
    let db_url = if db_path.starts_with("sqlite:") {
        db_path.to_string()
    } else {
        format!("sqlite://{}?mode=rwc", db_path)
    };
    let store = SqliteStore::open(&db_url).await?;
    let server = ZoppServer::new(Arc::new(store));

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
            cmd_serve(&cli.db, &addr).await?;
        }
        Command::Invite { invite_cmd } => match invite_cmd {
            InviteCommand::Create { expires_hours } => {
                cmd_invite_create(&cli.db, expires_hours).await?;
            }
            InviteCommand::List => {
                cmd_invite_list(&cli.db).await?;
            }
            InviteCommand::Revoke { token } => {
                cmd_invite_revoke(&cli.db, &token).await?;
            }
        },
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
        let server = ZoppServer::new(store.clone());

        // Create a server invite (no workspaces)
        let invite = store
            .create_invite(&CreateInviteParams {
                workspace_ids: vec![],
                expires_at: Utc::now() + chrono::Duration::hours(24),
                created_by_user_id: None,
            })
            .await
            .unwrap();

        // Generate keypair for join
        let signing_key = SigningKey::generate(&mut OsRng);
        let public_key = signing_key.verifying_key().to_bytes().to_vec();

        // Join using server invite
        let request = tonic::Request::new(JoinRequest {
            invite_token: invite.token.clone(),
            email: "test@example.com".to_string(),
            principal_name: "test-laptop".to_string(),
            public_key,
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
        let server = ZoppServer::new(Arc::new(store));

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
        let server = ZoppServer::new(Arc::new(store));

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
        let server = ZoppServer::new(Arc::new(store));

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
        let server = ZoppServer::new(Arc::new(store));

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
