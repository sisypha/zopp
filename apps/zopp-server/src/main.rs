mod backend;
mod server;

use chrono::Utc;
use clap::{Parser, Subcommand};
#[allow(unused_imports)]
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use futures::StreamExt;
#[allow(unused_imports)]
use rand_core::OsRng;
use std::sync::Arc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{transport::Server, Request, Response, Status};
use uuid::Uuid;

use backend::StoreBackend;
use server::{extract_signature, ZoppServer};
use zopp_events::{EventBus, EventType, SecretChangeEvent};
use zopp_events_memory::MemoryEventBus;
use zopp_proto::zopp_service_server::{ZoppService, ZoppServiceServer};
use zopp_proto::{
    CreateInviteRequest, CreateWorkspaceRequest, Empty, GetInviteRequest, GetPrincipalRequest,
    InviteList, InviteToken, JoinRequest, JoinResponse, LoginRequest, LoginResponse, PrincipalList,
    RegisterRequest, RegisterResponse, RenamePrincipalRequest, RevokeInviteRequest, WorkspaceList,
};
use zopp_storage::{AddWorkspacePrincipalParams, CreatePrincipalData, Store, *};
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

        /// Health check HTTP server address
        #[arg(long, default_value = "0.0.0.0:8080")]
        health_addr: String,

        /// Path to TLS certificate file (PEM format)
        #[arg(long, env = "ZOPP_TLS_CERT")]
        tls_cert: Option<String>,

        /// Path to TLS private key file (PEM format)
        #[arg(long, env = "ZOPP_TLS_KEY")]
        tls_key: Option<String>,

        /// Path to CA certificate for client verification (enables mTLS)
        #[arg(long, env = "ZOPP_TLS_CLIENT_CA")]
        tls_client_ca: Option<String>,
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

// ────────────────────────────────────── gRPC Server ──────────────────────────────────────

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
                // User exists - this is a workspace invite for an existing user
                // Get the existing user and create a new principal for them
                let existing_user = self
                    .store
                    .get_user_by_email(&req.email)
                    .await
                    .map_err(|e| Status::internal(format!("Failed to get existing user: {}", e)))?;

                // Create a new principal for this existing user
                let new_principal_id = self
                    .store
                    .create_principal(&zopp_storage::CreatePrincipalParams {
                        user_id: Some(existing_user.id.clone()),
                        name: req.principal_name.clone(),
                        public_key: req.public_key.clone(),
                        x25519_public_key: if req.x25519_public_key.is_empty() {
                            None
                        } else {
                            Some(req.x25519_public_key.clone())
                        },
                    })
                    .await
                    .map_err(|e| {
                        Status::internal(format!(
                            "Failed to create principal for existing user: {}",
                            e
                        ))
                    })?;

                // Add user to workspace memberships
                for workspace_id in &invite.workspace_ids {
                    // Ignore AlreadyExists - user may already be a member
                    let _ = self
                        .store
                        .add_user_to_workspace(workspace_id, &existing_user.id)
                        .await;
                }

                (existing_user.id, new_principal_id)
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

        let workspace_ids = workspace_ids?;

        // Check ADMIN permission for each workspace in the invite
        for ws_id in &workspace_ids {
            self.check_workspace_permission(&principal_id, ws_id, zopp_storage::Role::Admin)
                .await?;
        }

        let invite = self
            .store
            .create_invite(&CreateInviteParams {
                workspace_ids: workspace_ids.clone(),
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

    async fn list_workspace_service_principals(
        &self,
        request: Request<zopp_proto::ListWorkspaceServicePrincipalsRequest>,
    ) -> Result<Response<zopp_proto::ServicePrincipalList>, Status> {
        let (principal_id, timestamp, signature) = extract_signature(&request)?;
        let principal = self
            .verify_signature_and_get_principal(&principal_id, timestamp, &signature)
            .await?;
        let user_id = principal.user_id.ok_or_else(|| {
            Status::unauthenticated("Service accounts cannot list service principals")
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

        // Get all principals in the workspace
        let workspace_principals = self
            .store
            .list_workspace_principals(&workspace.id)
            .await
            .map_err(|e| Status::internal(format!("Failed to list workspace principals: {}", e)))?;

        // Get all projects in the workspace (for aggregating permissions)
        let projects = self
            .store
            .list_projects(&workspace.id)
            .await
            .map_err(|e| Status::internal(format!("Failed to list projects: {}", e)))?;

        let mut service_principals = Vec::new();

        for wp in workspace_principals {
            // Get the principal details
            let principal_info = match self.store.get_principal(&wp.principal_id).await {
                Ok(p) => p,
                Err(_) => continue, // Skip if principal not found
            };

            // Only include service principals (user_id is None)
            if principal_info.user_id.is_some() {
                continue;
            }

            // Aggregate permissions for this service principal
            let mut permissions = Vec::new();

            // Check project-level permissions
            for project in &projects {
                if let Ok(role) = self
                    .store
                    .get_project_permission(&project.id, &wp.principal_id)
                    .await
                {
                    permissions.push(zopp_proto::ServicePrincipalPermission {
                        scope: format!("project:{}", project.name),
                        role: match role {
                            zopp_storage::Role::Admin => zopp_proto::Role::Admin as i32,
                            zopp_storage::Role::Write => zopp_proto::Role::Write as i32,
                            zopp_storage::Role::Read => zopp_proto::Role::Read as i32,
                        },
                    });
                }

                // Check environment-level permissions within the project
                if let Ok(environments) = self.store.list_environments(&project.id).await {
                    for env in environments {
                        if let Ok(role) = self
                            .store
                            .get_environment_permission(&env.id, &wp.principal_id)
                            .await
                        {
                            permissions.push(zopp_proto::ServicePrincipalPermission {
                                scope: format!("environment:{}/{}", project.name, env.name),
                                role: match role {
                                    zopp_storage::Role::Admin => zopp_proto::Role::Admin as i32,
                                    zopp_storage::Role::Write => zopp_proto::Role::Write as i32,
                                    zopp_storage::Role::Read => zopp_proto::Role::Read as i32,
                                },
                            });
                        }
                    }
                }
            }

            service_principals.push(zopp_proto::ServicePrincipal {
                id: principal_info.id.0.to_string(),
                name: principal_info.name,
                created_at: principal_info.created_at.to_rfc3339(),
                permissions,
            });
        }

        Ok(Response::new(zopp_proto::ServicePrincipalList {
            service_principals,
        }))
    }

    async fn remove_principal_from_workspace(
        &self,
        request: Request<zopp_proto::RemovePrincipalFromWorkspaceRequest>,
    ) -> Result<Response<Empty>, Status> {
        let (principal_id, timestamp, signature) = extract_signature(&request)?;
        let principal = self
            .verify_signature_and_get_principal(&principal_id, timestamp, &signature)
            .await?;
        let user_id = principal.user_id.ok_or_else(|| {
            Status::unauthenticated("Service accounts cannot remove principals from workspaces")
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

        // Check ADMIN permission (only admins can remove principals)
        self.check_workspace_permission(&principal_id, &workspace.id, zopp_storage::Role::Admin)
            .await?;

        // Parse target principal ID
        let target_principal_id = Uuid::parse_str(&req.principal_id)
            .map(PrincipalId)
            .map_err(|_| Status::invalid_argument("Invalid principal ID"))?;

        // Verify principal exists
        self.store
            .get_principal(&target_principal_id)
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::NotFound => Status::not_found("Principal not found"),
                _ => Status::internal(format!("Failed to get principal: {}", e)),
            })?;

        // Prevent removing yourself
        if target_principal_id == principal_id {
            return Err(Status::invalid_argument("Cannot remove your own principal"));
        }

        // First remove all permissions for the principal
        self.store
            .remove_all_project_permissions_for_principal(&workspace.id, &target_principal_id)
            .await
            .map_err(|e| Status::internal(format!("Failed to remove project permissions: {}", e)))?;

        self.store
            .remove_all_environment_permissions_for_principal(&workspace.id, &target_principal_id)
            .await
            .map_err(|e| {
                Status::internal(format!("Failed to remove environment permissions: {}", e))
            })?;

        // Remove the principal from the workspace
        self.store
            .remove_workspace_principal(&workspace.id, &target_principal_id)
            .await
            .map_err(|e| {
                Status::internal(format!("Failed to remove principal from workspace: {}", e))
            })?;

        Ok(Response::new(Empty {}))
    }

    async fn revoke_all_principal_permissions(
        &self,
        request: Request<zopp_proto::RevokeAllPrincipalPermissionsRequest>,
    ) -> Result<Response<zopp_proto::RevokeAllPrincipalPermissionsResponse>, Status> {
        let (principal_id, timestamp, signature) = extract_signature(&request)?;
        let principal = self
            .verify_signature_and_get_principal(&principal_id, timestamp, &signature)
            .await?;
        let user_id = principal.user_id.ok_or_else(|| {
            Status::unauthenticated("Service accounts cannot revoke principal permissions")
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

        // Check ADMIN permission (only admins can bulk revoke permissions)
        self.check_workspace_permission(&principal_id, &workspace.id, zopp_storage::Role::Admin)
            .await?;

        // Parse target principal ID
        let target_principal_id = Uuid::parse_str(&req.principal_id)
            .map(PrincipalId)
            .map_err(|_| Status::invalid_argument("Invalid principal ID"))?;

        // Verify principal exists
        self.store
            .get_principal(&target_principal_id)
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::NotFound => Status::not_found("Principal not found"),
                _ => Status::internal(format!("Failed to get principal: {}", e)),
            })?;

        // Remove all permissions for the principal
        let project_removed = self
            .store
            .remove_all_project_permissions_for_principal(&workspace.id, &target_principal_id)
            .await
            .map_err(|e| Status::internal(format!("Failed to remove project permissions: {}", e)))?;

        let env_removed = self
            .store
            .remove_all_environment_permissions_for_principal(&workspace.id, &target_principal_id)
            .await
            .map_err(|e| {
                Status::internal(format!("Failed to remove environment permissions: {}", e))
            })?;

        Ok(Response::new(
            zopp_proto::RevokeAllPrincipalPermissionsResponse {
                permissions_revoked: (project_removed + env_removed) as i32,
            },
        ))
    }

    async fn get_effective_permissions(
        &self,
        request: Request<zopp_proto::GetEffectivePermissionsRequest>,
    ) -> Result<Response<zopp_proto::EffectivePermissionsResponse>, Status> {
        let (principal_id, timestamp, signature) = extract_signature(&request)?;
        let principal = self
            .verify_signature_and_get_principal(&principal_id, timestamp, &signature)
            .await?;
        let user_id = principal.user_id.ok_or_else(|| {
            Status::unauthenticated("Service accounts cannot query effective permissions")
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

        // Parse target principal ID
        let target_principal_id = Uuid::parse_str(&req.principal_id)
            .map(PrincipalId)
            .map_err(|_| Status::invalid_argument("Invalid principal ID"))?;

        // Get target principal info
        let target_principal = self
            .store
            .get_principal(&target_principal_id)
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::NotFound => Status::not_found("Principal not found"),
                _ => Status::internal(format!("Failed to get principal: {}", e)),
            })?;

        let is_service_principal = target_principal.user_id.is_none();

        // Get workspace-level effective role
        let workspace_role = self
            .get_effective_workspace_role(&target_principal_id, &workspace.id)
            .await?;

        // Get all projects in the workspace
        let projects = self
            .store
            .list_projects(&workspace.id)
            .await
            .map_err(|e| Status::internal(format!("Failed to list projects: {}", e)))?;

        let mut effective_projects = Vec::new();

        for project in projects {
            // Get project-level effective role
            let project_role = self
                .get_effective_project_role(&target_principal_id, &workspace.id, &project.id)
                .await?;

            // Get all environments in this project
            let environments = self
                .store
                .list_environments(&project.id)
                .await
                .map_err(|e| Status::internal(format!("Failed to list environments: {}", e)))?;

            let mut effective_environments = Vec::new();

            for env in environments {
                // Get environment-level effective role
                let env_role = self
                    .get_effective_environment_role(
                        &target_principal_id,
                        &workspace.id,
                        &project.id,
                        &env.id,
                    )
                    .await?;

                if let Some(role) = env_role {
                    effective_environments.push(zopp_proto::EffectiveEnvironmentPermission {
                        environment_id: env.id.0.to_string(),
                        environment_name: env.name,
                        effective_role: match role {
                            zopp_storage::Role::Admin => zopp_proto::Role::Admin as i32,
                            zopp_storage::Role::Write => zopp_proto::Role::Write as i32,
                            zopp_storage::Role::Read => zopp_proto::Role::Read as i32,
                        },
                    });
                }
            }

            // Only include project if there are permissions at any level
            if project_role.is_some() || !effective_environments.is_empty() {
                effective_projects.push(zopp_proto::EffectiveProjectPermission {
                    project_id: project.id.0.to_string(),
                    project_name: project.name,
                    effective_role: project_role.map(|r| match r {
                        zopp_storage::Role::Admin => zopp_proto::Role::Admin as i32,
                        zopp_storage::Role::Write => zopp_proto::Role::Write as i32,
                        zopp_storage::Role::Read => zopp_proto::Role::Read as i32,
                    }),
                    environments: effective_environments,
                });
            }
        }

        Ok(Response::new(zopp_proto::EffectivePermissionsResponse {
            principal_id: target_principal.id.0.to_string(),
            principal_name: target_principal.name,
            is_service_principal,
            workspace_role: workspace_role.map(|r| match r {
                zopp_storage::Role::Admin => zopp_proto::Role::Admin as i32,
                zopp_storage::Role::Write => zopp_proto::Role::Write as i32,
                zopp_storage::Role::Read => zopp_proto::Role::Read as i32,
            }),
            projects: effective_projects,
        }))
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

        // Check ADMIN permission for creating projects
        self.check_workspace_permission(&principal_id, &workspace.id, zopp_storage::Role::Admin)
            .await?;

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

        // Check ADMIN permission for deleting projects
        self.check_workspace_permission(&principal_id, &workspace.id, zopp_storage::Role::Admin)
            .await?;

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

        // Check ADMIN permission for creating environments (project-level or higher)
        self.check_project_permission(
            &principal_id,
            &workspace.id,
            &project.id,
            zopp_storage::Role::Admin,
        )
        .await?;

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

        // Check ADMIN permission for deleting environments (project-level or higher)
        self.check_project_permission(
            &principal_id,
            &workspace.id,
            &project.id,
            zopp_storage::Role::Admin,
        )
        .await?;

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

        // Check RBAC permission - upsert requires Write
        self.check_permission(
            &principal_id,
            &workspace.id,
            &project.id,
            &env.id,
            zopp_storage::Role::Write,
        )
        .await?;

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

        // Check RBAC permission - get requires Read
        self.check_permission(
            &principal_id,
            &workspace.id,
            &project.id,
            &env.id,
            zopp_storage::Role::Read,
        )
        .await?;

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

        // Check RBAC permission - list requires Read
        self.check_permission(
            &principal_id,
            &workspace.id,
            &project.id,
            &env.id,
            zopp_storage::Role::Read,
        )
        .await?;

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

        // Check RBAC permission - delete requires Write
        self.check_permission(
            &principal_id,
            &workspace.id,
            &project.id,
            &env.id,
            zopp_storage::Role::Write,
        )
        .await?;

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

        // Check RBAC permission - watch requires Read
        self.check_permission(
            &principal_id,
            &workspace.id,
            &project.id,
            &env.id,
            zopp_storage::Role::Read,
        )
        .await?;

        // Check if client is behind (needs resync)
        if let Some(client_version) = req.since_version {
            if client_version < env.version {
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

    // ───────────────────────────────────── Principal Permissions ─────────────────────────────────────

    async fn set_workspace_permission(
        &self,
        request: Request<zopp_proto::SetWorkspacePermissionRequest>,
    ) -> Result<Response<Empty>, Status> {
        let (principal_id, timestamp, signature) = extract_signature(&request)?;
        let principal = self
            .verify_signature_and_get_principal(&principal_id, timestamp, &signature)
            .await?;
        let user_id = principal
            .user_id
            .ok_or_else(|| Status::unauthenticated("Service accounts cannot set permissions"))?;

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

        // Parse principal ID
        let target_principal_id = Uuid::parse_str(&req.principal_id)
            .map(PrincipalId)
            .map_err(|_| Status::invalid_argument("Invalid principal ID"))?;

        // Convert proto Role to storage Role
        let role = match zopp_proto::Role::try_from(req.role) {
            Ok(zopp_proto::Role::Admin) => zopp_storage::Role::Admin,
            Ok(zopp_proto::Role::Write) => zopp_storage::Role::Write,
            Ok(zopp_proto::Role::Read) => zopp_storage::Role::Read,
            _ => return Err(Status::invalid_argument("Invalid role")),
        };

        self.store
            .set_workspace_permission(&workspace.id, &target_principal_id, role)
            .await
            .map_err(|e| Status::internal(format!("Failed to set permission: {}", e)))?;

        Ok(Response::new(Empty {}))
    }

    async fn get_workspace_permission(
        &self,
        request: Request<zopp_proto::GetWorkspacePermissionRequest>,
    ) -> Result<Response<zopp_proto::PermissionResponse>, Status> {
        let (principal_id, timestamp, signature) = extract_signature(&request)?;
        let principal = self
            .verify_signature_and_get_principal(&principal_id, timestamp, &signature)
            .await?;
        let user_id = principal
            .user_id
            .ok_or_else(|| Status::unauthenticated("Service accounts cannot get permissions"))?;

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

        // Parse principal ID
        let target_principal_id = Uuid::parse_str(&req.principal_id)
            .map(PrincipalId)
            .map_err(|_| Status::invalid_argument("Invalid principal ID"))?;

        let role = self
            .store
            .get_workspace_permission(&workspace.id, &target_principal_id)
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::NotFound => Status::not_found("Permission not found"),
                _ => Status::internal(format!("Failed to get permission: {}", e)),
            })?;

        // Convert storage Role to proto Role
        let proto_role = match role {
            zopp_storage::Role::Admin => zopp_proto::Role::Admin as i32,
            zopp_storage::Role::Write => zopp_proto::Role::Write as i32,
            zopp_storage::Role::Read => zopp_proto::Role::Read as i32,
        };

        Ok(Response::new(zopp_proto::PermissionResponse {
            role: proto_role,
        }))
    }

    async fn list_workspace_permissions(
        &self,
        request: Request<zopp_proto::ListWorkspacePermissionsRequest>,
    ) -> Result<Response<zopp_proto::PermissionList>, Status> {
        let (principal_id, timestamp, signature) = extract_signature(&request)?;
        let principal = self
            .verify_signature_and_get_principal(&principal_id, timestamp, &signature)
            .await?;
        let user_id = principal
            .user_id
            .ok_or_else(|| Status::unauthenticated("Service accounts cannot list permissions"))?;

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

        let permissions = self
            .store
            .list_workspace_permissions(&workspace.id)
            .await
            .map_err(|e| Status::internal(format!("Failed to list permissions: {}", e)))?;

        let mut proto_permissions = Vec::with_capacity(permissions.len());
        for p in permissions {
            let principal_name = match self.store.get_principal(&p.principal_id).await {
                Ok(principal) => principal.name,
                Err(_) => String::new(), // Principal might have been deleted
            };
            proto_permissions.push(zopp_proto::Permission {
                principal_id: p.principal_id.0.to_string(),
                principal_name,
                role: match p.role {
                    zopp_storage::Role::Admin => zopp_proto::Role::Admin as i32,
                    zopp_storage::Role::Write => zopp_proto::Role::Write as i32,
                    zopp_storage::Role::Read => zopp_proto::Role::Read as i32,
                },
            });
        }

        Ok(Response::new(zopp_proto::PermissionList {
            permissions: proto_permissions,
        }))
    }

    async fn remove_workspace_permission(
        &self,
        request: Request<zopp_proto::RemoveWorkspacePermissionRequest>,
    ) -> Result<Response<Empty>, Status> {
        let (principal_id, timestamp, signature) = extract_signature(&request)?;
        let principal = self
            .verify_signature_and_get_principal(&principal_id, timestamp, &signature)
            .await?;
        let user_id = principal
            .user_id
            .ok_or_else(|| Status::unauthenticated("Service accounts cannot remove permissions"))?;

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

        // Parse principal ID
        let target_principal_id = Uuid::parse_str(&req.principal_id)
            .map(PrincipalId)
            .map_err(|_| Status::invalid_argument("Invalid principal ID"))?;

        self.store
            .remove_workspace_permission(&workspace.id, &target_principal_id)
            .await
            .map_err(|e| Status::internal(format!("Failed to remove permission: {}", e)))?;

        Ok(Response::new(Empty {}))
    }

    async fn set_project_permission(
        &self,
        request: Request<zopp_proto::SetProjectPermissionRequest>,
    ) -> Result<Response<Empty>, Status> {
        let (principal_id, timestamp, signature) = extract_signature(&request)?;
        self.verify_signature_and_get_principal(&principal_id, timestamp, &signature)
            .await?;

        let req = request.into_inner();

        // Look up workspace by name for this principal
        let workspace = self
            .store
            .get_workspace_by_name_for_principal(&principal_id, &req.workspace_name)
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::NotFound => {
                    Status::not_found("Workspace not found or access denied")
                }
                _ => Status::internal(format!("Failed to get workspace: {}", e)),
            })?;

        // Look up project by name
        let project = self
            .store
            .get_project_by_name(&workspace.id, &req.project_name)
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::NotFound => Status::not_found("Project not found"),
                _ => Status::internal(format!("Failed to get project: {}", e)),
            })?;

        // Parse target principal ID
        let target_principal_id = Uuid::parse_str(&req.principal_id)
            .map(PrincipalId)
            .map_err(|_| Status::invalid_argument("Invalid principal ID"))?;

        // Convert proto Role to storage Role
        let role = match zopp_proto::Role::try_from(req.role) {
            Ok(zopp_proto::Role::Admin) => zopp_storage::Role::Admin,
            Ok(zopp_proto::Role::Write) => zopp_storage::Role::Write,
            Ok(zopp_proto::Role::Read) => zopp_storage::Role::Read,
            _ => return Err(Status::invalid_argument("Invalid role")),
        };

        // Delegated authority: requester can only grant permissions <= their own effective role
        let requester_role = self
            .get_effective_project_role(&principal_id, &workspace.id, &project.id)
            .await?
            .ok_or_else(|| {
                Status::permission_denied("No permission to set permissions on this project")
            })?;

        // Check if requester's role is sufficient to grant the requested role
        if !requester_role.includes(&role) {
            return Err(Status::permission_denied(format!(
                "Cannot grant {:?} permission (you only have {:?} access)",
                role, requester_role
            )));
        }

        self.store
            .set_project_permission(&project.id, &target_principal_id, role)
            .await
            .map_err(|e| Status::internal(format!("Failed to set permission: {}", e)))?;

        Ok(Response::new(Empty {}))
    }

    async fn get_project_permission(
        &self,
        request: Request<zopp_proto::GetProjectPermissionRequest>,
    ) -> Result<Response<zopp_proto::PermissionResponse>, Status> {
        let (principal_id, timestamp, signature) = extract_signature(&request)?;
        let principal = self
            .verify_signature_and_get_principal(&principal_id, timestamp, &signature)
            .await?;
        let user_id = principal
            .user_id
            .ok_or_else(|| Status::unauthenticated("Service accounts cannot get permissions"))?;

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

        // Look up project by name
        let project = self
            .store
            .get_project_by_name(&workspace.id, &req.project_name)
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::NotFound => Status::not_found("Project not found"),
                _ => Status::internal(format!("Failed to get project: {}", e)),
            })?;

        // Parse principal ID
        let target_principal_id = Uuid::parse_str(&req.principal_id)
            .map(PrincipalId)
            .map_err(|_| Status::invalid_argument("Invalid principal ID"))?;

        let role = self
            .store
            .get_project_permission(&project.id, &target_principal_id)
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::NotFound => Status::not_found("Permission not found"),
                _ => Status::internal(format!("Failed to get permission: {}", e)),
            })?;

        // Convert storage Role to proto Role
        let proto_role = match role {
            zopp_storage::Role::Admin => zopp_proto::Role::Admin as i32,
            zopp_storage::Role::Write => zopp_proto::Role::Write as i32,
            zopp_storage::Role::Read => zopp_proto::Role::Read as i32,
        };

        Ok(Response::new(zopp_proto::PermissionResponse {
            role: proto_role,
        }))
    }

    async fn list_project_permissions(
        &self,
        request: Request<zopp_proto::ListProjectPermissionsRequest>,
    ) -> Result<Response<zopp_proto::PermissionList>, Status> {
        let (principal_id, timestamp, signature) = extract_signature(&request)?;
        let principal = self
            .verify_signature_and_get_principal(&principal_id, timestamp, &signature)
            .await?;
        let user_id = principal
            .user_id
            .ok_or_else(|| Status::unauthenticated("Service accounts cannot list permissions"))?;

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

        // Look up project by name
        let project = self
            .store
            .get_project_by_name(&workspace.id, &req.project_name)
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::NotFound => Status::not_found("Project not found"),
                _ => Status::internal(format!("Failed to get project: {}", e)),
            })?;

        let permissions = self
            .store
            .list_project_permissions(&project.id)
            .await
            .map_err(|e| Status::internal(format!("Failed to list permissions: {}", e)))?;

        let mut proto_permissions = Vec::with_capacity(permissions.len());
        for p in permissions {
            let principal_name = match self.store.get_principal(&p.principal_id).await {
                Ok(principal) => principal.name,
                Err(_) => String::new(), // Principal might have been deleted
            };
            proto_permissions.push(zopp_proto::Permission {
                principal_id: p.principal_id.0.to_string(),
                principal_name,
                role: match p.role {
                    zopp_storage::Role::Admin => zopp_proto::Role::Admin as i32,
                    zopp_storage::Role::Write => zopp_proto::Role::Write as i32,
                    zopp_storage::Role::Read => zopp_proto::Role::Read as i32,
                },
            });
        }

        Ok(Response::new(zopp_proto::PermissionList {
            permissions: proto_permissions,
        }))
    }

    async fn remove_project_permission(
        &self,
        request: Request<zopp_proto::RemoveProjectPermissionRequest>,
    ) -> Result<Response<Empty>, Status> {
        let (principal_id, timestamp, signature) = extract_signature(&request)?;
        self.verify_signature_and_get_principal(&principal_id, timestamp, &signature)
            .await?;

        let req = request.into_inner();

        // Look up workspace by name for this principal
        let workspace = self
            .store
            .get_workspace_by_name_for_principal(&principal_id, &req.workspace_name)
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::NotFound => {
                    Status::not_found("Workspace not found or access denied")
                }
                _ => Status::internal(format!("Failed to get workspace: {}", e)),
            })?;

        // Look up project by name
        let project = self
            .store
            .get_project_by_name(&workspace.id, &req.project_name)
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::NotFound => Status::not_found("Project not found"),
                _ => Status::internal(format!("Failed to get project: {}", e)),
            })?;

        // Parse target principal ID
        let target_principal_id = Uuid::parse_str(&req.principal_id)
            .map(PrincipalId)
            .map_err(|_| Status::invalid_argument("Invalid principal ID"))?;

        // Get target's current permission level
        let target_role = self
            .store
            .get_project_permission(&project.id, &target_principal_id)
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::NotFound => {
                    Status::not_found("Permission not found for target principal")
                }
                _ => Status::internal(format!("Failed to get target permission: {}", e)),
            })?;

        // Delegated authority: requester can only remove permissions <= their own effective role
        let requester_role = self
            .get_effective_project_role(&principal_id, &workspace.id, &project.id)
            .await?
            .ok_or_else(|| {
                Status::permission_denied("No permission to remove permissions on this project")
            })?;

        // Check if requester's role is sufficient to remove the target's role
        if !requester_role.includes(&target_role) {
            return Err(Status::permission_denied(format!(
                "Cannot remove {:?} permission (you only have {:?} access)",
                target_role, requester_role
            )));
        }

        self.store
            .remove_project_permission(&project.id, &target_principal_id)
            .await
            .map_err(|e| Status::internal(format!("Failed to remove permission: {}", e)))?;

        Ok(Response::new(Empty {}))
    }

    async fn set_environment_permission(
        &self,
        request: Request<zopp_proto::SetEnvironmentPermissionRequest>,
    ) -> Result<Response<Empty>, Status> {
        let (principal_id, timestamp, signature) = extract_signature(&request)?;
        self.verify_signature_and_get_principal(&principal_id, timestamp, &signature)
            .await?;

        let req = request.into_inner();

        // Look up workspace by name for this principal
        let workspace = self
            .store
            .get_workspace_by_name_for_principal(&principal_id, &req.workspace_name)
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::NotFound => {
                    Status::not_found("Workspace not found or access denied")
                }
                _ => Status::internal(format!("Failed to get workspace: {}", e)),
            })?;

        // Look up project by name
        let project = self
            .store
            .get_project_by_name(&workspace.id, &req.project_name)
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::NotFound => Status::not_found("Project not found"),
                _ => Status::internal(format!("Failed to get project: {}", e)),
            })?;

        // Look up environment by name
        let env = self
            .store
            .get_environment_by_name(&project.id, &req.environment_name)
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::NotFound => Status::not_found("Environment not found"),
                _ => Status::internal(format!("Failed to get environment: {}", e)),
            })?;

        // Parse target principal ID
        let target_principal_id = Uuid::parse_str(&req.principal_id)
            .map(PrincipalId)
            .map_err(|_| Status::invalid_argument("Invalid principal ID"))?;

        // Convert proto Role to storage Role
        let role = match zopp_proto::Role::try_from(req.role) {
            Ok(zopp_proto::Role::Admin) => zopp_storage::Role::Admin,
            Ok(zopp_proto::Role::Write) => zopp_storage::Role::Write,
            Ok(zopp_proto::Role::Read) => zopp_storage::Role::Read,
            _ => return Err(Status::invalid_argument("Invalid role")),
        };

        // Delegated authority: requester can only grant permissions <= their own effective role
        let requester_role = self
            .get_effective_environment_role(&principal_id, &workspace.id, &project.id, &env.id)
            .await?
            .ok_or_else(|| {
                Status::permission_denied("No permission to set permissions on this environment")
            })?;

        // Check if requester's role is sufficient to grant the requested role
        if !requester_role.includes(&role) {
            return Err(Status::permission_denied(format!(
                "Cannot grant {:?} permission (you only have {:?} access)",
                role, requester_role
            )));
        }

        self.store
            .set_environment_permission(&env.id, &target_principal_id, role)
            .await
            .map_err(|e| Status::internal(format!("Failed to set permission: {}", e)))?;

        Ok(Response::new(Empty {}))
    }

    async fn get_environment_permission(
        &self,
        request: Request<zopp_proto::GetEnvironmentPermissionRequest>,
    ) -> Result<Response<zopp_proto::PermissionResponse>, Status> {
        let (principal_id, timestamp, signature) = extract_signature(&request)?;
        let principal = self
            .verify_signature_and_get_principal(&principal_id, timestamp, &signature)
            .await?;
        let user_id = principal
            .user_id
            .ok_or_else(|| Status::unauthenticated("Service accounts cannot get permissions"))?;

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

        // Look up project by name
        let project = self
            .store
            .get_project_by_name(&workspace.id, &req.project_name)
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::NotFound => Status::not_found("Project not found"),
                _ => Status::internal(format!("Failed to get project: {}", e)),
            })?;

        // Look up environment by name
        let env = self
            .store
            .get_environment_by_name(&project.id, &req.environment_name)
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::NotFound => Status::not_found("Environment not found"),
                _ => Status::internal(format!("Failed to get environment: {}", e)),
            })?;

        // Parse principal ID
        let target_principal_id = Uuid::parse_str(&req.principal_id)
            .map(PrincipalId)
            .map_err(|_| Status::invalid_argument("Invalid principal ID"))?;

        let role = self
            .store
            .get_environment_permission(&env.id, &target_principal_id)
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::NotFound => Status::not_found("Permission not found"),
                _ => Status::internal(format!("Failed to get permission: {}", e)),
            })?;

        // Convert storage Role to proto Role
        let proto_role = match role {
            zopp_storage::Role::Admin => zopp_proto::Role::Admin as i32,
            zopp_storage::Role::Write => zopp_proto::Role::Write as i32,
            zopp_storage::Role::Read => zopp_proto::Role::Read as i32,
        };

        Ok(Response::new(zopp_proto::PermissionResponse {
            role: proto_role,
        }))
    }

    async fn list_environment_permissions(
        &self,
        request: Request<zopp_proto::ListEnvironmentPermissionsRequest>,
    ) -> Result<Response<zopp_proto::PermissionList>, Status> {
        let (principal_id, timestamp, signature) = extract_signature(&request)?;
        let principal = self
            .verify_signature_and_get_principal(&principal_id, timestamp, &signature)
            .await?;
        let user_id = principal
            .user_id
            .ok_or_else(|| Status::unauthenticated("Service accounts cannot list permissions"))?;

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

        // Look up project by name
        let project = self
            .store
            .get_project_by_name(&workspace.id, &req.project_name)
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::NotFound => Status::not_found("Project not found"),
                _ => Status::internal(format!("Failed to get project: {}", e)),
            })?;

        // Look up environment by name
        let env = self
            .store
            .get_environment_by_name(&project.id, &req.environment_name)
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::NotFound => Status::not_found("Environment not found"),
                _ => Status::internal(format!("Failed to get environment: {}", e)),
            })?;

        let permissions = self
            .store
            .list_environment_permissions(&env.id)
            .await
            .map_err(|e| Status::internal(format!("Failed to list permissions: {}", e)))?;

        let mut proto_permissions = Vec::with_capacity(permissions.len());
        for p in permissions {
            let principal_name = match self.store.get_principal(&p.principal_id).await {
                Ok(principal) => principal.name,
                Err(_) => String::new(), // Principal might have been deleted
            };
            proto_permissions.push(zopp_proto::Permission {
                principal_id: p.principal_id.0.to_string(),
                principal_name,
                role: match p.role {
                    zopp_storage::Role::Admin => zopp_proto::Role::Admin as i32,
                    zopp_storage::Role::Write => zopp_proto::Role::Write as i32,
                    zopp_storage::Role::Read => zopp_proto::Role::Read as i32,
                },
            });
        }

        Ok(Response::new(zopp_proto::PermissionList {
            permissions: proto_permissions,
        }))
    }

    async fn remove_environment_permission(
        &self,
        request: Request<zopp_proto::RemoveEnvironmentPermissionRequest>,
    ) -> Result<Response<Empty>, Status> {
        let (principal_id, timestamp, signature) = extract_signature(&request)?;
        self.verify_signature_and_get_principal(&principal_id, timestamp, &signature)
            .await?;

        let req = request.into_inner();

        // Look up workspace by name for this principal
        let workspace = self
            .store
            .get_workspace_by_name_for_principal(&principal_id, &req.workspace_name)
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::NotFound => {
                    Status::not_found("Workspace not found or access denied")
                }
                _ => Status::internal(format!("Failed to get workspace: {}", e)),
            })?;

        // Look up project by name
        let project = self
            .store
            .get_project_by_name(&workspace.id, &req.project_name)
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::NotFound => Status::not_found("Project not found"),
                _ => Status::internal(format!("Failed to get project: {}", e)),
            })?;

        // Look up environment by name
        let env = self
            .store
            .get_environment_by_name(&project.id, &req.environment_name)
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::NotFound => Status::not_found("Environment not found"),
                _ => Status::internal(format!("Failed to get environment: {}", e)),
            })?;

        // Parse target principal ID
        let target_principal_id = Uuid::parse_str(&req.principal_id)
            .map(PrincipalId)
            .map_err(|_| Status::invalid_argument("Invalid principal ID"))?;

        // Get target's current permission level
        let target_role = self
            .store
            .get_environment_permission(&env.id, &target_principal_id)
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::NotFound => {
                    Status::not_found("Permission not found for target principal")
                }
                _ => Status::internal(format!("Failed to get target permission: {}", e)),
            })?;

        // Delegated authority: requester can only remove permissions <= their own effective role
        let requester_role = self
            .get_effective_environment_role(&principal_id, &workspace.id, &project.id, &env.id)
            .await?
            .ok_or_else(|| {
                Status::permission_denied("No permission to remove permissions on this environment")
            })?;

        // Check if requester's role is sufficient to remove the target's role
        if !requester_role.includes(&target_role) {
            return Err(Status::permission_denied(format!(
                "Cannot remove {:?} permission (you only have {:?} access)",
                target_role, requester_role
            )));
        }

        self.store
            .remove_environment_permission(&env.id, &target_principal_id)
            .await
            .map_err(|e| Status::internal(format!("Failed to remove permission: {}", e)))?;

        Ok(Response::new(Empty {}))
    }

    // ───────────────────────────────────── Groups ─────────────────────────────────────

    async fn create_group(
        &self,
        request: Request<zopp_proto::CreateGroupRequest>,
    ) -> Result<Response<zopp_proto::Group>, Status> {
        let (principal_id, timestamp, signature) = extract_signature(&request)?;
        let principal = self
            .verify_signature_and_get_principal(&principal_id, timestamp, &signature)
            .await?;
        let user_id = principal
            .user_id
            .ok_or_else(|| Status::unauthenticated("Service accounts cannot create groups"))?;

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

        // Check ADMIN permission for creating groups
        self.check_workspace_permission(&principal_id, &workspace.id, zopp_storage::Role::Admin)
            .await?;

        let group_id = self
            .store
            .create_group(&zopp_storage::CreateGroupParams {
                workspace_id: workspace.id.clone(),
                name: req.name,
                description: if req.description.is_empty() {
                    None
                } else {
                    Some(req.description)
                },
            })
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::AlreadyExists => {
                    Status::already_exists("Group with this name already exists")
                }
                _ => Status::internal(format!("Failed to create group: {}", e)),
            })?;

        let group = self
            .store
            .get_group(&group_id)
            .await
            .map_err(|e| Status::internal(format!("Failed to get group: {}", e)))?;

        Ok(Response::new(zopp_proto::Group {
            id: group.id.0.to_string(),
            workspace_id: group.workspace_id.0.to_string(),
            name: group.name,
            description: group.description.unwrap_or_default(),
            created_at: group.created_at.to_rfc3339(),
            updated_at: group.updated_at.to_rfc3339(),
        }))
    }

    async fn get_group(
        &self,
        request: Request<zopp_proto::GetGroupRequest>,
    ) -> Result<Response<zopp_proto::Group>, Status> {
        let (principal_id, timestamp, signature) = extract_signature(&request)?;
        let principal = self
            .verify_signature_and_get_principal(&principal_id, timestamp, &signature)
            .await?;
        let user_id = principal
            .user_id
            .ok_or_else(|| Status::unauthenticated("Service accounts cannot get groups"))?;

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

        let group = self
            .store
            .get_group_by_name(&workspace.id, &req.group_name)
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::NotFound => Status::not_found("Group not found"),
                _ => Status::internal(format!("Failed to get group: {}", e)),
            })?;

        Ok(Response::new(zopp_proto::Group {
            id: group.id.0.to_string(),
            workspace_id: group.workspace_id.0.to_string(),
            name: group.name,
            description: group.description.unwrap_or_default(),
            created_at: group.created_at.to_rfc3339(),
            updated_at: group.updated_at.to_rfc3339(),
        }))
    }

    async fn list_groups(
        &self,
        request: Request<zopp_proto::ListGroupsRequest>,
    ) -> Result<Response<zopp_proto::GroupList>, Status> {
        let (principal_id, timestamp, signature) = extract_signature(&request)?;
        let principal = self
            .verify_signature_and_get_principal(&principal_id, timestamp, &signature)
            .await?;
        let user_id = principal
            .user_id
            .ok_or_else(|| Status::unauthenticated("Service accounts cannot list groups"))?;

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

        let groups = self
            .store
            .list_groups(&workspace.id)
            .await
            .map_err(|e| Status::internal(format!("Failed to list groups: {}", e)))?;

        let proto_groups = groups
            .into_iter()
            .map(|g| zopp_proto::Group {
                id: g.id.0.to_string(),
                workspace_id: g.workspace_id.0.to_string(),
                name: g.name,
                description: g.description.unwrap_or_default(),
                created_at: g.created_at.to_rfc3339(),
                updated_at: g.updated_at.to_rfc3339(),
            })
            .collect();

        Ok(Response::new(zopp_proto::GroupList {
            groups: proto_groups,
        }))
    }

    async fn update_group(
        &self,
        request: Request<zopp_proto::UpdateGroupRequest>,
    ) -> Result<Response<zopp_proto::Group>, Status> {
        let (principal_id, timestamp, signature) = extract_signature(&request)?;
        let principal = self
            .verify_signature_and_get_principal(&principal_id, timestamp, &signature)
            .await?;
        let user_id = principal
            .user_id
            .ok_or_else(|| Status::unauthenticated("Service accounts cannot update groups"))?;

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

        let group = self
            .store
            .get_group_by_name(&workspace.id, &req.group_name)
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::NotFound => Status::not_found("Group not found"),
                _ => Status::internal(format!("Failed to get group: {}", e)),
            })?;

        self.store
            .update_group(
                &group.id,
                &req.new_name,
                if req.new_description.is_empty() {
                    None
                } else {
                    Some(&req.new_description)
                },
            )
            .await
            .map_err(|e| Status::internal(format!("Failed to update group: {}", e)))?;

        let updated_group = self
            .store
            .get_group(&group.id)
            .await
            .map_err(|e| Status::internal(format!("Failed to get updated group: {}", e)))?;

        Ok(Response::new(zopp_proto::Group {
            id: updated_group.id.0.to_string(),
            workspace_id: updated_group.workspace_id.0.to_string(),
            name: updated_group.name,
            description: updated_group.description.unwrap_or_default(),
            created_at: updated_group.created_at.to_rfc3339(),
            updated_at: updated_group.updated_at.to_rfc3339(),
        }))
    }

    async fn delete_group(
        &self,
        request: Request<zopp_proto::DeleteGroupRequest>,
    ) -> Result<Response<Empty>, Status> {
        let (principal_id, timestamp, signature) = extract_signature(&request)?;
        let principal = self
            .verify_signature_and_get_principal(&principal_id, timestamp, &signature)
            .await?;
        let user_id = principal
            .user_id
            .ok_or_else(|| Status::unauthenticated("Service accounts cannot delete groups"))?;

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

        // Check ADMIN permission for deleting groups
        self.check_workspace_permission(&principal_id, &workspace.id, zopp_storage::Role::Admin)
            .await?;

        let group = self
            .store
            .get_group_by_name(&workspace.id, &req.group_name)
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::NotFound => Status::not_found("Group not found"),
                _ => Status::internal(format!("Failed to get group: {}", e)),
            })?;

        self.store
            .delete_group(&group.id)
            .await
            .map_err(|e| Status::internal(format!("Failed to delete group: {}", e)))?;

        Ok(Response::new(Empty {}))
    }

    async fn add_group_member(
        &self,
        request: Request<zopp_proto::AddGroupMemberRequest>,
    ) -> Result<Response<Empty>, Status> {
        let (principal_id, timestamp, signature) = extract_signature(&request)?;
        let principal = self
            .verify_signature_and_get_principal(&principal_id, timestamp, &signature)
            .await?;
        let user_id = principal
            .user_id
            .ok_or_else(|| Status::unauthenticated("Service accounts cannot add group members"))?;

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

        // Check ADMIN permission for managing group members
        self.check_workspace_permission(&principal_id, &workspace.id, zopp_storage::Role::Admin)
            .await?;

        let group = self
            .store
            .get_group_by_name(&workspace.id, &req.group_name)
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::NotFound => Status::not_found("Group not found"),
                _ => Status::internal(format!("Failed to get group: {}", e)),
            })?;

        // Look up user by email
        let target_user = self
            .store
            .get_user_by_email(&req.user_email)
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::NotFound => Status::not_found("User not found"),
                _ => Status::internal(format!("Failed to get user: {}", e)),
            })?;

        self.store
            .add_group_member(&group.id, &target_user.id)
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::AlreadyExists => {
                    Status::already_exists("User is already a member of this group")
                }
                _ => Status::internal(format!("Failed to add group member: {}", e)),
            })?;

        Ok(Response::new(Empty {}))
    }

    async fn remove_group_member(
        &self,
        request: Request<zopp_proto::RemoveGroupMemberRequest>,
    ) -> Result<Response<Empty>, Status> {
        let (principal_id, timestamp, signature) = extract_signature(&request)?;
        let principal = self
            .verify_signature_and_get_principal(&principal_id, timestamp, &signature)
            .await?;
        let user_id = principal.user_id.ok_or_else(|| {
            Status::unauthenticated("Service accounts cannot remove group members")
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

        // Check ADMIN permission for managing group members
        self.check_workspace_permission(&principal_id, &workspace.id, zopp_storage::Role::Admin)
            .await?;

        let group = self
            .store
            .get_group_by_name(&workspace.id, &req.group_name)
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::NotFound => Status::not_found("Group not found"),
                _ => Status::internal(format!("Failed to get group: {}", e)),
            })?;

        // Look up user by email
        let target_user = self
            .store
            .get_user_by_email(&req.user_email)
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::NotFound => Status::not_found("User not found"),
                _ => Status::internal(format!("Failed to get user: {}", e)),
            })?;

        self.store
            .remove_group_member(&group.id, &target_user.id)
            .await
            .map_err(|e| Status::internal(format!("Failed to remove group member: {}", e)))?;

        Ok(Response::new(Empty {}))
    }

    async fn list_group_members(
        &self,
        request: Request<zopp_proto::ListGroupMembersRequest>,
    ) -> Result<Response<zopp_proto::GroupMemberList>, Status> {
        let (principal_id, timestamp, signature) = extract_signature(&request)?;
        let principal = self
            .verify_signature_and_get_principal(&principal_id, timestamp, &signature)
            .await?;
        let user_id = principal
            .user_id
            .ok_or_else(|| Status::unauthenticated("Service accounts cannot list group members"))?;

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

        let group = self
            .store
            .get_group_by_name(&workspace.id, &req.group_name)
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::NotFound => Status::not_found("Group not found"),
                _ => Status::internal(format!("Failed to get group: {}", e)),
            })?;

        let members = self
            .store
            .list_group_members(&group.id)
            .await
            .map_err(|e| Status::internal(format!("Failed to list group members: {}", e)))?;

        let mut proto_members = Vec::new();
        for member in members {
            // Look up user to get email
            let user = self
                .store
                .get_user_by_id(&member.user_id)
                .await
                .map_err(|e| Status::internal(format!("Failed to get user: {}", e)))?;

            proto_members.push(zopp_proto::GroupMember {
                user_id: member.user_id.0.to_string(),
                user_email: user.email,
                created_at: member.created_at.to_rfc3339(),
            });
        }

        Ok(Response::new(zopp_proto::GroupMemberList {
            members: proto_members,
        }))
    }

    async fn list_user_groups(
        &self,
        request: Request<zopp_proto::ListUserGroupsRequest>,
    ) -> Result<Response<zopp_proto::GroupList>, Status> {
        let (principal_id, timestamp, signature) = extract_signature(&request)?;
        let principal = self
            .verify_signature_and_get_principal(&principal_id, timestamp, &signature)
            .await?;
        let user_id = principal
            .user_id
            .ok_or_else(|| Status::unauthenticated("Service accounts cannot list user groups"))?;

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

        // Look up target user by email
        let target_user = self
            .store
            .get_user_by_email(&req.user_email)
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::NotFound => Status::not_found("User not found"),
                _ => Status::internal(format!("Failed to get user: {}", e)),
            })?;

        let groups = self
            .store
            .list_user_groups(&target_user.id)
            .await
            .map_err(|e| Status::internal(format!("Failed to list user groups: {}", e)))?;

        // Filter groups by workspace
        let proto_groups = groups
            .into_iter()
            .filter(|g| g.workspace_id == workspace.id)
            .map(|g| zopp_proto::Group {
                id: g.id.0.to_string(),
                workspace_id: g.workspace_id.0.to_string(),
                name: g.name,
                description: g.description.unwrap_or_default(),
                created_at: g.created_at.to_rfc3339(),
                updated_at: g.updated_at.to_rfc3339(),
            })
            .collect();

        Ok(Response::new(zopp_proto::GroupList {
            groups: proto_groups,
        }))
    }

    // ───────────────────────────────────── Group Permissions ─────────────────────────────────────

    async fn set_group_workspace_permission(
        &self,
        request: Request<zopp_proto::SetGroupWorkspacePermissionRequest>,
    ) -> Result<Response<Empty>, Status> {
        let (principal_id, timestamp, signature) = extract_signature(&request)?;
        let principal = self
            .verify_signature_and_get_principal(&principal_id, timestamp, &signature)
            .await?;
        let user_id = principal.user_id.ok_or_else(|| {
            Status::unauthenticated("Service accounts cannot set group permissions")
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

        // Check ADMIN permission for setting group permissions
        self.check_workspace_permission(&principal_id, &workspace.id, zopp_storage::Role::Admin)
            .await?;

        let group = self
            .store
            .get_group_by_name(&workspace.id, &req.group_name)
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::NotFound => Status::not_found("Group not found"),
                _ => Status::internal(format!("Failed to get group: {}", e)),
            })?;

        // Convert proto Role to storage Role
        let role = match zopp_proto::Role::try_from(req.role) {
            Ok(zopp_proto::Role::Admin) => zopp_storage::Role::Admin,
            Ok(zopp_proto::Role::Write) => zopp_storage::Role::Write,
            Ok(zopp_proto::Role::Read) => zopp_storage::Role::Read,
            _ => return Err(Status::invalid_argument("Invalid role")),
        };

        self.store
            .set_group_workspace_permission(&workspace.id, &group.id, role)
            .await
            .map_err(|e| Status::internal(format!("Failed to set group permission: {}", e)))?;

        Ok(Response::new(Empty {}))
    }

    async fn get_group_workspace_permission(
        &self,
        request: Request<zopp_proto::GetGroupWorkspacePermissionRequest>,
    ) -> Result<Response<zopp_proto::PermissionResponse>, Status> {
        let (principal_id, timestamp, signature) = extract_signature(&request)?;
        let principal = self
            .verify_signature_and_get_principal(&principal_id, timestamp, &signature)
            .await?;
        let user_id = principal.user_id.ok_or_else(|| {
            Status::unauthenticated("Service accounts cannot get group permissions")
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

        let group = self
            .store
            .get_group_by_name(&workspace.id, &req.group_name)
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::NotFound => Status::not_found("Group not found"),
                _ => Status::internal(format!("Failed to get group: {}", e)),
            })?;

        let role = self
            .store
            .get_group_workspace_permission(&workspace.id, &group.id)
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::NotFound => Status::not_found("Permission not found"),
                _ => Status::internal(format!("Failed to get group permission: {}", e)),
            })?;

        // Convert storage Role to proto Role
        let proto_role = match role {
            zopp_storage::Role::Admin => zopp_proto::Role::Admin as i32,
            zopp_storage::Role::Write => zopp_proto::Role::Write as i32,
            zopp_storage::Role::Read => zopp_proto::Role::Read as i32,
        };

        Ok(Response::new(zopp_proto::PermissionResponse {
            role: proto_role,
        }))
    }

    async fn list_group_workspace_permissions(
        &self,
        request: Request<zopp_proto::ListGroupWorkspacePermissionsRequest>,
    ) -> Result<Response<zopp_proto::GroupPermissionList>, Status> {
        let (principal_id, timestamp, signature) = extract_signature(&request)?;
        let principal = self
            .verify_signature_and_get_principal(&principal_id, timestamp, &signature)
            .await?;
        let user_id = principal.user_id.ok_or_else(|| {
            Status::unauthenticated("Service accounts cannot list group permissions")
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

        let permissions = self
            .store
            .list_group_workspace_permissions(&workspace.id)
            .await
            .map_err(|e| Status::internal(format!("Failed to list group permissions: {}", e)))?;

        let mut proto_permissions = Vec::new();
        for perm in permissions {
            // Look up group to get name
            let group = self
                .store
                .get_group(&perm.group_id)
                .await
                .map_err(|e| Status::internal(format!("Failed to get group: {}", e)))?;

            proto_permissions.push(zopp_proto::GroupPermission {
                group_id: perm.group_id.0.to_string(),
                group_name: group.name,
                role: match perm.role {
                    zopp_storage::Role::Admin => zopp_proto::Role::Admin as i32,
                    zopp_storage::Role::Write => zopp_proto::Role::Write as i32,
                    zopp_storage::Role::Read => zopp_proto::Role::Read as i32,
                },
            });
        }

        Ok(Response::new(zopp_proto::GroupPermissionList {
            permissions: proto_permissions,
        }))
    }

    async fn remove_group_workspace_permission(
        &self,
        request: Request<zopp_proto::RemoveGroupWorkspacePermissionRequest>,
    ) -> Result<Response<Empty>, Status> {
        let (principal_id, timestamp, signature) = extract_signature(&request)?;
        let principal = self
            .verify_signature_and_get_principal(&principal_id, timestamp, &signature)
            .await?;
        let user_id = principal.user_id.ok_or_else(|| {
            Status::unauthenticated("Service accounts cannot remove group permissions")
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

        let group = self
            .store
            .get_group_by_name(&workspace.id, &req.group_name)
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::NotFound => Status::not_found("Group not found"),
                _ => Status::internal(format!("Failed to get group: {}", e)),
            })?;

        self.store
            .remove_group_workspace_permission(&workspace.id, &group.id)
            .await
            .map_err(|e| Status::internal(format!("Failed to remove group permission: {}", e)))?;

        Ok(Response::new(Empty {}))
    }

    async fn set_group_project_permission(
        &self,
        request: Request<zopp_proto::SetGroupProjectPermissionRequest>,
    ) -> Result<Response<Empty>, Status> {
        let (principal_id, timestamp, signature) = extract_signature(&request)?;
        let principal = self
            .verify_signature_and_get_principal(&principal_id, timestamp, &signature)
            .await?;
        let user_id = principal.user_id.ok_or_else(|| {
            Status::unauthenticated("Service accounts cannot set group permissions")
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

        // Look up project by name
        let project = self
            .store
            .get_project_by_name(&workspace.id, &req.project_name)
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::NotFound => Status::not_found("Project not found"),
                _ => Status::internal(format!("Failed to get project: {}", e)),
            })?;

        let group = self
            .store
            .get_group_by_name(&workspace.id, &req.group_name)
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::NotFound => Status::not_found("Group not found"),
                _ => Status::internal(format!("Failed to get group: {}", e)),
            })?;

        // Convert proto Role to storage Role
        let role = match zopp_proto::Role::try_from(req.role) {
            Ok(zopp_proto::Role::Admin) => zopp_storage::Role::Admin,
            Ok(zopp_proto::Role::Write) => zopp_storage::Role::Write,
            Ok(zopp_proto::Role::Read) => zopp_storage::Role::Read,
            _ => return Err(Status::invalid_argument("Invalid role")),
        };

        self.store
            .set_group_project_permission(&project.id, &group.id, role)
            .await
            .map_err(|e| Status::internal(format!("Failed to set group permission: {}", e)))?;

        Ok(Response::new(Empty {}))
    }

    async fn get_group_project_permission(
        &self,
        request: Request<zopp_proto::GetGroupProjectPermissionRequest>,
    ) -> Result<Response<zopp_proto::PermissionResponse>, Status> {
        let (principal_id, timestamp, signature) = extract_signature(&request)?;
        let principal = self
            .verify_signature_and_get_principal(&principal_id, timestamp, &signature)
            .await?;
        let user_id = principal.user_id.ok_or_else(|| {
            Status::unauthenticated("Service accounts cannot get group permissions")
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

        // Look up project by name
        let project = self
            .store
            .get_project_by_name(&workspace.id, &req.project_name)
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::NotFound => Status::not_found("Project not found"),
                _ => Status::internal(format!("Failed to get project: {}", e)),
            })?;

        let group = self
            .store
            .get_group_by_name(&workspace.id, &req.group_name)
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::NotFound => Status::not_found("Group not found"),
                _ => Status::internal(format!("Failed to get group: {}", e)),
            })?;

        let role = self
            .store
            .get_group_project_permission(&project.id, &group.id)
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::NotFound => Status::not_found("Permission not found"),
                _ => Status::internal(format!("Failed to get group permission: {}", e)),
            })?;

        // Convert storage Role to proto Role
        let proto_role = match role {
            zopp_storage::Role::Admin => zopp_proto::Role::Admin as i32,
            zopp_storage::Role::Write => zopp_proto::Role::Write as i32,
            zopp_storage::Role::Read => zopp_proto::Role::Read as i32,
        };

        Ok(Response::new(zopp_proto::PermissionResponse {
            role: proto_role,
        }))
    }

    async fn list_group_project_permissions(
        &self,
        request: Request<zopp_proto::ListGroupProjectPermissionsRequest>,
    ) -> Result<Response<zopp_proto::GroupPermissionList>, Status> {
        let (principal_id, timestamp, signature) = extract_signature(&request)?;
        let principal = self
            .verify_signature_and_get_principal(&principal_id, timestamp, &signature)
            .await?;
        let user_id = principal.user_id.ok_or_else(|| {
            Status::unauthenticated("Service accounts cannot list group permissions")
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

        // Look up project by name
        let project = self
            .store
            .get_project_by_name(&workspace.id, &req.project_name)
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::NotFound => Status::not_found("Project not found"),
                _ => Status::internal(format!("Failed to get project: {}", e)),
            })?;

        let permissions = self
            .store
            .list_group_project_permissions(&project.id)
            .await
            .map_err(|e| Status::internal(format!("Failed to list group permissions: {}", e)))?;

        let mut proto_permissions = Vec::new();
        for perm in permissions {
            // Look up group to get name
            let group = self
                .store
                .get_group(&perm.group_id)
                .await
                .map_err(|e| Status::internal(format!("Failed to get group: {}", e)))?;

            proto_permissions.push(zopp_proto::GroupPermission {
                group_id: perm.group_id.0.to_string(),
                group_name: group.name,
                role: match perm.role {
                    zopp_storage::Role::Admin => zopp_proto::Role::Admin as i32,
                    zopp_storage::Role::Write => zopp_proto::Role::Write as i32,
                    zopp_storage::Role::Read => zopp_proto::Role::Read as i32,
                },
            });
        }

        Ok(Response::new(zopp_proto::GroupPermissionList {
            permissions: proto_permissions,
        }))
    }

    async fn remove_group_project_permission(
        &self,
        request: Request<zopp_proto::RemoveGroupProjectPermissionRequest>,
    ) -> Result<Response<Empty>, Status> {
        let (principal_id, timestamp, signature) = extract_signature(&request)?;
        let principal = self
            .verify_signature_and_get_principal(&principal_id, timestamp, &signature)
            .await?;
        let user_id = principal.user_id.ok_or_else(|| {
            Status::unauthenticated("Service accounts cannot remove group permissions")
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

        // Look up project by name
        let project = self
            .store
            .get_project_by_name(&workspace.id, &req.project_name)
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::NotFound => Status::not_found("Project not found"),
                _ => Status::internal(format!("Failed to get project: {}", e)),
            })?;

        let group = self
            .store
            .get_group_by_name(&workspace.id, &req.group_name)
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::NotFound => Status::not_found("Group not found"),
                _ => Status::internal(format!("Failed to get group: {}", e)),
            })?;

        self.store
            .remove_group_project_permission(&project.id, &group.id)
            .await
            .map_err(|e| Status::internal(format!("Failed to remove group permission: {}", e)))?;

        Ok(Response::new(Empty {}))
    }

    async fn set_group_environment_permission(
        &self,
        request: Request<zopp_proto::SetGroupEnvironmentPermissionRequest>,
    ) -> Result<Response<Empty>, Status> {
        let (principal_id, timestamp, signature) = extract_signature(&request)?;
        let principal = self
            .verify_signature_and_get_principal(&principal_id, timestamp, &signature)
            .await?;
        let user_id = principal.user_id.ok_or_else(|| {
            Status::unauthenticated("Service accounts cannot set group permissions")
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

        // Look up project by name
        let project = self
            .store
            .get_project_by_name(&workspace.id, &req.project_name)
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::NotFound => Status::not_found("Project not found"),
                _ => Status::internal(format!("Failed to get project: {}", e)),
            })?;

        // Look up environment by name
        let env = self
            .store
            .get_environment_by_name(&project.id, &req.environment_name)
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::NotFound => Status::not_found("Environment not found"),
                _ => Status::internal(format!("Failed to get environment: {}", e)),
            })?;

        let group = self
            .store
            .get_group_by_name(&workspace.id, &req.group_name)
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::NotFound => Status::not_found("Group not found"),
                _ => Status::internal(format!("Failed to get group: {}", e)),
            })?;

        // Convert proto Role to storage Role
        let role = match zopp_proto::Role::try_from(req.role) {
            Ok(zopp_proto::Role::Admin) => zopp_storage::Role::Admin,
            Ok(zopp_proto::Role::Write) => zopp_storage::Role::Write,
            Ok(zopp_proto::Role::Read) => zopp_storage::Role::Read,
            _ => return Err(Status::invalid_argument("Invalid role")),
        };

        self.store
            .set_group_environment_permission(&env.id, &group.id, role)
            .await
            .map_err(|e| Status::internal(format!("Failed to set group permission: {}", e)))?;

        Ok(Response::new(Empty {}))
    }

    async fn get_group_environment_permission(
        &self,
        request: Request<zopp_proto::GetGroupEnvironmentPermissionRequest>,
    ) -> Result<Response<zopp_proto::PermissionResponse>, Status> {
        let (principal_id, timestamp, signature) = extract_signature(&request)?;
        let principal = self
            .verify_signature_and_get_principal(&principal_id, timestamp, &signature)
            .await?;
        let user_id = principal.user_id.ok_or_else(|| {
            Status::unauthenticated("Service accounts cannot get group permissions")
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

        // Look up project by name
        let project = self
            .store
            .get_project_by_name(&workspace.id, &req.project_name)
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::NotFound => Status::not_found("Project not found"),
                _ => Status::internal(format!("Failed to get project: {}", e)),
            })?;

        // Look up environment by name
        let env = self
            .store
            .get_environment_by_name(&project.id, &req.environment_name)
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::NotFound => Status::not_found("Environment not found"),
                _ => Status::internal(format!("Failed to get environment: {}", e)),
            })?;

        let group = self
            .store
            .get_group_by_name(&workspace.id, &req.group_name)
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::NotFound => Status::not_found("Group not found"),
                _ => Status::internal(format!("Failed to get group: {}", e)),
            })?;

        let role = self
            .store
            .get_group_environment_permission(&env.id, &group.id)
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::NotFound => Status::not_found("Permission not found"),
                _ => Status::internal(format!("Failed to get group permission: {}", e)),
            })?;

        // Convert storage Role to proto Role
        let proto_role = match role {
            zopp_storage::Role::Admin => zopp_proto::Role::Admin as i32,
            zopp_storage::Role::Write => zopp_proto::Role::Write as i32,
            zopp_storage::Role::Read => zopp_proto::Role::Read as i32,
        };

        Ok(Response::new(zopp_proto::PermissionResponse {
            role: proto_role,
        }))
    }

    async fn list_group_environment_permissions(
        &self,
        request: Request<zopp_proto::ListGroupEnvironmentPermissionsRequest>,
    ) -> Result<Response<zopp_proto::GroupPermissionList>, Status> {
        let (principal_id, timestamp, signature) = extract_signature(&request)?;
        let principal = self
            .verify_signature_and_get_principal(&principal_id, timestamp, &signature)
            .await?;
        let user_id = principal.user_id.ok_or_else(|| {
            Status::unauthenticated("Service accounts cannot list group permissions")
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

        // Look up project by name
        let project = self
            .store
            .get_project_by_name(&workspace.id, &req.project_name)
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::NotFound => Status::not_found("Project not found"),
                _ => Status::internal(format!("Failed to get project: {}", e)),
            })?;

        // Look up environment by name
        let env = self
            .store
            .get_environment_by_name(&project.id, &req.environment_name)
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::NotFound => Status::not_found("Environment not found"),
                _ => Status::internal(format!("Failed to get environment: {}", e)),
            })?;

        let permissions = self
            .store
            .list_group_environment_permissions(&env.id)
            .await
            .map_err(|e| Status::internal(format!("Failed to list group permissions: {}", e)))?;

        let mut proto_permissions = Vec::new();
        for perm in permissions {
            // Look up group to get name
            let group = self
                .store
                .get_group(&perm.group_id)
                .await
                .map_err(|e| Status::internal(format!("Failed to get group: {}", e)))?;

            proto_permissions.push(zopp_proto::GroupPermission {
                group_id: perm.group_id.0.to_string(),
                group_name: group.name,
                role: match perm.role {
                    zopp_storage::Role::Admin => zopp_proto::Role::Admin as i32,
                    zopp_storage::Role::Write => zopp_proto::Role::Write as i32,
                    zopp_storage::Role::Read => zopp_proto::Role::Read as i32,
                },
            });
        }

        Ok(Response::new(zopp_proto::GroupPermissionList {
            permissions: proto_permissions,
        }))
    }

    async fn remove_group_environment_permission(
        &self,
        request: Request<zopp_proto::RemoveGroupEnvironmentPermissionRequest>,
    ) -> Result<Response<Empty>, Status> {
        let (principal_id, timestamp, signature) = extract_signature(&request)?;
        let principal = self
            .verify_signature_and_get_principal(&principal_id, timestamp, &signature)
            .await?;
        let user_id = principal.user_id.ok_or_else(|| {
            Status::unauthenticated("Service accounts cannot remove group permissions")
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

        // Look up project by name
        let project = self
            .store
            .get_project_by_name(&workspace.id, &req.project_name)
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::NotFound => Status::not_found("Project not found"),
                _ => Status::internal(format!("Failed to get project: {}", e)),
            })?;

        // Look up environment by name
        let env = self
            .store
            .get_environment_by_name(&project.id, &req.environment_name)
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::NotFound => Status::not_found("Environment not found"),
                _ => Status::internal(format!("Failed to get environment: {}", e)),
            })?;

        let group = self
            .store
            .get_group_by_name(&workspace.id, &req.group_name)
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::NotFound => Status::not_found("Group not found"),
                _ => Status::internal(format!("Failed to get group: {}", e)),
            })?;

        self.store
            .remove_group_environment_permission(&env.id, &group.id)
            .await
            .map_err(|e| Status::internal(format!("Failed to remove group permission: {}", e)))?;

        Ok(Response::new(Empty {}))
    }

    // ────────────────────────────────────── User Permissions ──────────────────────────────────────

    async fn set_user_workspace_permission(
        &self,
        request: Request<zopp_proto::SetUserWorkspacePermissionRequest>,
    ) -> Result<Response<Empty>, Status> {
        let (principal_id, timestamp, signature) = extract_signature(&request)?;
        let principal = self
            .verify_signature_and_get_principal(&principal_id, timestamp, &signature)
            .await?;
        let user_id = principal.user_id.ok_or_else(|| {
            Status::unauthenticated("Service accounts cannot set user permissions")
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

        // Check ADMIN permission for setting user permissions
        self.check_workspace_permission(&principal_id, &workspace.id, zopp_storage::Role::Admin)
            .await?;

        // Look up target user by email
        let target_user = self
            .store
            .get_user_by_email(&req.user_email)
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::NotFound => Status::not_found("User not found"),
                _ => Status::internal(format!("Failed to get user: {}", e)),
            })?;

        // Convert proto Role to storage Role
        let role = match zopp_proto::Role::try_from(req.role) {
            Ok(zopp_proto::Role::Admin) => zopp_storage::Role::Admin,
            Ok(zopp_proto::Role::Write) => zopp_storage::Role::Write,
            Ok(zopp_proto::Role::Read) => zopp_storage::Role::Read,
            _ => return Err(Status::invalid_argument("Invalid role")),
        };

        self.store
            .set_user_workspace_permission(&workspace.id, &target_user.id, role)
            .await
            .map_err(|e| Status::internal(format!("Failed to set user permission: {}", e)))?;

        Ok(Response::new(Empty {}))
    }

    async fn get_user_workspace_permission(
        &self,
        request: Request<zopp_proto::GetUserWorkspacePermissionRequest>,
    ) -> Result<Response<zopp_proto::PermissionResponse>, Status> {
        let (principal_id, timestamp, signature) = extract_signature(&request)?;
        let principal = self
            .verify_signature_and_get_principal(&principal_id, timestamp, &signature)
            .await?;
        let user_id = principal.user_id.ok_or_else(|| {
            Status::unauthenticated("Service accounts cannot get user permissions")
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

        // Look up target user by email
        let target_user = self
            .store
            .get_user_by_email(&req.user_email)
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::NotFound => Status::not_found("User not found"),
                _ => Status::internal(format!("Failed to get user: {}", e)),
            })?;

        let role = self
            .store
            .get_user_workspace_permission(&workspace.id, &target_user.id)
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::NotFound => Status::not_found("Permission not found"),
                _ => Status::internal(format!("Failed to get user permission: {}", e)),
            })?;

        let proto_role = match role {
            zopp_storage::Role::Admin => zopp_proto::Role::Admin,
            zopp_storage::Role::Write => zopp_proto::Role::Write,
            zopp_storage::Role::Read => zopp_proto::Role::Read,
        };

        Ok(Response::new(zopp_proto::PermissionResponse {
            role: proto_role as i32,
        }))
    }

    async fn list_user_workspace_permissions(
        &self,
        request: Request<zopp_proto::ListUserWorkspacePermissionsRequest>,
    ) -> Result<Response<zopp_proto::UserPermissionList>, Status> {
        let (principal_id, timestamp, signature) = extract_signature(&request)?;
        let principal = self
            .verify_signature_and_get_principal(&principal_id, timestamp, &signature)
            .await?;
        let user_id = principal.user_id.ok_or_else(|| {
            Status::unauthenticated("Service accounts cannot list user permissions")
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

        let permissions = self
            .store
            .list_user_workspace_permissions(&workspace.id)
            .await
            .map_err(|e| Status::internal(format!("Failed to list user permissions: {}", e)))?;

        let mut proto_permissions = Vec::with_capacity(permissions.len());
        for perm in permissions {
            let user = self.store.get_user_by_id(&perm.user_id).await.ok();
            let proto_role = match perm.role {
                zopp_storage::Role::Admin => zopp_proto::Role::Admin,
                zopp_storage::Role::Write => zopp_proto::Role::Write,
                zopp_storage::Role::Read => zopp_proto::Role::Read,
            };
            proto_permissions.push(zopp_proto::UserPermission {
                user_id: perm.user_id.0.to_string(),
                user_email: user.map(|u| u.email).unwrap_or_default(),
                role: proto_role as i32,
            });
        }

        Ok(Response::new(zopp_proto::UserPermissionList {
            permissions: proto_permissions,
        }))
    }

    async fn remove_user_workspace_permission(
        &self,
        request: Request<zopp_proto::RemoveUserWorkspacePermissionRequest>,
    ) -> Result<Response<Empty>, Status> {
        let (principal_id, timestamp, signature) = extract_signature(&request)?;
        let principal = self
            .verify_signature_and_get_principal(&principal_id, timestamp, &signature)
            .await?;
        let user_id = principal.user_id.ok_or_else(|| {
            Status::unauthenticated("Service accounts cannot remove user permissions")
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

        // Check ADMIN permission for removing user permissions
        self.check_workspace_permission(&principal_id, &workspace.id, zopp_storage::Role::Admin)
            .await?;

        // Look up target user by email
        let target_user = self
            .store
            .get_user_by_email(&req.user_email)
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::NotFound => Status::not_found("User not found"),
                _ => Status::internal(format!("Failed to get user: {}", e)),
            })?;

        self.store
            .remove_user_workspace_permission(&workspace.id, &target_user.id)
            .await
            .map_err(|e| Status::internal(format!("Failed to remove user permission: {}", e)))?;

        Ok(Response::new(Empty {}))
    }

    async fn set_user_project_permission(
        &self,
        request: Request<zopp_proto::SetUserProjectPermissionRequest>,
    ) -> Result<Response<Empty>, Status> {
        let (principal_id, timestamp, signature) = extract_signature(&request)?;
        let principal = self
            .verify_signature_and_get_principal(&principal_id, timestamp, &signature)
            .await?;
        let user_id = principal.user_id.ok_or_else(|| {
            Status::unauthenticated("Service accounts cannot set user permissions")
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

        // Look up project by name
        let project = self
            .store
            .get_project_by_name(&workspace.id, &req.project_name)
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::NotFound => Status::not_found("Project not found"),
                _ => Status::internal(format!("Failed to get project: {}", e)),
            })?;

        // Look up target user by email
        let target_user = self
            .store
            .get_user_by_email(&req.user_email)
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::NotFound => Status::not_found("User not found"),
                _ => Status::internal(format!("Failed to get user: {}", e)),
            })?;

        // Check ADMIN permission (project-level or higher)
        self.check_project_permission(
            &principal_id,
            &workspace.id,
            &project.id,
            zopp_storage::Role::Admin,
        )
        .await?;

        // Convert proto Role to storage Role
        let role = match zopp_proto::Role::try_from(req.role) {
            Ok(zopp_proto::Role::Admin) => zopp_storage::Role::Admin,
            Ok(zopp_proto::Role::Write) => zopp_storage::Role::Write,
            Ok(zopp_proto::Role::Read) => zopp_storage::Role::Read,
            _ => return Err(Status::invalid_argument("Invalid role")),
        };

        self.store
            .set_user_project_permission(&project.id, &target_user.id, role)
            .await
            .map_err(|e| Status::internal(format!("Failed to set user permission: {}", e)))?;

        Ok(Response::new(Empty {}))
    }

    async fn get_user_project_permission(
        &self,
        request: Request<zopp_proto::GetUserProjectPermissionRequest>,
    ) -> Result<Response<zopp_proto::PermissionResponse>, Status> {
        let (principal_id, timestamp, signature) = extract_signature(&request)?;
        let principal = self
            .verify_signature_and_get_principal(&principal_id, timestamp, &signature)
            .await?;
        let user_id = principal.user_id.ok_or_else(|| {
            Status::unauthenticated("Service accounts cannot get user permissions")
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

        // Look up project by name
        let project = self
            .store
            .get_project_by_name(&workspace.id, &req.project_name)
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::NotFound => Status::not_found("Project not found"),
                _ => Status::internal(format!("Failed to get project: {}", e)),
            })?;

        // Look up target user by email
        let target_user = self
            .store
            .get_user_by_email(&req.user_email)
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::NotFound => Status::not_found("User not found"),
                _ => Status::internal(format!("Failed to get user: {}", e)),
            })?;

        let role = self
            .store
            .get_user_project_permission(&project.id, &target_user.id)
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::NotFound => Status::not_found("Permission not found"),
                _ => Status::internal(format!("Failed to get user permission: {}", e)),
            })?;

        let proto_role = match role {
            zopp_storage::Role::Admin => zopp_proto::Role::Admin,
            zopp_storage::Role::Write => zopp_proto::Role::Write,
            zopp_storage::Role::Read => zopp_proto::Role::Read,
        };

        Ok(Response::new(zopp_proto::PermissionResponse {
            role: proto_role as i32,
        }))
    }

    async fn list_user_project_permissions(
        &self,
        request: Request<zopp_proto::ListUserProjectPermissionsRequest>,
    ) -> Result<Response<zopp_proto::UserPermissionList>, Status> {
        let (principal_id, timestamp, signature) = extract_signature(&request)?;
        let principal = self
            .verify_signature_and_get_principal(&principal_id, timestamp, &signature)
            .await?;
        let user_id = principal.user_id.ok_or_else(|| {
            Status::unauthenticated("Service accounts cannot list user permissions")
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

        // Look up project by name
        let project = self
            .store
            .get_project_by_name(&workspace.id, &req.project_name)
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::NotFound => Status::not_found("Project not found"),
                _ => Status::internal(format!("Failed to get project: {}", e)),
            })?;

        let permissions = self
            .store
            .list_user_project_permissions(&project.id)
            .await
            .map_err(|e| Status::internal(format!("Failed to list user permissions: {}", e)))?;

        let mut proto_permissions = Vec::with_capacity(permissions.len());
        for perm in permissions {
            let user = self.store.get_user_by_id(&perm.user_id).await.ok();
            let proto_role = match perm.role {
                zopp_storage::Role::Admin => zopp_proto::Role::Admin,
                zopp_storage::Role::Write => zopp_proto::Role::Write,
                zopp_storage::Role::Read => zopp_proto::Role::Read,
            };
            proto_permissions.push(zopp_proto::UserPermission {
                user_id: perm.user_id.0.to_string(),
                user_email: user.map(|u| u.email).unwrap_or_default(),
                role: proto_role as i32,
            });
        }

        Ok(Response::new(zopp_proto::UserPermissionList {
            permissions: proto_permissions,
        }))
    }

    async fn remove_user_project_permission(
        &self,
        request: Request<zopp_proto::RemoveUserProjectPermissionRequest>,
    ) -> Result<Response<Empty>, Status> {
        let (principal_id, timestamp, signature) = extract_signature(&request)?;
        let principal = self
            .verify_signature_and_get_principal(&principal_id, timestamp, &signature)
            .await?;
        let user_id = principal.user_id.ok_or_else(|| {
            Status::unauthenticated("Service accounts cannot remove user permissions")
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

        // Look up project by name
        let project = self
            .store
            .get_project_by_name(&workspace.id, &req.project_name)
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::NotFound => Status::not_found("Project not found"),
                _ => Status::internal(format!("Failed to get project: {}", e)),
            })?;

        // Look up target user by email
        let target_user = self
            .store
            .get_user_by_email(&req.user_email)
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::NotFound => Status::not_found("User not found"),
                _ => Status::internal(format!("Failed to get user: {}", e)),
            })?;

        // Check ADMIN permission (project-level or higher)
        self.check_project_permission(
            &principal_id,
            &workspace.id,
            &project.id,
            zopp_storage::Role::Admin,
        )
        .await?;

        self.store
            .remove_user_project_permission(&project.id, &target_user.id)
            .await
            .map_err(|e| Status::internal(format!("Failed to remove user permission: {}", e)))?;

        Ok(Response::new(Empty {}))
    }

    async fn set_user_environment_permission(
        &self,
        request: Request<zopp_proto::SetUserEnvironmentPermissionRequest>,
    ) -> Result<Response<Empty>, Status> {
        let (principal_id, timestamp, signature) = extract_signature(&request)?;
        let principal = self
            .verify_signature_and_get_principal(&principal_id, timestamp, &signature)
            .await?;
        let user_id = principal.user_id.ok_or_else(|| {
            Status::unauthenticated("Service accounts cannot set user permissions")
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

        // Look up project by name
        let project = self
            .store
            .get_project_by_name(&workspace.id, &req.project_name)
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::NotFound => Status::not_found("Project not found"),
                _ => Status::internal(format!("Failed to get project: {}", e)),
            })?;

        // Look up environment by name
        let env = self
            .store
            .get_environment_by_name(&project.id, &req.environment_name)
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::NotFound => Status::not_found("Environment not found"),
                _ => Status::internal(format!("Failed to get environment: {}", e)),
            })?;

        // Look up target user by email
        let target_user = self
            .store
            .get_user_by_email(&req.user_email)
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::NotFound => Status::not_found("User not found"),
                _ => Status::internal(format!("Failed to get user: {}", e)),
            })?;

        // Check ADMIN permission (environment-level or higher)
        self.check_environment_permission(
            &principal_id,
            &workspace.id,
            &project.id,
            &env.id,
            zopp_storage::Role::Admin,
        )
        .await?;

        // Convert proto Role to storage Role
        let role = match zopp_proto::Role::try_from(req.role) {
            Ok(zopp_proto::Role::Admin) => zopp_storage::Role::Admin,
            Ok(zopp_proto::Role::Write) => zopp_storage::Role::Write,
            Ok(zopp_proto::Role::Read) => zopp_storage::Role::Read,
            _ => return Err(Status::invalid_argument("Invalid role")),
        };

        self.store
            .set_user_environment_permission(&env.id, &target_user.id, role)
            .await
            .map_err(|e| Status::internal(format!("Failed to set user permission: {}", e)))?;

        Ok(Response::new(Empty {}))
    }

    async fn get_user_environment_permission(
        &self,
        request: Request<zopp_proto::GetUserEnvironmentPermissionRequest>,
    ) -> Result<Response<zopp_proto::PermissionResponse>, Status> {
        let (principal_id, timestamp, signature) = extract_signature(&request)?;
        let principal = self
            .verify_signature_and_get_principal(&principal_id, timestamp, &signature)
            .await?;
        let user_id = principal.user_id.ok_or_else(|| {
            Status::unauthenticated("Service accounts cannot get user permissions")
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

        // Look up project by name
        let project = self
            .store
            .get_project_by_name(&workspace.id, &req.project_name)
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::NotFound => Status::not_found("Project not found"),
                _ => Status::internal(format!("Failed to get project: {}", e)),
            })?;

        // Look up environment by name
        let env = self
            .store
            .get_environment_by_name(&project.id, &req.environment_name)
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::NotFound => Status::not_found("Environment not found"),
                _ => Status::internal(format!("Failed to get environment: {}", e)),
            })?;

        // Look up target user by email
        let target_user = self
            .store
            .get_user_by_email(&req.user_email)
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::NotFound => Status::not_found("User not found"),
                _ => Status::internal(format!("Failed to get user: {}", e)),
            })?;

        let role = self
            .store
            .get_user_environment_permission(&env.id, &target_user.id)
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::NotFound => Status::not_found("Permission not found"),
                _ => Status::internal(format!("Failed to get user permission: {}", e)),
            })?;

        let proto_role = match role {
            zopp_storage::Role::Admin => zopp_proto::Role::Admin,
            zopp_storage::Role::Write => zopp_proto::Role::Write,
            zopp_storage::Role::Read => zopp_proto::Role::Read,
        };

        Ok(Response::new(zopp_proto::PermissionResponse {
            role: proto_role as i32,
        }))
    }

    async fn list_user_environment_permissions(
        &self,
        request: Request<zopp_proto::ListUserEnvironmentPermissionsRequest>,
    ) -> Result<Response<zopp_proto::UserPermissionList>, Status> {
        let (principal_id, timestamp, signature) = extract_signature(&request)?;
        let principal = self
            .verify_signature_and_get_principal(&principal_id, timestamp, &signature)
            .await?;
        let user_id = principal.user_id.ok_or_else(|| {
            Status::unauthenticated("Service accounts cannot list user permissions")
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

        // Look up project by name
        let project = self
            .store
            .get_project_by_name(&workspace.id, &req.project_name)
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::NotFound => Status::not_found("Project not found"),
                _ => Status::internal(format!("Failed to get project: {}", e)),
            })?;

        // Look up environment by name
        let env = self
            .store
            .get_environment_by_name(&project.id, &req.environment_name)
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::NotFound => Status::not_found("Environment not found"),
                _ => Status::internal(format!("Failed to get environment: {}", e)),
            })?;

        let permissions = self
            .store
            .list_user_environment_permissions(&env.id)
            .await
            .map_err(|e| Status::internal(format!("Failed to list user permissions: {}", e)))?;

        let mut proto_permissions = Vec::with_capacity(permissions.len());
        for perm in permissions {
            let user = self.store.get_user_by_id(&perm.user_id).await.ok();
            let proto_role = match perm.role {
                zopp_storage::Role::Admin => zopp_proto::Role::Admin,
                zopp_storage::Role::Write => zopp_proto::Role::Write,
                zopp_storage::Role::Read => zopp_proto::Role::Read,
            };
            proto_permissions.push(zopp_proto::UserPermission {
                user_id: perm.user_id.0.to_string(),
                user_email: user.map(|u| u.email).unwrap_or_default(),
                role: proto_role as i32,
            });
        }

        Ok(Response::new(zopp_proto::UserPermissionList {
            permissions: proto_permissions,
        }))
    }

    async fn remove_user_environment_permission(
        &self,
        request: Request<zopp_proto::RemoveUserEnvironmentPermissionRequest>,
    ) -> Result<Response<Empty>, Status> {
        let (principal_id, timestamp, signature) = extract_signature(&request)?;
        let principal = self
            .verify_signature_and_get_principal(&principal_id, timestamp, &signature)
            .await?;
        let user_id = principal.user_id.ok_or_else(|| {
            Status::unauthenticated("Service accounts cannot remove user permissions")
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

        // Look up project by name
        let project = self
            .store
            .get_project_by_name(&workspace.id, &req.project_name)
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::NotFound => Status::not_found("Project not found"),
                _ => Status::internal(format!("Failed to get project: {}", e)),
            })?;

        // Look up environment by name
        let env = self
            .store
            .get_environment_by_name(&project.id, &req.environment_name)
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::NotFound => Status::not_found("Environment not found"),
                _ => Status::internal(format!("Failed to get environment: {}", e)),
            })?;

        // Look up target user by email
        let target_user = self
            .store
            .get_user_by_email(&req.user_email)
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::NotFound => Status::not_found("User not found"),
                _ => Status::internal(format!("Failed to get user: {}", e)),
            })?;

        // Check ADMIN permission (environment-level or higher)
        self.check_environment_permission(
            &principal_id,
            &workspace.id,
            &project.id,
            &env.id,
            zopp_storage::Role::Admin,
        )
        .await?;

        self.store
            .remove_user_environment_permission(&env.id, &target_user.id)
            .await
            .map_err(|e| Status::internal(format!("Failed to remove user permission: {}", e)))?;

        Ok(Response::new(Empty {}))
    }
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
    health_addr: &str,
    tls_cert: Option<String>,
    tls_key: Option<String>,
    tls_client_ca: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    cmd_serve_with_ready(
        database_url,
        legacy_db_path,
        addr,
        health_addr,
        tls_cert,
        tls_key,
        tls_client_ca,
        None,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn cmd_serve_with_ready(
    database_url: Option<String>,
    legacy_db_path: Option<String>,
    addr: &str,
    health_addr: &str,
    tls_cert: Option<String>,
    tls_key: Option<String>,
    tls_client_ca: Option<String>,
    ready_tx: Option<tokio::sync::oneshot::Sender<(std::net::SocketAddr, std::net::SocketAddr)>>,
) -> Result<(), Box<dyn std::error::Error>> {
    use axum::{routing::get, Router};

    let addr: std::net::SocketAddr = addr.parse()?;
    let health_addr: std::net::SocketAddr = health_addr.parse()?;

    // Validate TLS configuration BEFORE opening database
    // Validate TLS configuration: both cert and key must be provided together
    match (&tls_cert, &tls_key) {
        (Some(_), None) => {
            return Err("TLS certificate provided without key. Both --tls-cert and --tls-key are required for TLS.".into());
        }
        (None, Some(_)) => {
            return Err("TLS key provided without certificate. Both --tls-cert and --tls-key are required for TLS.".into());
        }
        _ => {}
    }

    // Validate client CA requires TLS to be configured
    if tls_client_ca.is_some() && tls_cert.is_none() {
        return Err("--tls-client-ca requires --tls-cert and --tls-key to be configured".into());
    }

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

    // Create gRPC health service (implements gRPC health checking protocol)
    let (health_reporter, health_service) = tonic_health::server::health_reporter();
    health_reporter
        .set_serving::<ZoppServiceServer<ZoppServer>>()
        .await;

    // Create a channel for HTTP readiness probe signaling
    let (readiness_tx, readiness_rx) = tokio::sync::watch::channel(false);
    let readiness_check = ReadinessCheck::new(readiness_rx);

    // Create HTTP health check server for Kubernetes liveness/readiness probes
    // /healthz - simple liveness check (always returns OK)
    // /readyz - readiness check (returns OK once gRPC listener is bound and ready)
    let health_router = Router::new()
        .route("/healthz", get(health_handler))
        .route("/readyz", get(readiness_handler))
        .with_state(readiness_check);

    // Bind listeners to get actual addresses
    let grpc_listener = tokio::net::TcpListener::bind(addr).await?;
    let grpc_actual_addr = grpc_listener.local_addr()?;

    let health_listener = tokio::net::TcpListener::bind(health_addr).await?;
    let health_actual_addr = health_listener.local_addr()?;

    println!("ZoppServer listening on {}", grpc_actual_addr);
    println!("Health checks listening on {}", health_actual_addr);

    // Build gRPC server with optional TLS
    let mut grpc_builder = if let (Some(cert_path), Some(key_path)) = (tls_cert, tls_key) {
        let cert = std::fs::read_to_string(&cert_path)?;
        let key = std::fs::read_to_string(&key_path)?;

        let identity = tonic::transport::Identity::from_pem(cert, key);

        let mut tls_config = tonic::transport::ServerTlsConfig::new().identity(identity);

        if let Some(ca_path) = tls_client_ca {
            let ca = std::fs::read_to_string(&ca_path)?;
            let ca_cert = tonic::transport::Certificate::from_pem(ca);
            tls_config = tls_config.client_ca_root(ca_cert);
        }

        Server::builder().tls_config(tls_config)?
    } else {
        Server::builder()
    };

    // Signal readiness after TLS config is successfully built
    // This ensures TLS configuration errors are caught before reporting ready
    let _ = readiness_tx.send(true);

    // Notify test that servers are ready
    if let Some(tx) = ready_tx {
        let _ = tx.send((grpc_actual_addr, health_actual_addr));
    }

    // Create a broadcast channel for shutdown signaling
    let (shutdown_tx, _) = tokio::sync::broadcast::channel::<()>(1);
    let shutdown_tx_clone = shutdown_tx.clone();

    // Spawn a task to wait for shutdown signal and mark not-ready
    tokio::spawn(async move {
        shutdown_signal(Some(readiness_tx)).await;
        let _ = shutdown_tx_clone.send(());
    });

    // Start health check server with graceful shutdown
    let mut shutdown_rx1 = shutdown_tx.subscribe();
    let health_server =
        axum::serve(health_listener, health_router).with_graceful_shutdown(async move {
            let _ = shutdown_rx1.recv().await;
        });

    // Start gRPC server with graceful shutdown - includes health service
    let mut shutdown_rx2 = shutdown_tx.subscribe();
    let grpc_server = grpc_builder
        .add_service(health_service)
        .add_service(ZoppServiceServer::new(server))
        .serve_with_incoming_shutdown(
            tokio_stream::wrappers::TcpListenerStream::new(grpc_listener),
            async move {
                let _ = shutdown_rx2.recv().await;
            },
        );

    // Run both servers concurrently - ensure both complete their shutdown sequences
    let (grpc_result, health_result) = tokio::join!(grpc_server, health_server);

    grpc_result?;
    health_result?;

    Ok(())
}

#[derive(Clone)]
struct ReadinessCheck {
    ready: tokio::sync::watch::Receiver<bool>,
}

impl ReadinessCheck {
    fn new(ready: tokio::sync::watch::Receiver<bool>) -> Self {
        Self { ready }
    }
}

async fn health_handler() -> &'static str {
    "ok"
}

async fn readiness_handler(
    axum::extract::State(check): axum::extract::State<ReadinessCheck>,
) -> Result<&'static str, axum::http::StatusCode> {
    // Check if gRPC server is ready
    if *check.ready.borrow() {
        Ok("ok")
    } else {
        Err(axum::http::StatusCode::SERVICE_UNAVAILABLE)
    }
}

async fn shutdown_signal(readiness_tx: Option<tokio::sync::watch::Sender<bool>>) {
    use tokio::signal::unix::{signal, SignalKind};

    let mut sigterm = signal(SignalKind::terminate()).expect("failed to install SIGTERM handler");
    let mut sigint = signal(SignalKind::interrupt()).expect("failed to install SIGINT handler");

    tokio::select! {
        _ = sigterm.recv() => {
            println!("Received SIGTERM, shutting down gracefully...");
        }
        _ = sigint.recv() => {
            println!("Received SIGINT, shutting down gracefully...");
        }
    }

    // Mark not ready on shutdown for clean traffic drain in Kubernetes
    if let Some(tx) = readiness_tx {
        let _ = tx.send(false);
    }
}

// ────────────────────────────────────── Main ──────────────────────────────────────

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Command::Serve {
            addr,
            health_addr,
            tls_cert,
            tls_key,
            tls_client_ca,
        } => {
            cmd_serve(
                cli.database_url,
                cli.db,
                &addr,
                &health_addr,
                tls_cert,
                tls_key,
                tls_client_ca,
            )
            .await?;
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

    #[tokio::test]
    async fn test_tls_config_validation_invalid_pem() {
        use std::io::Write;
        use tempfile::NamedTempFile;

        let mut cert_file = NamedTempFile::new().unwrap();
        cert_file.write_all(b"invalid cert").unwrap();
        cert_file.flush().unwrap();

        let mut key_file = NamedTempFile::new().unwrap();
        key_file.write_all(b"invalid key").unwrap();
        key_file.flush().unwrap();

        let result = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            cmd_serve(
                None,
                None,
                "127.0.0.1:50999",
                "127.0.0.1:58080",
                Some(cert_file.path().to_str().unwrap().to_string()),
                Some(key_file.path().to_str().unwrap().to_string()),
                None,
            ),
        )
        .await;

        assert!(result.unwrap().is_err());
    }

    #[tokio::test]
    async fn test_tls_config_validation_missing_cert() {
        let result = cmd_serve(
            None,
            None,
            "127.0.0.1:50999",
            "127.0.0.1:58080",
            None,
            Some("/path/to/key.pem".to_string()),
            None,
        )
        .await;

        let err = result.unwrap_err();
        let err_msg = err.to_string();
        assert!(
            err_msg.contains("TLS key provided without certificate"),
            "Expected error message to contain 'TLS key provided without certificate', got: {}",
            err_msg
        );
    }

    #[tokio::test]
    async fn test_tls_config_validation_missing_key() {
        let result = cmd_serve(
            None,
            None,
            "127.0.0.1:50999",
            "127.0.0.1:58080",
            Some("/path/to/cert.pem".to_string()),
            None,
            None,
        )
        .await;

        let err = result.unwrap_err();
        assert!(err
            .to_string()
            .contains("TLS certificate provided without key"));
    }

    #[tokio::test]
    async fn test_tls_config_validation_client_ca_without_tls() {
        let result = cmd_serve(
            None,
            None,
            "127.0.0.1:50999",
            "127.0.0.1:58080",
            None,
            None,
            Some("/path/to/ca.pem".to_string()),
        )
        .await;

        let err = result.unwrap_err();
        assert!(err
            .to_string()
            .contains("--tls-client-ca requires --tls-cert and --tls-key"));
    }

    #[tokio::test]
    async fn test_health_and_readiness_endpoints() {
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();

        // Start server in background
        tokio::spawn(async move {
            let _ = cmd_serve_with_ready(
                Some("sqlite::memory:".to_string()),
                None,
                "127.0.0.1:0",
                "127.0.0.1:0",
                None,
                None,
                None,
                Some(ready_tx),
            )
            .await;
        });

        // Wait for server to be ready
        let (_grpc_addr, health_addr) = ready_rx.await.unwrap();

        // Test /healthz
        let healthz_url = format!("http://{}/healthz", health_addr);
        let response = reqwest::get(&healthz_url).await.unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(response.text().await.unwrap(), "ok");

        // Test /readyz
        let readyz_url = format!("http://{}/readyz", health_addr);
        let response = reqwest::get(&readyz_url).await.unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(response.text().await.unwrap(), "ok");
    }

    #[tokio::test]
    async fn test_health_server_endpoints() {
        use axum::{routing::get, Router};

        // Create readiness check
        let (_tx, rx) = tokio::sync::watch::channel(true);
        let readiness_check = ReadinessCheck::new(rx);

        // Create health router
        let app = Router::new()
            .route("/healthz", get(health_handler))
            .route("/readyz", get(readiness_handler))
            .with_state(readiness_check);

        // Bind to random port
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Start server in background
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        // Wait for server to be ready with retry loop
        let healthz_url = format!("http://{}/healthz", addr);
        let mut ready = false;
        for _ in 0..30 {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            if reqwest::get(&healthz_url).await.is_ok() {
                ready = true;
                break;
            }
        }
        assert!(ready, "Health server failed to start");

        // Test /healthz
        let response = reqwest::get(&healthz_url).await.unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(response.text().await.unwrap(), "ok");

        // Test /readyz
        let readyz_url = format!("http://{}/readyz", addr);
        let response = reqwest::get(&readyz_url).await.unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(response.text().await.unwrap(), "ok");
    }

    #[tokio::test]
    async fn test_graceful_shutdown() {
        use axum::routing::get;

        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let (shutdown_tx, mut shutdown_rx) = tokio::sync::mpsc::channel::<()>(1);

        // Start server in background with graceful shutdown
        let server_handle = tokio::spawn(async move {
            let (readiness_tx, readiness_rx) = tokio::sync::watch::channel(false);
            let readiness_check = ReadinessCheck::new(readiness_rx);

            let health_router = axum::Router::new()
                .route("/healthz", get(health_handler))
                .route("/readyz", get(readiness_handler))
                .with_state(readiness_check);

            let health_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let health_addr = health_listener.local_addr().unwrap();

            let _ = readiness_tx.send(true);
            let _ = ready_tx.send(health_addr);

            // Simulate graceful shutdown signal
            let shutdown_signal = async move {
                shutdown_rx.recv().await;
            };

            axum::serve(health_listener, health_router)
                .with_graceful_shutdown(shutdown_signal)
                .await
                .unwrap();
        });

        // Wait for server to be ready
        let health_addr = ready_rx.await.unwrap();
        let healthz_url = format!("http://{}/healthz", health_addr);

        // Verify server is running
        let mut ready = false;
        for _ in 0..30 {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            if reqwest::get(&healthz_url).await.is_ok() {
                ready = true;
                break;
            }
        }
        assert!(ready, "Health server failed to start");

        // Trigger graceful shutdown
        shutdown_tx.send(()).await.unwrap();

        // Server should shut down gracefully
        let result = tokio::time::timeout(std::time::Duration::from_secs(5), server_handle).await;

        assert!(result.is_ok(), "Server did not shut down within timeout");
        assert!(result.unwrap().is_ok(), "Server shutdown returned error");

        // Verify server is no longer accepting connections
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert!(
            reqwest::get(&healthz_url).await.is_err(),
            "Server still accepting connections after shutdown"
        );
    }
}
