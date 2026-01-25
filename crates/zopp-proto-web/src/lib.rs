//! gRPC-web client for zopp
//!
//! This crate provides a gRPC-web client that works in the browser via WASM.
//! All authentication is handled client-side using Ed25519 signatures.

use chrono::Utc;
use ed25519_dalek::{Signer, SigningKey};
use prost::Message;
use sha2::{Digest, Sha256};
use tonic_web_wasm_client::Client as GrpcWebClient;

// Include the generated proto code
tonic::include_proto!("zopp");

/// Error type for the web client
#[derive(Debug)]
pub enum WebClientError {
    Transport(String),
    Signing(String),
    InvalidKey(String),
    DecodeError(String),
    Status(tonic::Status),
}

impl std::fmt::Display for WebClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WebClientError::Transport(s) => write!(f, "Transport error: {}", s),
            WebClientError::Signing(s) => write!(f, "Signing error: {}", s),
            WebClientError::InvalidKey(s) => write!(f, "Invalid key: {}", s),
            WebClientError::DecodeError(s) => write!(f, "Decode error: {}", s),
            WebClientError::Status(s) => write!(f, "gRPC status: {}", s),
        }
    }
}

impl std::error::Error for WebClientError {}

impl From<tonic::Status> for WebClientError {
    fn from(status: tonic::Status) -> Self {
        WebClientError::Status(status)
    }
}

/// Principal credentials for authentication
#[derive(Clone)]
pub struct PrincipalCredentials {
    /// Principal ID (UUID)
    pub principal_id: String,
    /// Ed25519 private key (32 bytes, hex-encoded)
    pub ed25519_private_key: String,
}

/// Compute SHA256 hash of request body for signature binding
pub fn compute_request_hash<T: Message>(method: &str, request: &T) -> Vec<u8> {
    let body_bytes = request.encode_to_vec();
    let mut hasher = Sha256::new();
    hasher.update(method.as_bytes());
    hasher.update(&body_bytes);
    hasher.finalize().to_vec()
}

/// Sign a request with method name and body hash to prevent replay attacks.
/// Returns (timestamp, signature_bytes)
pub fn sign_request(
    private_key_hex: &str,
    method: &str,
    request_hash: &[u8],
) -> Result<(i64, Vec<u8>), WebClientError> {
    let timestamp = Utc::now().timestamp();
    let private_key_bytes = hex::decode(private_key_hex)
        .map_err(|e| WebClientError::InvalidKey(format!("Invalid hex: {}", e)))?;

    let signing_key = SigningKey::from_bytes(
        private_key_bytes
            .as_slice()
            .try_into()
            .map_err(|_| WebClientError::InvalidKey("Invalid private key length".to_string()))?,
    );

    // Build message: method + request_hash + timestamp
    let mut message = Vec::new();
    message.extend_from_slice(method.as_bytes());
    message.extend_from_slice(request_hash);
    message.extend_from_slice(&timestamp.to_le_bytes());

    let signature = signing_key.sign(&message);
    Ok((timestamp, signature.to_bytes().to_vec()))
}

/// gRPC-web client for zopp
pub struct ZoppWebClient {
    base_url: String,
}

impl ZoppWebClient {
    /// Create a new client connected to the given base URL
    /// The URL should point to a gRPC-web proxy (e.g., Envoy)
    pub fn new(base_url: &str) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
        }
    }

    /// Get the gRPC-web client for making requests
    fn client(&self) -> GrpcWebClient {
        GrpcWebClient::new(self.base_url.clone())
    }

    /// Create authentication metadata for a request
    fn create_auth_metadata<T: Message>(
        &self,
        credentials: &PrincipalCredentials,
        method: &str,
        request: &T,
    ) -> Result<Vec<(&'static str, String)>, WebClientError> {
        let request_hash = compute_request_hash(method, request);
        let (timestamp, signature) =
            sign_request(&credentials.ed25519_private_key, method, &request_hash)?;

        Ok(vec![
            ("principal-id", credentials.principal_id.clone()),
            ("timestamp", timestamp.to_string()),
            ("signature", hex::encode(&signature)),
            ("request-hash", hex::encode(&request_hash)),
        ])
    }

    // ============ Auth RPCs ============

    /// Join a workspace using an invite token (unauthenticated)
    pub async fn join(&self, request: JoinRequest) -> Result<JoinResponse, WebClientError> {
        let mut client = zopp_service_client::ZoppServiceClient::new(self.client());
        let response = client.join(request).await.map_err(WebClientError::from)?;
        Ok(response.into_inner())
    }

    /// Register a new principal (unauthenticated)
    pub async fn register(
        &self,
        request: RegisterRequest,
    ) -> Result<RegisterResponse, WebClientError> {
        let mut client = zopp_service_client::ZoppServiceClient::new(self.client());
        let response = client
            .register(request)
            .await
            .map_err(WebClientError::from)?;
        Ok(response.into_inner())
    }

    // ============ Workspace RPCs ============

    /// List workspaces (authenticated)
    pub async fn list_workspaces(
        &self,
        credentials: &PrincipalCredentials,
    ) -> Result<WorkspaceList, WebClientError> {
        let method = "/zopp.ZoppService/ListWorkspaces";
        let request = Empty {};
        let metadata = self.create_auth_metadata(credentials, method, &request)?;

        let mut grpc_request = tonic::Request::new(request);
        for (key, value) in metadata {
            grpc_request.metadata_mut().insert(
                key,
                value.parse().map_err(|e| {
                    WebClientError::Transport(format!("Invalid metadata value: {}", e))
                })?,
            );
        }

        let mut client = zopp_service_client::ZoppServiceClient::new(self.client());
        let response = client
            .list_workspaces(grpc_request)
            .await
            .map_err(WebClientError::from)?;
        Ok(response.into_inner())
    }

    /// Create a workspace (authenticated)
    pub async fn create_workspace(
        &self,
        credentials: &PrincipalCredentials,
        request: CreateWorkspaceRequest,
    ) -> Result<Workspace, WebClientError> {
        let method = "/zopp.ZoppService/CreateWorkspace";
        let metadata = self.create_auth_metadata(credentials, method, &request)?;

        let mut grpc_request = tonic::Request::new(request);
        for (key, value) in metadata {
            grpc_request.metadata_mut().insert(
                key,
                value.parse().map_err(|e| {
                    WebClientError::Transport(format!("Invalid metadata value: {}", e))
                })?,
            );
        }

        let mut client = zopp_service_client::ZoppServiceClient::new(self.client());
        let response = client
            .create_workspace(grpc_request)
            .await
            .map_err(WebClientError::from)?;
        Ok(response.into_inner())
    }

    /// Get workspace keys (authenticated)
    pub async fn get_workspace_keys(
        &self,
        credentials: &PrincipalCredentials,
        request: GetWorkspaceKeysRequest,
    ) -> Result<WorkspaceKeys, WebClientError> {
        let method = "/zopp.ZoppService/GetWorkspaceKeys";
        let metadata = self.create_auth_metadata(credentials, method, &request)?;

        let mut grpc_request = tonic::Request::new(request);
        for (key, value) in metadata {
            grpc_request.metadata_mut().insert(
                key,
                value.parse().map_err(|e| {
                    WebClientError::Transport(format!("Invalid metadata value: {}", e))
                })?,
            );
        }

        let mut client = zopp_service_client::ZoppServiceClient::new(self.client());
        let response = client
            .get_workspace_keys(grpc_request)
            .await
            .map_err(WebClientError::from)?;
        Ok(response.into_inner())
    }

    // ============ Project RPCs ============

    /// List projects (authenticated)
    pub async fn list_projects(
        &self,
        credentials: &PrincipalCredentials,
        request: ListProjectsRequest,
    ) -> Result<ProjectList, WebClientError> {
        let method = "/zopp.ZoppService/ListProjects";
        let metadata = self.create_auth_metadata(credentials, method, &request)?;

        let mut grpc_request = tonic::Request::new(request);
        for (key, value) in metadata {
            grpc_request.metadata_mut().insert(
                key,
                value.parse().map_err(|e| {
                    WebClientError::Transport(format!("Invalid metadata value: {}", e))
                })?,
            );
        }

        let mut client = zopp_service_client::ZoppServiceClient::new(self.client());
        let response = client
            .list_projects(grpc_request)
            .await
            .map_err(WebClientError::from)?;
        Ok(response.into_inner())
    }

    /// Create a project (authenticated)
    pub async fn create_project(
        &self,
        credentials: &PrincipalCredentials,
        request: CreateProjectRequest,
    ) -> Result<Project, WebClientError> {
        let method = "/zopp.ZoppService/CreateProject";
        let metadata = self.create_auth_metadata(credentials, method, &request)?;

        let mut grpc_request = tonic::Request::new(request);
        for (key, value) in metadata {
            grpc_request.metadata_mut().insert(
                key,
                value.parse().map_err(|e| {
                    WebClientError::Transport(format!("Invalid metadata value: {}", e))
                })?,
            );
        }

        let mut client = zopp_service_client::ZoppServiceClient::new(self.client());
        let response = client
            .create_project(grpc_request)
            .await
            .map_err(WebClientError::from)?;
        Ok(response.into_inner())
    }

    // ============ Environment RPCs ============

    /// List environments (authenticated)
    pub async fn list_environments(
        &self,
        credentials: &PrincipalCredentials,
        request: ListEnvironmentsRequest,
    ) -> Result<EnvironmentList, WebClientError> {
        let method = "/zopp.ZoppService/ListEnvironments";
        let metadata = self.create_auth_metadata(credentials, method, &request)?;

        let mut grpc_request = tonic::Request::new(request);
        for (key, value) in metadata {
            grpc_request.metadata_mut().insert(
                key,
                value.parse().map_err(|e| {
                    WebClientError::Transport(format!("Invalid metadata value: {}", e))
                })?,
            );
        }

        let mut client = zopp_service_client::ZoppServiceClient::new(self.client());
        let response = client
            .list_environments(grpc_request)
            .await
            .map_err(WebClientError::from)?;
        Ok(response.into_inner())
    }

    /// Create an environment (authenticated)
    pub async fn create_environment(
        &self,
        credentials: &PrincipalCredentials,
        request: CreateEnvironmentRequest,
    ) -> Result<Environment, WebClientError> {
        let method = "/zopp.ZoppService/CreateEnvironment";
        let metadata = self.create_auth_metadata(credentials, method, &request)?;

        let mut grpc_request = tonic::Request::new(request);
        for (key, value) in metadata {
            grpc_request.metadata_mut().insert(
                key,
                value.parse().map_err(|e| {
                    WebClientError::Transport(format!("Invalid metadata value: {}", e))
                })?,
            );
        }

        let mut client = zopp_service_client::ZoppServiceClient::new(self.client());
        let response = client
            .create_environment(grpc_request)
            .await
            .map_err(WebClientError::from)?;
        Ok(response.into_inner())
    }

    // ============ Secret RPCs ============

    /// List secrets (authenticated)
    pub async fn list_secrets(
        &self,
        credentials: &PrincipalCredentials,
        request: ListSecretsRequest,
    ) -> Result<SecretList, WebClientError> {
        let method = "/zopp.ZoppService/ListSecrets";
        let metadata = self.create_auth_metadata(credentials, method, &request)?;

        let mut grpc_request = tonic::Request::new(request);
        for (key, value) in metadata {
            grpc_request.metadata_mut().insert(
                key,
                value.parse().map_err(|e| {
                    WebClientError::Transport(format!("Invalid metadata value: {}", e))
                })?,
            );
        }

        let mut client = zopp_service_client::ZoppServiceClient::new(self.client());
        let response = client
            .list_secrets(grpc_request)
            .await
            .map_err(WebClientError::from)?;
        Ok(response.into_inner())
    }

    /// Upsert a secret (authenticated)
    pub async fn upsert_secret(
        &self,
        credentials: &PrincipalCredentials,
        request: UpsertSecretRequest,
    ) -> Result<Empty, WebClientError> {
        let method = "/zopp.ZoppService/UpsertSecret";
        let metadata = self.create_auth_metadata(credentials, method, &request)?;

        let mut grpc_request = tonic::Request::new(request);
        for (key, value) in metadata {
            grpc_request.metadata_mut().insert(
                key,
                value.parse().map_err(|e| {
                    WebClientError::Transport(format!("Invalid metadata value: {}", e))
                })?,
            );
        }

        let mut client = zopp_service_client::ZoppServiceClient::new(self.client());
        let response = client
            .upsert_secret(grpc_request)
            .await
            .map_err(WebClientError::from)?;
        Ok(response.into_inner())
    }

    /// Get a secret (authenticated)
    pub async fn get_secret(
        &self,
        credentials: &PrincipalCredentials,
        request: GetSecretRequest,
    ) -> Result<Secret, WebClientError> {
        let method = "/zopp.ZoppService/GetSecret";
        let metadata = self.create_auth_metadata(credentials, method, &request)?;

        let mut grpc_request = tonic::Request::new(request);
        for (key, value) in metadata {
            grpc_request.metadata_mut().insert(
                key,
                value.parse().map_err(|e| {
                    WebClientError::Transport(format!("Invalid metadata value: {}", e))
                })?,
            );
        }

        let mut client = zopp_service_client::ZoppServiceClient::new(self.client());
        let response = client
            .get_secret(grpc_request)
            .await
            .map_err(WebClientError::from)?;
        Ok(response.into_inner())
    }

    /// Delete a secret (authenticated)
    pub async fn delete_secret(
        &self,
        credentials: &PrincipalCredentials,
        request: DeleteSecretRequest,
    ) -> Result<Empty, WebClientError> {
        let method = "/zopp.ZoppService/DeleteSecret";
        let metadata = self.create_auth_metadata(credentials, method, &request)?;

        let mut grpc_request = tonic::Request::new(request);
        for (key, value) in metadata {
            grpc_request.metadata_mut().insert(
                key,
                value.parse().map_err(|e| {
                    WebClientError::Transport(format!("Invalid metadata value: {}", e))
                })?,
            );
        }

        let mut client = zopp_service_client::ZoppServiceClient::new(self.client());
        let response = client
            .delete_secret(grpc_request)
            .await
            .map_err(WebClientError::from)?;
        Ok(response.into_inner())
    }

    // ============ Principal Export/Import RPCs ============

    /// Get a principal export (first call to get verification salt, unauthenticated)
    pub async fn get_principal_export(
        &self,
        request: GetPrincipalExportRequest,
    ) -> Result<GetPrincipalExportResponse, WebClientError> {
        let mut client = zopp_service_client::ZoppServiceClient::new(self.client());
        let response = client
            .get_principal_export(request)
            .await
            .map_err(WebClientError::from)?;
        Ok(response.into_inner())
    }

    /// Consume a principal export (unauthenticated)
    pub async fn consume_principal_export(
        &self,
        request: ConsumePrincipalExportRequest,
    ) -> Result<Empty, WebClientError> {
        let mut client = zopp_service_client::ZoppServiceClient::new(self.client());
        let response = client
            .consume_principal_export(request)
            .await
            .map_err(WebClientError::from)?;
        Ok(response.into_inner())
    }

    // ============ Invite RPCs ============

    /// Get invite info (unauthenticated - for joining)
    pub async fn get_invite(
        &self,
        request: GetInviteRequest,
    ) -> Result<InviteToken, WebClientError> {
        let mut client = zopp_service_client::ZoppServiceClient::new(self.client());
        let response = client
            .get_invite(request)
            .await
            .map_err(WebClientError::from)?;
        Ok(response.into_inner())
    }

    // ============ Email Verification RPCs ============

    /// Verify email with a code (unauthenticated)
    pub async fn verify_email(
        &self,
        request: VerifyEmailRequest,
    ) -> Result<VerifyEmailResponse, WebClientError> {
        let mut client = zopp_service_client::ZoppServiceClient::new(self.client());
        let response = client
            .verify_email(request)
            .await
            .map_err(WebClientError::from)?;
        Ok(response.into_inner())
    }

    /// Resend verification email (unauthenticated)
    pub async fn resend_verification(
        &self,
        request: ResendVerificationRequest,
    ) -> Result<ResendVerificationResponse, WebClientError> {
        let mut client = zopp_service_client::ZoppServiceClient::new(self.client());
        let response = client
            .resend_verification(request)
            .await
            .map_err(WebClientError::from)?;
        Ok(response.into_inner())
    }

    /// Create an invite (authenticated)
    pub async fn create_invite(
        &self,
        credentials: &PrincipalCredentials,
        request: CreateInviteRequest,
    ) -> Result<InviteToken, WebClientError> {
        let method = "/zopp.ZoppService/CreateInvite";
        let metadata = self.create_auth_metadata(credentials, method, &request)?;

        let mut grpc_request = tonic::Request::new(request);
        for (key, value) in metadata {
            grpc_request.metadata_mut().insert(
                key,
                value.parse().map_err(|e| {
                    WebClientError::Transport(format!("Invalid metadata value: {}", e))
                })?,
            );
        }

        let mut client = zopp_service_client::ZoppServiceClient::new(self.client());
        let response = client
            .create_invite(grpc_request)
            .await
            .map_err(WebClientError::from)?;
        Ok(response.into_inner())
    }

    // ============ Audit Log RPCs ============

    /// List audit logs (authenticated)
    pub async fn list_audit_logs(
        &self,
        credentials: &PrincipalCredentials,
        request: ListAuditLogsRequest,
    ) -> Result<AuditLogList, WebClientError> {
        let method = "/zopp.ZoppService/ListAuditLogs";
        let metadata = self.create_auth_metadata(credentials, method, &request)?;

        let mut grpc_request = tonic::Request::new(request);
        for (key, value) in metadata {
            grpc_request.metadata_mut().insert(
                key,
                value.parse().map_err(|e| {
                    WebClientError::Transport(format!("Invalid metadata value: {}", e))
                })?,
            );
        }

        let mut client = zopp_service_client::ZoppServiceClient::new(self.client());
        let response = client
            .list_audit_logs(grpc_request)
            .await
            .map_err(WebClientError::from)?;
        Ok(response.into_inner())
    }

    // ============ Permission RPCs ============

    /// List workspace permissions (authenticated)
    pub async fn list_workspace_permissions(
        &self,
        credentials: &PrincipalCredentials,
        request: ListWorkspacePermissionsRequest,
    ) -> Result<PermissionList, WebClientError> {
        let method = "/zopp.ZoppService/ListWorkspacePermissions";
        let metadata = self.create_auth_metadata(credentials, method, &request)?;

        let mut grpc_request = tonic::Request::new(request);
        for (key, value) in metadata {
            grpc_request.metadata_mut().insert(
                key,
                value.parse().map_err(|e| {
                    WebClientError::Transport(format!("Invalid metadata value: {}", e))
                })?,
            );
        }

        let mut client = zopp_service_client::ZoppServiceClient::new(self.client());
        let response = client
            .list_workspace_permissions(grpc_request)
            .await
            .map_err(WebClientError::from)?;
        Ok(response.into_inner())
    }

    // ============ Group RPCs ============

    /// List groups (authenticated)
    pub async fn list_groups(
        &self,
        credentials: &PrincipalCredentials,
        request: ListGroupsRequest,
    ) -> Result<GroupList, WebClientError> {
        let method = "/zopp.ZoppService/ListGroups";
        let metadata = self.create_auth_metadata(credentials, method, &request)?;

        let mut grpc_request = tonic::Request::new(request);
        for (key, value) in metadata {
            grpc_request.metadata_mut().insert(
                key,
                value.parse().map_err(|e| {
                    WebClientError::Transport(format!("Invalid metadata value: {}", e))
                })?,
            );
        }

        let mut client = zopp_service_client::ZoppServiceClient::new(self.client());
        let response = client
            .list_groups(grpc_request)
            .await
            .map_err(WebClientError::from)?;
        Ok(response.into_inner())
    }

    /// Create a group (authenticated)
    pub async fn create_group(
        &self,
        credentials: &PrincipalCredentials,
        request: CreateGroupRequest,
    ) -> Result<Group, WebClientError> {
        let method = "/zopp.ZoppService/CreateGroup";
        let metadata = self.create_auth_metadata(credentials, method, &request)?;

        let mut grpc_request = tonic::Request::new(request);
        for (key, value) in metadata {
            grpc_request.metadata_mut().insert(
                key,
                value.parse().map_err(|e| {
                    WebClientError::Transport(format!("Invalid metadata value: {}", e))
                })?,
            );
        }

        let mut client = zopp_service_client::ZoppServiceClient::new(self.client());
        let response = client
            .create_group(grpc_request)
            .await
            .map_err(WebClientError::from)?;
        Ok(response.into_inner())
    }

    /// List group members (authenticated)
    pub async fn list_group_members(
        &self,
        credentials: &PrincipalCredentials,
        request: ListGroupMembersRequest,
    ) -> Result<GroupMemberList, WebClientError> {
        let method = "/zopp.ZoppService/ListGroupMembers";
        let metadata = self.create_auth_metadata(credentials, method, &request)?;

        let mut grpc_request = tonic::Request::new(request);
        for (key, value) in metadata {
            grpc_request.metadata_mut().insert(
                key,
                value.parse().map_err(|e| {
                    WebClientError::Transport(format!("Invalid metadata value: {}", e))
                })?,
            );
        }

        let mut client = zopp_service_client::ZoppServiceClient::new(self.client());
        let response = client
            .list_group_members(grpc_request)
            .await
            .map_err(WebClientError::from)?;
        Ok(response.into_inner())
    }

    // ============ Principal Export RPCs ============

    /// Create a principal export (authenticated)
    pub async fn create_principal_export(
        &self,
        credentials: &PrincipalCredentials,
        request: CreatePrincipalExportRequest,
    ) -> Result<CreatePrincipalExportResponse, WebClientError> {
        let method = "/zopp.ZoppService/CreatePrincipalExport";
        let metadata = self.create_auth_metadata(credentials, method, &request)?;

        let mut grpc_request = tonic::Request::new(request);
        for (key, value) in metadata {
            grpc_request.metadata_mut().insert(
                key,
                value.parse().map_err(|e| {
                    WebClientError::Transport(format!("Invalid metadata value: {}", e))
                })?,
            );
        }

        let mut client = zopp_service_client::ZoppServiceClient::new(self.client());
        let response = client
            .create_principal_export(grpc_request)
            .await
            .map_err(WebClientError::from)?;
        Ok(response.into_inner())
    }
}
