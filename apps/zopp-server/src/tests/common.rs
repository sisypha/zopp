//! Common test helpers and utilities for server tests.
//!
//! This module provides shared test infrastructure including:
//! - Test server creation (with and without email verification)
//! - User and principal creation helpers
//! - Workspace, project, and environment creation helpers
//! - Signed request creation for authenticated tests

use crate::config::ServerConfig;
use crate::server::ZoppServer;
use chrono::Utc;
use ed25519_dalek::{Signer, SigningKey};
use prost::Message;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tonic::metadata::MetadataValue;
use tonic::Request;
use zopp_events_memory::MemoryEventBus;
use zopp_storage::*;
use zopp_store_sqlite::SqliteStore;

/// Test helper: Create a ZoppServer with in-memory SQLite
pub async fn create_test_server() -> ZoppServer {
    let store = Arc::new(SqliteStore::open_in_memory().await.unwrap());
    let events = Arc::new(MemoryEventBus::new());
    // Use default config with no email verification for tests
    let config = ServerConfig::default();
    ZoppServer::new_sqlite(store, events, config, None)
}

/// Test helper: Create a ZoppServer with email verification required
pub async fn create_test_server_with_verification() -> ZoppServer {
    use crate::config::{EmailConfig, EmailProviderConfig};

    let store = Arc::new(SqliteStore::open_in_memory().await.unwrap());
    let events = Arc::new(MemoryEventBus::new());
    // Config with verification required
    let config = ServerConfig {
        email: Some(EmailConfig {
            verification_required: true,
            provider: EmailProviderConfig::Smtp {
                host: "localhost".to_string(),
                port: 25,
                username: None,
                password: None,
                use_tls: false,
            },
            from_address: "test@example.com".to_string(),
            from_name: None,
        }),
    };
    // No actual email provider - we're testing enforcement, not email sending
    ZoppServer::new_sqlite(store, events, config, None)
}

/// Test helper: Generate a random Ed25519 keypair and return (public_key, private_key)
pub fn generate_keypair() -> (Vec<u8>, SigningKey) {
    let signing_key = SigningKey::generate(&mut rand_core::OsRng);
    let public_key = signing_key.verifying_key().to_bytes().to_vec();
    (public_key, signing_key)
}

/// Test helper: Generate a random X25519 keypair
pub fn generate_x25519_keypair() -> (Vec<u8>, [u8; 32]) {
    use rand_core::RngCore;
    let mut private_key = [0u8; 32];
    rand_core::OsRng.fill_bytes(&mut private_key);
    let secret = x25519_dalek::StaticSecret::from(private_key);
    let public = x25519_dalek::PublicKey::from(&secret);
    (public.as_bytes().to_vec(), private_key)
}

/// Test helper: Create a user with principal for testing.
/// The user is automatically verified (non-verification flow behavior).
pub async fn create_test_user(
    server: &ZoppServer,
    email: &str,
    principal_name: &str,
) -> (UserId, PrincipalId, SigningKey) {
    let (public_key, signing_key) = generate_keypair();
    let (x25519_public, _) = generate_x25519_keypair();

    let (user_id, principal_id) = server
        .store
        .create_user(&CreateUserParams {
            email: email.to_string(),
            principal: Some(CreatePrincipalData {
                name: principal_name.to_string(),
                public_key,
                x25519_public_key: Some(x25519_public),
                is_service: false,
            }),
            workspace_ids: vec![],
        })
        .await
        .unwrap();

    (user_id, principal_id.unwrap(), signing_key)
}

/// Test helper: Create an unverified user with principal.
/// This simulates the state after join but before email verification completes.
pub async fn create_unverified_test_user(
    server: &ZoppServer,
    email: &str,
    principal_name: &str,
) -> (UserId, PrincipalId, SigningKey) {
    let (public_key, signing_key) = generate_keypair();
    let (x25519_public, _) = generate_x25519_keypair();

    // Create user WITHOUT principal (verified=false)
    let (user_id, _) = server
        .store
        .create_user(&CreateUserParams {
            email: email.to_string(),
            principal: None, // No principal = unverified
            workspace_ids: vec![],
        })
        .await
        .unwrap();

    // Create principal separately
    let principal_id = server
        .store
        .create_principal(&CreatePrincipalParams {
            user_id: Some(user_id.clone()),
            name: principal_name.to_string(),
            public_key,
            x25519_public_key: Some(x25519_public),
        })
        .await
        .unwrap();

    (user_id, principal_id, signing_key)
}

/// Test helper: Create a workspace owned by a user
pub async fn create_test_workspace(
    server: &ZoppServer,
    owner_user_id: &UserId,
    name: &str,
) -> WorkspaceId {
    let workspace_id = WorkspaceId(uuid::Uuid::now_v7());
    server
        .store
        .create_workspace(&CreateWorkspaceParams {
            id: workspace_id.clone(),
            name: name.to_string(),
            owner_user_id: owner_user_id.clone(),
            kdf_salt: vec![0u8; 16],
            m_cost_kib: 64 * 1024,
            t_cost: 3,
            p_cost: 1,
        })
        .await
        .unwrap();
    // Add owner to workspace_members (required for listing workspaces)
    server
        .store
        .add_user_to_workspace(&workspace_id, owner_user_id)
        .await
        .unwrap();
    workspace_id
}

/// Test helper: Create a project in a workspace
pub async fn create_test_project(
    server: &ZoppServer,
    workspace_id: &WorkspaceId,
    name: &str,
) -> ProjectId {
    server
        .store
        .create_project(&CreateProjectParams {
            workspace_id: workspace_id.clone(),
            name: name.to_string(),
        })
        .await
        .unwrap()
}

/// Test helper: Create an environment in a project
pub async fn create_test_environment(
    server: &ZoppServer,
    project_id: &ProjectId,
    name: &str,
) -> EnvironmentId {
    server
        .store
        .create_env(&CreateEnvParams {
            project_id: project_id.clone(),
            name: name.to_string(),
            dek_wrapped: vec![0u8; 32],
            dek_nonce: vec![0u8; 24],
        })
        .await
        .unwrap()
}

/// Test helper: Create a group in a workspace
pub async fn create_test_group(
    server: &ZoppServer,
    workspace_id: &WorkspaceId,
    name: &str,
) -> zopp_storage::GroupId {
    server
        .store
        .create_group(&zopp_storage::CreateGroupParams {
            workspace_id: workspace_id.clone(),
            name: name.to_string(),
            description: None,
        })
        .await
        .unwrap()
}

/// Test helper: Add a principal to a workspace (in workspace_principals table)
pub async fn add_principal_to_workspace(
    server: &ZoppServer,
    workspace_id: &WorkspaceId,
    principal_id: &PrincipalId,
) {
    server
        .store
        .add_workspace_principal(&AddWorkspacePrincipalParams {
            workspace_id: workspace_id.clone(),
            principal_id: principal_id.clone(),
            ephemeral_pub: vec![0u8; 32],
            kek_wrapped: vec![0u8; 48],
            kek_nonce: vec![0u8; 24],
        })
        .await
        .unwrap();
}

/// Test helper: Add a user to a workspace with a specific role
/// This adds them to workspace_members table AND sets their permission role
pub async fn add_user_to_workspace(
    server: &ZoppServer,
    workspace_id: &WorkspaceId,
    user_id: &UserId,
    role: Role,
) {
    // Add to workspace_members table (required for get_workspace_by_name)
    server
        .store
        .add_user_to_workspace(workspace_id, user_id)
        .await
        .unwrap();
    // Set their permission role
    server
        .store
        .set_user_workspace_permission(workspace_id, user_id, role)
        .await
        .unwrap();
}

/// Test helper: Create a service principal (no associated user)
pub async fn create_service_principal(
    server: &ZoppServer,
    name: &str,
) -> (PrincipalId, SigningKey) {
    let (public_key, signing_key) = generate_keypair();
    let (x25519_public, _) = generate_x25519_keypair();

    let principal_id = server
        .store
        .create_principal(&CreatePrincipalParams {
            user_id: None, // Service principal has no user
            name: name.to_string(),
            public_key,
            x25519_public_key: Some(x25519_public),
        })
        .await
        .unwrap();

    (principal_id, signing_key)
}

/// Test helper: Create a signed request with proper authentication metadata
pub fn create_signed_request<T: Message + Default>(
    principal_id: &PrincipalId,
    signing_key: &SigningKey,
    method: &str,
    request_body: T,
) -> Request<T> {
    let body_bytes = request_body.encode_to_vec();
    let mut hasher = Sha256::new();
    hasher.update(method.as_bytes());
    hasher.update(&body_bytes);
    let request_hash = hasher.finalize().to_vec();

    let timestamp = Utc::now().timestamp();

    // Build message: method + hash + timestamp
    let mut message = Vec::new();
    message.extend_from_slice(method.as_bytes());
    message.extend_from_slice(&request_hash);
    message.extend_from_slice(&timestamp.to_le_bytes());

    let signature = signing_key.sign(&message);

    let mut request = Request::new(request_body);
    request.metadata_mut().insert(
        "principal-id",
        MetadataValue::try_from(principal_id.0.to_string()).unwrap(),
    );
    request.metadata_mut().insert(
        "timestamp",
        MetadataValue::try_from(timestamp.to_string()).unwrap(),
    );
    request.metadata_mut().insert(
        "signature",
        MetadataValue::try_from(hex::encode(signature.to_bytes())).unwrap(),
    );
    request.metadata_mut().insert(
        "request-hash",
        MetadataValue::try_from(hex::encode(&request_hash)).unwrap(),
    );

    request
}
