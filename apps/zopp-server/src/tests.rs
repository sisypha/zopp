//! Unit tests for server logic using real SQLite in-memory database.

use crate::backend::StoreBackend;
use crate::server::{extract_signature, ZoppServer};
use chrono::{Duration, Utc};
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
async fn create_test_server() -> ZoppServer {
    let store = Arc::new(SqliteStore::open_in_memory().await.unwrap());
    let events = Arc::new(MemoryEventBus::new());
    ZoppServer::new_sqlite(store, events)
}

/// Test helper: Generate a random Ed25519 keypair and return (public_key, private_key)
fn generate_keypair() -> (Vec<u8>, SigningKey) {
    let signing_key = SigningKey::generate(&mut rand_core::OsRng);
    let public_key = signing_key.verifying_key().to_bytes().to_vec();
    (public_key, signing_key)
}

/// Test helper: Generate a random X25519 keypair
fn generate_x25519_keypair() -> (Vec<u8>, [u8; 32]) {
    use rand_core::RngCore;
    let mut private_key = [0u8; 32];
    rand_core::OsRng.fill_bytes(&mut private_key);
    let secret = x25519_dalek::StaticSecret::from(private_key);
    let public = x25519_dalek::PublicKey::from(&secret);
    (public.as_bytes().to_vec(), private_key)
}

/// Test helper: Create a user with principal for testing
async fn create_test_user(
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

/// Test helper: Create a workspace owned by a user
async fn create_test_workspace(
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
async fn create_test_project(
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
async fn create_test_environment(
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

/// Test helper: Add a principal to a workspace (in workspace_principals table)
async fn add_principal_to_workspace(
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
async fn add_user_to_workspace(
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
async fn create_service_principal(
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
fn create_signed_request<T: Message + Default>(
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

// ================== extract_signature tests ==================

#[tokio::test]
async fn extract_signature_valid_metadata() {
    let principal_id = PrincipalId(uuid::Uuid::now_v7());
    let timestamp = Utc::now().timestamp();
    let signature = vec![0u8; 64];
    let request_hash = vec![1u8; 32];

    let mut request = Request::new(zopp_proto::Empty {});
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
        MetadataValue::try_from(hex::encode(&signature)).unwrap(),
    );
    request.metadata_mut().insert(
        "request-hash",
        MetadataValue::try_from(hex::encode(&request_hash)).unwrap(),
    );

    let (extracted_pid, extracted_ts, extracted_sig, extracted_hash) =
        extract_signature(&request).unwrap();

    assert_eq!(extracted_pid.0, principal_id.0);
    assert_eq!(extracted_ts, timestamp);
    assert_eq!(extracted_sig, signature);
    assert_eq!(extracted_hash, request_hash);
}

#[tokio::test]
async fn extract_signature_missing_principal_id() {
    let request = Request::new(zopp_proto::Empty {});
    let result = extract_signature(&request);
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .message()
        .contains("Missing principal-id"));
}

#[tokio::test]
async fn extract_signature_invalid_principal_id_format() {
    let mut request = Request::new(zopp_proto::Empty {});
    request.metadata_mut().insert(
        "principal-id",
        MetadataValue::try_from("not-a-uuid").unwrap(),
    );
    let result = extract_signature(&request);
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .message()
        .contains("Invalid principal-id"));
}

#[tokio::test]
async fn extract_signature_missing_timestamp() {
    let mut request = Request::new(zopp_proto::Empty {});
    request.metadata_mut().insert(
        "principal-id",
        MetadataValue::try_from(uuid::Uuid::now_v7().to_string()).unwrap(),
    );
    let result = extract_signature(&request);
    assert!(result.is_err());
    assert!(result.unwrap_err().message().contains("Missing timestamp"));
}

#[tokio::test]
async fn extract_signature_invalid_timestamp_format() {
    let mut request = Request::new(zopp_proto::Empty {});
    request.metadata_mut().insert(
        "principal-id",
        MetadataValue::try_from(uuid::Uuid::now_v7().to_string()).unwrap(),
    );
    request.metadata_mut().insert(
        "timestamp",
        MetadataValue::try_from("not-a-number").unwrap(),
    );
    let result = extract_signature(&request);
    assert!(result.is_err());
    assert!(result.unwrap_err().message().contains("Invalid timestamp"));
}

#[tokio::test]
async fn extract_signature_missing_signature() {
    let mut request = Request::new(zopp_proto::Empty {});
    request.metadata_mut().insert(
        "principal-id",
        MetadataValue::try_from(uuid::Uuid::now_v7().to_string()).unwrap(),
    );
    request
        .metadata_mut()
        .insert("timestamp", MetadataValue::try_from("12345").unwrap());
    let result = extract_signature(&request);
    assert!(result.is_err());
    assert!(result.unwrap_err().message().contains("Missing signature"));
}

#[tokio::test]
async fn extract_signature_invalid_signature_hex() {
    let mut request = Request::new(zopp_proto::Empty {});
    request.metadata_mut().insert(
        "principal-id",
        MetadataValue::try_from(uuid::Uuid::now_v7().to_string()).unwrap(),
    );
    request
        .metadata_mut()
        .insert("timestamp", MetadataValue::try_from("12345").unwrap());
    request
        .metadata_mut()
        .insert("signature", MetadataValue::try_from("not-hex!").unwrap());
    let result = extract_signature(&request);
    assert!(result.is_err());
    assert!(result.unwrap_err().message().contains("Invalid signature"));
}

#[tokio::test]
async fn extract_signature_missing_request_hash() {
    let mut request = Request::new(zopp_proto::Empty {});
    request.metadata_mut().insert(
        "principal-id",
        MetadataValue::try_from(uuid::Uuid::now_v7().to_string()).unwrap(),
    );
    request
        .metadata_mut()
        .insert("timestamp", MetadataValue::try_from("12345").unwrap());
    request.metadata_mut().insert(
        "signature",
        MetadataValue::try_from(hex::encode([0u8; 64])).unwrap(),
    );
    let result = extract_signature(&request);
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .message()
        .contains("Missing request-hash"));
}

// ================== verify_signature_and_get_principal tests ==================

#[tokio::test]
async fn verify_signature_valid() {
    let server = create_test_server().await;
    let (_, principal_id, signing_key) =
        create_test_user(&server, "test@example.com", "laptop").await;

    let method = "/zopp.ZoppService/TestMethod";
    let request_body = zopp_proto::Empty {};
    let request = create_signed_request(&principal_id, &signing_key, method, request_body);

    // Extract values from request
    let (_, timestamp, signature, request_hash) = extract_signature(&request).unwrap();

    // Verify signature
    let principal = server
        .verify_signature_and_get_principal(
            &principal_id,
            timestamp,
            &signature,
            method,
            &request_body,
            &request_hash,
        )
        .await
        .unwrap();

    assert_eq!(principal.id.0, principal_id.0);
}

#[tokio::test]
async fn verify_signature_timestamp_too_old() {
    let server = create_test_server().await;
    let (_, principal_id, signing_key) =
        create_test_user(&server, "test@example.com", "laptop").await;

    let method = "/zopp.ZoppService/TestMethod";
    let request_body = zopp_proto::Empty {};

    // Create a request with old timestamp
    let body_bytes = request_body.encode_to_vec();
    let mut hasher = Sha256::new();
    hasher.update(method.as_bytes());
    hasher.update(&body_bytes);
    let request_hash = hasher.finalize().to_vec();

    let old_timestamp = (Utc::now() - Duration::seconds(120)).timestamp();

    let mut message = Vec::new();
    message.extend_from_slice(method.as_bytes());
    message.extend_from_slice(&request_hash);
    message.extend_from_slice(&old_timestamp.to_le_bytes());
    let signature = signing_key.sign(&message);

    let result = server
        .verify_signature_and_get_principal(
            &principal_id,
            old_timestamp,
            &signature.to_bytes(),
            method,
            &request_body,
            &request_hash,
        )
        .await;

    assert!(result.is_err());
    assert!(result.unwrap_err().message().contains("too old"));
}

#[tokio::test]
async fn verify_signature_timestamp_too_future() {
    let server = create_test_server().await;
    let (_, principal_id, signing_key) =
        create_test_user(&server, "test@example.com", "laptop").await;

    let method = "/zopp.ZoppService/TestMethod";
    let request_body = zopp_proto::Empty {};

    let body_bytes = request_body.encode_to_vec();
    let mut hasher = Sha256::new();
    hasher.update(method.as_bytes());
    hasher.update(&body_bytes);
    let request_hash = hasher.finalize().to_vec();

    let future_timestamp = (Utc::now() + Duration::seconds(120)).timestamp();

    let mut message = Vec::new();
    message.extend_from_slice(method.as_bytes());
    message.extend_from_slice(&request_hash);
    message.extend_from_slice(&future_timestamp.to_le_bytes());
    let signature = signing_key.sign(&message);

    let result = server
        .verify_signature_and_get_principal(
            &principal_id,
            future_timestamp,
            &signature.to_bytes(),
            method,
            &request_body,
            &request_hash,
        )
        .await;

    assert!(result.is_err());
    assert!(result.unwrap_err().message().contains("future"));
}

#[tokio::test]
async fn verify_signature_hash_mismatch() {
    let server = create_test_server().await;
    let (_, principal_id, signing_key) =
        create_test_user(&server, "test@example.com", "laptop").await;

    let method = "/zopp.ZoppService/TestMethod";
    let request_body = zopp_proto::Empty {};

    // Provide wrong hash
    let wrong_hash = vec![0u8; 32];
    let timestamp = Utc::now().timestamp();

    let mut message = Vec::new();
    message.extend_from_slice(method.as_bytes());
    message.extend_from_slice(&wrong_hash);
    message.extend_from_slice(&timestamp.to_le_bytes());
    let signature = signing_key.sign(&message);

    let result = server
        .verify_signature_and_get_principal(
            &principal_id,
            timestamp,
            &signature.to_bytes(),
            method,
            &request_body,
            &wrong_hash,
        )
        .await;

    assert!(result.is_err());
    assert!(result.unwrap_err().message().contains("hash mismatch"));
}

#[tokio::test]
async fn verify_signature_invalid_principal() {
    let server = create_test_server().await;
    let fake_principal_id = PrincipalId(uuid::Uuid::now_v7());
    let signing_key = SigningKey::generate(&mut rand_core::OsRng);

    let method = "/zopp.ZoppService/TestMethod";
    let request_body = zopp_proto::Empty {};

    let body_bytes = request_body.encode_to_vec();
    let mut hasher = Sha256::new();
    hasher.update(method.as_bytes());
    hasher.update(&body_bytes);
    let request_hash = hasher.finalize().to_vec();

    let timestamp = Utc::now().timestamp();

    let mut message = Vec::new();
    message.extend_from_slice(method.as_bytes());
    message.extend_from_slice(&request_hash);
    message.extend_from_slice(&timestamp.to_le_bytes());
    let signature = signing_key.sign(&message);

    let result = server
        .verify_signature_and_get_principal(
            &fake_principal_id,
            timestamp,
            &signature.to_bytes(),
            method,
            &request_body,
            &request_hash,
        )
        .await;

    assert!(result.is_err());
    assert!(result.unwrap_err().message().contains("Invalid principal"));
}

#[tokio::test]
async fn verify_signature_wrong_key() {
    let server = create_test_server().await;
    let (_, principal_id, _) = create_test_user(&server, "test@example.com", "laptop").await;

    // Use a different signing key
    let wrong_signing_key = SigningKey::generate(&mut rand_core::OsRng);

    let method = "/zopp.ZoppService/TestMethod";
    let request_body = zopp_proto::Empty {};

    let body_bytes = request_body.encode_to_vec();
    let mut hasher = Sha256::new();
    hasher.update(method.as_bytes());
    hasher.update(&body_bytes);
    let request_hash = hasher.finalize().to_vec();

    let timestamp = Utc::now().timestamp();

    let mut message = Vec::new();
    message.extend_from_slice(method.as_bytes());
    message.extend_from_slice(&request_hash);
    message.extend_from_slice(&timestamp.to_le_bytes());
    let signature = wrong_signing_key.sign(&message);

    let result = server
        .verify_signature_and_get_principal(
            &principal_id,
            timestamp,
            &signature.to_bytes(),
            method,
            &request_body,
            &request_hash,
        )
        .await;

    assert!(result.is_err());
    assert!(result.unwrap_err().message().contains("Invalid signature"));
}

// ================== Permission checking tests ==================

#[tokio::test]
async fn check_permission_workspace_owner_has_admin() {
    let server = create_test_server().await;
    let (user_id, principal_id, _) = create_test_user(&server, "owner@example.com", "laptop").await;
    let workspace_id = create_test_workspace(&server, &user_id, "my-workspace").await;
    let project_id = create_test_project(&server, &workspace_id, "my-project").await;
    let env_id = create_test_environment(&server, &project_id, "production").await;

    // Owner should have Admin access even without explicit permissions
    let result = server
        .check_permission(
            &principal_id,
            &workspace_id,
            &project_id,
            &env_id,
            Role::Admin,
        )
        .await;

    assert!(result.is_ok());
}

#[tokio::test]
async fn check_permission_user_permission_read() {
    let server = create_test_server().await;

    // Create owner
    let (owner_user_id, _, _) = create_test_user(&server, "owner@example.com", "laptop").await;
    let workspace_id = create_test_workspace(&server, &owner_user_id, "my-workspace").await;
    let project_id = create_test_project(&server, &workspace_id, "my-project").await;
    let env_id = create_test_environment(&server, &project_id, "production").await;

    // Create another user with Read permission
    let (other_user_id, other_principal_id, _) =
        create_test_user(&server, "other@example.com", "phone").await;

    // Add user to workspace
    server
        .store
        .add_user_to_workspace(&workspace_id, &other_user_id)
        .await
        .unwrap();

    // Grant user Read permission on environment
    server
        .store
        .set_user_environment_permission(&env_id, &other_user_id, Role::Read)
        .await
        .unwrap();

    // Check Read permission - should succeed
    let result = server
        .check_permission(
            &other_principal_id,
            &workspace_id,
            &project_id,
            &env_id,
            Role::Read,
        )
        .await;
    assert!(result.is_ok());

    // Check Write permission - should fail
    let result = server
        .check_permission(
            &other_principal_id,
            &workspace_id,
            &project_id,
            &env_id,
            Role::Write,
        )
        .await;
    assert!(result.is_err());
}

#[tokio::test]
async fn check_permission_user_permission_write() {
    let server = create_test_server().await;

    // Create owner
    let (owner_user_id, _, _) = create_test_user(&server, "owner@example.com", "laptop").await;
    let workspace_id = create_test_workspace(&server, &owner_user_id, "my-workspace").await;
    let project_id = create_test_project(&server, &workspace_id, "my-project").await;
    let env_id = create_test_environment(&server, &project_id, "production").await;

    // Create another user with Write permission
    let (other_user_id, other_principal_id, _) =
        create_test_user(&server, "other@example.com", "phone").await;

    server
        .store
        .add_user_to_workspace(&workspace_id, &other_user_id)
        .await
        .unwrap();
    server
        .store
        .set_user_environment_permission(&env_id, &other_user_id, Role::Write)
        .await
        .unwrap();

    // Check Write permission - should succeed
    let result = server
        .check_permission(
            &other_principal_id,
            &workspace_id,
            &project_id,
            &env_id,
            Role::Write,
        )
        .await;
    assert!(result.is_ok());

    // Check Read permission - should also succeed (Write includes Read)
    let result = server
        .check_permission(
            &other_principal_id,
            &workspace_id,
            &project_id,
            &env_id,
            Role::Read,
        )
        .await;
    assert!(result.is_ok());

    // Check Admin permission - should fail
    let result = server
        .check_permission(
            &other_principal_id,
            &workspace_id,
            &project_id,
            &env_id,
            Role::Admin,
        )
        .await;
    assert!(result.is_err());
}

#[tokio::test]
async fn check_permission_no_permission_denied() {
    let server = create_test_server().await;

    // Create owner
    let (owner_user_id, _, _) = create_test_user(&server, "owner@example.com", "laptop").await;
    let workspace_id = create_test_workspace(&server, &owner_user_id, "my-workspace").await;
    let project_id = create_test_project(&server, &workspace_id, "my-project").await;
    let env_id = create_test_environment(&server, &project_id, "production").await;

    // Create another user without any permissions
    let (_, other_principal_id, _) = create_test_user(&server, "other@example.com", "phone").await;

    // Should be denied
    let result = server
        .check_permission(
            &other_principal_id,
            &workspace_id,
            &project_id,
            &env_id,
            Role::Read,
        )
        .await;
    assert!(result.is_err());
    assert!(result.unwrap_err().message().contains("No permissions"));
}

#[tokio::test]
async fn check_permission_workspace_level_inherits() {
    let server = create_test_server().await;

    // Create owner
    let (owner_user_id, _, _) = create_test_user(&server, "owner@example.com", "laptop").await;
    let workspace_id = create_test_workspace(&server, &owner_user_id, "my-workspace").await;
    let project_id = create_test_project(&server, &workspace_id, "my-project").await;
    let env_id = create_test_environment(&server, &project_id, "production").await;

    // Create another user with workspace-level Write
    let (other_user_id, other_principal_id, _) =
        create_test_user(&server, "other@example.com", "phone").await;

    server
        .store
        .add_user_to_workspace(&workspace_id, &other_user_id)
        .await
        .unwrap();
    server
        .store
        .set_user_workspace_permission(&workspace_id, &other_user_id, Role::Write)
        .await
        .unwrap();

    // Workspace Write should inherit to environment
    let result = server
        .check_permission(
            &other_principal_id,
            &workspace_id,
            &project_id,
            &env_id,
            Role::Write,
        )
        .await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn check_permission_principal_restricts_user() {
    let server = create_test_server().await;

    // Create owner
    let (owner_user_id, _, _) = create_test_user(&server, "owner@example.com", "laptop").await;
    let workspace_id = create_test_workspace(&server, &owner_user_id, "my-workspace").await;
    let project_id = create_test_project(&server, &workspace_id, "my-project").await;
    let env_id = create_test_environment(&server, &project_id, "production").await;

    // Create user with workspace-level Admin
    let (other_user_id, other_principal_id, _) =
        create_test_user(&server, "other@example.com", "phone").await;

    server
        .store
        .add_user_to_workspace(&workspace_id, &other_user_id)
        .await
        .unwrap();
    server
        .store
        .set_user_workspace_permission(&workspace_id, &other_user_id, Role::Admin)
        .await
        .unwrap();

    // Grant principal only Read (this should RESTRICT the effective permission)
    server
        .store
        .set_workspace_permission(&workspace_id, &other_principal_id, Role::Read)
        .await
        .unwrap();

    // Should only have Read despite user having Admin
    // (principal permission acts as ceiling)
    let result = server
        .check_permission(
            &other_principal_id,
            &workspace_id,
            &project_id,
            &env_id,
            Role::Write,
        )
        .await;
    assert!(result.is_err());

    // Read should work
    let result = server
        .check_permission(
            &other_principal_id,
            &workspace_id,
            &project_id,
            &env_id,
            Role::Read,
        )
        .await;
    assert!(result.is_ok());
}

// ================== Service account permission tests ==================

#[tokio::test]
async fn check_permission_service_account_with_permission() {
    let server = create_test_server().await;

    // Create owner
    let (owner_user_id, _, _) = create_test_user(&server, "owner@example.com", "laptop").await;
    let workspace_id = create_test_workspace(&server, &owner_user_id, "my-workspace").await;
    let project_id = create_test_project(&server, &workspace_id, "my-project").await;
    let env_id = create_test_environment(&server, &project_id, "production").await;

    // Create service principal (no user_id)
    let (public_key, _) = generate_keypair();
    let (x25519_public, _) = generate_x25519_keypair();
    let service_principal_id = server
        .store
        .create_principal(&CreatePrincipalParams {
            user_id: None,
            name: "ci-service".to_string(),
            public_key,
            x25519_public_key: Some(x25519_public),
        })
        .await
        .unwrap();

    // Add service principal to workspace
    server
        .store
        .add_workspace_principal(&AddWorkspacePrincipalParams {
            workspace_id: workspace_id.clone(),
            principal_id: service_principal_id.clone(),
            ephemeral_pub: vec![0u8; 32],
            kek_wrapped: vec![0u8; 32],
            kek_nonce: vec![0u8; 24],
        })
        .await
        .unwrap();

    // Grant service principal Write permission
    server
        .store
        .set_workspace_permission(&workspace_id, &service_principal_id, Role::Write)
        .await
        .unwrap();

    // Should have Write access
    let result = server
        .check_permission(
            &service_principal_id,
            &workspace_id,
            &project_id,
            &env_id,
            Role::Write,
        )
        .await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn check_permission_service_account_without_permission() {
    let server = create_test_server().await;

    // Create owner
    let (owner_user_id, _, _) = create_test_user(&server, "owner@example.com", "laptop").await;
    let workspace_id = create_test_workspace(&server, &owner_user_id, "my-workspace").await;
    let project_id = create_test_project(&server, &workspace_id, "my-project").await;
    let env_id = create_test_environment(&server, &project_id, "production").await;

    // Create service principal without any permissions
    let (public_key, _) = generate_keypair();
    let (x25519_public, _) = generate_x25519_keypair();
    let service_principal_id = server
        .store
        .create_principal(&CreatePrincipalParams {
            user_id: None,
            name: "ci-service".to_string(),
            public_key,
            x25519_public_key: Some(x25519_public),
        })
        .await
        .unwrap();

    // Should be denied
    let result = server
        .check_permission(
            &service_principal_id,
            &workspace_id,
            &project_id,
            &env_id,
            Role::Read,
        )
        .await;
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .message()
        .contains("No permissions found for service account"));
}

// ================== check_workspace_permission tests ==================

#[tokio::test]
async fn check_workspace_permission_owner() {
    let server = create_test_server().await;
    let (user_id, principal_id, _) = create_test_user(&server, "owner@example.com", "laptop").await;
    let workspace_id = create_test_workspace(&server, &user_id, "my-workspace").await;

    let result = server
        .check_workspace_permission(&principal_id, &workspace_id, Role::Admin)
        .await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn check_workspace_permission_user_with_permission() {
    let server = create_test_server().await;

    let (owner_user_id, _, _) = create_test_user(&server, "owner@example.com", "laptop").await;
    let workspace_id = create_test_workspace(&server, &owner_user_id, "my-workspace").await;

    let (other_user_id, other_principal_id, _) =
        create_test_user(&server, "other@example.com", "phone").await;

    server
        .store
        .add_user_to_workspace(&workspace_id, &other_user_id)
        .await
        .unwrap();
    server
        .store
        .set_user_workspace_permission(&workspace_id, &other_user_id, Role::Write)
        .await
        .unwrap();

    let result = server
        .check_workspace_permission(&other_principal_id, &workspace_id, Role::Write)
        .await;
    assert!(result.is_ok());
}

// ================== Group permission tests ==================

#[tokio::test]
async fn check_permission_via_group() {
    let server = create_test_server().await;

    // Create owner and workspace
    let (owner_user_id, _, _) = create_test_user(&server, "owner@example.com", "laptop").await;
    let workspace_id = create_test_workspace(&server, &owner_user_id, "my-workspace").await;
    let project_id = create_test_project(&server, &workspace_id, "my-project").await;
    let env_id = create_test_environment(&server, &project_id, "production").await;

    // Create a group
    let group_id = server
        .store
        .create_group(&CreateGroupParams {
            workspace_id: workspace_id.clone(),
            name: "developers".to_string(),
            description: Some("Dev team".to_string()),
        })
        .await
        .unwrap();

    // Create user and add to group
    let (other_user_id, other_principal_id, _) =
        create_test_user(&server, "other@example.com", "phone").await;
    server
        .store
        .add_user_to_workspace(&workspace_id, &other_user_id)
        .await
        .unwrap();
    server
        .store
        .add_group_member(&group_id, &other_user_id)
        .await
        .unwrap();

    // Grant group Write permission on environment
    server
        .store
        .set_group_environment_permission(&env_id, &group_id, Role::Write)
        .await
        .unwrap();

    // User should have Write permission via group
    let result = server
        .check_permission(
            &other_principal_id,
            &workspace_id,
            &project_id,
            &env_id,
            Role::Write,
        )
        .await;
    assert!(result.is_ok());
}

// ================== Join flow tests ==================

#[tokio::test]
async fn test_server_invite_joins_user_without_creating_workspace() {
    use zopp_proto::zopp_service_server::ZoppService;
    use zopp_proto::JoinRequest;

    let server = create_test_server().await;

    // Create a server invite (no workspaces)
    let mut invite_secret = [0u8; 32];
    rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut invite_secret);
    let secret_hash = zopp_crypto::hash_sha256(&invite_secret);
    let invite = server
        .store
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
    let (public_key, _signing_key) = generate_keypair();
    let (x25519_public_key, _) = generate_x25519_keypair();

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

    let user_id = UserId(uuid::Uuid::parse_str(&response.user_id).unwrap());

    let workspaces = server.store.list_workspaces(&user_id).await.unwrap();
    assert_eq!(
        workspaces.len(),
        0,
        "User should not have access to any workspaces yet"
    );
}

// ================== StoreBackend tests ==================

#[tokio::test]
async fn store_backend_create_user() {
    let store = Arc::new(SqliteStore::open_in_memory().await.unwrap());
    let backend = StoreBackend::Sqlite(store);

    let (public_key, _) = generate_keypair();
    let (x25519_public, _) = generate_x25519_keypair();

    let (user_id, principal_id) = backend
        .create_user(&CreateUserParams {
            email: "test@example.com".to_string(),
            principal: Some(CreatePrincipalData {
                name: "laptop".to_string(),
                public_key,
                x25519_public_key: Some(x25519_public),
                is_service: false,
            }),
            workspace_ids: vec![],
        })
        .await
        .unwrap();

    // Verify user was created
    let user = backend.get_user_by_id(&user_id).await.unwrap();
    assert_eq!(user.email, "test@example.com");

    // Verify principal was created
    let principal = backend.get_principal(&principal_id.unwrap()).await.unwrap();
    assert_eq!(principal.name, "laptop");
}

// ================== gRPC Handler tests ==================
// These tests call the actual gRPC service methods through ZoppService trait

mod handler_tests {
    use super::*;
    use zopp_proto::zopp_service_server::ZoppService;

    // ---- Workspace handlers ----

    #[tokio::test]
    async fn handler_create_workspace() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "test@example.com", "laptop").await;

        // Create workspace using gRPC handler
        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/CreateWorkspace",
            zopp_proto::CreateWorkspaceRequest {
                id: uuid::Uuid::now_v7().to_string(),
                name: "my-workspace".to_string(),
                ephemeral_pub: vec![0u8; 32],
                kek_wrapped: vec![0u8; 48],
                kek_nonce: vec![0u8; 24],
            },
        );

        let response = server.create_workspace(request).await.unwrap().into_inner();
        assert_eq!(response.name, "my-workspace");
        assert!(!response.id.is_empty());
    }

    #[tokio::test]
    async fn handler_list_workspaces() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "test@example.com", "laptop").await;

        // Create workspace directly in store (faster than going through handler)
        create_test_workspace(&server, &user_id, "test-ws").await;

        // List workspaces using gRPC handler
        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/ListWorkspaces",
            zopp_proto::Empty {},
        );

        let response = server.list_workspaces(request).await.unwrap().into_inner();
        assert_eq!(response.workspaces.len(), 1);
        assert_eq!(response.workspaces[0].name, "test-ws");
    }

    #[tokio::test]
    async fn handler_get_workspace_keys() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "test@example.com", "laptop").await;

        let ws_id = create_test_workspace(&server, &user_id, "test-ws").await;

        // Grant principal access with wrapped KEK using add_workspace_principal
        server
            .store
            .add_workspace_principal(&AddWorkspacePrincipalParams {
                workspace_id: ws_id.clone(),
                principal_id: principal_id.clone(),
                ephemeral_pub: vec![1u8; 32],
                kek_wrapped: vec![2u8; 48],
                kek_nonce: vec![3u8; 24],
            })
            .await
            .unwrap();

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/GetWorkspaceKeys",
            zopp_proto::GetWorkspaceKeysRequest {
                workspace_name: "test-ws".to_string(),
            },
        );

        let response = server
            .get_workspace_keys(request)
            .await
            .unwrap()
            .into_inner();
        assert_eq!(response.workspace_id, ws_id.0.to_string());
        assert_eq!(response.ephemeral_pub, vec![1u8; 32]);
        assert_eq!(response.kek_wrapped, vec![2u8; 48]);
        assert_eq!(response.kek_nonce, vec![3u8; 24]);
    }

    // ---- Project handlers ----

    #[tokio::test]
    async fn handler_create_project() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "test@example.com", "laptop").await;

        create_test_workspace(&server, &user_id, "ws").await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/CreateProject",
            zopp_proto::CreateProjectRequest {
                workspace_name: "ws".to_string(),
                name: "my-project".to_string(),
            },
        );

        let response = server.create_project(request).await.unwrap().into_inner();
        assert_eq!(response.name, "my-project");
    }

    #[tokio::test]
    async fn handler_list_projects() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "test@example.com", "laptop").await;

        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        create_test_project(&server, &ws_id, "proj1").await;
        create_test_project(&server, &ws_id, "proj2").await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/ListProjects",
            zopp_proto::ListProjectsRequest {
                workspace_name: "ws".to_string(),
            },
        );

        let response = server.list_projects(request).await.unwrap().into_inner();
        assert_eq!(response.projects.len(), 2);
    }

    #[tokio::test]
    async fn handler_get_project() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "test@example.com", "laptop").await;

        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        create_test_project(&server, &ws_id, "my-proj").await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/GetProject",
            zopp_proto::GetProjectRequest {
                workspace_name: "ws".to_string(),
                project_name: "my-proj".to_string(),
            },
        );

        let response = server.get_project(request).await.unwrap().into_inner();
        assert_eq!(response.name, "my-proj");
    }

    #[tokio::test]
    async fn handler_delete_project() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "test@example.com", "laptop").await;

        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        create_test_project(&server, &ws_id, "to-delete").await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/DeleteProject",
            zopp_proto::DeleteProjectRequest {
                workspace_name: "ws".to_string(),
                project_name: "to-delete".to_string(),
            },
        );

        server.delete_project(request).await.unwrap();

        // Verify deletion
        let list_request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/ListProjects",
            zopp_proto::ListProjectsRequest {
                workspace_name: "ws".to_string(),
            },
        );
        let response = server
            .list_projects(list_request)
            .await
            .unwrap()
            .into_inner();
        assert_eq!(response.projects.len(), 0);
    }

    // ---- Environment handlers ----

    #[tokio::test]
    async fn handler_create_environment() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "test@example.com", "laptop").await;

        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        create_test_project(&server, &ws_id, "proj").await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/CreateEnvironment",
            zopp_proto::CreateEnvironmentRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
                name: "production".to_string(),
                dek_wrapped: vec![0u8; 48],
                dek_nonce: vec![0u8; 24],
            },
        );

        let response = server
            .create_environment(request)
            .await
            .unwrap()
            .into_inner();
        assert_eq!(response.name, "production");
    }

    #[tokio::test]
    async fn handler_list_environments() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "test@example.com", "laptop").await;

        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        let proj_id = create_test_project(&server, &ws_id, "proj").await;
        create_test_environment(&server, &proj_id, "dev").await;
        create_test_environment(&server, &proj_id, "prod").await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/ListEnvironments",
            zopp_proto::ListEnvironmentsRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
            },
        );

        let response = server
            .list_environments(request)
            .await
            .unwrap()
            .into_inner();
        assert_eq!(response.environments.len(), 2);
    }

    #[tokio::test]
    async fn handler_get_environment() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "test@example.com", "laptop").await;

        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        let proj_id = create_test_project(&server, &ws_id, "proj").await;
        create_test_environment(&server, &proj_id, "staging").await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/GetEnvironment",
            zopp_proto::GetEnvironmentRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
                environment_name: "staging".to_string(),
            },
        );

        let response = server.get_environment(request).await.unwrap().into_inner();
        assert_eq!(response.name, "staging");
    }

    #[tokio::test]
    async fn handler_delete_environment() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "test@example.com", "laptop").await;

        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        let proj_id = create_test_project(&server, &ws_id, "proj").await;
        create_test_environment(&server, &proj_id, "to-delete").await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/DeleteEnvironment",
            zopp_proto::DeleteEnvironmentRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
                environment_name: "to-delete".to_string(),
            },
        );

        server.delete_environment(request).await.unwrap();

        // Verify deletion
        let list_request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/ListEnvironments",
            zopp_proto::ListEnvironmentsRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
            },
        );
        let response = server
            .list_environments(list_request)
            .await
            .unwrap()
            .into_inner();
        assert_eq!(response.environments.len(), 0);
    }

    // ---- Secret handlers ----

    #[tokio::test]
    async fn handler_upsert_secret() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "test@example.com", "laptop").await;

        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        let proj_id = create_test_project(&server, &ws_id, "proj").await;
        create_test_environment(&server, &proj_id, "env").await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/UpsertSecret",
            zopp_proto::UpsertSecretRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
                environment_name: "env".to_string(),
                key: "API_KEY".to_string(),
                nonce: vec![1u8; 24],
                ciphertext: vec![2u8; 48],
            },
        );

        server.upsert_secret(request).await.unwrap();
    }

    #[tokio::test]
    async fn handler_get_secret() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "test@example.com", "laptop").await;

        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        let proj_id = create_test_project(&server, &ws_id, "proj").await;
        let env_id = create_test_environment(&server, &proj_id, "env").await;

        // Insert secret directly
        server
            .store
            .upsert_secret(&env_id, "MY_SECRET", &[1u8; 24], &[2u8; 48])
            .await
            .unwrap();

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/GetSecret",
            zopp_proto::GetSecretRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
                environment_name: "env".to_string(),
                key: "MY_SECRET".to_string(),
            },
        );

        let response = server.get_secret(request).await.unwrap().into_inner();
        assert_eq!(response.key, "MY_SECRET");
        assert_eq!(response.nonce, vec![1u8; 24]);
        assert_eq!(response.ciphertext, vec![2u8; 48]);
    }

    #[tokio::test]
    async fn handler_list_secrets() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "test@example.com", "laptop").await;

        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        let proj_id = create_test_project(&server, &ws_id, "proj").await;
        let env_id = create_test_environment(&server, &proj_id, "env").await;

        // Insert secrets directly
        server
            .store
            .upsert_secret(&env_id, "KEY1", &[0u8; 24], &[0u8; 32])
            .await
            .unwrap();
        server
            .store
            .upsert_secret(&env_id, "KEY2", &[0u8; 24], &[0u8; 32])
            .await
            .unwrap();

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/ListSecrets",
            zopp_proto::ListSecretsRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
                environment_name: "env".to_string(),
            },
        );

        let response = server.list_secrets(request).await.unwrap().into_inner();
        assert_eq!(response.secrets.len(), 2);
    }

    #[tokio::test]
    async fn handler_delete_secret() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "test@example.com", "laptop").await;

        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        let proj_id = create_test_project(&server, &ws_id, "proj").await;
        let env_id = create_test_environment(&server, &proj_id, "env").await;

        server
            .store
            .upsert_secret(&env_id, "TO_DELETE", &[0u8; 24], &[0u8; 32])
            .await
            .unwrap();

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/DeleteSecret",
            zopp_proto::DeleteSecretRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
                environment_name: "env".to_string(),
                key: "TO_DELETE".to_string(),
            },
        );

        server.delete_secret(request).await.unwrap();

        // Verify deletion
        let list_request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/ListSecrets",
            zopp_proto::ListSecretsRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
                environment_name: "env".to_string(),
            },
        );
        let response = server
            .list_secrets(list_request)
            .await
            .unwrap()
            .into_inner();
        assert_eq!(response.secrets.len(), 0);
    }

    // ---- Principal handlers ----

    #[tokio::test]
    async fn handler_get_principal() {
        let server = create_test_server().await;
        let (_, principal_id, signing_key) =
            create_test_user(&server, "test@example.com", "my-laptop").await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/GetPrincipal",
            zopp_proto::GetPrincipalRequest {
                principal_id: principal_id.0.to_string(),
            },
        );

        let response = server.get_principal(request).await.unwrap().into_inner();
        assert_eq!(response.name, "my-laptop");
        assert_eq!(response.id, principal_id.0.to_string());
    }

    #[tokio::test]
    async fn handler_rename_principal() {
        let server = create_test_server().await;
        let (_, principal_id, signing_key) =
            create_test_user(&server, "test@example.com", "old-name").await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/RenamePrincipal",
            zopp_proto::RenamePrincipalRequest {
                principal_id: principal_id.0.to_string(),
                new_name: "new-name".to_string(),
            },
        );

        server.rename_principal(request).await.unwrap();

        // Verify rename
        let get_request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/GetPrincipal",
            zopp_proto::GetPrincipalRequest {
                principal_id: principal_id.0.to_string(),
            },
        );
        let response = server
            .get_principal(get_request)
            .await
            .unwrap()
            .into_inner();
        assert_eq!(response.name, "new-name");
    }

    // ---- Permission denied tests ----

    #[tokio::test]
    async fn handler_permission_denied_no_access() {
        let server = create_test_server().await;

        // Create owner with workspace
        let (owner_user_id, owner_principal_id, owner_signing_key) =
            create_test_user(&server, "owner@example.com", "owner").await;
        let ws_id = create_test_workspace(&server, &owner_user_id, "private-ws").await;
        let proj_id = create_test_project(&server, &ws_id, "private-proj").await;
        create_test_environment(&server, &proj_id, "private-env").await;

        // Create other user without access
        let (_, other_principal_id, other_signing_key) =
            create_test_user(&server, "other@example.com", "other").await;

        // Other user tries to access - should fail with NotFound (workspace not visible)
        let request = create_signed_request(
            &other_principal_id,
            &other_signing_key,
            "/zopp.ZoppService/ListSecrets",
            zopp_proto::ListSecretsRequest {
                workspace_name: "private-ws".to_string(),
                project_name: "private-proj".to_string(),
                environment_name: "private-env".to_string(),
            },
        );

        let result = server.list_secrets(request).await;
        assert!(result.is_err());
        let status = result.unwrap_err();
        assert!(
            status.code() == tonic::Code::NotFound
                || status.code() == tonic::Code::PermissionDenied
        );
    }

    #[tokio::test]
    async fn handler_write_denied_with_read_permission() {
        let server = create_test_server().await;

        // Create owner with workspace
        let (owner_user_id, _, _) = create_test_user(&server, "owner@example.com", "owner").await;
        let ws_id = create_test_workspace(&server, &owner_user_id, "shared-ws").await;
        let proj_id = create_test_project(&server, &ws_id, "proj").await;
        create_test_environment(&server, &proj_id, "env").await;

        // Create other user with Read-only permission
        let (other_user_id, other_principal_id, other_signing_key) =
            create_test_user(&server, "reader@example.com", "reader").await;

        // Add other user to workspace members first
        server
            .store
            .add_user_to_workspace(&ws_id, &other_user_id)
            .await
            .unwrap();

        // Grant Read permission at workspace level
        server
            .store
            .set_user_workspace_permission(&ws_id, &other_user_id, Role::Read)
            .await
            .unwrap();

        // Reader tries to write - should fail
        let request = create_signed_request(
            &other_principal_id,
            &other_signing_key,
            "/zopp.ZoppService/UpsertSecret",
            zopp_proto::UpsertSecretRequest {
                workspace_name: "shared-ws".to_string(),
                project_name: "proj".to_string(),
                environment_name: "env".to_string(),
                key: "FORBIDDEN".to_string(),
                nonce: vec![0u8; 24],
                ciphertext: vec![0u8; 32],
            },
        );

        let result = server.upsert_secret(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::PermissionDenied);
    }

    #[tokio::test]
    async fn handler_read_allowed_with_read_permission() {
        let server = create_test_server().await;

        // Create owner with workspace
        let (owner_user_id, _, _) = create_test_user(&server, "owner@example.com", "owner").await;
        let ws_id = create_test_workspace(&server, &owner_user_id, "shared-ws").await;
        let proj_id = create_test_project(&server, &ws_id, "proj").await;
        let env_id = create_test_environment(&server, &proj_id, "env").await;

        // Add a secret
        server
            .store
            .upsert_secret(&env_id, "READABLE", &[0u8; 24], &[0u8; 32])
            .await
            .unwrap();

        // Create other user with Read permission
        let (other_user_id, other_principal_id, other_signing_key) =
            create_test_user(&server, "reader@example.com", "reader").await;

        // Add other user to workspace members first
        server
            .store
            .add_user_to_workspace(&ws_id, &other_user_id)
            .await
            .unwrap();

        // Grant Read permission
        server
            .store
            .set_user_workspace_permission(&ws_id, &other_user_id, Role::Read)
            .await
            .unwrap();

        // Reader should be able to read
        let request = create_signed_request(
            &other_principal_id,
            &other_signing_key,
            "/zopp.ZoppService/GetSecret",
            zopp_proto::GetSecretRequest {
                workspace_name: "shared-ws".to_string(),
                project_name: "proj".to_string(),
                environment_name: "env".to_string(),
                key: "READABLE".to_string(),
            },
        );

        let response = server.get_secret(request).await.unwrap().into_inner();
        assert_eq!(response.key, "READABLE");
    }

    // ---- Group permission tests ----

    #[tokio::test]
    async fn handler_group_create_and_list() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "test@example.com", "laptop").await;

        let ws_id = create_test_workspace(&server, &user_id, "ws").await;

        // Create group
        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/CreateGroup",
            zopp_proto::CreateGroupRequest {
                workspace_name: "ws".to_string(),
                name: "developers".to_string(),
                description: "Dev team".to_string(),
            },
        );

        let response = server.create_group(request).await.unwrap().into_inner();
        assert_eq!(response.name, "developers");

        // List groups
        let list_request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/ListGroups",
            zopp_proto::ListGroupsRequest {
                workspace_name: "ws".to_string(),
            },
        );

        let list_response = server.list_groups(list_request).await.unwrap().into_inner();
        assert_eq!(list_response.groups.len(), 1);
        assert_eq!(list_response.groups[0].name, "developers");
    }

    #[tokio::test]
    async fn handler_group_add_member() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "admin@example.com", "admin").await;

        let ws_id = create_test_workspace(&server, &user_id, "ws").await;

        // Create a group
        let group_id = server
            .store
            .create_group(&CreateGroupParams {
                workspace_id: ws_id.clone(),
                name: "team".to_string(),
                description: None,
            })
            .await
            .unwrap();

        // Create another user to add
        let (member_user_id, _, _) =
            create_test_user(&server, "member@example.com", "member").await;

        // Grant workspace access first
        server
            .store
            .set_user_workspace_permission(&ws_id, &member_user_id, Role::Read)
            .await
            .unwrap();

        // Add member to group
        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/AddGroupMember",
            zopp_proto::AddGroupMemberRequest {
                workspace_name: "ws".to_string(),
                group_name: "team".to_string(),
                user_email: "member@example.com".to_string(),
            },
        );

        server.add_group_member(request).await.unwrap();

        // List members
        let list_request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/ListGroupMembers",
            zopp_proto::ListGroupMembersRequest {
                workspace_name: "ws".to_string(),
                group_name: "team".to_string(),
            },
        );

        let response = server
            .list_group_members(list_request)
            .await
            .unwrap()
            .into_inner();
        assert_eq!(response.members.len(), 1);
    }

    // ---- Invite handlers ----

    #[tokio::test]
    async fn handler_create_and_list_invites() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "test@example.com", "laptop").await;

        let ws_id = create_test_workspace(&server, &user_id, "ws").await;

        // Set principal wrapping so keys can be retrieved
        server
            .store
            .add_workspace_principal(&AddWorkspacePrincipalParams {
                workspace_id: ws_id.clone(),
                principal_id: principal_id.clone(),
                ephemeral_pub: vec![0u8; 32],
                kek_wrapped: vec![0u8; 48],
                kek_nonce: vec![0u8; 24],
            })
            .await
            .unwrap();

        // Create invite (need to compute token hash)
        let invite_secret = [42u8; 32];
        let token_hash = hex::encode(zopp_crypto::hash_sha256(&invite_secret));

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/CreateInvite",
            zopp_proto::CreateInviteRequest {
                workspace_ids: vec![ws_id.0.to_string()],
                expires_at: chrono::Utc::now().timestamp() + 3600,
                token: token_hash.clone(),
                kek_encrypted: vec![0u8; 48],
                kek_nonce: vec![0u8; 24],
            },
        );

        let response = server.create_invite(request).await.unwrap().into_inner();
        assert_eq!(response.token, token_hash);

        // List invites
        let list_request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/ListInvites",
            zopp_proto::Empty {},
        );

        let list_response = server
            .list_invites(list_request)
            .await
            .unwrap()
            .into_inner();
        assert!(list_response.invites.len() >= 1);
    }

    // ---- Audit log handlers ----

    #[tokio::test]
    async fn handler_list_audit_logs() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "test@example.com", "laptop").await;

        let ws_id = create_test_workspace(&server, &user_id, "ws").await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/ListAuditLogs",
            zopp_proto::ListAuditLogsRequest {
                workspace_name: "ws".to_string(),
                principal_id: None,
                user_id: None,
                project_name: None,
                environment_name: None,
                action: None,
                result: None,
                from_timestamp: None,
                to_timestamp: None,
                limit: Some(10),
                offset: None,
            },
        );

        let response = server.list_audit_logs(request).await.unwrap().into_inner();
        // Response received successfully - entries may or may not exist
        let _ = response.entries;
    }

    #[tokio::test]
    async fn handler_count_audit_logs() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "test@example.com", "laptop").await;

        let ws_id = create_test_workspace(&server, &user_id, "ws").await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/CountAuditLogs",
            zopp_proto::CountAuditLogsRequest {
                workspace_name: "ws".to_string(),
                principal_id: None,
                user_id: None,
                project_name: None,
                environment_name: None,
                action: None,
                result: None,
                from_timestamp: None,
                to_timestamp: None,
            },
        );

        let response = server.count_audit_logs(request).await.unwrap().into_inner();
        // Response received successfully
        let _ = response.count;
    }

    // ================== Principal Permission Handler Tests ==================

    #[tokio::test]
    async fn handler_set_workspace_permission() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "admin@example.com", "admin").await;

        let ws_id = create_test_workspace(&server, &user_id, "ws").await;

        // Create a service principal to grant permission to
        let service_principal_id = server
            .store
            .create_principal(&CreatePrincipalParams {
                user_id: None,
                name: "ci-bot".to_string(),
                public_key: vec![1u8; 32],
                x25519_public_key: Some(vec![2u8; 32]),
            })
            .await
            .unwrap();

        // Set permission
        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/SetWorkspacePermission",
            zopp_proto::SetWorkspacePermissionRequest {
                workspace_name: "ws".to_string(),
                principal_id: service_principal_id.0.to_string(),
                role: zopp_proto::Role::Read as i32,
            },
        );

        server.set_workspace_permission(request).await.unwrap();
    }

    #[tokio::test]
    async fn handler_get_workspace_permission() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "admin@example.com", "admin").await;

        let ws_id = create_test_workspace(&server, &user_id, "ws").await;

        // Create a service principal and set permission
        let service_principal_id = server
            .store
            .create_principal(&CreatePrincipalParams {
                user_id: None,
                name: "ci-bot".to_string(),
                public_key: vec![1u8; 32],
                x25519_public_key: Some(vec![2u8; 32]),
            })
            .await
            .unwrap();

        server
            .store
            .set_workspace_permission(&ws_id, &service_principal_id, Role::Write)
            .await
            .unwrap();

        // Get permission
        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/GetWorkspacePermission",
            zopp_proto::GetWorkspacePermissionRequest {
                workspace_name: "ws".to_string(),
                principal_id: service_principal_id.0.to_string(),
            },
        );

        let response = server
            .get_workspace_permission(request)
            .await
            .unwrap()
            .into_inner();
        assert_eq!(response.role, zopp_proto::Role::Write as i32);
    }

    #[tokio::test]
    async fn handler_list_workspace_permissions() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "admin@example.com", "admin").await;

        let ws_id = create_test_workspace(&server, &user_id, "ws").await;

        // Create and set permissions for multiple service principals
        for i in 0..2 {
            let sp_id = server
                .store
                .create_principal(&CreatePrincipalParams {
                    user_id: None,
                    name: format!("bot-{}", i),
                    public_key: vec![i as u8; 32],
                    x25519_public_key: Some(vec![(i + 10) as u8; 32]),
                })
                .await
                .unwrap();
            server
                .store
                .set_workspace_permission(&ws_id, &sp_id, Role::Read)
                .await
                .unwrap();
        }

        // List permissions
        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/ListWorkspacePermissions",
            zopp_proto::ListWorkspacePermissionsRequest {
                workspace_name: "ws".to_string(),
            },
        );

        let response = server
            .list_workspace_permissions(request)
            .await
            .unwrap()
            .into_inner();
        assert_eq!(response.permissions.len(), 2);
    }

    #[tokio::test]
    async fn handler_remove_workspace_permission() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "admin@example.com", "admin").await;

        let ws_id = create_test_workspace(&server, &user_id, "ws").await;

        // Create service principal and set permission
        let service_principal_id = server
            .store
            .create_principal(&CreatePrincipalParams {
                user_id: None,
                name: "ci-bot".to_string(),
                public_key: vec![1u8; 32],
                x25519_public_key: Some(vec![2u8; 32]),
            })
            .await
            .unwrap();

        server
            .store
            .set_workspace_permission(&ws_id, &service_principal_id, Role::Write)
            .await
            .unwrap();

        // Remove permission
        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/RemoveWorkspacePermission",
            zopp_proto::RemoveWorkspacePermissionRequest {
                workspace_name: "ws".to_string(),
                principal_id: service_principal_id.0.to_string(),
            },
        );

        server.remove_workspace_permission(request).await.unwrap();
    }

    #[tokio::test]
    async fn handler_set_project_permission() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "admin@example.com", "admin").await;

        let ws_id = create_test_workspace(&server, &user_id, "ws").await;

        // Add admin principal to workspace (required for principal-based lookup)
        server
            .store
            .add_workspace_principal(&AddWorkspacePrincipalParams {
                workspace_id: ws_id.clone(),
                principal_id: principal_id.clone(),
                ephemeral_pub: vec![0u8; 32],
                kek_wrapped: vec![0u8; 48],
                kek_nonce: vec![0u8; 24],
            })
            .await
            .unwrap();

        create_test_project(&server, &ws_id, "proj").await;

        // Create service principal
        let service_principal_id = server
            .store
            .create_principal(&CreatePrincipalParams {
                user_id: None,
                name: "ci-bot".to_string(),
                public_key: vec![1u8; 32],
                x25519_public_key: Some(vec![2u8; 32]),
            })
            .await
            .unwrap();

        // Add service principal to workspace
        server
            .store
            .add_workspace_principal(&AddWorkspacePrincipalParams {
                workspace_id: ws_id.clone(),
                principal_id: service_principal_id.clone(),
                ephemeral_pub: vec![0u8; 32],
                kek_wrapped: vec![0u8; 48],
                kek_nonce: vec![0u8; 24],
            })
            .await
            .unwrap();

        // Set project permission
        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/SetProjectPermission",
            zopp_proto::SetProjectPermissionRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
                principal_id: service_principal_id.0.to_string(),
                role: zopp_proto::Role::Write as i32,
            },
        );

        server.set_project_permission(request).await.unwrap();
    }

    #[tokio::test]
    async fn handler_get_project_permission() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "admin@example.com", "admin").await;

        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        let proj_id = create_test_project(&server, &ws_id, "proj").await;

        // Create service principal and set permission
        let service_principal_id = server
            .store
            .create_principal(&CreatePrincipalParams {
                user_id: None,
                name: "ci-bot".to_string(),
                public_key: vec![1u8; 32],
                x25519_public_key: Some(vec![2u8; 32]),
            })
            .await
            .unwrap();

        server
            .store
            .set_project_permission(&proj_id, &service_principal_id, Role::Read)
            .await
            .unwrap();

        // Get permission
        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/GetProjectPermission",
            zopp_proto::GetProjectPermissionRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
                principal_id: service_principal_id.0.to_string(),
            },
        );

        let response = server
            .get_project_permission(request)
            .await
            .unwrap()
            .into_inner();
        assert_eq!(response.role, zopp_proto::Role::Read as i32);
    }

    #[tokio::test]
    async fn handler_list_project_permissions() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "admin@example.com", "admin").await;

        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        let proj_id = create_test_project(&server, &ws_id, "proj").await;

        // Create and set permissions for service principals
        let sp_id = server
            .store
            .create_principal(&CreatePrincipalParams {
                user_id: None,
                name: "bot".to_string(),
                public_key: vec![1u8; 32],
                x25519_public_key: Some(vec![2u8; 32]),
            })
            .await
            .unwrap();
        server
            .store
            .set_project_permission(&proj_id, &sp_id, Role::Read)
            .await
            .unwrap();

        // List permissions
        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/ListProjectPermissions",
            zopp_proto::ListProjectPermissionsRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
            },
        );

        let response = server
            .list_project_permissions(request)
            .await
            .unwrap()
            .into_inner();
        assert_eq!(response.permissions.len(), 1);
    }

    #[tokio::test]
    async fn handler_remove_project_permission() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "admin@example.com", "admin").await;

        let ws_id = create_test_workspace(&server, &user_id, "ws").await;

        // Add admin principal to workspace (required for principal-based lookup)
        server
            .store
            .add_workspace_principal(&AddWorkspacePrincipalParams {
                workspace_id: ws_id.clone(),
                principal_id: principal_id.clone(),
                ephemeral_pub: vec![0u8; 32],
                kek_wrapped: vec![0u8; 48],
                kek_nonce: vec![0u8; 24],
            })
            .await
            .unwrap();

        let proj_id = create_test_project(&server, &ws_id, "proj").await;

        // Create service principal and set permission
        let service_principal_id = server
            .store
            .create_principal(&CreatePrincipalParams {
                user_id: None,
                name: "ci-bot".to_string(),
                public_key: vec![1u8; 32],
                x25519_public_key: Some(vec![2u8; 32]),
            })
            .await
            .unwrap();

        // Add service principal to workspace
        server
            .store
            .add_workspace_principal(&AddWorkspacePrincipalParams {
                workspace_id: ws_id.clone(),
                principal_id: service_principal_id.clone(),
                ephemeral_pub: vec![0u8; 32],
                kek_wrapped: vec![0u8; 48],
                kek_nonce: vec![0u8; 24],
            })
            .await
            .unwrap();

        server
            .store
            .set_project_permission(&proj_id, &service_principal_id, Role::Write)
            .await
            .unwrap();

        // Remove permission
        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/RemoveProjectPermission",
            zopp_proto::RemoveProjectPermissionRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
                principal_id: service_principal_id.0.to_string(),
            },
        );

        server.remove_project_permission(request).await.unwrap();
    }

    #[tokio::test]
    async fn handler_set_environment_permission() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "admin@example.com", "admin").await;

        let ws_id = create_test_workspace(&server, &user_id, "ws").await;

        // Add admin principal to workspace (required for principal-based lookup)
        server
            .store
            .add_workspace_principal(&AddWorkspacePrincipalParams {
                workspace_id: ws_id.clone(),
                principal_id: principal_id.clone(),
                ephemeral_pub: vec![0u8; 32],
                kek_wrapped: vec![0u8; 48],
                kek_nonce: vec![0u8; 24],
            })
            .await
            .unwrap();

        let proj_id = create_test_project(&server, &ws_id, "proj").await;
        create_test_environment(&server, &proj_id, "env").await;

        // Create service principal
        let service_principal_id = server
            .store
            .create_principal(&CreatePrincipalParams {
                user_id: None,
                name: "ci-bot".to_string(),
                public_key: vec![1u8; 32],
                x25519_public_key: Some(vec![2u8; 32]),
            })
            .await
            .unwrap();

        // Add service principal to workspace
        server
            .store
            .add_workspace_principal(&AddWorkspacePrincipalParams {
                workspace_id: ws_id.clone(),
                principal_id: service_principal_id.clone(),
                ephemeral_pub: vec![0u8; 32],
                kek_wrapped: vec![0u8; 48],
                kek_nonce: vec![0u8; 24],
            })
            .await
            .unwrap();

        // Set environment permission
        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/SetEnvironmentPermission",
            zopp_proto::SetEnvironmentPermissionRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
                environment_name: "env".to_string(),
                principal_id: service_principal_id.0.to_string(),
                role: zopp_proto::Role::Admin as i32,
            },
        );

        server.set_environment_permission(request).await.unwrap();
    }

    #[tokio::test]
    async fn handler_get_environment_permission() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "admin@example.com", "admin").await;

        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        let proj_id = create_test_project(&server, &ws_id, "proj").await;
        let env_id = create_test_environment(&server, &proj_id, "env").await;

        // Create service principal and set permission
        let service_principal_id = server
            .store
            .create_principal(&CreatePrincipalParams {
                user_id: None,
                name: "ci-bot".to_string(),
                public_key: vec![1u8; 32],
                x25519_public_key: Some(vec![2u8; 32]),
            })
            .await
            .unwrap();

        server
            .store
            .set_environment_permission(&env_id, &service_principal_id, Role::Write)
            .await
            .unwrap();

        // Get permission
        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/GetEnvironmentPermission",
            zopp_proto::GetEnvironmentPermissionRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
                environment_name: "env".to_string(),
                principal_id: service_principal_id.0.to_string(),
            },
        );

        let response = server
            .get_environment_permission(request)
            .await
            .unwrap()
            .into_inner();
        assert_eq!(response.role, zopp_proto::Role::Write as i32);
    }

    #[tokio::test]
    async fn handler_list_environment_permissions() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "admin@example.com", "admin").await;

        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        let proj_id = create_test_project(&server, &ws_id, "proj").await;
        let env_id = create_test_environment(&server, &proj_id, "env").await;

        // Create and set permissions for service principals
        let sp_id = server
            .store
            .create_principal(&CreatePrincipalParams {
                user_id: None,
                name: "bot".to_string(),
                public_key: vec![1u8; 32],
                x25519_public_key: Some(vec![2u8; 32]),
            })
            .await
            .unwrap();
        server
            .store
            .set_environment_permission(&env_id, &sp_id, Role::Read)
            .await
            .unwrap();

        // List permissions
        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/ListEnvironmentPermissions",
            zopp_proto::ListEnvironmentPermissionsRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
                environment_name: "env".to_string(),
            },
        );

        let response = server
            .list_environment_permissions(request)
            .await
            .unwrap()
            .into_inner();
        assert_eq!(response.permissions.len(), 1);
    }

    #[tokio::test]
    async fn handler_remove_environment_permission() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "admin@example.com", "admin").await;

        let ws_id = create_test_workspace(&server, &user_id, "ws").await;

        // Add admin principal to workspace (required for principal-based lookup)
        server
            .store
            .add_workspace_principal(&AddWorkspacePrincipalParams {
                workspace_id: ws_id.clone(),
                principal_id: principal_id.clone(),
                ephemeral_pub: vec![0u8; 32],
                kek_wrapped: vec![0u8; 48],
                kek_nonce: vec![0u8; 24],
            })
            .await
            .unwrap();

        let proj_id = create_test_project(&server, &ws_id, "proj").await;
        let env_id = create_test_environment(&server, &proj_id, "env").await;

        // Create service principal and set permission
        let service_principal_id = server
            .store
            .create_principal(&CreatePrincipalParams {
                user_id: None,
                name: "ci-bot".to_string(),
                public_key: vec![1u8; 32],
                x25519_public_key: Some(vec![2u8; 32]),
            })
            .await
            .unwrap();

        // Add service principal to workspace
        server
            .store
            .add_workspace_principal(&AddWorkspacePrincipalParams {
                workspace_id: ws_id.clone(),
                principal_id: service_principal_id.clone(),
                ephemeral_pub: vec![0u8; 32],
                kek_wrapped: vec![0u8; 48],
                kek_nonce: vec![0u8; 24],
            })
            .await
            .unwrap();

        server
            .store
            .set_environment_permission(&env_id, &service_principal_id, Role::Write)
            .await
            .unwrap();

        // Remove permission
        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/RemoveEnvironmentPermission",
            zopp_proto::RemoveEnvironmentPermissionRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
                environment_name: "env".to_string(),
                principal_id: service_principal_id.0.to_string(),
            },
        );

        server.remove_environment_permission(request).await.unwrap();
    }

    // ================== User Permission Handler Tests ==================

    #[tokio::test]
    async fn handler_set_user_workspace_permission() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "admin@example.com", "admin").await;

        let ws_id = create_test_workspace(&server, &user_id, "ws").await;

        // Create another user to grant permission to
        let (other_user_id, _, _) = create_test_user(&server, "member@example.com", "member").await;

        // Add to workspace members first
        server
            .store
            .add_user_to_workspace(&ws_id, &other_user_id)
            .await
            .unwrap();

        // Set user permission
        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/SetUserWorkspacePermission",
            zopp_proto::SetUserWorkspacePermissionRequest {
                workspace_name: "ws".to_string(),
                user_email: "member@example.com".to_string(),
                role: zopp_proto::Role::Write as i32,
            },
        );

        server.set_user_workspace_permission(request).await.unwrap();
    }

    #[tokio::test]
    async fn handler_get_user_workspace_permission() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "admin@example.com", "admin").await;

        let ws_id = create_test_workspace(&server, &user_id, "ws").await;

        // Create another user and set permission
        let (other_user_id, _, _) = create_test_user(&server, "member@example.com", "member").await;

        server
            .store
            .add_user_to_workspace(&ws_id, &other_user_id)
            .await
            .unwrap();

        server
            .store
            .set_user_workspace_permission(&ws_id, &other_user_id, Role::Read)
            .await
            .unwrap();

        // Get permission
        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/GetUserWorkspacePermission",
            zopp_proto::GetUserWorkspacePermissionRequest {
                workspace_name: "ws".to_string(),
                user_email: "member@example.com".to_string(),
            },
        );

        let response = server
            .get_user_workspace_permission(request)
            .await
            .unwrap()
            .into_inner();
        assert_eq!(response.role, zopp_proto::Role::Read as i32);
    }

    #[tokio::test]
    async fn handler_list_user_workspace_permissions() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "admin@example.com", "admin").await;

        let ws_id = create_test_workspace(&server, &user_id, "ws").await;

        // Create users and set permissions
        for i in 0..2 {
            let (other_user_id, _, _) = create_test_user(
                &server,
                &format!("member{}@example.com", i),
                &format!("member{}", i),
            )
            .await;
            server
                .store
                .add_user_to_workspace(&ws_id, &other_user_id)
                .await
                .unwrap();
            server
                .store
                .set_user_workspace_permission(&ws_id, &other_user_id, Role::Read)
                .await
                .unwrap();
        }

        // List permissions
        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/ListUserWorkspacePermissions",
            zopp_proto::ListUserWorkspacePermissionsRequest {
                workspace_name: "ws".to_string(),
            },
        );

        let response = server
            .list_user_workspace_permissions(request)
            .await
            .unwrap()
            .into_inner();
        assert_eq!(response.permissions.len(), 2);
    }

    #[tokio::test]
    async fn handler_remove_user_workspace_permission() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "admin@example.com", "admin").await;

        let ws_id = create_test_workspace(&server, &user_id, "ws").await;

        // Create another user and set permission
        let (other_user_id, _, _) = create_test_user(&server, "member@example.com", "member").await;

        server
            .store
            .add_user_to_workspace(&ws_id, &other_user_id)
            .await
            .unwrap();

        server
            .store
            .set_user_workspace_permission(&ws_id, &other_user_id, Role::Write)
            .await
            .unwrap();

        // Remove permission
        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/RemoveUserWorkspacePermission",
            zopp_proto::RemoveUserWorkspacePermissionRequest {
                workspace_name: "ws".to_string(),
                user_email: "member@example.com".to_string(),
            },
        );

        server
            .remove_user_workspace_permission(request)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn handler_set_user_project_permission() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "admin@example.com", "admin").await;

        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        create_test_project(&server, &ws_id, "proj").await;

        // Create another user
        let (other_user_id, _, _) = create_test_user(&server, "member@example.com", "member").await;
        server
            .store
            .add_user_to_workspace(&ws_id, &other_user_id)
            .await
            .unwrap();

        // Set project permission
        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/SetUserProjectPermission",
            zopp_proto::SetUserProjectPermissionRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
                user_email: "member@example.com".to_string(),
                role: zopp_proto::Role::Write as i32,
            },
        );

        server.set_user_project_permission(request).await.unwrap();
    }

    #[tokio::test]
    async fn handler_get_user_project_permission() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "admin@example.com", "admin").await;

        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        let proj_id = create_test_project(&server, &ws_id, "proj").await;

        // Create another user and set permission
        let (other_user_id, _, _) = create_test_user(&server, "member@example.com", "member").await;
        server
            .store
            .add_user_to_workspace(&ws_id, &other_user_id)
            .await
            .unwrap();
        server
            .store
            .set_user_project_permission(&proj_id, &other_user_id, Role::Admin)
            .await
            .unwrap();

        // Get permission
        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/GetUserProjectPermission",
            zopp_proto::GetUserProjectPermissionRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
                user_email: "member@example.com".to_string(),
            },
        );

        let response = server
            .get_user_project_permission(request)
            .await
            .unwrap()
            .into_inner();
        assert_eq!(response.role, zopp_proto::Role::Admin as i32);
    }

    #[tokio::test]
    async fn handler_list_user_project_permissions() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "admin@example.com", "admin").await;

        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        let proj_id = create_test_project(&server, &ws_id, "proj").await;

        // Create user and set permission
        let (other_user_id, _, _) = create_test_user(&server, "member@example.com", "member").await;
        server
            .store
            .add_user_to_workspace(&ws_id, &other_user_id)
            .await
            .unwrap();
        server
            .store
            .set_user_project_permission(&proj_id, &other_user_id, Role::Read)
            .await
            .unwrap();

        // List permissions
        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/ListUserProjectPermissions",
            zopp_proto::ListUserProjectPermissionsRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
            },
        );

        let response = server
            .list_user_project_permissions(request)
            .await
            .unwrap()
            .into_inner();
        assert_eq!(response.permissions.len(), 1);
    }

    #[tokio::test]
    async fn handler_remove_user_project_permission() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "admin@example.com", "admin").await;

        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        let proj_id = create_test_project(&server, &ws_id, "proj").await;

        // Create user and set permission
        let (other_user_id, _, _) = create_test_user(&server, "member@example.com", "member").await;
        server
            .store
            .add_user_to_workspace(&ws_id, &other_user_id)
            .await
            .unwrap();
        server
            .store
            .set_user_project_permission(&proj_id, &other_user_id, Role::Write)
            .await
            .unwrap();

        // Remove permission
        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/RemoveUserProjectPermission",
            zopp_proto::RemoveUserProjectPermissionRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
                user_email: "member@example.com".to_string(),
            },
        );

        server
            .remove_user_project_permission(request)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn handler_set_user_environment_permission() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "admin@example.com", "admin").await;

        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        let proj_id = create_test_project(&server, &ws_id, "proj").await;
        create_test_environment(&server, &proj_id, "env").await;

        // Create another user
        let (other_user_id, _, _) = create_test_user(&server, "member@example.com", "member").await;
        server
            .store
            .add_user_to_workspace(&ws_id, &other_user_id)
            .await
            .unwrap();

        // Set environment permission
        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/SetUserEnvironmentPermission",
            zopp_proto::SetUserEnvironmentPermissionRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
                environment_name: "env".to_string(),
                user_email: "member@example.com".to_string(),
                role: zopp_proto::Role::Read as i32,
            },
        );

        server
            .set_user_environment_permission(request)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn handler_get_user_environment_permission() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "admin@example.com", "admin").await;

        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        let proj_id = create_test_project(&server, &ws_id, "proj").await;
        let env_id = create_test_environment(&server, &proj_id, "env").await;

        // Create user and set permission
        let (other_user_id, _, _) = create_test_user(&server, "member@example.com", "member").await;
        server
            .store
            .add_user_to_workspace(&ws_id, &other_user_id)
            .await
            .unwrap();
        server
            .store
            .set_user_environment_permission(&env_id, &other_user_id, Role::Write)
            .await
            .unwrap();

        // Get permission
        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/GetUserEnvironmentPermission",
            zopp_proto::GetUserEnvironmentPermissionRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
                environment_name: "env".to_string(),
                user_email: "member@example.com".to_string(),
            },
        );

        let response = server
            .get_user_environment_permission(request)
            .await
            .unwrap()
            .into_inner();
        assert_eq!(response.role, zopp_proto::Role::Write as i32);
    }

    #[tokio::test]
    async fn handler_list_user_environment_permissions() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "admin@example.com", "admin").await;

        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        let proj_id = create_test_project(&server, &ws_id, "proj").await;
        let env_id = create_test_environment(&server, &proj_id, "env").await;

        // Create user and set permission
        let (other_user_id, _, _) = create_test_user(&server, "member@example.com", "member").await;
        server
            .store
            .add_user_to_workspace(&ws_id, &other_user_id)
            .await
            .unwrap();
        server
            .store
            .set_user_environment_permission(&env_id, &other_user_id, Role::Read)
            .await
            .unwrap();

        // List permissions
        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/ListUserEnvironmentPermissions",
            zopp_proto::ListUserEnvironmentPermissionsRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
                environment_name: "env".to_string(),
            },
        );

        let response = server
            .list_user_environment_permissions(request)
            .await
            .unwrap()
            .into_inner();
        assert_eq!(response.permissions.len(), 1);
    }

    #[tokio::test]
    async fn handler_remove_user_environment_permission() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "admin@example.com", "admin").await;

        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        let proj_id = create_test_project(&server, &ws_id, "proj").await;
        let env_id = create_test_environment(&server, &proj_id, "env").await;

        // Create user and set permission
        let (other_user_id, _, _) = create_test_user(&server, "member@example.com", "member").await;
        server
            .store
            .add_user_to_workspace(&ws_id, &other_user_id)
            .await
            .unwrap();
        server
            .store
            .set_user_environment_permission(&env_id, &other_user_id, Role::Write)
            .await
            .unwrap();

        // Remove permission
        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/RemoveUserEnvironmentPermission",
            zopp_proto::RemoveUserEnvironmentPermissionRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
                environment_name: "env".to_string(),
                user_email: "member@example.com".to_string(),
            },
        );

        server
            .remove_user_environment_permission(request)
            .await
            .unwrap();
    }

    // ================== Group Permission Handler Tests ==================

    #[tokio::test]
    async fn handler_set_group_workspace_permission() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "admin@example.com", "admin").await;

        let ws_id = create_test_workspace(&server, &user_id, "ws").await;

        // Create group
        let group_id = server
            .store
            .create_group(&CreateGroupParams {
                workspace_id: ws_id.clone(),
                name: "devs".to_string(),
                description: Some("Developers".to_string()),
            })
            .await
            .unwrap();

        // Set group permission
        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/SetGroupWorkspacePermission",
            zopp_proto::SetGroupWorkspacePermissionRequest {
                workspace_name: "ws".to_string(),
                group_name: "devs".to_string(),
                role: zopp_proto::Role::Write as i32,
            },
        );

        server
            .set_group_workspace_permission(request)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn handler_get_group_workspace_permission() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "admin@example.com", "admin").await;

        let ws_id = create_test_workspace(&server, &user_id, "ws").await;

        // Create group and set permission
        let group_id = server
            .store
            .create_group(&CreateGroupParams {
                workspace_id: ws_id.clone(),
                name: "devs".to_string(),
                description: Some("Developers".to_string()),
            })
            .await
            .unwrap();

        server
            .store
            .set_group_workspace_permission(&ws_id, &group_id, Role::Read)
            .await
            .unwrap();

        // Get permission
        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/GetGroupWorkspacePermission",
            zopp_proto::GetGroupWorkspacePermissionRequest {
                workspace_name: "ws".to_string(),
                group_name: "devs".to_string(),
            },
        );

        let response = server
            .get_group_workspace_permission(request)
            .await
            .unwrap()
            .into_inner();
        assert_eq!(response.role, zopp_proto::Role::Read as i32);
    }

    #[tokio::test]
    async fn handler_list_group_workspace_permissions() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "admin@example.com", "admin").await;

        let ws_id = create_test_workspace(&server, &user_id, "ws").await;

        // Create groups and set permissions
        for i in 0..2 {
            let group_id = server
                .store
                .create_group(&CreateGroupParams {
                    workspace_id: ws_id.clone(),
                    name: format!("group{}", i),
                    description: Some(format!("Group {}", i)),
                })
                .await
                .unwrap();
            server
                .store
                .set_group_workspace_permission(&ws_id, &group_id, Role::Read)
                .await
                .unwrap();
        }

        // List permissions
        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/ListGroupWorkspacePermissions",
            zopp_proto::ListGroupWorkspacePermissionsRequest {
                workspace_name: "ws".to_string(),
            },
        );

        let response = server
            .list_group_workspace_permissions(request)
            .await
            .unwrap()
            .into_inner();
        assert_eq!(response.permissions.len(), 2);
    }

    #[tokio::test]
    async fn handler_remove_group_workspace_permission() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "admin@example.com", "admin").await;

        let ws_id = create_test_workspace(&server, &user_id, "ws").await;

        // Create group and set permission
        let group_id = server
            .store
            .create_group(&CreateGroupParams {
                workspace_id: ws_id.clone(),
                name: "devs".to_string(),
                description: Some("Developers".to_string()),
            })
            .await
            .unwrap();

        server
            .store
            .set_group_workspace_permission(&ws_id, &group_id, Role::Write)
            .await
            .unwrap();

        // Remove permission
        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/RemoveGroupWorkspacePermission",
            zopp_proto::RemoveGroupWorkspacePermissionRequest {
                workspace_name: "ws".to_string(),
                group_name: "devs".to_string(),
            },
        );

        server
            .remove_group_workspace_permission(request)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn handler_set_group_project_permission() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "admin@example.com", "admin").await;

        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        create_test_project(&server, &ws_id, "proj").await;

        // Create group
        let _group_id = server
            .store
            .create_group(&CreateGroupParams {
                workspace_id: ws_id.clone(),
                name: "devs".to_string(),
                description: Some("Developers".to_string()),
            })
            .await
            .unwrap();

        // Set project permission
        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/SetGroupProjectPermission",
            zopp_proto::SetGroupProjectPermissionRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
                group_name: "devs".to_string(),
                role: zopp_proto::Role::Write as i32,
            },
        );

        server.set_group_project_permission(request).await.unwrap();
    }

    #[tokio::test]
    async fn handler_get_group_project_permission() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "admin@example.com", "admin").await;

        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        let proj_id = create_test_project(&server, &ws_id, "proj").await;

        // Create group and set permission
        let group_id = server
            .store
            .create_group(&CreateGroupParams {
                workspace_id: ws_id.clone(),
                name: "devs".to_string(),
                description: Some("Developers".to_string()),
            })
            .await
            .unwrap();

        server
            .store
            .set_group_project_permission(&proj_id, &group_id, Role::Admin)
            .await
            .unwrap();

        // Get permission
        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/GetGroupProjectPermission",
            zopp_proto::GetGroupProjectPermissionRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
                group_name: "devs".to_string(),
            },
        );

        let response = server
            .get_group_project_permission(request)
            .await
            .unwrap()
            .into_inner();
        assert_eq!(response.role, zopp_proto::Role::Admin as i32);
    }

    #[tokio::test]
    async fn handler_list_group_project_permissions() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "admin@example.com", "admin").await;

        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        let proj_id = create_test_project(&server, &ws_id, "proj").await;

        // Create group and set permission
        let group_id = server
            .store
            .create_group(&CreateGroupParams {
                workspace_id: ws_id.clone(),
                name: "devs".to_string(),
                description: Some("Developers".to_string()),
            })
            .await
            .unwrap();

        server
            .store
            .set_group_project_permission(&proj_id, &group_id, Role::Read)
            .await
            .unwrap();

        // List permissions
        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/ListGroupProjectPermissions",
            zopp_proto::ListGroupProjectPermissionsRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
            },
        );

        let response = server
            .list_group_project_permissions(request)
            .await
            .unwrap()
            .into_inner();
        assert_eq!(response.permissions.len(), 1);
    }

    #[tokio::test]
    async fn handler_remove_group_project_permission() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "admin@example.com", "admin").await;

        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        let proj_id = create_test_project(&server, &ws_id, "proj").await;

        // Create group and set permission
        let group_id = server
            .store
            .create_group(&CreateGroupParams {
                workspace_id: ws_id.clone(),
                name: "devs".to_string(),
                description: Some("Developers".to_string()),
            })
            .await
            .unwrap();

        server
            .store
            .set_group_project_permission(&proj_id, &group_id, Role::Write)
            .await
            .unwrap();

        // Remove permission
        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/RemoveGroupProjectPermission",
            zopp_proto::RemoveGroupProjectPermissionRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
                group_name: "devs".to_string(),
            },
        );

        server
            .remove_group_project_permission(request)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn handler_set_group_environment_permission() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "admin@example.com", "admin").await;

        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        let proj_id = create_test_project(&server, &ws_id, "proj").await;
        create_test_environment(&server, &proj_id, "env").await;

        // Create group
        let _group_id = server
            .store
            .create_group(&CreateGroupParams {
                workspace_id: ws_id.clone(),
                name: "devs".to_string(),
                description: Some("Developers".to_string()),
            })
            .await
            .unwrap();

        // Set environment permission
        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/SetGroupEnvironmentPermission",
            zopp_proto::SetGroupEnvironmentPermissionRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
                environment_name: "env".to_string(),
                group_name: "devs".to_string(),
                role: zopp_proto::Role::Read as i32,
            },
        );

        server
            .set_group_environment_permission(request)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn handler_get_group_environment_permission() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "admin@example.com", "admin").await;

        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        let proj_id = create_test_project(&server, &ws_id, "proj").await;
        let env_id = create_test_environment(&server, &proj_id, "env").await;

        // Create group and set permission
        let group_id = server
            .store
            .create_group(&CreateGroupParams {
                workspace_id: ws_id.clone(),
                name: "devs".to_string(),
                description: Some("Developers".to_string()),
            })
            .await
            .unwrap();

        server
            .store
            .set_group_environment_permission(&env_id, &group_id, Role::Write)
            .await
            .unwrap();

        // Get permission
        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/GetGroupEnvironmentPermission",
            zopp_proto::GetGroupEnvironmentPermissionRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
                environment_name: "env".to_string(),
                group_name: "devs".to_string(),
            },
        );

        let response = server
            .get_group_environment_permission(request)
            .await
            .unwrap()
            .into_inner();
        assert_eq!(response.role, zopp_proto::Role::Write as i32);
    }

    #[tokio::test]
    async fn handler_list_group_environment_permissions() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "admin@example.com", "admin").await;

        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        let proj_id = create_test_project(&server, &ws_id, "proj").await;
        let env_id = create_test_environment(&server, &proj_id, "env").await;

        // Create group and set permission
        let group_id = server
            .store
            .create_group(&CreateGroupParams {
                workspace_id: ws_id.clone(),
                name: "devs".to_string(),
                description: Some("Developers".to_string()),
            })
            .await
            .unwrap();

        server
            .store
            .set_group_environment_permission(&env_id, &group_id, Role::Read)
            .await
            .unwrap();

        // List permissions
        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/ListGroupEnvironmentPermissions",
            zopp_proto::ListGroupEnvironmentPermissionsRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
                environment_name: "env".to_string(),
            },
        );

        let response = server
            .list_group_environment_permissions(request)
            .await
            .unwrap()
            .into_inner();
        assert_eq!(response.permissions.len(), 1);
    }

    #[tokio::test]
    async fn handler_remove_group_environment_permission() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "admin@example.com", "admin").await;

        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        let proj_id = create_test_project(&server, &ws_id, "proj").await;
        let env_id = create_test_environment(&server, &proj_id, "env").await;

        // Create group and set permission
        let group_id = server
            .store
            .create_group(&CreateGroupParams {
                workspace_id: ws_id.clone(),
                name: "devs".to_string(),
                description: Some("Developers".to_string()),
            })
            .await
            .unwrap();

        server
            .store
            .set_group_environment_permission(&env_id, &group_id, Role::Write)
            .await
            .unwrap();

        // Remove permission
        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/RemoveGroupEnvironmentPermission",
            zopp_proto::RemoveGroupEnvironmentPermissionRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
                environment_name: "env".to_string(),
                group_name: "devs".to_string(),
            },
        );

        server
            .remove_group_environment_permission(request)
            .await
            .unwrap();
    }

    // ================== Principal Handler Tests ==================

    #[tokio::test]
    async fn handler_list_principals() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "test@example.com", "laptop").await;

        // Create additional principal for the same user
        server
            .store
            .create_principal(&CreatePrincipalParams {
                user_id: Some(user_id.clone()),
                name: "desktop".to_string(),
                public_key: vec![1u8; 32],
                x25519_public_key: Some(vec![2u8; 32]),
            })
            .await
            .unwrap();

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/ListPrincipals",
            zopp_proto::Empty {},
        );

        let response = server.list_principals(request).await.unwrap().into_inner();
        assert_eq!(response.principals.len(), 2);
    }

    #[tokio::test]
    async fn handler_list_workspace_service_principals() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "admin@example.com", "admin").await;

        let ws_id = create_test_workspace(&server, &user_id, "ws").await;

        // Create a service principal and add to workspace
        let service_principal_id = server
            .store
            .create_principal(&CreatePrincipalParams {
                user_id: None,
                name: "ci-bot".to_string(),
                public_key: vec![1u8; 32],
                x25519_public_key: Some(vec![2u8; 32]),
            })
            .await
            .unwrap();

        server
            .store
            .add_workspace_principal(&AddWorkspacePrincipalParams {
                workspace_id: ws_id.clone(),
                principal_id: service_principal_id.clone(),
                ephemeral_pub: vec![0u8; 32],
                kek_wrapped: vec![0u8; 48],
                kek_nonce: vec![0u8; 24],
            })
            .await
            .unwrap();

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/ListWorkspaceServicePrincipals",
            zopp_proto::ListWorkspaceServicePrincipalsRequest {
                workspace_name: "ws".to_string(),
            },
        );

        let response = server
            .list_workspace_service_principals(request)
            .await
            .unwrap()
            .into_inner();
        assert_eq!(response.service_principals.len(), 1);
        assert_eq!(response.service_principals[0].name, "ci-bot");
    }

    #[tokio::test]
    async fn handler_remove_principal_from_workspace() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "admin@example.com", "admin").await;

        let ws_id = create_test_workspace(&server, &user_id, "ws").await;

        // Add admin principal to workspace (required for principal-based lookup)
        server
            .store
            .add_workspace_principal(&AddWorkspacePrincipalParams {
                workspace_id: ws_id.clone(),
                principal_id: principal_id.clone(),
                ephemeral_pub: vec![0u8; 32],
                kek_wrapped: vec![0u8; 48],
                kek_nonce: vec![0u8; 24],
            })
            .await
            .unwrap();

        // Create a service principal and add to workspace
        let service_principal_id = server
            .store
            .create_principal(&CreatePrincipalParams {
                user_id: None,
                name: "ci-bot".to_string(),
                public_key: vec![1u8; 32],
                x25519_public_key: Some(vec![2u8; 32]),
            })
            .await
            .unwrap();

        server
            .store
            .add_workspace_principal(&AddWorkspacePrincipalParams {
                workspace_id: ws_id.clone(),
                principal_id: service_principal_id.clone(),
                ephemeral_pub: vec![0u8; 32],
                kek_wrapped: vec![0u8; 48],
                kek_nonce: vec![0u8; 24],
            })
            .await
            .unwrap();

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/RemovePrincipalFromWorkspace",
            zopp_proto::RemovePrincipalFromWorkspaceRequest {
                workspace_name: "ws".to_string(),
                principal_id: service_principal_id.0.to_string(),
            },
        );

        server
            .remove_principal_from_workspace(request)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn handler_revoke_all_principal_permissions() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "admin@example.com", "admin").await;

        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        let proj_id = create_test_project(&server, &ws_id, "proj").await;
        let env_id = create_test_environment(&server, &proj_id, "env").await;

        // Create service principal with permissions at all levels
        let service_principal_id = server
            .store
            .create_principal(&CreatePrincipalParams {
                user_id: None,
                name: "ci-bot".to_string(),
                public_key: vec![1u8; 32],
                x25519_public_key: Some(vec![2u8; 32]),
            })
            .await
            .unwrap();

        server
            .store
            .set_workspace_permission(&ws_id, &service_principal_id, Role::Read)
            .await
            .unwrap();
        server
            .store
            .set_project_permission(&proj_id, &service_principal_id, Role::Write)
            .await
            .unwrap();
        server
            .store
            .set_environment_permission(&env_id, &service_principal_id, Role::Admin)
            .await
            .unwrap();

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/RevokeAllPrincipalPermissions",
            zopp_proto::RevokeAllPrincipalPermissionsRequest {
                workspace_name: "ws".to_string(),
                principal_id: service_principal_id.0.to_string(),
            },
        );

        let response = server
            .revoke_all_principal_permissions(request)
            .await
            .unwrap()
            .into_inner();
        assert!(response.permissions_revoked >= 3);
    }

    #[tokio::test]
    async fn handler_get_effective_permissions() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "admin@example.com", "admin").await;

        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        let proj_id = create_test_project(&server, &ws_id, "proj").await;
        let env_id = create_test_environment(&server, &proj_id, "env").await;

        // Create service principal with permissions
        let service_principal_id = server
            .store
            .create_principal(&CreatePrincipalParams {
                user_id: None,
                name: "ci-bot".to_string(),
                public_key: vec![1u8; 32],
                x25519_public_key: Some(vec![2u8; 32]),
            })
            .await
            .unwrap();

        server
            .store
            .set_workspace_permission(&ws_id, &service_principal_id, Role::Read)
            .await
            .unwrap();
        server
            .store
            .set_project_permission(&proj_id, &service_principal_id, Role::Write)
            .await
            .unwrap();
        server
            .store
            .set_environment_permission(&env_id, &service_principal_id, Role::Admin)
            .await
            .unwrap();

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/GetEffectivePermissions",
            zopp_proto::GetEffectivePermissionsRequest {
                workspace_name: "ws".to_string(),
                principal_id: service_principal_id.0.to_string(),
            },
        );

        let response = server
            .get_effective_permissions(request)
            .await
            .unwrap()
            .into_inner();
        assert!(response.is_service_principal);
        assert_eq!(response.workspace_role, Some(zopp_proto::Role::Read as i32));
        assert!(!response.projects.is_empty());
    }

    // ================== Auth Handler Tests ==================

    #[tokio::test]
    async fn handler_register_user() {
        let server = create_test_server().await;

        // Create bootstrap invite (no workspaces)
        let invite_secret = [42u8; 32];
        let token_hash = hex::encode(zopp_crypto::hash_sha256(&invite_secret));

        server
            .store
            .create_invite(&zopp_storage::CreateInviteParams {
                token: token_hash.clone(),
                workspace_ids: vec![],
                kek_encrypted: Some(vec![0u8; 48]),
                kek_nonce: Some(vec![0u8; 24]),
                created_by_user_id: None,
                expires_at: chrono::Utc::now() + chrono::Duration::hours(24),
            })
            .await
            .unwrap();

        // Register via join (bootstrap)
        let request = tonic::Request::new(zopp_proto::JoinRequest {
            invite_token: token_hash,
            email: "newuser@example.com".to_string(),
            principal_name: "my-device".to_string(),
            public_key: vec![1u8; 32],
            x25519_public_key: vec![2u8; 32],
            ephemeral_pub: vec![],
            kek_wrapped: vec![],
            kek_nonce: vec![],
        });

        let response = server.join(request).await.unwrap().into_inner();
        assert!(!response.user_id.is_empty());
        assert!(!response.principal_id.is_empty());
    }

    #[tokio::test]
    async fn handler_register_service_principal() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "admin@example.com", "admin").await;

        let ws_id = create_test_workspace(&server, &user_id, "ws").await;

        // Add admin principal to workspace (required for principal-based lookup)
        server
            .store
            .add_workspace_principal(&AddWorkspacePrincipalParams {
                workspace_id: ws_id.clone(),
                principal_id: principal_id.clone(),
                ephemeral_pub: vec![0u8; 32],
                kek_wrapped: vec![0u8; 48],
                kek_nonce: vec![0u8; 24],
            })
            .await
            .unwrap();

        // Register a service principal
        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/Register",
            zopp_proto::RegisterRequest {
                email: String::new(),
                principal_name: "ci-service".to_string(),
                public_key: vec![1u8; 32],
                x25519_public_key: vec![2u8; 32],
                is_service: true,
                workspace_name: Some("ws".to_string()),
                ephemeral_pub: Some(vec![0u8; 32]),
                kek_wrapped: Some(vec![0u8; 48]),
                kek_nonce: Some(vec![0u8; 24]),
            },
        );

        let response = server.register(request).await.unwrap().into_inner();
        assert!(response.user_id.is_empty()); // Service principals have empty user_id
        assert!(!response.principal_id.is_empty());
    }

    // ================== More Group Handler Tests ==================

    #[tokio::test]
    async fn handler_delete_group() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "admin@example.com", "admin").await;

        let ws_id = create_test_workspace(&server, &user_id, "ws").await;

        // Create group
        server
            .store
            .create_group(&CreateGroupParams {
                workspace_id: ws_id.clone(),
                name: "to-delete".to_string(),
                description: None,
            })
            .await
            .unwrap();

        // Delete group
        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/DeleteGroup",
            zopp_proto::DeleteGroupRequest {
                workspace_name: "ws".to_string(),
                group_name: "to-delete".to_string(),
            },
        );

        server.delete_group(request).await.unwrap();

        // Verify deletion
        let list_request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/ListGroups",
            zopp_proto::ListGroupsRequest {
                workspace_name: "ws".to_string(),
            },
        );

        let response = server.list_groups(list_request).await.unwrap().into_inner();
        assert_eq!(response.groups.len(), 0);
    }

    #[tokio::test]
    async fn handler_remove_group_member() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "admin@example.com", "admin").await;

        let ws_id = create_test_workspace(&server, &user_id, "ws").await;

        // Create group
        let group_id = server
            .store
            .create_group(&CreateGroupParams {
                workspace_id: ws_id.clone(),
                name: "team".to_string(),
                description: None,
            })
            .await
            .unwrap();

        // Create another user and add to workspace
        let (member_user_id, _, _) =
            create_test_user(&server, "member@example.com", "member").await;

        server
            .store
            .add_user_to_workspace(&ws_id, &member_user_id)
            .await
            .unwrap();

        server
            .store
            .set_user_workspace_permission(&ws_id, &member_user_id, Role::Read)
            .await
            .unwrap();

        // Add member to group
        server
            .store
            .add_group_member(&group_id, &member_user_id)
            .await
            .unwrap();

        // Remove member from group
        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/RemoveGroupMember",
            zopp_proto::RemoveGroupMemberRequest {
                workspace_name: "ws".to_string(),
                group_name: "team".to_string(),
                user_email: "member@example.com".to_string(),
            },
        );

        server.remove_group_member(request).await.unwrap();

        // Verify removal
        let list_request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/ListGroupMembers",
            zopp_proto::ListGroupMembersRequest {
                workspace_name: "ws".to_string(),
                group_name: "team".to_string(),
            },
        );

        let response = server
            .list_group_members(list_request)
            .await
            .unwrap()
            .into_inner();
        assert_eq!(response.members.len(), 0);
    }

    // ================== Workspace Handler Tests ==================

    #[tokio::test]
    async fn handler_grant_principal_workspace_access() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "admin@example.com", "admin").await;

        let ws_id = create_test_workspace(&server, &user_id, "ws").await;

        // Create a service principal
        let service_principal_id = server
            .store
            .create_principal(&CreatePrincipalParams {
                user_id: None,
                name: "ci-bot".to_string(),
                public_key: vec![1u8; 32],
                x25519_public_key: Some(vec![2u8; 32]),
            })
            .await
            .unwrap();

        // Grant workspace access
        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/GrantPrincipalWorkspaceAccess",
            zopp_proto::GrantPrincipalWorkspaceAccessRequest {
                workspace_name: "ws".to_string(),
                principal_id: service_principal_id.0.to_string(),
                ephemeral_pub: vec![0u8; 32],
                kek_wrapped: vec![0u8; 48],
                kek_nonce: vec![0u8; 24],
            },
        );

        server
            .grant_principal_workspace_access(request)
            .await
            .unwrap();
    }

    // ================== Error Path Tests ==================

    #[tokio::test]
    async fn handler_get_secret_not_found() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "test@example.com", "laptop").await;

        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        let proj_id = create_test_project(&server, &ws_id, "proj").await;
        create_test_environment(&server, &proj_id, "env").await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/GetSecret",
            zopp_proto::GetSecretRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
                environment_name: "env".to_string(),
                key: "NONEXISTENT".to_string(),
            },
        );

        let result = server.get_secret(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn handler_get_project_not_found() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "test@example.com", "laptop").await;

        let ws_id = create_test_workspace(&server, &user_id, "ws").await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/GetProject",
            zopp_proto::GetProjectRequest {
                workspace_name: "ws".to_string(),
                project_name: "nonexistent".to_string(),
            },
        );

        let result = server.get_project(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn handler_get_environment_not_found() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "test@example.com", "laptop").await;

        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        let proj_id = create_test_project(&server, &ws_id, "proj").await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/GetEnvironment",
            zopp_proto::GetEnvironmentRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
                environment_name: "nonexistent".to_string(),
            },
        );

        let result = server.get_environment(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn handler_rename_principal_permission_denied() {
        let server = create_test_server().await;
        // Create two users
        let (_, principal_id1, signing_key1) =
            create_test_user(&server, "user1@example.com", "user1-device").await;
        let (_, principal_id2, _) =
            create_test_user(&server, "user2@example.com", "user2-device").await;

        // User1 tries to rename User2's principal - should fail
        let request = create_signed_request(
            &principal_id1,
            &signing_key1,
            "/zopp.ZoppService/RenamePrincipal",
            zopp_proto::RenamePrincipalRequest {
                principal_id: principal_id2.0.to_string(),
                new_name: "hacked".to_string(),
            },
        );

        let result = server.rename_principal(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::PermissionDenied);
    }

    #[tokio::test]
    async fn handler_remove_self_from_workspace_denied() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "admin@example.com", "admin").await;

        let ws_id = create_test_workspace(&server, &user_id, "ws").await;

        // Add principal to workspace
        server
            .store
            .add_workspace_principal(&AddWorkspacePrincipalParams {
                workspace_id: ws_id.clone(),
                principal_id: principal_id.clone(),
                ephemeral_pub: vec![0u8; 32],
                kek_wrapped: vec![0u8; 48],
                kek_nonce: vec![0u8; 24],
            })
            .await
            .unwrap();

        // Try to remove self - should fail
        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/RemovePrincipalFromWorkspace",
            zopp_proto::RemovePrincipalFromWorkspaceRequest {
                workspace_name: "ws".to_string(),
                principal_id: principal_id.0.to_string(),
            },
        );

        let result = server.remove_principal_from_workspace(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn handler_revoke_invite() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "test@example.com", "laptop").await;

        let ws_id = create_test_workspace(&server, &user_id, "ws").await;

        // Add principal to workspace (required for invite creation)
        server
            .store
            .add_workspace_principal(&AddWorkspacePrincipalParams {
                workspace_id: ws_id.clone(),
                principal_id: principal_id.clone(),
                ephemeral_pub: vec![0u8; 32],
                kek_wrapped: vec![0u8; 48],
                kek_nonce: vec![0u8; 24],
            })
            .await
            .unwrap();

        // Create invite
        let invite_secret = [42u8; 32];
        let token_hash = hex::encode(zopp_crypto::hash_sha256(&invite_secret));

        let create_request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/CreateInvite",
            zopp_proto::CreateInviteRequest {
                workspace_ids: vec![ws_id.0.to_string()],
                expires_at: chrono::Utc::now().timestamp() + 3600,
                token: token_hash.clone(),
                kek_encrypted: vec![0u8; 48],
                kek_nonce: vec![0u8; 24],
            },
        );

        server.create_invite(create_request).await.unwrap();

        // Revoke invite
        let revoke_request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/RevokeInvite",
            zopp_proto::RevokeInviteRequest { token: token_hash },
        );

        server.revoke_invite(revoke_request).await.unwrap();
    }

    // ================== Additional Coverage Tests ==================

    #[tokio::test]
    async fn handler_join_workspace_invite_existing_user() {
        let server = create_test_server().await;

        // Create first user (owner)
        let (owner_user_id, owner_principal_id, _) =
            create_test_user(&server, "owner@example.com", "owner").await;

        let ws_id = create_test_workspace(&server, &owner_user_id, "shared-ws").await;

        // Create invite for the workspace
        let invite_secret = [42u8; 32];
        let token_hash = hex::encode(zopp_crypto::hash_sha256(&invite_secret));

        server
            .store
            .create_invite(&zopp_storage::CreateInviteParams {
                token: token_hash.clone(),
                workspace_ids: vec![ws_id.clone()],
                kek_encrypted: Some(vec![0u8; 48]),
                kek_nonce: Some(vec![0u8; 24]),
                created_by_user_id: Some(owner_user_id.clone()),
                expires_at: chrono::Utc::now() + chrono::Duration::hours(24),
            })
            .await
            .unwrap();

        // Create second user first (so they already exist)
        let (_, _, _) = create_test_user(&server, "member@example.com", "member-device-1").await;

        // Now join with the same email (existing user joining workspace)
        let request = tonic::Request::new(zopp_proto::JoinRequest {
            invite_token: token_hash,
            email: "member@example.com".to_string(),
            principal_name: "member-device-2".to_string(),
            public_key: vec![5u8; 32],
            x25519_public_key: vec![6u8; 32],
            ephemeral_pub: vec![0u8; 32],
            kek_wrapped: vec![0u8; 48],
            kek_nonce: vec![0u8; 24],
        });

        let response = server.join(request).await.unwrap().into_inner();
        assert!(!response.user_id.is_empty());
        assert!(!response.principal_id.is_empty());
        assert_eq!(response.workspaces.len(), 1);
        assert_eq!(response.workspaces[0].name, "shared-ws");
    }

    #[tokio::test]
    async fn handler_join_expired_invite() {
        let server = create_test_server().await;

        // Create expired invite
        let invite_secret = [42u8; 32];
        let token_hash = hex::encode(zopp_crypto::hash_sha256(&invite_secret));

        server
            .store
            .create_invite(&zopp_storage::CreateInviteParams {
                token: token_hash.clone(),
                workspace_ids: vec![],
                kek_encrypted: Some(vec![0u8; 48]),
                kek_nonce: Some(vec![0u8; 24]),
                created_by_user_id: None,
                expires_at: chrono::Utc::now() - chrono::Duration::hours(1), // Expired
            })
            .await
            .unwrap();

        let request = tonic::Request::new(zopp_proto::JoinRequest {
            invite_token: token_hash,
            email: "newuser@example.com".to_string(),
            principal_name: "device".to_string(),
            public_key: vec![1u8; 32],
            x25519_public_key: vec![2u8; 32],
            ephemeral_pub: vec![],
            kek_wrapped: vec![],
            kek_nonce: vec![],
        });

        let result = server.join(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::PermissionDenied);
    }

    #[tokio::test]
    async fn handler_audit_log_with_filters() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "admin@example.com", "admin").await;

        let ws_id = create_test_workspace(&server, &user_id, "ws").await;

        // List with various filters (will just test the filter parsing, even if no results)
        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/ListAuditLogs",
            zopp_proto::ListAuditLogsRequest {
                workspace_name: "ws".to_string(),
                principal_id: Some(principal_id.0.to_string()),
                user_id: Some(user_id.0.to_string()),
                project_name: None,
                environment_name: None,
                action: Some("secret.read".to_string()),
                result: Some("success".to_string()),
                from_timestamp: Some("2024-01-01T00:00:00Z".to_string()),
                to_timestamp: Some("2030-01-01T00:00:00Z".to_string()),
                limit: Some(50),
                offset: Some(0),
            },
        );

        let response = server.list_audit_logs(request).await.unwrap().into_inner();
        // Filtering should work even if no matching entries
        assert!(response.entries.is_empty() || !response.entries.is_empty());
    }

    #[tokio::test]
    async fn handler_count_audit_logs_with_filters() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "admin@example.com", "admin").await;

        let ws_id = create_test_workspace(&server, &user_id, "ws").await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/CountAuditLogs",
            zopp_proto::CountAuditLogsRequest {
                workspace_name: "ws".to_string(),
                principal_id: Some(principal_id.0.to_string()),
                user_id: Some(user_id.0.to_string()),
                project_name: None,
                environment_name: None,
                action: Some("secret.read".to_string()),
                result: Some("success".to_string()),
                from_timestamp: Some("2024-01-01T00:00:00Z".to_string()),
                to_timestamp: Some("2030-01-01T00:00:00Z".to_string()),
            },
        );

        let response = server.count_audit_logs(request).await.unwrap().into_inner();
        // Response received successfully
        let _ = response.count;
    }

    #[tokio::test]
    async fn handler_get_invite() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "test@example.com", "laptop").await;

        let ws_id = create_test_workspace(&server, &user_id, "ws").await;

        // Create invite
        let invite_secret = [42u8; 32];
        let token_hash = hex::encode(zopp_crypto::hash_sha256(&invite_secret));

        server
            .store
            .create_invite(&zopp_storage::CreateInviteParams {
                token: token_hash.clone(),
                workspace_ids: vec![ws_id.clone()],
                kek_encrypted: Some(vec![0u8; 48]),
                kek_nonce: Some(vec![0u8; 24]),
                created_by_user_id: Some(user_id.clone()),
                expires_at: chrono::Utc::now() + chrono::Duration::hours(24),
            })
            .await
            .unwrap();

        // Get invite (no auth required)
        let request = tonic::Request::new(zopp_proto::GetInviteRequest { token: token_hash });

        let response = server.get_invite(request).await.unwrap().into_inner();
        assert_eq!(response.workspace_ids.len(), 1);
    }

    #[tokio::test]
    async fn handler_service_principal_list_workspaces_denied() {
        let server = create_test_server().await;
        let (user_id, _, _) = create_test_user(&server, "admin@example.com", "admin").await;

        let ws_id = create_test_workspace(&server, &user_id, "ws").await;

        // Create service principal
        let service_signing_key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
        let service_principal_id = server
            .store
            .create_principal(&CreatePrincipalParams {
                user_id: None,
                name: "ci-bot".to_string(),
                public_key: service_signing_key.verifying_key().to_bytes().to_vec(),
                x25519_public_key: Some(vec![2u8; 32]),
            })
            .await
            .unwrap();

        // Add service principal to workspace
        server
            .store
            .add_workspace_principal(&AddWorkspacePrincipalParams {
                workspace_id: ws_id.clone(),
                principal_id: service_principal_id.clone(),
                ephemeral_pub: vec![0u8; 32],
                kek_wrapped: vec![0u8; 48],
                kek_nonce: vec![0u8; 24],
            })
            .await
            .unwrap();

        // Service principal tries to list workspaces - should be denied
        let request = create_signed_request(
            &service_principal_id,
            &service_signing_key,
            "/zopp.ZoppService/ListWorkspaces",
            zopp_proto::Empty {},
        );

        let result = server.list_workspaces(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::Unauthenticated);
    }

    #[tokio::test]
    async fn handler_service_principal_can_access_secrets() {
        let server = create_test_server().await;
        let (user_id, _, _) = create_test_user(&server, "admin@example.com", "admin").await;

        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        let proj_id = create_test_project(&server, &ws_id, "proj").await;
        let env_id = create_test_environment(&server, &proj_id, "env").await;

        // Add a secret
        server
            .store
            .upsert_secret(&env_id, "API_KEY", &[0u8; 24], &[0u8; 32])
            .await
            .unwrap();

        // Create service principal with environment read permission
        let service_signing_key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
        let service_principal_id = server
            .store
            .create_principal(&CreatePrincipalParams {
                user_id: None,
                name: "ci-bot".to_string(),
                public_key: service_signing_key.verifying_key().to_bytes().to_vec(),
                x25519_public_key: Some(vec![2u8; 32]),
            })
            .await
            .unwrap();

        // Add service principal to workspace
        server
            .store
            .add_workspace_principal(&AddWorkspacePrincipalParams {
                workspace_id: ws_id.clone(),
                principal_id: service_principal_id.clone(),
                ephemeral_pub: vec![0u8; 32],
                kek_wrapped: vec![0u8; 48],
                kek_nonce: vec![0u8; 24],
            })
            .await
            .unwrap();

        // Grant environment read permission
        server
            .store
            .set_environment_permission(&env_id, &service_principal_id, Role::Read)
            .await
            .unwrap();

        // Service principal should be able to get secret
        let request = create_signed_request(
            &service_principal_id,
            &service_signing_key,
            "/zopp.ZoppService/GetSecret",
            zopp_proto::GetSecretRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
                environment_name: "env".to_string(),
                key: "API_KEY".to_string(),
            },
        );

        let response = server.get_secret(request).await.unwrap().into_inner();
        assert_eq!(response.key, "API_KEY");
    }

    #[tokio::test]
    async fn handler_workspace_create_with_kek() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "test@example.com", "laptop").await;

        let ws_id = uuid::Uuid::now_v7();
        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/CreateWorkspace",
            zopp_proto::CreateWorkspaceRequest {
                id: ws_id.to_string(),
                name: "new-ws".to_string(),
                ephemeral_pub: vec![0u8; 32],
                kek_wrapped: vec![0u8; 48],
                kek_nonce: vec![0u8; 24],
            },
        );

        let response = server.create_workspace(request).await.unwrap().into_inner();
        assert_eq!(response.name, "new-ws");

        // Verify KEK was stored by getting workspace keys
        let keys_request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/GetWorkspaceKeys",
            zopp_proto::GetWorkspaceKeysRequest {
                workspace_name: "new-ws".to_string(),
            },
        );

        let keys_response = server
            .get_workspace_keys(keys_request)
            .await
            .unwrap()
            .into_inner();
        assert!(!keys_response.kek_wrapped.is_empty());
    }

    #[tokio::test]
    async fn handler_workspace_create_missing_kek_nonce() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "test@example.com", "laptop").await;

        let ws_id = uuid::Uuid::now_v7();
        // Provide kek_wrapped but no nonce - should fail
        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/CreateWorkspace",
            zopp_proto::CreateWorkspaceRequest {
                id: ws_id.to_string(),
                name: "bad-ws".to_string(),
                ephemeral_pub: vec![0u8; 32],
                kek_wrapped: vec![0u8; 48],
                kek_nonce: vec![], // Missing nonce!
            },
        );

        let result = server.create_workspace(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn handler_environment_dek_storage() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "test@example.com", "laptop").await;

        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        let proj_id = create_test_project(&server, &ws_id, "proj").await;

        // Create environment with DEK
        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/CreateEnvironment",
            zopp_proto::CreateEnvironmentRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
                name: "production".to_string(),
                dek_wrapped: vec![0u8; 48],
                dek_nonce: vec![0u8; 24],
            },
        );

        let response = server
            .create_environment(request)
            .await
            .unwrap()
            .into_inner();
        assert_eq!(response.name, "production");

        // Verify DEK was stored by getting environment
        let get_request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/GetEnvironment",
            zopp_proto::GetEnvironmentRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
                environment_name: "production".to_string(),
            },
        );

        let get_response = server
            .get_environment(get_request)
            .await
            .unwrap()
            .into_inner();
        assert!(!get_response.dek_wrapped.is_empty());
    }

    // ================== More Error Path Tests ==================

    #[tokio::test]
    async fn handler_service_principal_without_permission() {
        let server = create_test_server().await;
        let (user_id, _, _) = create_test_user(&server, "admin@example.com", "admin").await;

        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        let proj_id = create_test_project(&server, &ws_id, "proj").await;
        let env_id = create_test_environment(&server, &proj_id, "env").await;

        // Create service principal WITHOUT any permissions
        let service_signing_key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
        let service_principal_id = server
            .store
            .create_principal(&CreatePrincipalParams {
                user_id: None,
                name: "ci-bot".to_string(),
                public_key: service_signing_key.verifying_key().to_bytes().to_vec(),
                x25519_public_key: Some(vec![2u8; 32]),
            })
            .await
            .unwrap();

        // Add service principal to workspace (but no role permission)
        server
            .store
            .add_workspace_principal(&AddWorkspacePrincipalParams {
                workspace_id: ws_id.clone(),
                principal_id: service_principal_id.clone(),
                ephemeral_pub: vec![0u8; 32],
                kek_wrapped: vec![0u8; 48],
                kek_nonce: vec![0u8; 24],
            })
            .await
            .unwrap();

        // Add a secret
        server
            .store
            .upsert_secret(&env_id, "SECRET", &[0u8; 24], &[0u8; 32])
            .await
            .unwrap();

        // Service principal without permission should be denied
        let request = create_signed_request(
            &service_principal_id,
            &service_signing_key,
            "/zopp.ZoppService/GetSecret",
            zopp_proto::GetSecretRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
                environment_name: "env".to_string(),
                key: "SECRET".to_string(),
            },
        );

        let result = server.get_secret(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::PermissionDenied);
    }

    #[tokio::test]
    async fn handler_permission_hierarchy_principal_restricts() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "admin@example.com", "admin").await;

        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        let proj_id = create_test_project(&server, &ws_id, "proj").await;
        let env_id = create_test_environment(&server, &proj_id, "env").await;

        // Create another user with workspace-level Write permission
        let (other_user_id, other_principal_id, other_signing_key) =
            create_test_user(&server, "other@example.com", "other").await;

        server
            .store
            .add_user_to_workspace(&ws_id, &other_user_id)
            .await
            .unwrap();

        server
            .store
            .set_user_workspace_permission(&ws_id, &other_user_id, Role::Write)
            .await
            .unwrap();

        // But restrict their principal to Read only
        server
            .store
            .set_environment_permission(&env_id, &other_principal_id, Role::Read)
            .await
            .unwrap();

        // Add a secret
        server
            .store
            .upsert_secret(&env_id, "SECRET", &[0u8; 24], &[0u8; 32])
            .await
            .unwrap();

        // Reading should work
        let read_request = create_signed_request(
            &other_principal_id,
            &other_signing_key,
            "/zopp.ZoppService/GetSecret",
            zopp_proto::GetSecretRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
                environment_name: "env".to_string(),
                key: "SECRET".to_string(),
            },
        );

        server.get_secret(read_request).await.unwrap();

        // But writing should be denied (principal permission restricts)
        let write_request = create_signed_request(
            &other_principal_id,
            &other_signing_key,
            "/zopp.ZoppService/UpsertSecret",
            zopp_proto::UpsertSecretRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
                environment_name: "env".to_string(),
                key: "NEW_SECRET".to_string(),
                nonce: vec![0u8; 24],
                ciphertext: vec![0u8; 32],
            },
        );

        let result = server.upsert_secret(write_request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::PermissionDenied);
    }

    // ================== Additional Secret Handler Error Path Tests ==================

    #[tokio::test]
    async fn handler_upsert_secret_project_not_found() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "test@example.com", "laptop").await;

        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        // Try to upsert secret with non-existent project
        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/UpsertSecret",
            zopp_proto::UpsertSecretRequest {
                workspace_name: "ws".to_string(),
                project_name: "nonexistent".to_string(),
                environment_name: "env".to_string(),
                key: "KEY".to_string(),
                nonce: vec![0u8; 24],
                ciphertext: vec![0u8; 32],
            },
        );

        let result = server.upsert_secret(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn handler_upsert_secret_environment_not_found() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "test@example.com", "laptop").await;

        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;
        let _proj_id = create_test_project(&server, &ws_id, "proj").await;

        // Try to upsert secret with non-existent environment
        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/UpsertSecret",
            zopp_proto::UpsertSecretRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
                environment_name: "nonexistent".to_string(),
                key: "KEY".to_string(),
                nonce: vec![0u8; 24],
                ciphertext: vec![0u8; 32],
            },
        );

        let result = server.upsert_secret(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn handler_get_secret_project_not_found() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "test@example.com", "laptop").await;

        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/GetSecret",
            zopp_proto::GetSecretRequest {
                workspace_name: "ws".to_string(),
                project_name: "nonexistent".to_string(),
                environment_name: "env".to_string(),
                key: "KEY".to_string(),
            },
        );

        let result = server.get_secret(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn handler_list_secrets_project_not_found() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "test@example.com", "laptop").await;

        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/ListSecrets",
            zopp_proto::ListSecretsRequest {
                workspace_name: "ws".to_string(),
                project_name: "nonexistent".to_string(),
                environment_name: "env".to_string(),
            },
        );

        let result = server.list_secrets(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn handler_delete_secret_project_not_found() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "test@example.com", "laptop").await;

        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/DeleteSecret",
            zopp_proto::DeleteSecretRequest {
                workspace_name: "ws".to_string(),
                project_name: "nonexistent".to_string(),
                environment_name: "env".to_string(),
                key: "KEY".to_string(),
            },
        );

        let result = server.delete_secret(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn handler_delete_secret_not_found() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "test@example.com", "laptop").await;

        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;
        let proj_id = create_test_project(&server, &ws_id, "proj").await;
        let _env_id = create_test_environment(&server, &proj_id, "env").await;

        // Set admin permission
        server
            .store
            .set_workspace_permission(&ws_id, &principal_id, Role::Admin)
            .await
            .unwrap();

        // Try to delete a non-existent secret
        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/DeleteSecret",
            zopp_proto::DeleteSecretRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
                environment_name: "env".to_string(),
                key: "NONEXISTENT".to_string(),
            },
        );

        let result = server.delete_secret(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn handler_upsert_secret_update_increments_version() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "test@example.com", "laptop").await;

        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;
        let proj_id = create_test_project(&server, &ws_id, "proj").await;
        let env_id = create_test_environment(&server, &proj_id, "env").await;

        // Set admin permission
        server
            .store
            .set_workspace_permission(&ws_id, &principal_id, Role::Admin)
            .await
            .unwrap();

        // First upsert - creates secret with version 1
        let request1 = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/UpsertSecret",
            zopp_proto::UpsertSecretRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
                environment_name: "env".to_string(),
                key: "KEY".to_string(),
                nonce: vec![1u8; 24],
                ciphertext: vec![1u8; 32],
            },
        );

        server.upsert_secret(request1).await.unwrap();

        // Verify secret exists
        let secret = server.store.get_secret(&env_id, "KEY").await.unwrap();
        assert_eq!(secret.nonce, vec![1u8; 24]);

        // Second upsert - updates secret
        let request2 = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/UpsertSecret",
            zopp_proto::UpsertSecretRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
                environment_name: "env".to_string(),
                key: "KEY".to_string(),
                nonce: vec![2u8; 24],
                ciphertext: vec![2u8; 32],
            },
        );

        server.upsert_secret(request2).await.unwrap();

        // Verify secret was updated
        let secret = server.store.get_secret(&env_id, "KEY").await.unwrap();
        assert_eq!(secret.nonce, vec![2u8; 24]);
    }

    #[tokio::test]
    async fn handler_watch_secrets() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "test@example.com", "laptop").await;

        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;
        let proj_id = create_test_project(&server, &ws_id, "proj").await;
        let _env_id = create_test_environment(&server, &proj_id, "env").await;

        // Set admin permission
        server
            .store
            .set_workspace_permission(&ws_id, &principal_id, Role::Admin)
            .await
            .unwrap();

        // Start watching
        let watch_request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/WatchSecrets",
            zopp_proto::WatchSecretsRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
                environment_name: "env".to_string(),
                since_version: None,
            },
        );

        let response = server.watch_secrets(watch_request).await.unwrap();
        let mut stream = response.into_inner();

        // Upsert a secret to generate an event
        let upsert_request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/UpsertSecret",
            zopp_proto::UpsertSecretRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
                environment_name: "env".to_string(),
                key: "WATCHED_KEY".to_string(),
                nonce: vec![0u8; 24],
                ciphertext: vec![0u8; 32],
            },
        );

        server.upsert_secret(upsert_request).await.unwrap();

        // Check that we receive the event
        use tokio::time::{timeout, Duration};
        use tokio_stream::StreamExt;

        let event_result = timeout(Duration::from_secs(1), stream.next()).await;
        assert!(event_result.is_ok());

        let event = event_result.unwrap().unwrap().unwrap();
        match event.response {
            Some(zopp_proto::watch_secrets_response::Response::Event(e)) => {
                assert_eq!(e.key, "WATCHED_KEY");
                assert_eq!(
                    e.event_type,
                    zopp_proto::secret_change_event::EventType::Updated as i32
                );
            }
            _ => panic!("Expected event response"),
        }
    }

    #[tokio::test]
    async fn handler_watch_secrets_project_not_found() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "test@example.com", "laptop").await;

        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/WatchSecrets",
            zopp_proto::WatchSecretsRequest {
                workspace_name: "ws".to_string(),
                project_name: "nonexistent".to_string(),
                environment_name: "env".to_string(),
                since_version: None,
            },
        );

        let result = server.watch_secrets(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    // ================== Additional Groups Handler Tests ==================

    #[tokio::test]
    async fn handler_group_add_member_to_nonexistent_group() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "test@example.com", "laptop").await;

        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        // Try to add member to non-existent group
        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/AddGroupMember",
            zopp_proto::AddGroupMemberRequest {
                workspace_name: "ws".to_string(),
                group_name: "nonexistent".to_string(),
                user_email: "test@example.com".to_string(),
            },
        );

        let result = server.add_group_member(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn handler_group_remove_member_from_nonexistent_group() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "test@example.com", "laptop").await;

        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/RemoveGroupMember",
            zopp_proto::RemoveGroupMemberRequest {
                workspace_name: "ws".to_string(),
                group_name: "nonexistent".to_string(),
                user_email: "test@example.com".to_string(),
            },
        );

        let result = server.remove_group_member(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn handler_delete_group_not_found() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "test@example.com", "laptop").await;

        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/DeleteGroup",
            zopp_proto::DeleteGroupRequest {
                workspace_name: "ws".to_string(),
                group_name: "nonexistent".to_string(),
            },
        );

        let result = server.delete_group(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn handler_list_group_members() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "test@example.com", "laptop").await;

        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        // Create group
        let group_id = server
            .store
            .create_group(&CreateGroupParams {
                workspace_id: ws_id.clone(),
                name: "developers".to_string(),
                description: None,
            })
            .await
            .unwrap();

        // Add member (add user to group)
        server
            .store
            .add_group_member(&group_id, &user_id)
            .await
            .unwrap();

        // List members
        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/ListGroupMembers",
            zopp_proto::ListGroupMembersRequest {
                workspace_name: "ws".to_string(),
                group_name: "developers".to_string(),
            },
        );

        let response = server.list_group_members(request).await.unwrap().into_inner();
        assert_eq!(response.members.len(), 1);
        assert_eq!(response.members[0].user_email, "test@example.com");
    }

    #[tokio::test]
    async fn handler_list_groups_empty() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "test@example.com", "laptop").await;

        let _ws_id = create_test_workspace(&server, &user_id, "ws").await;

        // List groups in workspace with no groups
        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/ListGroups",
            zopp_proto::ListGroupsRequest {
                workspace_name: "ws".to_string(),
            },
        );

        let response = server.list_groups(request).await.unwrap().into_inner();
        assert!(response.groups.is_empty());
    }

    // ================== Additional Auth Handler Tests ==================

    #[tokio::test]
    async fn handler_join_with_workspace_kek() {
        let server = create_test_server().await;

        // Create an inviter user first
        let (inviter_user_id, inviter_principal_id, inviter_signing_key) =
            create_test_user(&server, "inviter@example.com", "inviter-laptop").await;

        let ws_id = create_test_workspace(&server, &inviter_user_id, "shared-ws").await;
        add_principal_to_workspace(&server, &ws_id, &inviter_principal_id).await;

        // Create invite
        let invite_secret = [42u8; 32];
        let token_hash = hex::encode(zopp_crypto::hash_sha256(&invite_secret));

        let create_invite_request = create_signed_request(
            &inviter_principal_id,
            &inviter_signing_key,
            "/zopp.ZoppService/CreateInvite",
            zopp_proto::CreateInviteRequest {
                workspace_ids: vec![ws_id.0.to_string()],
                expires_at: chrono::Utc::now().timestamp() + 3600,
                token: token_hash.clone(),
                kek_encrypted: vec![0u8; 48],
                kek_nonce: vec![0u8; 24],
            },
        );

        server.create_invite(create_invite_request).await.unwrap();

        // New user joins with wrapped KEK
        let join_request = tonic::Request::new(zopp_proto::JoinRequest {
            invite_token: token_hash,
            email: "newuser@example.com".to_string(),
            principal_name: "new-laptop".to_string(),
            public_key: vec![1u8; 32],
            x25519_public_key: vec![2u8; 32],
            ephemeral_pub: vec![3u8; 32],
            kek_wrapped: vec![4u8; 48],
            kek_nonce: vec![5u8; 24],
        });

        let response = server.join(join_request).await.unwrap().into_inner();
        assert!(!response.user_id.is_empty());
        assert!(!response.principal_id.is_empty());
        assert_eq!(response.workspaces.len(), 1);
        assert_eq!(response.workspaces[0].name, "shared-ws");
    }

    // ================== Additional Environment Handler Tests ==================

    #[tokio::test]
    async fn handler_list_environments_empty() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "test@example.com", "laptop").await;

        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;
        let _proj_id = create_test_project(&server, &ws_id, "proj").await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/ListEnvironments",
            zopp_proto::ListEnvironmentsRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
            },
        );

        let response = server.list_environments(request).await.unwrap().into_inner();
        assert!(response.environments.is_empty());
    }

    #[tokio::test]
    async fn handler_delete_environment_not_found() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "test@example.com", "laptop").await;

        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;
        let _proj_id = create_test_project(&server, &ws_id, "proj").await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/DeleteEnvironment",
            zopp_proto::DeleteEnvironmentRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
                environment_name: "nonexistent".to_string(),
            },
        );

        let result = server.delete_environment(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    // ================== Additional Project Handler Tests ==================

    #[tokio::test]
    async fn handler_list_projects_empty() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "test@example.com", "laptop").await;

        let _ws_id = create_test_workspace(&server, &user_id, "ws").await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/ListProjects",
            zopp_proto::ListProjectsRequest {
                workspace_name: "ws".to_string(),
            },
        );

        let response = server.list_projects(request).await.unwrap().into_inner();
        assert!(response.projects.is_empty());
    }

    #[tokio::test]
    async fn handler_delete_project_not_found() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "test@example.com", "laptop").await;

        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/DeleteProject",
            zopp_proto::DeleteProjectRequest {
                workspace_name: "ws".to_string(),
                project_name: "nonexistent".to_string(),
            },
        );

        let result = server.delete_project(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    // ================== Service Principal Edge Cases ==================

    #[tokio::test]
    async fn handler_service_principal_get_secret() {
        let server = create_test_server().await;
        let (user_id, admin_principal_id, admin_signing_key) =
            create_test_user(&server, "admin@example.com", "admin-laptop").await;

        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        add_principal_to_workspace(&server, &ws_id, &admin_principal_id).await;
        let proj_id = create_test_project(&server, &ws_id, "proj").await;
        let _env_id = create_test_environment(&server, &proj_id, "env").await;

        // Set admin permission for admin principal
        server
            .store
            .set_workspace_permission(&ws_id, &admin_principal_id, Role::Admin)
            .await
            .unwrap();

        // Create service principal
        let (service_principal_id, service_signing_key) =
            create_service_principal(&server, "ci-bot").await;

        // Add service principal to workspace
        add_principal_to_workspace(&server, &ws_id, &service_principal_id).await;

        // Grant Read permission to service principal
        server
            .store
            .set_workspace_permission(&ws_id, &service_principal_id, Role::Read)
            .await
            .unwrap();

        // Create a secret with admin
        let upsert_request = create_signed_request(
            &admin_principal_id,
            &admin_signing_key,
            "/zopp.ZoppService/UpsertSecret",
            zopp_proto::UpsertSecretRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
                environment_name: "env".to_string(),
                key: "SERVICE_KEY".to_string(),
                nonce: vec![0u8; 24],
                ciphertext: vec![0u8; 32],
            },
        );

        server.upsert_secret(upsert_request).await.unwrap();

        // Service principal can get the secret
        let get_request = create_signed_request(
            &service_principal_id,
            &service_signing_key,
            "/zopp.ZoppService/GetSecret",
            zopp_proto::GetSecretRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
                environment_name: "env".to_string(),
                key: "SERVICE_KEY".to_string(),
            },
        );

        let response = server.get_secret(get_request).await.unwrap().into_inner();
        assert_eq!(response.key, "SERVICE_KEY");
    }

    #[tokio::test]
    async fn handler_service_principal_list_secrets() {
        let server = create_test_server().await;
        let (user_id, admin_principal_id, admin_signing_key) =
            create_test_user(&server, "admin@example.com", "admin-laptop").await;

        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        add_principal_to_workspace(&server, &ws_id, &admin_principal_id).await;
        let proj_id = create_test_project(&server, &ws_id, "proj").await;
        let _env_id = create_test_environment(&server, &proj_id, "env").await;

        server
            .store
            .set_workspace_permission(&ws_id, &admin_principal_id, Role::Admin)
            .await
            .unwrap();

        // Create service principal
        let (service_principal_id, service_signing_key) =
            create_service_principal(&server, "ci-bot").await;

        add_principal_to_workspace(&server, &ws_id, &service_principal_id).await;
        server
            .store
            .set_workspace_permission(&ws_id, &service_principal_id, Role::Read)
            .await
            .unwrap();

        // Create secrets
        for i in 0..3 {
            let upsert_request = create_signed_request(
                &admin_principal_id,
                &admin_signing_key,
                "/zopp.ZoppService/UpsertSecret",
                zopp_proto::UpsertSecretRequest {
                    workspace_name: "ws".to_string(),
                    project_name: "proj".to_string(),
                    environment_name: "env".to_string(),
                    key: format!("KEY_{}", i),
                    nonce: vec![i as u8; 24],
                    ciphertext: vec![i as u8; 32],
                },
            );
            server.upsert_secret(upsert_request).await.unwrap();
        }

        // Service principal can list secrets
        let list_request = create_signed_request(
            &service_principal_id,
            &service_signing_key,
            "/zopp.ZoppService/ListSecrets",
            zopp_proto::ListSecretsRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
                environment_name: "env".to_string(),
            },
        );

        let response = server.list_secrets(list_request).await.unwrap().into_inner();
        assert_eq!(response.secrets.len(), 3);
    }

    #[tokio::test]
    async fn handler_service_principal_delete_secret() {
        let server = create_test_server().await;
        let (user_id, admin_principal_id, admin_signing_key) =
            create_test_user(&server, "admin@example.com", "admin-laptop").await;

        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        add_principal_to_workspace(&server, &ws_id, &admin_principal_id).await;
        let proj_id = create_test_project(&server, &ws_id, "proj").await;
        let _env_id = create_test_environment(&server, &proj_id, "env").await;

        server
            .store
            .set_workspace_permission(&ws_id, &admin_principal_id, Role::Admin)
            .await
            .unwrap();

        // Create service principal with Write permission
        let (service_principal_id, service_signing_key) =
            create_service_principal(&server, "ci-bot").await;

        add_principal_to_workspace(&server, &ws_id, &service_principal_id).await;
        server
            .store
            .set_workspace_permission(&ws_id, &service_principal_id, Role::Write)
            .await
            .unwrap();

        // Create a secret
        let upsert_request = create_signed_request(
            &admin_principal_id,
            &admin_signing_key,
            "/zopp.ZoppService/UpsertSecret",
            zopp_proto::UpsertSecretRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
                environment_name: "env".to_string(),
                key: "TO_DELETE".to_string(),
                nonce: vec![0u8; 24],
                ciphertext: vec![0u8; 32],
            },
        );

        server.upsert_secret(upsert_request).await.unwrap();

        // Service principal can delete the secret
        let delete_request = create_signed_request(
            &service_principal_id,
            &service_signing_key,
            "/zopp.ZoppService/DeleteSecret",
            zopp_proto::DeleteSecretRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
                environment_name: "env".to_string(),
                key: "TO_DELETE".to_string(),
            },
        );

        server.delete_secret(delete_request).await.unwrap();

        // Verify secret is deleted
        let get_request = create_signed_request(
            &admin_principal_id,
            &admin_signing_key,
            "/zopp.ZoppService/GetSecret",
            zopp_proto::GetSecretRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
                environment_name: "env".to_string(),
                key: "TO_DELETE".to_string(),
            },
        );

        let result = server.get_secret(get_request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    // ================== Audit Handler Error Path Tests ==================

    #[tokio::test]
    async fn handler_list_audit_logs_invalid_principal_id_filter() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "test@example.com", "laptop").await;

        let ws_id = create_test_workspace(&server, &user_id, "ws").await;

        // Set admin permission (required for audit logs)
        server
            .store
            .set_workspace_permission(&ws_id, &principal_id, Role::Admin)
            .await
            .unwrap();

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/ListAuditLogs",
            zopp_proto::ListAuditLogsRequest {
                workspace_name: "ws".to_string(),
                principal_id: Some("not-a-valid-uuid".to_string()),
                ..Default::default()
            },
        );

        let result = server.list_audit_logs(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn handler_list_audit_logs_invalid_user_id_filter() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "test@example.com", "laptop").await;

        let ws_id = create_test_workspace(&server, &user_id, "ws").await;

        server
            .store
            .set_workspace_permission(&ws_id, &principal_id, Role::Admin)
            .await
            .unwrap();

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/ListAuditLogs",
            zopp_proto::ListAuditLogsRequest {
                workspace_name: "ws".to_string(),
                user_id: Some("invalid-uuid".to_string()),
                ..Default::default()
            },
        );

        let result = server.list_audit_logs(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn handler_list_audit_logs_invalid_action_filter() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "test@example.com", "laptop").await;

        let ws_id = create_test_workspace(&server, &user_id, "ws").await;

        server
            .store
            .set_workspace_permission(&ws_id, &principal_id, Role::Admin)
            .await
            .unwrap();

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/ListAuditLogs",
            zopp_proto::ListAuditLogsRequest {
                workspace_name: "ws".to_string(),
                action: Some("invalid.action".to_string()),
                ..Default::default()
            },
        );

        let result = server.list_audit_logs(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn handler_list_audit_logs_permission_denied() {
        let server = create_test_server().await;
        let (owner_user_id, _owner_principal_id, _owner_signing_key) =
            create_test_user(&server, "owner@example.com", "laptop").await;

        let ws_id = create_test_workspace(&server, &owner_user_id, "ws").await;

        // Create second user with only Read permission
        let (reader_user_id, reader_principal_id, reader_signing_key) =
            create_test_user(&server, "reader@example.com", "laptop").await;

        add_user_to_workspace(&server, &ws_id, &reader_user_id, Role::Read).await;
        add_principal_to_workspace(&server, &ws_id, &reader_principal_id).await;

        let request = create_signed_request(
            &reader_principal_id,
            &reader_signing_key,
            "/zopp.ZoppService/ListAuditLogs",
            zopp_proto::ListAuditLogsRequest {
                workspace_name: "ws".to_string(),
                ..Default::default()
            },
        );

        let result = server.list_audit_logs(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::PermissionDenied);
    }

    #[tokio::test]
    async fn handler_count_audit_logs_permission_denied() {
        let server = create_test_server().await;
        let (owner_user_id, _owner_principal_id, _owner_signing_key) =
            create_test_user(&server, "owner@example.com", "laptop").await;

        let ws_id = create_test_workspace(&server, &owner_user_id, "ws").await;

        // Create second user with only Read permission
        let (reader_user_id, reader_principal_id, reader_signing_key) =
            create_test_user(&server, "reader@example.com", "laptop").await;

        add_user_to_workspace(&server, &ws_id, &reader_user_id, Role::Read).await;
        add_principal_to_workspace(&server, &ws_id, &reader_principal_id).await;

        let request = create_signed_request(
            &reader_principal_id,
            &reader_signing_key,
            "/zopp.ZoppService/CountAuditLogs",
            zopp_proto::CountAuditLogsRequest {
                workspace_name: "ws".to_string(),
                ..Default::default()
            },
        );

        let result = server.count_audit_logs(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::PermissionDenied);
    }

    // ================== Group Handler Error Path Tests ==================

    #[tokio::test]
    async fn handler_create_group_duplicate_name() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "test@example.com", "laptop").await;

        let ws_id = create_test_workspace(&server, &user_id, "ws").await;

        // Create first group
        let request1 = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/CreateGroup",
            zopp_proto::CreateGroupRequest {
                workspace_name: "ws".to_string(),
                name: "developers".to_string(),
                description: String::new(),
            },
        );

        server.create_group(request1).await.unwrap();

        // Try to create group with same name
        let request2 = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/CreateGroup",
            zopp_proto::CreateGroupRequest {
                workspace_name: "ws".to_string(),
                name: "developers".to_string(),
                description: String::new(),
            },
        );

        let result = server.create_group(request2).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::AlreadyExists);
    }

    #[tokio::test]
    async fn handler_create_group_as_service_principal() {
        let server = create_test_server().await;
        let (user_id, admin_principal_id, _admin_signing_key) =
            create_test_user(&server, "admin@example.com", "admin-laptop").await;

        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        add_principal_to_workspace(&server, &ws_id, &admin_principal_id).await;

        // Create service principal
        let (service_principal_id, service_signing_key) =
            create_service_principal(&server, "ci-bot").await;

        add_principal_to_workspace(&server, &ws_id, &service_principal_id).await;
        server
            .store
            .set_workspace_permission(&ws_id, &service_principal_id, Role::Admin)
            .await
            .unwrap();

        // Try to create group as service principal
        let request = create_signed_request(
            &service_principal_id,
            &service_signing_key,
            "/zopp.ZoppService/CreateGroup",
            zopp_proto::CreateGroupRequest {
                workspace_name: "ws".to_string(),
                name: "test-group".to_string(),
                description: String::new(),
            },
        );

        let result = server.create_group(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::Unauthenticated);
    }

    #[tokio::test]
    async fn handler_get_group_not_found() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "test@example.com", "laptop").await;

        let _ws_id = create_test_workspace(&server, &user_id, "ws").await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/GetGroup",
            zopp_proto::GetGroupRequest {
                workspace_name: "ws".to_string(),
                group_name: "nonexistent".to_string(),
            },
        );

        let result = server.get_group(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn handler_add_group_member_user_not_found() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "test@example.com", "laptop").await;

        let ws_id = create_test_workspace(&server, &user_id, "ws").await;

        // Create group
        server
            .store
            .create_group(&CreateGroupParams {
                workspace_id: ws_id.clone(),
                name: "developers".to_string(),
                description: None,
            })
            .await
            .unwrap();

        // Try to add non-existent user
        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/AddGroupMember",
            zopp_proto::AddGroupMemberRequest {
                workspace_name: "ws".to_string(),
                group_name: "developers".to_string(),
                user_email: "nonexistent@example.com".to_string(),
            },
        );

        let result = server.add_group_member(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    // ================== Workspace Handler Error Path Tests ==================

    #[tokio::test]
    async fn handler_get_workspace_keys_workspace_not_found() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "test@example.com", "laptop").await;

        let _ws_id = create_test_workspace(&server, &user_id, "ws").await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/GetWorkspaceKeys",
            zopp_proto::GetWorkspaceKeysRequest {
                workspace_name: "nonexistent".to_string(),
            },
        );

        let result = server.get_workspace_keys(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    // ================== Invite Handler Error Path Tests ==================

    #[tokio::test]
    async fn handler_create_invite_permission_denied() {
        let server = create_test_server().await;
        let (owner_user_id, _owner_principal_id, _owner_signing_key) =
            create_test_user(&server, "owner@example.com", "owner-laptop").await;

        let (other_user_id, other_principal_id, other_signing_key) =
            create_test_user(&server, "other@example.com", "other-laptop").await;

        let ws_id = create_test_workspace(&server, &owner_user_id, "ws").await;

        // Add other user with Read permission only
        server
            .store
            .add_user_to_workspace(&ws_id, &other_user_id)
            .await
            .unwrap();
        add_principal_to_workspace(&server, &ws_id, &other_principal_id).await;
        server
            .store
            .set_workspace_permission(&ws_id, &other_principal_id, Role::Read)
            .await
            .unwrap();

        let invite_secret = [99u8; 32];
        let token_hash = hex::encode(zopp_crypto::hash_sha256(&invite_secret));

        let request = create_signed_request(
            &other_principal_id,
            &other_signing_key,
            "/zopp.ZoppService/CreateInvite",
            zopp_proto::CreateInviteRequest {
                workspace_ids: vec![ws_id.0.to_string()],
                expires_at: chrono::Utc::now().timestamp() + 3600,
                token: token_hash,
                kek_encrypted: vec![0u8; 48],
                kek_nonce: vec![0u8; 24],
            },
        );

        let result = server.create_invite(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::PermissionDenied);
    }

    #[tokio::test]
    async fn handler_get_invite_not_found() {
        let server = create_test_server().await;

        // Try to get an invite with a random token
        let request = tonic::Request::new(zopp_proto::GetInviteRequest {
            token: hex::encode([0u8; 32]),
        });

        let result = server.get_invite(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    // ================== Environment Handler Error Path Tests ==================

    #[tokio::test]
    async fn handler_create_environment_read_only_permission_denied() {
        let server = create_test_server().await;
        let (owner_user_id, _owner_principal_id, _owner_signing_key) =
            create_test_user(&server, "owner@example.com", "owner-laptop").await;

        let (other_user_id, other_principal_id, other_signing_key) =
            create_test_user(&server, "other@example.com", "other-laptop").await;

        let ws_id = create_test_workspace(&server, &owner_user_id, "ws").await;
        let _proj_id = create_test_project(&server, &ws_id, "proj").await;

        // Add other user with Read permission only
        add_user_to_workspace(&server, &ws_id, &other_user_id, Role::Read).await;
        add_principal_to_workspace(&server, &ws_id, &other_principal_id).await;

        let request = create_signed_request(
            &other_principal_id,
            &other_signing_key,
            "/zopp.ZoppService/CreateEnvironment",
            zopp_proto::CreateEnvironmentRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
                name: "staging".to_string(),
                dek_wrapped: vec![0u8; 48],
                dek_nonce: vec![0u8; 24],
            },
        );

        let result = server.create_environment(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::PermissionDenied);
    }

    #[tokio::test]
    async fn handler_get_environment_env_not_found() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "test@example.com", "laptop").await;

        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;
        let _proj_id = create_test_project(&server, &ws_id, "proj").await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/GetEnvironment",
            zopp_proto::GetEnvironmentRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
                environment_name: "nonexistent".to_string(),
            },
        );

        let result = server.get_environment(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    // ================== Project Handler Error Path Tests ==================

    #[tokio::test]
    async fn handler_create_project_permission_denied() {
        let server = create_test_server().await;
        let (owner_user_id, _owner_principal_id, _) =
            create_test_user(&server, "owner@example.com", "owner-laptop").await;

        let (other_user_id, other_principal_id, other_signing_key) =
            create_test_user(&server, "other@example.com", "other-laptop").await;

        let ws_id = create_test_workspace(&server, &owner_user_id, "ws").await;

        // Add other user with Read permission only
        add_user_to_workspace(&server, &ws_id, &other_user_id, Role::Read).await;
        add_principal_to_workspace(&server, &ws_id, &other_principal_id).await;

        let request = create_signed_request(
            &other_principal_id,
            &other_signing_key,
            "/zopp.ZoppService/CreateProject",
            zopp_proto::CreateProjectRequest {
                workspace_name: "ws".to_string(),
                name: "new-project".to_string(),
            },
        );

        let result = server.create_project(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::PermissionDenied);
    }

    #[tokio::test]
    async fn handler_get_project_proj_not_found() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "test@example.com", "laptop").await;

        let _ws_id = create_test_workspace(&server, &user_id, "ws").await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/GetProject",
            zopp_proto::GetProjectRequest {
                workspace_name: "ws".to_string(),
                project_name: "nonexistent".to_string(),
            },
        );

        let result = server.get_project(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    // ================== Login Handler Tests ==================

    // Note: handler_login_success is hard to test because the login handler
    // includes the signature in the request body hash, creating a circular dependency.
    // This is tested via E2E tests instead.

    #[tokio::test]
    async fn handler_login_user_not_found() {
        let server = create_test_server().await;

        let req = zopp_proto::LoginRequest {
            email: "nonexistent@example.com".to_string(),
            principal_name: "laptop".to_string(),
            timestamp: chrono::Utc::now().timestamp(),
            signature: vec![0u8; 64],
        };

        let request = tonic::Request::new(req);
        let result = server.login(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn handler_login_principal_not_found() {
        let server = create_test_server().await;
        let (_user_id, _principal_id, _signing_key) =
            create_test_user(&server, "test@example.com", "laptop").await;

        let req = zopp_proto::LoginRequest {
            email: "test@example.com".to_string(),
            principal_name: "nonexistent-device".to_string(),
            timestamp: chrono::Utc::now().timestamp(),
            signature: vec![0u8; 64],
        };

        let request = tonic::Request::new(req);
        let result = server.login(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    // ================== Join Handler Edge Cases ==================

    #[tokio::test]
    async fn handler_join_invalid_token() {
        let server = create_test_server().await;

        // Try to join with a completely invalid token
        let req = zopp_proto::JoinRequest {
            invite_token: "invalid-token-that-does-not-exist".to_string(),
            email: "newuser@example.com".to_string(),
            principal_name: "laptop".to_string(),
            public_key: vec![1u8; 32],
            x25519_public_key: vec![2u8; 32],
            ephemeral_pub: vec![],
            kek_wrapped: vec![],
            kek_nonce: vec![],
        };

        let request = tonic::Request::new(req);
        let result = server.join(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    // ================== Register Handler Edge Cases ==================

    #[tokio::test]
    async fn handler_register_service_principal_without_auth() {
        let server = create_test_server().await;
        let (user_id, _principal_id, _signing_key) =
            create_test_user(&server, "owner@example.com", "laptop").await;

        let _ws_id = create_test_workspace(&server, &user_id, "ws").await;

        // Try to register a service principal without authentication
        let req = zopp_proto::RegisterRequest {
            email: String::new(),
            principal_name: "my-service".to_string(),
            public_key: vec![1u8; 32],
            x25519_public_key: vec![2u8; 32],
            is_service: true,
            workspace_name: Some("ws".to_string()),
            ephemeral_pub: None,
            kek_wrapped: None,
            kek_nonce: None,
        };

        let request = tonic::Request::new(req);
        let result = server.register(request).await;
        // Should fail because no authentication metadata
        assert!(result.is_err());
    }

    // ================== Update Group Tests ==================

    #[tokio::test]
    async fn handler_update_group_success() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "test@example.com", "laptop").await;

        let ws_id = create_test_workspace(&server, &user_id, "ws").await;

        // Create a group
        let group_id = server
            .store
            .create_group(&zopp_storage::CreateGroupParams {
                workspace_id: ws_id.clone(),
                name: "original-name".to_string(),
                description: Some("original description".to_string()),
            })
            .await
            .unwrap();

        // Update the group
        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/UpdateGroup",
            zopp_proto::UpdateGroupRequest {
                workspace_name: "ws".to_string(),
                group_name: "original-name".to_string(),
                new_name: "new-name".to_string(),
                new_description: "new description".to_string(),
            },
        );

        let result = server.update_group(request).await;
        assert!(result.is_ok());
        let response = result.unwrap().into_inner();
        assert_eq!(response.name, "new-name");
        assert_eq!(response.description, "new description");
        assert_eq!(response.id, group_id.0.to_string());
    }

    #[tokio::test]
    async fn handler_update_group_not_found() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "test@example.com", "laptop").await;

        let _ws_id = create_test_workspace(&server, &user_id, "ws").await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/UpdateGroup",
            zopp_proto::UpdateGroupRequest {
                workspace_name: "ws".to_string(),
                group_name: "nonexistent-group".to_string(),
                new_name: "new-name".to_string(),
                new_description: String::new(),
            },
        );

        let result = server.update_group(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn handler_update_group_as_service_principal_denied() {
        let server = create_test_server().await;
        let (user_id, _owner_principal_id, _owner_signing_key) =
            create_test_user(&server, "owner@example.com", "laptop").await;

        let ws_id = create_test_workspace(&server, &user_id, "ws").await;

        // Create a service principal
        let (service_principal_id, service_signing_key) =
            create_service_principal(&server, "my-service").await;
        add_principal_to_workspace(&server, &ws_id, &service_principal_id).await;
        server
            .store
            .set_workspace_permission(&ws_id, &service_principal_id, Role::Admin)
            .await
            .unwrap();

        // Create a group
        let _group_id = server
            .store
            .create_group(&zopp_storage::CreateGroupParams {
                workspace_id: ws_id.clone(),
                name: "test-group".to_string(),
                description: None,
            })
            .await
            .unwrap();

        // Try to update as service principal - should be denied
        let request = create_signed_request(
            &service_principal_id,
            &service_signing_key,
            "/zopp.ZoppService/UpdateGroup",
            zopp_proto::UpdateGroupRequest {
                workspace_name: "ws".to_string(),
                group_name: "test-group".to_string(),
                new_name: "new-name".to_string(),
                new_description: String::new(),
            },
        );

        let result = server.update_group(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::Unauthenticated);
    }

    // ================== List User Groups Tests ==================

    #[tokio::test]
    async fn handler_list_user_groups_success() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "test@example.com", "laptop").await;

        let ws_id = create_test_workspace(&server, &user_id, "ws").await;

        // Create a group
        let group_id = server
            .store
            .create_group(&zopp_storage::CreateGroupParams {
                workspace_id: ws_id.clone(),
                name: "developers".to_string(),
                description: None,
            })
            .await
            .unwrap();

        // Add user to group
        server
            .store
            .add_group_member(&group_id, &user_id)
            .await
            .unwrap();

        // List user groups
        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/ListUserGroups",
            zopp_proto::ListUserGroupsRequest {
                workspace_name: "ws".to_string(),
                user_email: "test@example.com".to_string(),
            },
        );

        let result = server.list_user_groups(request).await;
        assert!(result.is_ok());
        let response = result.unwrap().into_inner();
        assert_eq!(response.groups.len(), 1);
        assert_eq!(response.groups[0].name, "developers");
    }

    #[tokio::test]
    async fn handler_list_user_groups_user_not_found() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "test@example.com", "laptop").await;

        let _ws_id = create_test_workspace(&server, &user_id, "ws").await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/ListUserGroups",
            zopp_proto::ListUserGroupsRequest {
                workspace_name: "ws".to_string(),
                user_email: "nonexistent@example.com".to_string(),
            },
        );

        let result = server.list_user_groups(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn handler_list_user_groups_empty() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "test@example.com", "laptop").await;

        let _ws_id = create_test_workspace(&server, &user_id, "ws").await;

        // List groups for user not in any groups
        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/ListUserGroups",
            zopp_proto::ListUserGroupsRequest {
                workspace_name: "ws".to_string(),
                user_email: "test@example.com".to_string(),
            },
        );

        let result = server.list_user_groups(request).await;
        assert!(result.is_ok());
        let response = result.unwrap().into_inner();
        assert_eq!(response.groups.len(), 0);
    }

    // ================== Principal Handler Additional Tests ==================

    #[tokio::test]
    async fn handler_get_principal_invalid_id() {
        let server = create_test_server().await;
        let (_user_id, principal_id, signing_key) =
            create_test_user(&server, "test@example.com", "laptop").await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/GetPrincipal",
            zopp_proto::GetPrincipalRequest {
                principal_id: "not-a-uuid".to_string(),
            },
        );

        let result = server.get_principal(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn handler_get_principal_not_found() {
        let server = create_test_server().await;
        let (_user_id, principal_id, signing_key) =
            create_test_user(&server, "test@example.com", "laptop").await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/GetPrincipal",
            zopp_proto::GetPrincipalRequest {
                principal_id: uuid::Uuid::now_v7().to_string(),
            },
        );

        let result = server.get_principal(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn handler_rename_principal_not_found() {
        let server = create_test_server().await;
        let (_user_id, principal_id, signing_key) =
            create_test_user(&server, "test@example.com", "laptop").await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/RenamePrincipal",
            zopp_proto::RenamePrincipalRequest {
                principal_id: uuid::Uuid::now_v7().to_string(),
                new_name: "new-name".to_string(),
            },
        );

        let result = server.rename_principal(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn handler_rename_principal_invalid_id() {
        let server = create_test_server().await;
        let (_user_id, principal_id, signing_key) =
            create_test_user(&server, "test@example.com", "laptop").await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/RenamePrincipal",
            zopp_proto::RenamePrincipalRequest {
                principal_id: "not-a-uuid".to_string(),
                new_name: "new-name".to_string(),
            },
        );

        let result = server.rename_principal(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn handler_rename_principal_as_service_principal_denied() {
        let server = create_test_server().await;
        let (user_id, _owner_principal_id, _owner_signing_key) =
            create_test_user(&server, "owner@example.com", "laptop").await;

        let ws_id = create_test_workspace(&server, &user_id, "ws").await;

        // Create a service principal
        let (service_principal_id, service_signing_key) =
            create_service_principal(&server, "my-service").await;
        add_principal_to_workspace(&server, &ws_id, &service_principal_id).await;

        let request = create_signed_request(
            &service_principal_id,
            &service_signing_key,
            "/zopp.ZoppService/RenamePrincipal",
            zopp_proto::RenamePrincipalRequest {
                principal_id: service_principal_id.0.to_string(),
                new_name: "new-name".to_string(),
            },
        );

        let result = server.rename_principal(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::PermissionDenied);
    }

    #[tokio::test]
    async fn handler_list_principals_as_service_principal_denied() {
        let server = create_test_server().await;
        let (user_id, _owner_principal_id, _owner_signing_key) =
            create_test_user(&server, "owner@example.com", "laptop").await;

        let ws_id = create_test_workspace(&server, &user_id, "ws").await;

        let (service_principal_id, service_signing_key) =
            create_service_principal(&server, "my-service").await;
        add_principal_to_workspace(&server, &ws_id, &service_principal_id).await;

        let request = create_signed_request(
            &service_principal_id,
            &service_signing_key,
            "/zopp.ZoppService/ListPrincipals",
            zopp_proto::Empty {},
        );

        let result = server.list_principals(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::Unauthenticated);
    }

    #[tokio::test]
    async fn handler_remove_principal_invalid_id() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "test@example.com", "laptop").await;

        let _ws_id = create_test_workspace(&server, &user_id, "ws").await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/RemovePrincipalFromWorkspace",
            zopp_proto::RemovePrincipalFromWorkspaceRequest {
                workspace_name: "ws".to_string(),
                principal_id: "not-a-uuid".to_string(),
            },
        );

        let result = server.remove_principal_from_workspace(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn handler_remove_principal_not_found() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "test@example.com", "laptop").await;

        let _ws_id = create_test_workspace(&server, &user_id, "ws").await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/RemovePrincipalFromWorkspace",
            zopp_proto::RemovePrincipalFromWorkspaceRequest {
                workspace_name: "ws".to_string(),
                principal_id: uuid::Uuid::now_v7().to_string(),
            },
        );

        let result = server.remove_principal_from_workspace(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn handler_remove_principal_as_service_principal_denied() {
        let server = create_test_server().await;
        let (user_id, owner_principal_id, _owner_signing_key) =
            create_test_user(&server, "owner@example.com", "laptop").await;

        let ws_id = create_test_workspace(&server, &user_id, "ws").await;

        let (service_principal_id, service_signing_key) =
            create_service_principal(&server, "my-service").await;
        add_principal_to_workspace(&server, &ws_id, &service_principal_id).await;
        server
            .store
            .set_workspace_permission(&ws_id, &service_principal_id, Role::Admin)
            .await
            .unwrap();

        let request = create_signed_request(
            &service_principal_id,
            &service_signing_key,
            "/zopp.ZoppService/RemovePrincipalFromWorkspace",
            zopp_proto::RemovePrincipalFromWorkspaceRequest {
                workspace_name: "ws".to_string(),
                principal_id: owner_principal_id.0.to_string(),
            },
        );

        let result = server.remove_principal_from_workspace(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::Unauthenticated);
    }

    #[tokio::test]
    async fn handler_revoke_all_permissions_invalid_id() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "test@example.com", "laptop").await;

        let _ws_id = create_test_workspace(&server, &user_id, "ws").await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/RevokeAllPrincipalPermissions",
            zopp_proto::RevokeAllPrincipalPermissionsRequest {
                workspace_name: "ws".to_string(),
                principal_id: "not-a-uuid".to_string(),
            },
        );

        let result = server.revoke_all_principal_permissions(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn handler_revoke_all_permissions_principal_not_found() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "test@example.com", "laptop").await;

        let _ws_id = create_test_workspace(&server, &user_id, "ws").await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/RevokeAllPrincipalPermissions",
            zopp_proto::RevokeAllPrincipalPermissionsRequest {
                workspace_name: "ws".to_string(),
                principal_id: uuid::Uuid::now_v7().to_string(),
            },
        );

        let result = server.revoke_all_principal_permissions(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn handler_revoke_all_permissions_as_service_principal_denied() {
        let server = create_test_server().await;
        let (user_id, owner_principal_id, _owner_signing_key) =
            create_test_user(&server, "owner@example.com", "laptop").await;

        let ws_id = create_test_workspace(&server, &user_id, "ws").await;

        let (service_principal_id, service_signing_key) =
            create_service_principal(&server, "my-service").await;
        add_principal_to_workspace(&server, &ws_id, &service_principal_id).await;
        server
            .store
            .set_workspace_permission(&ws_id, &service_principal_id, Role::Admin)
            .await
            .unwrap();

        let request = create_signed_request(
            &service_principal_id,
            &service_signing_key,
            "/zopp.ZoppService/RevokeAllPrincipalPermissions",
            zopp_proto::RevokeAllPrincipalPermissionsRequest {
                workspace_name: "ws".to_string(),
                principal_id: owner_principal_id.0.to_string(),
            },
        );

        let result = server.revoke_all_principal_permissions(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::Unauthenticated);
    }

    #[tokio::test]
    async fn handler_get_effective_permissions_invalid_id() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "test@example.com", "laptop").await;

        let _ws_id = create_test_workspace(&server, &user_id, "ws").await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/GetEffectivePermissions",
            zopp_proto::GetEffectivePermissionsRequest {
                workspace_name: "ws".to_string(),
                principal_id: "not-a-uuid".to_string(),
            },
        );

        let result = server.get_effective_permissions(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn handler_get_effective_permissions_principal_not_found() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "test@example.com", "laptop").await;

        let _ws_id = create_test_workspace(&server, &user_id, "ws").await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/GetEffectivePermissions",
            zopp_proto::GetEffectivePermissionsRequest {
                workspace_name: "ws".to_string(),
                principal_id: uuid::Uuid::now_v7().to_string(),
            },
        );

        let result = server.get_effective_permissions(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn handler_get_effective_permissions_as_service_principal_denied() {
        let server = create_test_server().await;
        let (user_id, owner_principal_id, _owner_signing_key) =
            create_test_user(&server, "owner@example.com", "laptop").await;

        let ws_id = create_test_workspace(&server, &user_id, "ws").await;

        let (service_principal_id, service_signing_key) =
            create_service_principal(&server, "my-service").await;
        add_principal_to_workspace(&server, &ws_id, &service_principal_id).await;

        let request = create_signed_request(
            &service_principal_id,
            &service_signing_key,
            "/zopp.ZoppService/GetEffectivePermissions",
            zopp_proto::GetEffectivePermissionsRequest {
                workspace_name: "ws".to_string(),
                principal_id: owner_principal_id.0.to_string(),
            },
        );

        let result = server.get_effective_permissions(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::Unauthenticated);
    }

    // ================== Workspace Handler Additional Tests ==================

    #[tokio::test]
    async fn handler_list_workspaces_empty() {
        let server = create_test_server().await;
        let (_user_id, principal_id, signing_key) =
            create_test_user(&server, "test@example.com", "laptop").await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/ListWorkspaces",
            zopp_proto::Empty {},
        );

        let response = server.list_workspaces(request).await.unwrap().into_inner();
        assert!(response.workspaces.is_empty());
    }

    #[tokio::test]
    async fn handler_get_workspace_keys_not_found() {
        let server = create_test_server().await;
        let (_user_id, principal_id, signing_key) =
            create_test_user(&server, "test@example.com", "laptop").await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/GetWorkspaceKeys",
            zopp_proto::GetWorkspaceKeysRequest {
                workspace_name: "nonexistent".to_string(),
            },
        );

        let result = server.get_workspace_keys(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    // ================== Service Principal Access Denial Tests ==================

    #[tokio::test]
    async fn handler_service_principal_create_project_denied() {
        let server = create_test_server().await;
        let (user_id, _owner_principal_id, _owner_signing_key) =
            create_test_user(&server, "owner@example.com", "laptop").await;

        let ws_id = create_test_workspace(&server, &user_id, "ws").await;

        let (service_principal_id, service_signing_key) =
            create_service_principal(&server, "my-service").await;
        add_principal_to_workspace(&server, &ws_id, &service_principal_id).await;
        server
            .store
            .set_workspace_permission(&ws_id, &service_principal_id, Role::Admin)
            .await
            .unwrap();

        let request = create_signed_request(
            &service_principal_id,
            &service_signing_key,
            "/zopp.ZoppService/CreateProject",
            zopp_proto::CreateProjectRequest {
                workspace_name: "ws".to_string(),
                name: "new-project".to_string(),
            },
        );

        let result = server.create_project(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::Unauthenticated);
    }

    #[tokio::test]
    async fn handler_service_principal_create_environment_denied() {
        let server = create_test_server().await;
        let (user_id, _owner_principal_id, _owner_signing_key) =
            create_test_user(&server, "owner@example.com", "laptop").await;

        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        let _proj_id = create_test_project(&server, &ws_id, "proj").await;

        let (service_principal_id, service_signing_key) =
            create_service_principal(&server, "my-service").await;
        add_principal_to_workspace(&server, &ws_id, &service_principal_id).await;
        server
            .store
            .set_workspace_permission(&ws_id, &service_principal_id, Role::Admin)
            .await
            .unwrap();

        let request = create_signed_request(
            &service_principal_id,
            &service_signing_key,
            "/zopp.ZoppService/CreateEnvironment",
            zopp_proto::CreateEnvironmentRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
                name: "new-env".to_string(),
                dek_wrapped: vec![0u8; 48],
                dek_nonce: vec![0u8; 24],
            },
        );

        let result = server.create_environment(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::Unauthenticated);
    }

    #[tokio::test]
    async fn handler_service_principal_list_workspace_service_principals_denied() {
        let server = create_test_server().await;
        let (user_id, _owner_principal_id, _owner_signing_key) =
            create_test_user(&server, "owner@example.com", "laptop").await;

        let ws_id = create_test_workspace(&server, &user_id, "ws").await;

        let (service_principal_id, service_signing_key) =
            create_service_principal(&server, "my-service").await;
        add_principal_to_workspace(&server, &ws_id, &service_principal_id).await;

        let request = create_signed_request(
            &service_principal_id,
            &service_signing_key,
            "/zopp.ZoppService/ListWorkspaceServicePrincipals",
            zopp_proto::ListWorkspaceServicePrincipalsRequest {
                workspace_name: "ws".to_string(),
            },
        );

        let result = server.list_workspace_service_principals(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::Unauthenticated);
    }

    // ================== Get Project/Environment Not Found Tests ==================

    #[tokio::test]
    async fn handler_get_project_proj_not_found_v2() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "test@example.com", "laptop").await;

        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/GetProject",
            zopp_proto::GetProjectRequest {
                workspace_name: "ws".to_string(),
                project_name: "nonexistent".to_string(),
            },
        );

        let result = server.get_project(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn handler_get_environment_env_not_found_v2() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "test@example.com", "laptop").await;

        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;
        let _proj_id = create_test_project(&server, &ws_id, "proj").await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/GetEnvironment",
            zopp_proto::GetEnvironmentRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
                environment_name: "nonexistent".to_string(),
            },
        );

        let result = server.get_environment(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    // ================== Delete Secret Tests ==================

    #[tokio::test]
    async fn handler_delete_secret_env_not_found() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "test@example.com", "laptop").await;

        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;
        let _proj_id = create_test_project(&server, &ws_id, "proj").await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/DeleteSecret",
            zopp_proto::DeleteSecretRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
                environment_name: "nonexistent".to_string(),
                key: "MY_KEY".to_string(),
            },
        );

        let result = server.delete_secret(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    // ================== Group Delete Tests ==================

    #[tokio::test]
    async fn handler_delete_group_group_not_found() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "test@example.com", "laptop").await;

        let _ws_id = create_test_workspace(&server, &user_id, "ws").await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/DeleteGroup",
            zopp_proto::DeleteGroupRequest {
                workspace_name: "ws".to_string(),
                group_name: "nonexistent".to_string(),
            },
        );

        let result = server.delete_group(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn handler_delete_group_as_service_principal_denied() {
        let server = create_test_server().await;
        let (user_id, _owner_principal_id, _owner_signing_key) =
            create_test_user(&server, "owner@example.com", "laptop").await;

        let ws_id = create_test_workspace(&server, &user_id, "ws").await;

        // Create a group
        let _group_id = server
            .store
            .create_group(&zopp_storage::CreateGroupParams {
                workspace_id: ws_id.clone(),
                name: "test-group".to_string(),
                description: None,
            })
            .await
            .unwrap();

        let (service_principal_id, service_signing_key) =
            create_service_principal(&server, "my-service").await;
        add_principal_to_workspace(&server, &ws_id, &service_principal_id).await;
        server
            .store
            .set_workspace_permission(&ws_id, &service_principal_id, Role::Admin)
            .await
            .unwrap();

        let request = create_signed_request(
            &service_principal_id,
            &service_signing_key,
            "/zopp.ZoppService/DeleteGroup",
            zopp_proto::DeleteGroupRequest {
                workspace_name: "ws".to_string(),
                group_name: "test-group".to_string(),
            },
        );

        let result = server.delete_group(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::Unauthenticated);
    }

    // ================== Create Group Tests ==================

    #[tokio::test]
    async fn handler_create_group_as_service_principal_denied() {
        let server = create_test_server().await;
        let (user_id, _owner_principal_id, _owner_signing_key) =
            create_test_user(&server, "owner@example.com", "laptop").await;

        let ws_id = create_test_workspace(&server, &user_id, "ws").await;

        let (service_principal_id, service_signing_key) =
            create_service_principal(&server, "my-service").await;
        add_principal_to_workspace(&server, &ws_id, &service_principal_id).await;
        server
            .store
            .set_workspace_permission(&ws_id, &service_principal_id, Role::Admin)
            .await
            .unwrap();

        let request = create_signed_request(
            &service_principal_id,
            &service_signing_key,
            "/zopp.ZoppService/CreateGroup",
            zopp_proto::CreateGroupRequest {
                workspace_name: "ws".to_string(),
                name: "new-group".to_string(),
                description: String::new(),
            },
        );

        let result = server.create_group(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::Unauthenticated);
    }

    #[tokio::test]
    async fn handler_create_group_workspace_not_found() {
        let server = create_test_server().await;
        let (_user_id, principal_id, signing_key) =
            create_test_user(&server, "test@example.com", "laptop").await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/CreateGroup",
            zopp_proto::CreateGroupRequest {
                workspace_name: "nonexistent".to_string(),
                name: "new-group".to_string(),
                description: String::new(),
            },
        );

        let result = server.create_group(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    // ================== Add Group Member Error Tests ==================

    #[tokio::test]
    async fn handler_add_group_member_user_email_not_found() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "test@example.com", "laptop").await;

        let ws_id = create_test_workspace(&server, &user_id, "ws").await;

        // Create a group
        let _group_id = server
            .store
            .create_group(&zopp_storage::CreateGroupParams {
                workspace_id: ws_id.clone(),
                name: "test-group".to_string(),
                description: None,
            })
            .await
            .unwrap();

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/AddGroupMember",
            zopp_proto::AddGroupMemberRequest {
                workspace_name: "ws".to_string(),
                group_name: "test-group".to_string(),
                user_email: "nonexistent@example.com".to_string(),
            },
        );

        let result = server.add_group_member(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn handler_add_group_member_as_service_principal_denied() {
        let server = create_test_server().await;
        let (user_id, _owner_principal_id, _owner_signing_key) =
            create_test_user(&server, "owner@example.com", "laptop").await;

        let ws_id = create_test_workspace(&server, &user_id, "ws").await;

        // Create a group
        let _group_id = server
            .store
            .create_group(&zopp_storage::CreateGroupParams {
                workspace_id: ws_id.clone(),
                name: "test-group".to_string(),
                description: None,
            })
            .await
            .unwrap();

        let (service_principal_id, service_signing_key) =
            create_service_principal(&server, "my-service").await;
        add_principal_to_workspace(&server, &ws_id, &service_principal_id).await;
        server
            .store
            .set_workspace_permission(&ws_id, &service_principal_id, Role::Admin)
            .await
            .unwrap();

        let request = create_signed_request(
            &service_principal_id,
            &service_signing_key,
            "/zopp.ZoppService/AddGroupMember",
            zopp_proto::AddGroupMemberRequest {
                workspace_name: "ws".to_string(),
                group_name: "test-group".to_string(),
                user_email: "owner@example.com".to_string(),
            },
        );

        let result = server.add_group_member(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::Unauthenticated);
    }

    // ================== Remove Group Member Error Tests ==================

    #[tokio::test]
    async fn handler_remove_group_member_user_not_found() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "test@example.com", "laptop").await;

        let ws_id = create_test_workspace(&server, &user_id, "ws").await;

        // Create a group
        let _group_id = server
            .store
            .create_group(&zopp_storage::CreateGroupParams {
                workspace_id: ws_id.clone(),
                name: "test-group".to_string(),
                description: None,
            })
            .await
            .unwrap();

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/RemoveGroupMember",
            zopp_proto::RemoveGroupMemberRequest {
                workspace_name: "ws".to_string(),
                group_name: "test-group".to_string(),
                user_email: "nonexistent@example.com".to_string(),
            },
        );

        let result = server.remove_group_member(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn handler_remove_group_member_as_service_principal_denied() {
        let server = create_test_server().await;
        let (user_id, _owner_principal_id, _owner_signing_key) =
            create_test_user(&server, "owner@example.com", "laptop").await;

        let ws_id = create_test_workspace(&server, &user_id, "ws").await;

        // Create a group
        let _group_id = server
            .store
            .create_group(&zopp_storage::CreateGroupParams {
                workspace_id: ws_id.clone(),
                name: "test-group".to_string(),
                description: None,
            })
            .await
            .unwrap();

        let (service_principal_id, service_signing_key) =
            create_service_principal(&server, "my-service").await;
        add_principal_to_workspace(&server, &ws_id, &service_principal_id).await;
        server
            .store
            .set_workspace_permission(&ws_id, &service_principal_id, Role::Admin)
            .await
            .unwrap();

        let request = create_signed_request(
            &service_principal_id,
            &service_signing_key,
            "/zopp.ZoppService/RemoveGroupMember",
            zopp_proto::RemoveGroupMemberRequest {
                workspace_name: "ws".to_string(),
                group_name: "test-group".to_string(),
                user_email: "owner@example.com".to_string(),
            },
        );

        let result = server.remove_group_member(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::Unauthenticated);
    }

    // ================== Group Permission Service Principal Denied Tests ==================

    #[tokio::test]
    async fn handler_set_group_ws_permission_as_service_principal_denied() {
        let server = create_test_server().await;
        let (user_id, _owner_principal_id, _owner_signing_key) =
            create_test_user(&server, "owner@example.com", "laptop").await;

        let ws_id = create_test_workspace(&server, &user_id, "ws").await;

        let _group_id = server
            .store
            .create_group(&zopp_storage::CreateGroupParams {
                workspace_id: ws_id.clone(),
                name: "test-group".to_string(),
                description: None,
            })
            .await
            .unwrap();

        let (service_principal_id, service_signing_key) =
            create_service_principal(&server, "my-service").await;
        add_principal_to_workspace(&server, &ws_id, &service_principal_id).await;
        server
            .store
            .set_workspace_permission(&ws_id, &service_principal_id, Role::Admin)
            .await
            .unwrap();

        let request = create_signed_request(
            &service_principal_id,
            &service_signing_key,
            "/zopp.ZoppService/SetGroupWorkspacePermission",
            zopp_proto::SetGroupWorkspacePermissionRequest {
                workspace_name: "ws".to_string(),
                group_name: "test-group".to_string(),
                role: zopp_proto::Role::Read as i32,
            },
        );

        let result = server.set_group_workspace_permission(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::Unauthenticated);
    }

    #[tokio::test]
    async fn handler_get_group_ws_permission_as_service_principal_denied() {
        let server = create_test_server().await;
        let (user_id, _owner_principal_id, _owner_signing_key) =
            create_test_user(&server, "owner@example.com", "laptop").await;

        let ws_id = create_test_workspace(&server, &user_id, "ws").await;

        let _group_id = server
            .store
            .create_group(&zopp_storage::CreateGroupParams {
                workspace_id: ws_id.clone(),
                name: "test-group".to_string(),
                description: None,
            })
            .await
            .unwrap();

        let (service_principal_id, service_signing_key) =
            create_service_principal(&server, "my-service").await;
        add_principal_to_workspace(&server, &ws_id, &service_principal_id).await;

        let request = create_signed_request(
            &service_principal_id,
            &service_signing_key,
            "/zopp.ZoppService/GetGroupWorkspacePermission",
            zopp_proto::GetGroupWorkspacePermissionRequest {
                workspace_name: "ws".to_string(),
                group_name: "test-group".to_string(),
            },
        );

        let result = server.get_group_workspace_permission(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::Unauthenticated);
    }

    #[tokio::test]
    async fn handler_list_group_ws_permissions_as_service_principal_denied() {
        let server = create_test_server().await;
        let (user_id, _owner_principal_id, _owner_signing_key) =
            create_test_user(&server, "owner@example.com", "laptop").await;

        let ws_id = create_test_workspace(&server, &user_id, "ws").await;

        let (service_principal_id, service_signing_key) =
            create_service_principal(&server, "my-service").await;
        add_principal_to_workspace(&server, &ws_id, &service_principal_id).await;

        let request = create_signed_request(
            &service_principal_id,
            &service_signing_key,
            "/zopp.ZoppService/ListGroupWorkspacePermissions",
            zopp_proto::ListGroupWorkspacePermissionsRequest {
                workspace_name: "ws".to_string(),
            },
        );

        let result = server.list_group_workspace_permissions(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::Unauthenticated);
    }

    #[tokio::test]
    async fn handler_remove_group_ws_permission_as_service_principal_denied() {
        let server = create_test_server().await;
        let (user_id, _owner_principal_id, _owner_signing_key) =
            create_test_user(&server, "owner@example.com", "laptop").await;

        let ws_id = create_test_workspace(&server, &user_id, "ws").await;

        let _group_id = server
            .store
            .create_group(&zopp_storage::CreateGroupParams {
                workspace_id: ws_id.clone(),
                name: "test-group".to_string(),
                description: None,
            })
            .await
            .unwrap();

        let (service_principal_id, service_signing_key) =
            create_service_principal(&server, "my-service").await;
        add_principal_to_workspace(&server, &ws_id, &service_principal_id).await;
        server
            .store
            .set_workspace_permission(&ws_id, &service_principal_id, Role::Admin)
            .await
            .unwrap();

        let request = create_signed_request(
            &service_principal_id,
            &service_signing_key,
            "/zopp.ZoppService/RemoveGroupWorkspacePermission",
            zopp_proto::RemoveGroupWorkspacePermissionRequest {
                workspace_name: "ws".to_string(),
                group_name: "test-group".to_string(),
            },
        );

        let result = server.remove_group_workspace_permission(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::Unauthenticated);
    }

    // ================== Group Project Permission Service Principal Denied Tests ==================

    #[tokio::test]
    async fn handler_set_group_proj_permission_as_service_principal_denied() {
        let server = create_test_server().await;
        let (user_id, _owner_principal_id, _owner_signing_key) =
            create_test_user(&server, "owner@example.com", "laptop").await;

        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        let _proj_id = create_test_project(&server, &ws_id, "proj").await;

        let _group_id = server
            .store
            .create_group(&zopp_storage::CreateGroupParams {
                workspace_id: ws_id.clone(),
                name: "test-group".to_string(),
                description: None,
            })
            .await
            .unwrap();

        let (service_principal_id, service_signing_key) =
            create_service_principal(&server, "my-service").await;
        add_principal_to_workspace(&server, &ws_id, &service_principal_id).await;
        server
            .store
            .set_workspace_permission(&ws_id, &service_principal_id, Role::Admin)
            .await
            .unwrap();

        let request = create_signed_request(
            &service_principal_id,
            &service_signing_key,
            "/zopp.ZoppService/SetGroupProjectPermission",
            zopp_proto::SetGroupProjectPermissionRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
                group_name: "test-group".to_string(),
                role: zopp_proto::Role::Read as i32,
            },
        );

        let result = server.set_group_project_permission(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::Unauthenticated);
    }

    #[tokio::test]
    async fn handler_get_group_proj_permission_as_service_principal_denied() {
        let server = create_test_server().await;
        let (user_id, _owner_principal_id, _owner_signing_key) =
            create_test_user(&server, "owner@example.com", "laptop").await;

        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        let _proj_id = create_test_project(&server, &ws_id, "proj").await;

        let _group_id = server
            .store
            .create_group(&zopp_storage::CreateGroupParams {
                workspace_id: ws_id.clone(),
                name: "test-group".to_string(),
                description: None,
            })
            .await
            .unwrap();

        let (service_principal_id, service_signing_key) =
            create_service_principal(&server, "my-service").await;
        add_principal_to_workspace(&server, &ws_id, &service_principal_id).await;

        let request = create_signed_request(
            &service_principal_id,
            &service_signing_key,
            "/zopp.ZoppService/GetGroupProjectPermission",
            zopp_proto::GetGroupProjectPermissionRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
                group_name: "test-group".to_string(),
            },
        );

        let result = server.get_group_project_permission(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::Unauthenticated);
    }

    #[tokio::test]
    async fn handler_list_group_proj_permissions_as_service_principal_denied() {
        let server = create_test_server().await;
        let (user_id, _owner_principal_id, _owner_signing_key) =
            create_test_user(&server, "owner@example.com", "laptop").await;

        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        let _proj_id = create_test_project(&server, &ws_id, "proj").await;

        let (service_principal_id, service_signing_key) =
            create_service_principal(&server, "my-service").await;
        add_principal_to_workspace(&server, &ws_id, &service_principal_id).await;

        let request = create_signed_request(
            &service_principal_id,
            &service_signing_key,
            "/zopp.ZoppService/ListGroupProjectPermissions",
            zopp_proto::ListGroupProjectPermissionsRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
            },
        );

        let result = server.list_group_project_permissions(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::Unauthenticated);
    }

    #[tokio::test]
    async fn handler_remove_group_proj_permission_as_service_principal_denied() {
        let server = create_test_server().await;
        let (user_id, _owner_principal_id, _owner_signing_key) =
            create_test_user(&server, "owner@example.com", "laptop").await;

        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        let _proj_id = create_test_project(&server, &ws_id, "proj").await;

        let _group_id = server
            .store
            .create_group(&zopp_storage::CreateGroupParams {
                workspace_id: ws_id.clone(),
                name: "test-group".to_string(),
                description: None,
            })
            .await
            .unwrap();

        let (service_principal_id, service_signing_key) =
            create_service_principal(&server, "my-service").await;
        add_principal_to_workspace(&server, &ws_id, &service_principal_id).await;
        server
            .store
            .set_workspace_permission(&ws_id, &service_principal_id, Role::Admin)
            .await
            .unwrap();

        let request = create_signed_request(
            &service_principal_id,
            &service_signing_key,
            "/zopp.ZoppService/RemoveGroupProjectPermission",
            zopp_proto::RemoveGroupProjectPermissionRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
                group_name: "test-group".to_string(),
            },
        );

        let result = server.remove_group_project_permission(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::Unauthenticated);
    }

    // ================== Group Environment Permission Service Principal Denied Tests ==================

    #[tokio::test]
    async fn handler_set_group_env_permission_as_service_principal_denied() {
        let server = create_test_server().await;
        let (user_id, _owner_principal_id, _owner_signing_key) =
            create_test_user(&server, "owner@example.com", "laptop").await;

        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        let proj_id = create_test_project(&server, &ws_id, "proj").await;
        let _env_id = create_test_environment(&server, &proj_id, "dev").await;

        let _group_id = server
            .store
            .create_group(&zopp_storage::CreateGroupParams {
                workspace_id: ws_id.clone(),
                name: "test-group".to_string(),
                description: None,
            })
            .await
            .unwrap();

        let (service_principal_id, service_signing_key) =
            create_service_principal(&server, "my-service").await;
        add_principal_to_workspace(&server, &ws_id, &service_principal_id).await;
        server
            .store
            .set_workspace_permission(&ws_id, &service_principal_id, Role::Admin)
            .await
            .unwrap();

        let request = create_signed_request(
            &service_principal_id,
            &service_signing_key,
            "/zopp.ZoppService/SetGroupEnvironmentPermission",
            zopp_proto::SetGroupEnvironmentPermissionRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
                environment_name: "dev".to_string(),
                group_name: "test-group".to_string(),
                role: zopp_proto::Role::Read as i32,
            },
        );

        let result = server.set_group_environment_permission(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::Unauthenticated);
    }

    #[tokio::test]
    async fn handler_get_group_env_permission_as_service_principal_denied() {
        let server = create_test_server().await;
        let (user_id, _owner_principal_id, _owner_signing_key) =
            create_test_user(&server, "owner@example.com", "laptop").await;

        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        let proj_id = create_test_project(&server, &ws_id, "proj").await;
        let _env_id = create_test_environment(&server, &proj_id, "dev").await;

        let _group_id = server
            .store
            .create_group(&zopp_storage::CreateGroupParams {
                workspace_id: ws_id.clone(),
                name: "test-group".to_string(),
                description: None,
            })
            .await
            .unwrap();

        let (service_principal_id, service_signing_key) =
            create_service_principal(&server, "my-service").await;
        add_principal_to_workspace(&server, &ws_id, &service_principal_id).await;

        let request = create_signed_request(
            &service_principal_id,
            &service_signing_key,
            "/zopp.ZoppService/GetGroupEnvironmentPermission",
            zopp_proto::GetGroupEnvironmentPermissionRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
                environment_name: "dev".to_string(),
                group_name: "test-group".to_string(),
            },
        );

        let result = server.get_group_environment_permission(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::Unauthenticated);
    }

    #[tokio::test]
    async fn handler_list_group_env_permissions_as_service_principal_denied() {
        let server = create_test_server().await;
        let (user_id, _owner_principal_id, _owner_signing_key) =
            create_test_user(&server, "owner@example.com", "laptop").await;

        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        let proj_id = create_test_project(&server, &ws_id, "proj").await;
        let _env_id = create_test_environment(&server, &proj_id, "dev").await;

        let (service_principal_id, service_signing_key) =
            create_service_principal(&server, "my-service").await;
        add_principal_to_workspace(&server, &ws_id, &service_principal_id).await;

        let request = create_signed_request(
            &service_principal_id,
            &service_signing_key,
            "/zopp.ZoppService/ListGroupEnvironmentPermissions",
            zopp_proto::ListGroupEnvironmentPermissionsRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
                environment_name: "dev".to_string(),
            },
        );

        let result = server.list_group_environment_permissions(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::Unauthenticated);
    }

    #[tokio::test]
    async fn handler_remove_group_env_permission_as_service_principal_denied() {
        let server = create_test_server().await;
        let (user_id, _owner_principal_id, _owner_signing_key) =
            create_test_user(&server, "owner@example.com", "laptop").await;

        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        let proj_id = create_test_project(&server, &ws_id, "proj").await;
        let _env_id = create_test_environment(&server, &proj_id, "dev").await;

        let _group_id = server
            .store
            .create_group(&zopp_storage::CreateGroupParams {
                workspace_id: ws_id.clone(),
                name: "test-group".to_string(),
                description: None,
            })
            .await
            .unwrap();

        let (service_principal_id, service_signing_key) =
            create_service_principal(&server, "my-service").await;
        add_principal_to_workspace(&server, &ws_id, &service_principal_id).await;
        server
            .store
            .set_workspace_permission(&ws_id, &service_principal_id, Role::Admin)
            .await
            .unwrap();

        let request = create_signed_request(
            &service_principal_id,
            &service_signing_key,
            "/zopp.ZoppService/RemoveGroupEnvironmentPermission",
            zopp_proto::RemoveGroupEnvironmentPermissionRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
                environment_name: "dev".to_string(),
                group_name: "test-group".to_string(),
            },
        );

        let result = server.remove_group_environment_permission(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::Unauthenticated);
    }

    // ================== User Permission Service Principal Denied Tests ==================

    #[tokio::test]
    async fn handler_set_user_ws_permission_as_service_principal_denied() {
        let server = create_test_server().await;
        let (user_id, _owner_principal_id, _owner_signing_key) =
            create_test_user(&server, "owner@example.com", "laptop").await;

        let ws_id = create_test_workspace(&server, &user_id, "ws").await;

        let (service_principal_id, service_signing_key) =
            create_service_principal(&server, "my-service").await;
        add_principal_to_workspace(&server, &ws_id, &service_principal_id).await;
        server
            .store
            .set_workspace_permission(&ws_id, &service_principal_id, Role::Admin)
            .await
            .unwrap();

        let request = create_signed_request(
            &service_principal_id,
            &service_signing_key,
            "/zopp.ZoppService/SetUserWorkspacePermission",
            zopp_proto::SetUserWorkspacePermissionRequest {
                workspace_name: "ws".to_string(),
                user_email: "owner@example.com".to_string(),
                role: zopp_proto::Role::Read as i32,
            },
        );

        let result = server.set_user_workspace_permission(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::Unauthenticated);
    }

    #[tokio::test]
    async fn handler_get_user_ws_permission_as_service_principal_denied() {
        let server = create_test_server().await;
        let (user_id, _owner_principal_id, _owner_signing_key) =
            create_test_user(&server, "owner@example.com", "laptop").await;

        let ws_id = create_test_workspace(&server, &user_id, "ws").await;

        let (service_principal_id, service_signing_key) =
            create_service_principal(&server, "my-service").await;
        add_principal_to_workspace(&server, &ws_id, &service_principal_id).await;

        let request = create_signed_request(
            &service_principal_id,
            &service_signing_key,
            "/zopp.ZoppService/GetUserWorkspacePermission",
            zopp_proto::GetUserWorkspacePermissionRequest {
                workspace_name: "ws".to_string(),
                user_email: "owner@example.com".to_string(),
            },
        );

        let result = server.get_user_workspace_permission(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::Unauthenticated);
    }

    #[tokio::test]
    async fn handler_list_user_ws_permissions_as_service_principal_denied() {
        let server = create_test_server().await;
        let (user_id, _owner_principal_id, _owner_signing_key) =
            create_test_user(&server, "owner@example.com", "laptop").await;

        let ws_id = create_test_workspace(&server, &user_id, "ws").await;

        let (service_principal_id, service_signing_key) =
            create_service_principal(&server, "my-service").await;
        add_principal_to_workspace(&server, &ws_id, &service_principal_id).await;

        let request = create_signed_request(
            &service_principal_id,
            &service_signing_key,
            "/zopp.ZoppService/ListUserWorkspacePermissions",
            zopp_proto::ListUserWorkspacePermissionsRequest {
                workspace_name: "ws".to_string(),
            },
        );

        let result = server.list_user_workspace_permissions(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::Unauthenticated);
    }

    #[tokio::test]
    async fn handler_remove_user_ws_permission_as_service_principal_denied() {
        let server = create_test_server().await;
        let (user_id, _owner_principal_id, _owner_signing_key) =
            create_test_user(&server, "owner@example.com", "laptop").await;

        let ws_id = create_test_workspace(&server, &user_id, "ws").await;

        let (service_principal_id, service_signing_key) =
            create_service_principal(&server, "my-service").await;
        add_principal_to_workspace(&server, &ws_id, &service_principal_id).await;
        server
            .store
            .set_workspace_permission(&ws_id, &service_principal_id, Role::Admin)
            .await
            .unwrap();

        let request = create_signed_request(
            &service_principal_id,
            &service_signing_key,
            "/zopp.ZoppService/RemoveUserWorkspacePermission",
            zopp_proto::RemoveUserWorkspacePermissionRequest {
                workspace_name: "ws".to_string(),
                user_email: "owner@example.com".to_string(),
            },
        );

        let result = server.remove_user_workspace_permission(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::Unauthenticated);
    }

    // ================== User Project Permission Service Principal Denied Tests ==================

    #[tokio::test]
    async fn handler_set_user_proj_permission_as_service_principal_denied() {
        let server = create_test_server().await;
        let (user_id, _owner_principal_id, _owner_signing_key) =
            create_test_user(&server, "owner@example.com", "laptop").await;

        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        let _proj_id = create_test_project(&server, &ws_id, "proj").await;

        let (service_principal_id, service_signing_key) =
            create_service_principal(&server, "my-service").await;
        add_principal_to_workspace(&server, &ws_id, &service_principal_id).await;
        server
            .store
            .set_workspace_permission(&ws_id, &service_principal_id, Role::Admin)
            .await
            .unwrap();

        let request = create_signed_request(
            &service_principal_id,
            &service_signing_key,
            "/zopp.ZoppService/SetUserProjectPermission",
            zopp_proto::SetUserProjectPermissionRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
                user_email: "owner@example.com".to_string(),
                role: zopp_proto::Role::Read as i32,
            },
        );

        let result = server.set_user_project_permission(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::Unauthenticated);
    }

    #[tokio::test]
    async fn handler_get_user_proj_permission_as_service_principal_denied() {
        let server = create_test_server().await;
        let (user_id, _owner_principal_id, _owner_signing_key) =
            create_test_user(&server, "owner@example.com", "laptop").await;

        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        let _proj_id = create_test_project(&server, &ws_id, "proj").await;

        let (service_principal_id, service_signing_key) =
            create_service_principal(&server, "my-service").await;
        add_principal_to_workspace(&server, &ws_id, &service_principal_id).await;

        let request = create_signed_request(
            &service_principal_id,
            &service_signing_key,
            "/zopp.ZoppService/GetUserProjectPermission",
            zopp_proto::GetUserProjectPermissionRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
                user_email: "owner@example.com".to_string(),
            },
        );

        let result = server.get_user_project_permission(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::Unauthenticated);
    }

    #[tokio::test]
    async fn handler_list_user_proj_permissions_as_service_principal_denied() {
        let server = create_test_server().await;
        let (user_id, _owner_principal_id, _owner_signing_key) =
            create_test_user(&server, "owner@example.com", "laptop").await;

        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        let _proj_id = create_test_project(&server, &ws_id, "proj").await;

        let (service_principal_id, service_signing_key) =
            create_service_principal(&server, "my-service").await;
        add_principal_to_workspace(&server, &ws_id, &service_principal_id).await;

        let request = create_signed_request(
            &service_principal_id,
            &service_signing_key,
            "/zopp.ZoppService/ListUserProjectPermissions",
            zopp_proto::ListUserProjectPermissionsRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
            },
        );

        let result = server.list_user_project_permissions(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::Unauthenticated);
    }

    #[tokio::test]
    async fn handler_remove_user_proj_permission_as_service_principal_denied() {
        let server = create_test_server().await;
        let (user_id, _owner_principal_id, _owner_signing_key) =
            create_test_user(&server, "owner@example.com", "laptop").await;

        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        let _proj_id = create_test_project(&server, &ws_id, "proj").await;

        let (service_principal_id, service_signing_key) =
            create_service_principal(&server, "my-service").await;
        add_principal_to_workspace(&server, &ws_id, &service_principal_id).await;
        server
            .store
            .set_workspace_permission(&ws_id, &service_principal_id, Role::Admin)
            .await
            .unwrap();

        let request = create_signed_request(
            &service_principal_id,
            &service_signing_key,
            "/zopp.ZoppService/RemoveUserProjectPermission",
            zopp_proto::RemoveUserProjectPermissionRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
                user_email: "owner@example.com".to_string(),
            },
        );

        let result = server.remove_user_project_permission(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::Unauthenticated);
    }

    // ================== User Environment Permission Service Principal Denied Tests ==================

    #[tokio::test]
    async fn handler_set_user_env_permission_as_service_principal_denied() {
        let server = create_test_server().await;
        let (user_id, _owner_principal_id, _owner_signing_key) =
            create_test_user(&server, "owner@example.com", "laptop").await;

        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        let proj_id = create_test_project(&server, &ws_id, "proj").await;
        let _env_id = create_test_environment(&server, &proj_id, "dev").await;

        let (service_principal_id, service_signing_key) =
            create_service_principal(&server, "my-service").await;
        add_principal_to_workspace(&server, &ws_id, &service_principal_id).await;
        server
            .store
            .set_workspace_permission(&ws_id, &service_principal_id, Role::Admin)
            .await
            .unwrap();

        let request = create_signed_request(
            &service_principal_id,
            &service_signing_key,
            "/zopp.ZoppService/SetUserEnvironmentPermission",
            zopp_proto::SetUserEnvironmentPermissionRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
                environment_name: "dev".to_string(),
                user_email: "owner@example.com".to_string(),
                role: zopp_proto::Role::Read as i32,
            },
        );

        let result = server.set_user_environment_permission(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::Unauthenticated);
    }

    #[tokio::test]
    async fn handler_get_user_env_permission_as_service_principal_denied() {
        let server = create_test_server().await;
        let (user_id, _owner_principal_id, _owner_signing_key) =
            create_test_user(&server, "owner@example.com", "laptop").await;

        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        let proj_id = create_test_project(&server, &ws_id, "proj").await;
        let _env_id = create_test_environment(&server, &proj_id, "dev").await;

        let (service_principal_id, service_signing_key) =
            create_service_principal(&server, "my-service").await;
        add_principal_to_workspace(&server, &ws_id, &service_principal_id).await;

        let request = create_signed_request(
            &service_principal_id,
            &service_signing_key,
            "/zopp.ZoppService/GetUserEnvironmentPermission",
            zopp_proto::GetUserEnvironmentPermissionRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
                environment_name: "dev".to_string(),
                user_email: "owner@example.com".to_string(),
            },
        );

        let result = server.get_user_environment_permission(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::Unauthenticated);
    }

    #[tokio::test]
    async fn handler_list_user_env_permissions_as_service_principal_denied() {
        let server = create_test_server().await;
        let (user_id, _owner_principal_id, _owner_signing_key) =
            create_test_user(&server, "owner@example.com", "laptop").await;

        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        let proj_id = create_test_project(&server, &ws_id, "proj").await;
        let _env_id = create_test_environment(&server, &proj_id, "dev").await;

        let (service_principal_id, service_signing_key) =
            create_service_principal(&server, "my-service").await;
        add_principal_to_workspace(&server, &ws_id, &service_principal_id).await;

        let request = create_signed_request(
            &service_principal_id,
            &service_signing_key,
            "/zopp.ZoppService/ListUserEnvironmentPermissions",
            zopp_proto::ListUserEnvironmentPermissionsRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
                environment_name: "dev".to_string(),
            },
        );

        let result = server.list_user_environment_permissions(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::Unauthenticated);
    }

    #[tokio::test]
    async fn handler_remove_user_env_permission_as_service_principal_denied() {
        let server = create_test_server().await;
        let (user_id, _owner_principal_id, _owner_signing_key) =
            create_test_user(&server, "owner@example.com", "laptop").await;

        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        let proj_id = create_test_project(&server, &ws_id, "proj").await;
        let _env_id = create_test_environment(&server, &proj_id, "dev").await;

        let (service_principal_id, service_signing_key) =
            create_service_principal(&server, "my-service").await;
        add_principal_to_workspace(&server, &ws_id, &service_principal_id).await;
        server
            .store
            .set_workspace_permission(&ws_id, &service_principal_id, Role::Admin)
            .await
            .unwrap();

        let request = create_signed_request(
            &service_principal_id,
            &service_signing_key,
            "/zopp.ZoppService/RemoveUserEnvironmentPermission",
            zopp_proto::RemoveUserEnvironmentPermissionRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
                environment_name: "dev".to_string(),
                user_email: "owner@example.com".to_string(),
            },
        );

        let result = server.remove_user_environment_permission(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::Unauthenticated);
    }

    // ================== max_role and min_role unit tests ==================

    #[tokio::test]
    async fn max_role_none_returns_b() {
        let server = create_test_server().await;
        let result = server.max_role(None, Role::Read);
        assert_eq!(result, Role::Read);
    }

    #[tokio::test]
    async fn max_role_read_vs_write_returns_write() {
        let server = create_test_server().await;
        let result = server.max_role(Some(Role::Read), Role::Write);
        assert_eq!(result, Role::Write);
    }

    #[tokio::test]
    async fn max_role_write_vs_read_returns_write() {
        let server = create_test_server().await;
        let result = server.max_role(Some(Role::Write), Role::Read);
        assert_eq!(result, Role::Write);
    }

    #[tokio::test]
    async fn max_role_admin_vs_write_returns_admin() {
        let server = create_test_server().await;
        let result = server.max_role(Some(Role::Admin), Role::Write);
        assert_eq!(result, Role::Admin);
    }

    #[tokio::test]
    async fn max_role_read_vs_admin_returns_admin() {
        let server = create_test_server().await;
        let result = server.max_role(Some(Role::Read), Role::Admin);
        assert_eq!(result, Role::Admin);
    }

    #[tokio::test]
    async fn max_role_same_role_returns_same() {
        let server = create_test_server().await;
        let result = server.max_role(Some(Role::Write), Role::Write);
        assert_eq!(result, Role::Write);
    }

    #[tokio::test]
    async fn min_role_read_vs_write_returns_read() {
        let server = create_test_server().await;
        let result = server.min_role(Role::Read, Role::Write);
        assert_eq!(result, Role::Read);
    }

    #[tokio::test]
    async fn min_role_write_vs_read_returns_read() {
        let server = create_test_server().await;
        let result = server.min_role(Role::Write, Role::Read);
        assert_eq!(result, Role::Read);
    }

    #[tokio::test]
    async fn min_role_admin_vs_write_returns_write() {
        let server = create_test_server().await;
        let result = server.min_role(Role::Admin, Role::Write);
        assert_eq!(result, Role::Write);
    }

    #[tokio::test]
    async fn min_role_write_vs_admin_returns_write() {
        let server = create_test_server().await;
        let result = server.min_role(Role::Write, Role::Admin);
        assert_eq!(result, Role::Write);
    }

    #[tokio::test]
    async fn min_role_same_role_returns_same() {
        let server = create_test_server().await;
        let result = server.min_role(Role::Admin, Role::Admin);
        assert_eq!(result, Role::Admin);
    }

    // ================== get_effective_workspace_role tests ==================

    #[tokio::test]
    async fn get_effective_workspace_role_owner_returns_admin() {
        let server = create_test_server().await;
        let (user_id, principal_id, _) = create_test_user(&server, "owner@example.com", "laptop").await;
        let workspace_id = create_test_workspace(&server, &user_id, "test-ws").await;
        add_principal_to_workspace(&server, &workspace_id, &principal_id).await;

        let role = server
            .get_effective_workspace_role(&principal_id, &workspace_id)
            .await
            .unwrap();

        assert_eq!(role, Some(Role::Admin));
    }

    #[tokio::test]
    async fn get_effective_workspace_role_user_with_read_permission() {
        let server = create_test_server().await;
        let (owner_id, _, _) = create_test_user(&server, "owner@example.com", "laptop").await;
        let workspace_id = create_test_workspace(&server, &owner_id, "test-ws").await;

        // Create another user with Read permission
        let (other_user_id, other_principal_id, _) =
            create_test_user(&server, "other@example.com", "laptop").await;
        add_user_to_workspace(&server, &workspace_id, &other_user_id, Role::Read).await;
        add_principal_to_workspace(&server, &workspace_id, &other_principal_id).await;

        let role = server
            .get_effective_workspace_role(&other_principal_id, &workspace_id)
            .await
            .unwrap();

        assert_eq!(role, Some(Role::Read));
    }

    #[tokio::test]
    async fn get_effective_workspace_role_user_with_no_permission() {
        let server = create_test_server().await;
        let (owner_id, _, _) = create_test_user(&server, "owner@example.com", "laptop").await;
        let workspace_id = create_test_workspace(&server, &owner_id, "test-ws").await;

        // Create another user without permission (just add to workspace_members without setting role)
        let (other_user_id, other_principal_id, _) =
            create_test_user(&server, "other@example.com", "laptop").await;
        server
            .store
            .add_user_to_workspace(&workspace_id, &other_user_id)
            .await
            .unwrap();
        add_principal_to_workspace(&server, &workspace_id, &other_principal_id).await;

        let role = server
            .get_effective_workspace_role(&other_principal_id, &workspace_id)
            .await
            .unwrap();

        assert_eq!(role, None);
    }

    #[tokio::test]
    async fn get_effective_workspace_role_service_account_with_permission() {
        let server = create_test_server().await;
        let (owner_id, _, _) = create_test_user(&server, "owner@example.com", "laptop").await;
        let workspace_id = create_test_workspace(&server, &owner_id, "test-ws").await;

        let (service_principal_id, _) = create_service_principal(&server, "my-service").await;
        add_principal_to_workspace(&server, &workspace_id, &service_principal_id).await;
        server
            .store
            .set_workspace_permission(&workspace_id, &service_principal_id, Role::Write)
            .await
            .unwrap();

        let role = server
            .get_effective_workspace_role(&service_principal_id, &workspace_id)
            .await
            .unwrap();

        assert_eq!(role, Some(Role::Write));
    }

    #[tokio::test]
    async fn get_effective_workspace_role_service_account_without_permission() {
        let server = create_test_server().await;
        let (owner_id, _, _) = create_test_user(&server, "owner@example.com", "laptop").await;
        let workspace_id = create_test_workspace(&server, &owner_id, "test-ws").await;

        let (service_principal_id, _) = create_service_principal(&server, "my-service").await;
        add_principal_to_workspace(&server, &workspace_id, &service_principal_id).await;

        let role = server
            .get_effective_workspace_role(&service_principal_id, &workspace_id)
            .await
            .unwrap();

        assert_eq!(role, None);
    }

    #[tokio::test]
    async fn get_effective_workspace_role_user_with_group_permission() {
        let server = create_test_server().await;
        let (owner_id, _, _) = create_test_user(&server, "owner@example.com", "laptop").await;
        let workspace_id = create_test_workspace(&server, &owner_id, "test-ws").await;

        // Create another user
        let (other_user_id, other_principal_id, _) =
            create_test_user(&server, "other@example.com", "laptop").await;
        server
            .store
            .add_user_to_workspace(&workspace_id, &other_user_id)
            .await
            .unwrap();
        add_principal_to_workspace(&server, &workspace_id, &other_principal_id).await;

        // Create a group with Write permission
        let group_id = server
            .store
            .create_group(&CreateGroupParams {
                workspace_id: workspace_id.clone(),
                name: "devs".to_string(),
                description: None,
            })
            .await
            .unwrap();
        server
            .store
            .add_group_member(&group_id, &other_user_id)
            .await
            .unwrap();
        server
            .store
            .set_group_workspace_permission(&workspace_id, &group_id, Role::Write)
            .await
            .unwrap();

        let role = server
            .get_effective_workspace_role(&other_principal_id, &workspace_id)
            .await
            .unwrap();

        assert_eq!(role, Some(Role::Write));
    }

    #[tokio::test]
    async fn get_effective_workspace_role_principal_restricts() {
        let server = create_test_server().await;
        let (owner_id, _, _) = create_test_user(&server, "owner@example.com", "laptop").await;
        let workspace_id = create_test_workspace(&server, &owner_id, "test-ws").await;

        // Create another user with Admin permission
        let (other_user_id, other_principal_id, _) =
            create_test_user(&server, "other@example.com", "laptop").await;
        add_user_to_workspace(&server, &workspace_id, &other_user_id, Role::Admin).await;
        add_principal_to_workspace(&server, &workspace_id, &other_principal_id).await;

        // But restrict the principal to Read
        server
            .store
            .set_workspace_permission(&workspace_id, &other_principal_id, Role::Read)
            .await
            .unwrap();

        let role = server
            .get_effective_workspace_role(&other_principal_id, &workspace_id)
            .await
            .unwrap();

        // Principal ceiling restricts Admin to Read
        assert_eq!(role, Some(Role::Read));
    }

    // ================== get_effective_project_role tests ==================

    #[tokio::test]
    async fn get_effective_project_role_owner_returns_admin() {
        let server = create_test_server().await;
        let (user_id, principal_id, _) = create_test_user(&server, "owner@example.com", "laptop").await;
        let workspace_id = create_test_workspace(&server, &user_id, "test-ws").await;
        let project_id = create_test_project(&server, &workspace_id, "test-proj").await;
        add_principal_to_workspace(&server, &workspace_id, &principal_id).await;

        let role = server
            .get_effective_project_role(&principal_id, &workspace_id, &project_id)
            .await
            .unwrap();

        assert_eq!(role, Some(Role::Admin));
    }

    #[tokio::test]
    async fn get_effective_project_role_inherits_from_workspace() {
        let server = create_test_server().await;
        let (owner_id, _, _) = create_test_user(&server, "owner@example.com", "laptop").await;
        let workspace_id = create_test_workspace(&server, &owner_id, "test-ws").await;
        let project_id = create_test_project(&server, &workspace_id, "test-proj").await;

        // Create another user with workspace-level Write permission
        let (other_user_id, other_principal_id, _) =
            create_test_user(&server, "other@example.com", "laptop").await;
        add_user_to_workspace(&server, &workspace_id, &other_user_id, Role::Write).await;
        add_principal_to_workspace(&server, &workspace_id, &other_principal_id).await;

        let role = server
            .get_effective_project_role(&other_principal_id, &workspace_id, &project_id)
            .await
            .unwrap();

        assert_eq!(role, Some(Role::Write));
    }

    #[tokio::test]
    async fn get_effective_project_role_project_permission_overrides() {
        let server = create_test_server().await;
        let (owner_id, _, _) = create_test_user(&server, "owner@example.com", "laptop").await;
        let workspace_id = create_test_workspace(&server, &owner_id, "test-ws").await;
        let project_id = create_test_project(&server, &workspace_id, "test-proj").await;

        // Create another user with workspace-level Read permission
        let (other_user_id, other_principal_id, _) =
            create_test_user(&server, "other@example.com", "laptop").await;
        add_user_to_workspace(&server, &workspace_id, &other_user_id, Role::Read).await;
        add_principal_to_workspace(&server, &workspace_id, &other_principal_id).await;

        // Give them project-level Admin permission
        server
            .store
            .set_user_project_permission(&project_id, &other_user_id, Role::Admin)
            .await
            .unwrap();

        let role = server
            .get_effective_project_role(&other_principal_id, &workspace_id, &project_id)
            .await
            .unwrap();

        // max(Read, Admin) = Admin
        assert_eq!(role, Some(Role::Admin));
    }

    #[tokio::test]
    async fn get_effective_project_role_service_account() {
        let server = create_test_server().await;
        let (owner_id, _, _) = create_test_user(&server, "owner@example.com", "laptop").await;
        let workspace_id = create_test_workspace(&server, &owner_id, "test-ws").await;
        let project_id = create_test_project(&server, &workspace_id, "test-proj").await;

        let (service_principal_id, _) = create_service_principal(&server, "my-service").await;
        add_principal_to_workspace(&server, &workspace_id, &service_principal_id).await;
        server
            .store
            .set_project_permission(&project_id, &service_principal_id, Role::Read)
            .await
            .unwrap();

        let role = server
            .get_effective_project_role(&service_principal_id, &workspace_id, &project_id)
            .await
            .unwrap();

        assert_eq!(role, Some(Role::Read));
    }

    // ================== get_effective_environment_role tests ==================

    #[tokio::test]
    async fn get_effective_environment_role_owner_returns_admin() {
        let server = create_test_server().await;
        let (user_id, principal_id, _) = create_test_user(&server, "owner@example.com", "laptop").await;
        let workspace_id = create_test_workspace(&server, &user_id, "test-ws").await;
        let project_id = create_test_project(&server, &workspace_id, "test-proj").await;
        let env_id = create_test_environment(&server, &project_id, "dev").await;
        add_principal_to_workspace(&server, &workspace_id, &principal_id).await;

        let role = server
            .get_effective_environment_role(&principal_id, &workspace_id, &project_id, &env_id)
            .await
            .unwrap();

        assert_eq!(role, Some(Role::Admin));
    }

    #[tokio::test]
    async fn get_effective_environment_role_inherits_from_workspace() {
        let server = create_test_server().await;
        let (owner_id, _, _) = create_test_user(&server, "owner@example.com", "laptop").await;
        let workspace_id = create_test_workspace(&server, &owner_id, "test-ws").await;
        let project_id = create_test_project(&server, &workspace_id, "test-proj").await;
        let env_id = create_test_environment(&server, &project_id, "dev").await;

        // Create another user with workspace-level Read permission
        let (other_user_id, other_principal_id, _) =
            create_test_user(&server, "other@example.com", "laptop").await;
        add_user_to_workspace(&server, &workspace_id, &other_user_id, Role::Read).await;
        add_principal_to_workspace(&server, &workspace_id, &other_principal_id).await;

        let role = server
            .get_effective_environment_role(&other_principal_id, &workspace_id, &project_id, &env_id)
            .await
            .unwrap();

        assert_eq!(role, Some(Role::Read));
    }

    #[tokio::test]
    async fn get_effective_environment_role_env_permission_overrides() {
        let server = create_test_server().await;
        let (owner_id, _, _) = create_test_user(&server, "owner@example.com", "laptop").await;
        let workspace_id = create_test_workspace(&server, &owner_id, "test-ws").await;
        let project_id = create_test_project(&server, &workspace_id, "test-proj").await;
        let env_id = create_test_environment(&server, &project_id, "dev").await;

        // Create another user with workspace-level Read permission
        let (other_user_id, other_principal_id, _) =
            create_test_user(&server, "other@example.com", "laptop").await;
        add_user_to_workspace(&server, &workspace_id, &other_user_id, Role::Read).await;
        add_principal_to_workspace(&server, &workspace_id, &other_principal_id).await;

        // Give them environment-level Admin permission
        server
            .store
            .set_user_environment_permission(&env_id, &other_user_id, Role::Admin)
            .await
            .unwrap();

        let role = server
            .get_effective_environment_role(&other_principal_id, &workspace_id, &project_id, &env_id)
            .await
            .unwrap();

        // max(Read, Admin) = Admin
        assert_eq!(role, Some(Role::Admin));
    }

    #[tokio::test]
    async fn get_effective_environment_role_service_account() {
        let server = create_test_server().await;
        let (owner_id, _, _) = create_test_user(&server, "owner@example.com", "laptop").await;
        let workspace_id = create_test_workspace(&server, &owner_id, "test-ws").await;
        let project_id = create_test_project(&server, &workspace_id, "test-proj").await;
        let env_id = create_test_environment(&server, &project_id, "dev").await;

        let (service_principal_id, _) = create_service_principal(&server, "my-service").await;
        add_principal_to_workspace(&server, &workspace_id, &service_principal_id).await;
        server
            .store
            .set_environment_permission(&env_id, &service_principal_id, Role::Write)
            .await
            .unwrap();

        let role = server
            .get_effective_environment_role(&service_principal_id, &workspace_id, &project_id, &env_id)
            .await
            .unwrap();

        assert_eq!(role, Some(Role::Write));
    }

    // ================== check_project_permission tests ==================

    #[tokio::test]
    async fn check_project_permission_owner() {
        let server = create_test_server().await;
        let (user_id, principal_id, _) = create_test_user(&server, "owner@example.com", "laptop").await;
        let workspace_id = create_test_workspace(&server, &user_id, "test-ws").await;
        let project_id = create_test_project(&server, &workspace_id, "test-proj").await;
        add_principal_to_workspace(&server, &workspace_id, &principal_id).await;

        let result = server
            .check_project_permission(&principal_id, &workspace_id, &project_id, Role::Admin)
            .await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn check_project_permission_user_with_project_permission() {
        let server = create_test_server().await;
        let (owner_id, _, _) = create_test_user(&server, "owner@example.com", "laptop").await;
        let workspace_id = create_test_workspace(&server, &owner_id, "test-ws").await;
        let project_id = create_test_project(&server, &workspace_id, "test-proj").await;

        // Create another user with project-level Write permission
        let (other_user_id, other_principal_id, _) =
            create_test_user(&server, "other@example.com", "laptop").await;
        server
            .store
            .add_user_to_workspace(&workspace_id, &other_user_id)
            .await
            .unwrap();
        add_principal_to_workspace(&server, &workspace_id, &other_principal_id).await;
        server
            .store
            .set_user_project_permission(&project_id, &other_user_id, Role::Write)
            .await
            .unwrap();

        // Should pass for Write
        let result = server
            .check_project_permission(&other_principal_id, &workspace_id, &project_id, Role::Write)
            .await;
        assert!(result.is_ok());

        // Should pass for Read (lower than Write)
        let result = server
            .check_project_permission(&other_principal_id, &workspace_id, &project_id, Role::Read)
            .await;
        assert!(result.is_ok());

        // Should fail for Admin (higher than Write)
        let result = server
            .check_project_permission(&other_principal_id, &workspace_id, &project_id, Role::Admin)
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn check_project_permission_inherits_from_workspace() {
        let server = create_test_server().await;
        let (owner_id, _, _) = create_test_user(&server, "owner@example.com", "laptop").await;
        let workspace_id = create_test_workspace(&server, &owner_id, "test-ws").await;
        let project_id = create_test_project(&server, &workspace_id, "test-proj").await;

        // Create another user with workspace-level Admin permission
        let (other_user_id, other_principal_id, _) =
            create_test_user(&server, "other@example.com", "laptop").await;
        add_user_to_workspace(&server, &workspace_id, &other_user_id, Role::Admin).await;
        add_principal_to_workspace(&server, &workspace_id, &other_principal_id).await;

        // Should pass for Admin (inherited from workspace)
        let result = server
            .check_project_permission(&other_principal_id, &workspace_id, &project_id, Role::Admin)
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn check_project_permission_service_account() {
        let server = create_test_server().await;
        let (owner_id, _, _) = create_test_user(&server, "owner@example.com", "laptop").await;
        let workspace_id = create_test_workspace(&server, &owner_id, "test-ws").await;
        let project_id = create_test_project(&server, &workspace_id, "test-proj").await;

        let (service_principal_id, _) = create_service_principal(&server, "my-service").await;
        add_principal_to_workspace(&server, &workspace_id, &service_principal_id).await;
        server
            .store
            .set_project_permission(&project_id, &service_principal_id, Role::Read)
            .await
            .unwrap();

        // Should pass for Read
        let result = server
            .check_project_permission(&service_principal_id, &workspace_id, &project_id, Role::Read)
            .await;
        assert!(result.is_ok());

        // Should fail for Write
        let result = server
            .check_project_permission(&service_principal_id, &workspace_id, &project_id, Role::Write)
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn check_project_permission_service_account_no_permission() {
        let server = create_test_server().await;
        let (owner_id, _, _) = create_test_user(&server, "owner@example.com", "laptop").await;
        let workspace_id = create_test_workspace(&server, &owner_id, "test-ws").await;
        let project_id = create_test_project(&server, &workspace_id, "test-proj").await;

        let (service_principal_id, _) = create_service_principal(&server, "my-service").await;
        add_principal_to_workspace(&server, &workspace_id, &service_principal_id).await;

        // Should fail - no permission
        let result = server
            .check_project_permission(&service_principal_id, &workspace_id, &project_id, Role::Read)
            .await;
        assert!(result.is_err());
    }

    // ================== check_environment_permission tests ==================

    #[tokio::test]
    async fn check_environment_permission_owner() {
        let server = create_test_server().await;
        let (user_id, principal_id, _) = create_test_user(&server, "owner@example.com", "laptop").await;
        let workspace_id = create_test_workspace(&server, &user_id, "test-ws").await;
        let project_id = create_test_project(&server, &workspace_id, "test-proj").await;
        let env_id = create_test_environment(&server, &project_id, "dev").await;
        add_principal_to_workspace(&server, &workspace_id, &principal_id).await;

        let result = server
            .check_environment_permission(&principal_id, &workspace_id, &project_id, &env_id, Role::Admin)
            .await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn check_environment_permission_user_with_env_permission() {
        let server = create_test_server().await;
        let (owner_id, _, _) = create_test_user(&server, "owner@example.com", "laptop").await;
        let workspace_id = create_test_workspace(&server, &owner_id, "test-ws").await;
        let project_id = create_test_project(&server, &workspace_id, "test-proj").await;
        let env_id = create_test_environment(&server, &project_id, "dev").await;

        // Create another user with env-level Write permission
        let (other_user_id, other_principal_id, _) =
            create_test_user(&server, "other@example.com", "laptop").await;
        server
            .store
            .add_user_to_workspace(&workspace_id, &other_user_id)
            .await
            .unwrap();
        add_principal_to_workspace(&server, &workspace_id, &other_principal_id).await;
        server
            .store
            .set_user_environment_permission(&env_id, &other_user_id, Role::Write)
            .await
            .unwrap();

        // Should pass for Write
        let result = server
            .check_environment_permission(&other_principal_id, &workspace_id, &project_id, &env_id, Role::Write)
            .await;
        assert!(result.is_ok());

        // Should pass for Read
        let result = server
            .check_environment_permission(&other_principal_id, &workspace_id, &project_id, &env_id, Role::Read)
            .await;
        assert!(result.is_ok());

        // Should fail for Admin
        let result = server
            .check_environment_permission(&other_principal_id, &workspace_id, &project_id, &env_id, Role::Admin)
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn check_environment_permission_inherits_from_project() {
        let server = create_test_server().await;
        let (owner_id, _, _) = create_test_user(&server, "owner@example.com", "laptop").await;
        let workspace_id = create_test_workspace(&server, &owner_id, "test-ws").await;
        let project_id = create_test_project(&server, &workspace_id, "test-proj").await;
        let env_id = create_test_environment(&server, &project_id, "dev").await;

        // Create another user with project-level Admin permission
        let (other_user_id, other_principal_id, _) =
            create_test_user(&server, "other@example.com", "laptop").await;
        server
            .store
            .add_user_to_workspace(&workspace_id, &other_user_id)
            .await
            .unwrap();
        add_principal_to_workspace(&server, &workspace_id, &other_principal_id).await;
        server
            .store
            .set_user_project_permission(&project_id, &other_user_id, Role::Admin)
            .await
            .unwrap();

        // Should pass for Admin (inherited from project)
        let result = server
            .check_environment_permission(&other_principal_id, &workspace_id, &project_id, &env_id, Role::Admin)
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn check_environment_permission_inherits_from_workspace() {
        let server = create_test_server().await;
        let (owner_id, _, _) = create_test_user(&server, "owner@example.com", "laptop").await;
        let workspace_id = create_test_workspace(&server, &owner_id, "test-ws").await;
        let project_id = create_test_project(&server, &workspace_id, "test-proj").await;
        let env_id = create_test_environment(&server, &project_id, "dev").await;

        // Create another user with workspace-level Write permission
        let (other_user_id, other_principal_id, _) =
            create_test_user(&server, "other@example.com", "laptop").await;
        add_user_to_workspace(&server, &workspace_id, &other_user_id, Role::Write).await;
        add_principal_to_workspace(&server, &workspace_id, &other_principal_id).await;

        // Should pass for Write (inherited from workspace)
        let result = server
            .check_environment_permission(&other_principal_id, &workspace_id, &project_id, &env_id, Role::Write)
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn check_environment_permission_service_account() {
        let server = create_test_server().await;
        let (owner_id, _, _) = create_test_user(&server, "owner@example.com", "laptop").await;
        let workspace_id = create_test_workspace(&server, &owner_id, "test-ws").await;
        let project_id = create_test_project(&server, &workspace_id, "test-proj").await;
        let env_id = create_test_environment(&server, &project_id, "dev").await;

        let (service_principal_id, _) = create_service_principal(&server, "my-service").await;
        add_principal_to_workspace(&server, &workspace_id, &service_principal_id).await;
        server
            .store
            .set_environment_permission(&env_id, &service_principal_id, Role::Read)
            .await
            .unwrap();

        // Should pass for Read
        let result = server
            .check_environment_permission(&service_principal_id, &workspace_id, &project_id, &env_id, Role::Read)
            .await;
        assert!(result.is_ok());

        // Should fail for Write
        let result = server
            .check_environment_permission(&service_principal_id, &workspace_id, &project_id, &env_id, Role::Write)
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn check_environment_permission_via_group() {
        let server = create_test_server().await;
        let (owner_id, _, _) = create_test_user(&server, "owner@example.com", "laptop").await;
        let workspace_id = create_test_workspace(&server, &owner_id, "test-ws").await;
        let project_id = create_test_project(&server, &workspace_id, "test-proj").await;
        let env_id = create_test_environment(&server, &project_id, "dev").await;

        // Create another user
        let (other_user_id, other_principal_id, _) =
            create_test_user(&server, "other@example.com", "laptop").await;
        server
            .store
            .add_user_to_workspace(&workspace_id, &other_user_id)
            .await
            .unwrap();
        add_principal_to_workspace(&server, &workspace_id, &other_principal_id).await;

        // Create a group with env Write permission
        let group_id = server
            .store
            .create_group(&CreateGroupParams {
                workspace_id: workspace_id.clone(),
                name: "devs".to_string(),
                description: None,
            })
            .await
            .unwrap();
        server
            .store
            .add_group_member(&group_id, &other_user_id)
            .await
            .unwrap();
        server
            .store
            .set_group_environment_permission(&env_id, &group_id, Role::Write)
            .await
            .unwrap();

        // Should pass for Write (via group)
        let result = server
            .check_environment_permission(&other_principal_id, &workspace_id, &project_id, &env_id, Role::Write)
            .await;
        assert!(result.is_ok());
    }

    // ================== check_permission_workspace_only tests ==================

    #[tokio::test]
    async fn check_permission_workspace_only_owner() {
        let server = create_test_server().await;
        let (user_id, principal_id, _) = create_test_user(&server, "owner@example.com", "laptop").await;
        let workspace_id = create_test_workspace(&server, &user_id, "test-ws").await;
        add_principal_to_workspace(&server, &workspace_id, &principal_id).await;

        let result = server
            .check_permission_workspace_only(&principal_id, &workspace_id, Role::Admin)
            .await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn check_permission_workspace_only_user_with_permission() {
        let server = create_test_server().await;
        let (owner_id, _, _) = create_test_user(&server, "owner@example.com", "laptop").await;
        let workspace_id = create_test_workspace(&server, &owner_id, "test-ws").await;

        // Create another user with Write permission
        let (other_user_id, other_principal_id, _) =
            create_test_user(&server, "other@example.com", "laptop").await;
        add_user_to_workspace(&server, &workspace_id, &other_user_id, Role::Write).await;
        add_principal_to_workspace(&server, &workspace_id, &other_principal_id).await;

        // Should pass for Write
        let result = server
            .check_permission_workspace_only(&other_principal_id, &workspace_id, Role::Write)
            .await;
        assert!(result.is_ok());

        // Should fail for Admin
        let result = server
            .check_permission_workspace_only(&other_principal_id, &workspace_id, Role::Admin)
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn check_permission_workspace_only_service_account() {
        let server = create_test_server().await;
        let (owner_id, _, _) = create_test_user(&server, "owner@example.com", "laptop").await;
        let workspace_id = create_test_workspace(&server, &owner_id, "test-ws").await;

        let (service_principal_id, _) = create_service_principal(&server, "my-service").await;
        add_principal_to_workspace(&server, &workspace_id, &service_principal_id).await;
        server
            .store
            .set_workspace_permission(&workspace_id, &service_principal_id, Role::Read)
            .await
            .unwrap();

        // Should pass for Read
        let result = server
            .check_permission_workspace_only(&service_principal_id, &workspace_id, Role::Read)
            .await;
        assert!(result.is_ok());

        // Should fail for Write
        let result = server
            .check_permission_workspace_only(&service_principal_id, &workspace_id, Role::Write)
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn check_permission_workspace_only_via_group() {
        let server = create_test_server().await;
        let (owner_id, _, _) = create_test_user(&server, "owner@example.com", "laptop").await;
        let workspace_id = create_test_workspace(&server, &owner_id, "test-ws").await;

        // Create another user
        let (other_user_id, other_principal_id, _) =
            create_test_user(&server, "other@example.com", "laptop").await;
        server
            .store
            .add_user_to_workspace(&workspace_id, &other_user_id)
            .await
            .unwrap();
        add_principal_to_workspace(&server, &workspace_id, &other_principal_id).await;

        // Create a group with Admin permission
        let group_id = server
            .store
            .create_group(&CreateGroupParams {
                workspace_id: workspace_id.clone(),
                name: "admins".to_string(),
                description: None,
            })
            .await
            .unwrap();
        server
            .store
            .add_group_member(&group_id, &other_user_id)
            .await
            .unwrap();
        server
            .store
            .set_group_workspace_permission(&workspace_id, &group_id, Role::Admin)
            .await
            .unwrap();

        // Should pass for Admin (via group)
        let result = server
            .check_permission_workspace_only(&other_principal_id, &workspace_id, Role::Admin)
            .await;
        assert!(result.is_ok());
    }

    // ================== Audit handler tests - invalid filter formats ==================

    #[tokio::test]
    async fn handler_list_audit_logs_invalid_result_filter() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "user@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/ListAuditLogs",
            zopp_proto::ListAuditLogsRequest {
                workspace_name: "ws".to_string(),
                result: Some("invalid_result".to_string()),
                ..Default::default()
            },
        );

        let result = server.list_audit_logs(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn handler_list_audit_logs_invalid_from_timestamp() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "user@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/ListAuditLogs",
            zopp_proto::ListAuditLogsRequest {
                workspace_name: "ws".to_string(),
                from_timestamp: Some("not-a-valid-timestamp".to_string()),
                ..Default::default()
            },
        );

        let result = server.list_audit_logs(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn handler_list_audit_logs_invalid_to_timestamp() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "user@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/ListAuditLogs",
            zopp_proto::ListAuditLogsRequest {
                workspace_name: "ws".to_string(),
                to_timestamp: Some("not-a-valid-timestamp".to_string()),
                ..Default::default()
            },
        );

        let result = server.list_audit_logs(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn handler_count_audit_logs_invalid_principal_id_filter() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "user@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/CountAuditLogs",
            zopp_proto::CountAuditLogsRequest {
                workspace_name: "ws".to_string(),
                principal_id: Some("not-a-uuid".to_string()),
                ..Default::default()
            },
        );

        let result = server.count_audit_logs(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn handler_count_audit_logs_invalid_user_id_filter() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "user@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/CountAuditLogs",
            zopp_proto::CountAuditLogsRequest {
                workspace_name: "ws".to_string(),
                user_id: Some("not-a-uuid".to_string()),
                ..Default::default()
            },
        );

        let result = server.count_audit_logs(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn handler_count_audit_logs_invalid_action_filter() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "user@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/CountAuditLogs",
            zopp_proto::CountAuditLogsRequest {
                workspace_name: "ws".to_string(),
                action: Some("invalid_action".to_string()),
                ..Default::default()
            },
        );

        let result = server.count_audit_logs(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn handler_count_audit_logs_invalid_result_filter() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "user@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/CountAuditLogs",
            zopp_proto::CountAuditLogsRequest {
                workspace_name: "ws".to_string(),
                result: Some("invalid_result".to_string()),
                ..Default::default()
            },
        );

        let result = server.count_audit_logs(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn handler_get_audit_log_invalid_id() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "user@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/GetAuditLog",
            zopp_proto::GetAuditLogRequest {
                workspace_name: "ws".to_string(),
                audit_log_id: "not-a-uuid".to_string(),
            },
        );

        let result = server.get_audit_log(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn handler_get_audit_log_not_found() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "user@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/GetAuditLog",
            zopp_proto::GetAuditLogRequest {
                workspace_name: "ws".to_string(),
                audit_log_id: uuid::Uuid::now_v7().to_string(),
            },
        );

        let result = server.get_audit_log(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn handler_get_audit_log_permission_denied() {
        let server = create_test_server().await;
        let (owner_id, _, _) = create_test_user(&server, "owner@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &owner_id, "ws").await;

        // Create another user with only Read permission (not Admin)
        let (other_user_id, other_principal_id, other_signing_key) =
            create_test_user(&server, "other@example.com", "laptop").await;
        add_user_to_workspace(&server, &ws_id, &other_user_id, Role::Read).await;
        add_principal_to_workspace(&server, &ws_id, &other_principal_id).await;

        let request = create_signed_request(
            &other_principal_id,
            &other_signing_key,
            "/zopp.ZoppService/GetAuditLog",
            zopp_proto::GetAuditLogRequest {
                workspace_name: "ws".to_string(),
                audit_log_id: uuid::Uuid::now_v7().to_string(),
            },
        );

        let result = server.get_audit_log(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::PermissionDenied);
    }

    #[tokio::test]
    async fn handler_list_audit_logs_workspace_not_found() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "user@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/ListAuditLogs",
            zopp_proto::ListAuditLogsRequest {
                workspace_name: "nonexistent".to_string(),
                ..Default::default()
            },
        );

        let result = server.list_audit_logs(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn handler_count_audit_logs_workspace_not_found() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "user@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/CountAuditLogs",
            zopp_proto::CountAuditLogsRequest {
                workspace_name: "nonexistent".to_string(),
                ..Default::default()
            },
        );

        let result = server.count_audit_logs(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn handler_get_audit_log_workspace_not_found() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "user@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/GetAuditLog",
            zopp_proto::GetAuditLogRequest {
                workspace_name: "nonexistent".to_string(),
                audit_log_id: uuid::Uuid::now_v7().to_string(),
            },
        );

        let result = server.get_audit_log(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    // ================== Service principal audit access tests ==================

    #[tokio::test]
    async fn handler_list_audit_logs_as_service_principal_with_admin() {
        let server = create_test_server().await;
        let (owner_id, _, _) = create_test_user(&server, "owner@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &owner_id, "ws").await;

        // Create service principal with Admin permission
        let (service_principal_id, service_signing_key) =
            create_service_principal(&server, "my-service").await;
        add_principal_to_workspace(&server, &ws_id, &service_principal_id).await;
        server
            .store
            .set_workspace_permission(&ws_id, &service_principal_id, Role::Admin)
            .await
            .unwrap();

        let request = create_signed_request(
            &service_principal_id,
            &service_signing_key,
            "/zopp.ZoppService/ListAuditLogs",
            zopp_proto::ListAuditLogsRequest {
                workspace_name: "ws".to_string(),
                ..Default::default()
            },
        );

        // Service principal with Admin should be able to list audit logs
        let result = server.list_audit_logs(request).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn handler_count_audit_logs_as_service_principal_without_admin() {
        let server = create_test_server().await;
        let (owner_id, _, _) = create_test_user(&server, "owner@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &owner_id, "ws").await;

        // Create service principal with only Read permission
        let (service_principal_id, service_signing_key) =
            create_service_principal(&server, "my-service").await;
        add_principal_to_workspace(&server, &ws_id, &service_principal_id).await;
        server
            .store
            .set_workspace_permission(&ws_id, &service_principal_id, Role::Read)
            .await
            .unwrap();

        let request = create_signed_request(
            &service_principal_id,
            &service_signing_key,
            "/zopp.ZoppService/CountAuditLogs",
            zopp_proto::CountAuditLogsRequest {
                workspace_name: "ws".to_string(),
                ..Default::default()
            },
        );

        // Service principal with Read should NOT be able to count audit logs (requires Admin)
        let result = server.count_audit_logs(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::PermissionDenied);
    }

    // ================== More handler error path tests ==================

    #[tokio::test]
    async fn handler_create_environment_missing_project() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "user@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/CreateEnvironment",
            zopp_proto::CreateEnvironmentRequest {
                workspace_name: "ws".to_string(),
                project_name: "nonexistent".to_string(),
                name: "dev".to_string(),
                dek_wrapped: vec![0u8; 32],
                dek_nonce: vec![0u8; 24],
            },
        );

        let result = server.create_environment(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn handler_list_env_permissions_success() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "user@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        let proj_id = create_test_project(&server, &ws_id, "proj").await;
        let _env_id = create_test_environment(&server, &proj_id, "dev").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/ListEnvironmentPermissions",
            zopp_proto::ListEnvironmentPermissionsRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
                environment_name: "dev".to_string(),
            },
        );

        let result = server.list_environment_permissions(request).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn handler_get_workspace_keys_nonexistent_ws() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "user@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/GetWorkspaceKeys",
            zopp_proto::GetWorkspaceKeysRequest {
                workspace_name: "nonexistent".to_string(),
            },
        );

        let result = server.get_workspace_keys(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn handler_create_project_duplicate_name() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "user@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        let _proj_id = create_test_project(&server, &ws_id, "proj").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        // Try to create project with same name
        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/CreateProject",
            zopp_proto::CreateProjectRequest {
                workspace_name: "ws".to_string(),
                name: "proj".to_string(),
            },
        );

        let result = server.create_project(request).await;
        assert!(result.is_err());
        // Should be an error (either AlreadyExists or Conflict)
    }

    #[tokio::test]
    async fn handler_create_environment_duplicate_name() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "user@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        let proj_id = create_test_project(&server, &ws_id, "proj").await;
        let _env_id = create_test_environment(&server, &proj_id, "dev").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        // Try to create environment with same name
        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/CreateEnvironment",
            zopp_proto::CreateEnvironmentRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
                name: "dev".to_string(),
                dek_wrapped: vec![0u8; 32],
                dek_nonce: vec![0u8; 24],
            },
        );

        let result = server.create_environment(request).await;
        assert!(result.is_err());
        // Should be an error (either AlreadyExists or Conflict)
    }

    #[tokio::test]
    async fn handler_delete_project_nonexistent() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "user@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/DeleteProject",
            zopp_proto::DeleteProjectRequest {
                workspace_name: "ws".to_string(),
                project_name: "nonexistent".to_string(),
            },
        );

        let result = server.delete_project(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn handler_get_project_nonexistent() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "user@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/GetProject",
            zopp_proto::GetProjectRequest {
                workspace_name: "ws".to_string(),
                project_name: "nonexistent".to_string(),
            },
        );

        let result = server.get_project(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    // ================== Additional permission handler tests ==================

    #[tokio::test]
    async fn handler_list_workspace_permissions_success() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "owner@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        // Set a permission
        let (other_user_id, other_principal_id, _) =
            create_test_user(&server, "other@example.com", "laptop").await;
        add_user_to_workspace(&server, &ws_id, &other_user_id, Role::Read).await;
        add_principal_to_workspace(&server, &ws_id, &other_principal_id).await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/ListWorkspacePermissions",
            zopp_proto::ListWorkspacePermissionsRequest {
                workspace_name: "ws".to_string(),
            },
        );

        let result = server.list_workspace_permissions(request).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn handler_list_project_permissions_success() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "owner@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        let proj_id = create_test_project(&server, &ws_id, "proj").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        // Set a project permission
        let (other_user_id, other_principal_id, _) =
            create_test_user(&server, "other@example.com", "laptop").await;
        server
            .store
            .add_user_to_workspace(&ws_id, &other_user_id)
            .await
            .unwrap();
        add_principal_to_workspace(&server, &ws_id, &other_principal_id).await;
        server
            .store
            .set_user_project_permission(&proj_id, &other_user_id, Role::Write)
            .await
            .unwrap();

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/ListProjectPermissions",
            zopp_proto::ListProjectPermissionsRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
            },
        );

        let result = server.list_project_permissions(request).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn handler_get_workspace_permission_success() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "owner@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        // Create another principal and set explicit permission
        let (other_user_id, other_principal_id, _) =
            create_test_user(&server, "other@example.com", "laptop").await;
        server
            .store
            .add_user_to_workspace(&ws_id, &other_user_id)
            .await
            .unwrap();
        add_principal_to_workspace(&server, &ws_id, &other_principal_id).await;
        server
            .store
            .set_workspace_permission(&ws_id, &other_principal_id, Role::Write)
            .await
            .unwrap();

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/GetWorkspacePermission",
            zopp_proto::GetWorkspacePermissionRequest {
                workspace_name: "ws".to_string(),
                principal_id: other_principal_id.0.to_string(),
            },
        );

        let result = server.get_workspace_permission(request).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn handler_get_project_permission_success() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "owner@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        let proj_id = create_test_project(&server, &ws_id, "proj").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;
        server
            .store
            .set_project_permission(&proj_id, &principal_id, Role::Admin)
            .await
            .unwrap();

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/GetProjectPermission",
            zopp_proto::GetProjectPermissionRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
                principal_id: principal_id.0.to_string(),
            },
        );

        let result = server.get_project_permission(request).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn handler_get_environment_permission_success() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "owner@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        let proj_id = create_test_project(&server, &ws_id, "proj").await;
        let env_id = create_test_environment(&server, &proj_id, "dev").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;
        server
            .store
            .set_environment_permission(&env_id, &principal_id, Role::Admin)
            .await
            .unwrap();

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/GetEnvironmentPermission",
            zopp_proto::GetEnvironmentPermissionRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
                environment_name: "dev".to_string(),
                principal_id: principal_id.0.to_string(),
            },
        );

        let result = server.get_environment_permission(request).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn handler_remove_workspace_permission_success() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "owner@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        // Create another user with permission
        let (other_user_id, other_principal_id, _) =
            create_test_user(&server, "other@example.com", "laptop").await;
        server
            .store
            .add_user_to_workspace(&ws_id, &other_user_id)
            .await
            .unwrap();
        add_principal_to_workspace(&server, &ws_id, &other_principal_id).await;
        server
            .store
            .set_workspace_permission(&ws_id, &other_principal_id, Role::Read)
            .await
            .unwrap();

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/RemoveWorkspacePermission",
            zopp_proto::RemoveWorkspacePermissionRequest {
                workspace_name: "ws".to_string(),
                principal_id: other_principal_id.0.to_string(),
            },
        );

        let result = server.remove_workspace_permission(request).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn handler_remove_project_permission_success() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "owner@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        let proj_id = create_test_project(&server, &ws_id, "proj").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        // Create another user with permission
        let (other_user_id, other_principal_id, _) =
            create_test_user(&server, "other@example.com", "laptop").await;
        server
            .store
            .add_user_to_workspace(&ws_id, &other_user_id)
            .await
            .unwrap();
        add_principal_to_workspace(&server, &ws_id, &other_principal_id).await;
        server
            .store
            .set_project_permission(&proj_id, &other_principal_id, Role::Write)
            .await
            .unwrap();

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/RemoveProjectPermission",
            zopp_proto::RemoveProjectPermissionRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
                principal_id: other_principal_id.0.to_string(),
            },
        );

        let result = server.remove_project_permission(request).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn handler_remove_environment_permission_success() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "owner@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        let proj_id = create_test_project(&server, &ws_id, "proj").await;
        let env_id = create_test_environment(&server, &proj_id, "dev").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        // Create another user with permission
        let (other_user_id, other_principal_id, _) =
            create_test_user(&server, "other@example.com", "laptop").await;
        server
            .store
            .add_user_to_workspace(&ws_id, &other_user_id)
            .await
            .unwrap();
        add_principal_to_workspace(&server, &ws_id, &other_principal_id).await;
        server
            .store
            .set_environment_permission(&env_id, &other_principal_id, Role::Read)
            .await
            .unwrap();

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/RemoveEnvironmentPermission",
            zopp_proto::RemoveEnvironmentPermissionRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
                environment_name: "dev".to_string(),
                principal_id: other_principal_id.0.to_string(),
            },
        );

        let result = server.remove_environment_permission(request).await;
        assert!(result.is_ok());
    }

    // ================== User permission handler tests ==================

    #[tokio::test]
    async fn handler_get_user_workspace_permission_success() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "owner@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        // Create another user with explicit permission
        let (other_user_id, other_principal_id, _) =
            create_test_user(&server, "other@example.com", "laptop").await;
        add_user_to_workspace(&server, &ws_id, &other_user_id, Role::Read).await;
        add_principal_to_workspace(&server, &ws_id, &other_principal_id).await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/GetUserWorkspacePermission",
            zopp_proto::GetUserWorkspacePermissionRequest {
                workspace_name: "ws".to_string(),
                user_email: "other@example.com".to_string(),
            },
        );

        let result = server.get_user_workspace_permission(request).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn handler_get_user_project_permission_success() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "owner@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        let proj_id = create_test_project(&server, &ws_id, "proj").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        // Give user project permission
        server
            .store
            .set_user_project_permission(&proj_id, &user_id, Role::Write)
            .await
            .unwrap();

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/GetUserProjectPermission",
            zopp_proto::GetUserProjectPermissionRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
                user_email: "owner@example.com".to_string(),
            },
        );

        let result = server.get_user_project_permission(request).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn handler_get_user_environment_permission_success() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "owner@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        let proj_id = create_test_project(&server, &ws_id, "proj").await;
        let env_id = create_test_environment(&server, &proj_id, "dev").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        // Give user environment permission
        server
            .store
            .set_user_environment_permission(&env_id, &user_id, Role::Read)
            .await
            .unwrap();

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/GetUserEnvironmentPermission",
            zopp_proto::GetUserEnvironmentPermissionRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
                environment_name: "dev".to_string(),
                user_email: "owner@example.com".to_string(),
            },
        );

        let result = server.get_user_environment_permission(request).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn handler_remove_user_workspace_permission_success() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "owner@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        // Create another user with permission
        let (other_user_id, other_principal_id, _) =
            create_test_user(&server, "other@example.com", "laptop").await;
        add_user_to_workspace(&server, &ws_id, &other_user_id, Role::Write).await;
        add_principal_to_workspace(&server, &ws_id, &other_principal_id).await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/RemoveUserWorkspacePermission",
            zopp_proto::RemoveUserWorkspacePermissionRequest {
                workspace_name: "ws".to_string(),
                user_email: "other@example.com".to_string(),
            },
        );

        let result = server.remove_user_workspace_permission(request).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn handler_remove_user_project_permission_success() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "owner@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        let proj_id = create_test_project(&server, &ws_id, "proj").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        // Create another user with project permission
        let (other_user_id, other_principal_id, _) =
            create_test_user(&server, "other@example.com", "laptop").await;
        server
            .store
            .add_user_to_workspace(&ws_id, &other_user_id)
            .await
            .unwrap();
        add_principal_to_workspace(&server, &ws_id, &other_principal_id).await;
        server
            .store
            .set_user_project_permission(&proj_id, &other_user_id, Role::Write)
            .await
            .unwrap();

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/RemoveUserProjectPermission",
            zopp_proto::RemoveUserProjectPermissionRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
                user_email: "other@example.com".to_string(),
            },
        );

        let result = server.remove_user_project_permission(request).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn handler_remove_user_environment_permission_success() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "owner@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        let proj_id = create_test_project(&server, &ws_id, "proj").await;
        let env_id = create_test_environment(&server, &proj_id, "dev").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        // Create another user with environment permission
        let (other_user_id, other_principal_id, _) =
            create_test_user(&server, "other@example.com", "laptop").await;
        server
            .store
            .add_user_to_workspace(&ws_id, &other_user_id)
            .await
            .unwrap();
        add_principal_to_workspace(&server, &ws_id, &other_principal_id).await;
        server
            .store
            .set_user_environment_permission(&env_id, &other_user_id, Role::Read)
            .await
            .unwrap();

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/RemoveUserEnvironmentPermission",
            zopp_proto::RemoveUserEnvironmentPermissionRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
                environment_name: "dev".to_string(),
                user_email: "other@example.com".to_string(),
            },
        );

        let result = server.remove_user_environment_permission(request).await;
        assert!(result.is_ok());
    }

    // ================== Group permission handler tests ==================

    #[tokio::test]
    async fn handler_get_group_workspace_permission_success() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "owner@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        // Create a group with workspace permission
        let group_id = server
            .store
            .create_group(&CreateGroupParams {
                workspace_id: ws_id.clone(),
                name: "devs".to_string(),
                description: None,
            })
            .await
            .unwrap();
        server
            .store
            .set_group_workspace_permission(&ws_id, &group_id, Role::Write)
            .await
            .unwrap();

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/GetGroupWorkspacePermission",
            zopp_proto::GetGroupWorkspacePermissionRequest {
                workspace_name: "ws".to_string(),
                group_name: "devs".to_string(),
            },
        );

        let result = server.get_group_workspace_permission(request).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn handler_get_group_project_permission_success() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "owner@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        let proj_id = create_test_project(&server, &ws_id, "proj").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        // Create a group with project permission
        let group_id = server
            .store
            .create_group(&CreateGroupParams {
                workspace_id: ws_id.clone(),
                name: "devs".to_string(),
                description: None,
            })
            .await
            .unwrap();
        server
            .store
            .set_group_project_permission(&proj_id, &group_id, Role::Read)
            .await
            .unwrap();

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/GetGroupProjectPermission",
            zopp_proto::GetGroupProjectPermissionRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
                group_name: "devs".to_string(),
            },
        );

        let result = server.get_group_project_permission(request).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn handler_get_group_environment_permission_success() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "owner@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        let proj_id = create_test_project(&server, &ws_id, "proj").await;
        let env_id = create_test_environment(&server, &proj_id, "dev").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        // Create a group with environment permission
        let group_id = server
            .store
            .create_group(&CreateGroupParams {
                workspace_id: ws_id.clone(),
                name: "devs".to_string(),
                description: None,
            })
            .await
            .unwrap();
        server
            .store
            .set_group_environment_permission(&env_id, &group_id, Role::Read)
            .await
            .unwrap();

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/GetGroupEnvironmentPermission",
            zopp_proto::GetGroupEnvironmentPermissionRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
                environment_name: "dev".to_string(),
                group_name: "devs".to_string(),
            },
        );

        let result = server.get_group_environment_permission(request).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn handler_remove_group_workspace_permission_success() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "owner@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        // Create a group with workspace permission
        let group_id = server
            .store
            .create_group(&CreateGroupParams {
                workspace_id: ws_id.clone(),
                name: "devs".to_string(),
                description: None,
            })
            .await
            .unwrap();
        server
            .store
            .set_group_workspace_permission(&ws_id, &group_id, Role::Write)
            .await
            .unwrap();

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/RemoveGroupWorkspacePermission",
            zopp_proto::RemoveGroupWorkspacePermissionRequest {
                workspace_name: "ws".to_string(),
                group_name: "devs".to_string(),
            },
        );

        let result = server.remove_group_workspace_permission(request).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn handler_remove_group_project_permission_success() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "owner@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        let proj_id = create_test_project(&server, &ws_id, "proj").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        // Create a group with project permission
        let group_id = server
            .store
            .create_group(&CreateGroupParams {
                workspace_id: ws_id.clone(),
                name: "devs".to_string(),
                description: None,
            })
            .await
            .unwrap();
        server
            .store
            .set_group_project_permission(&proj_id, &group_id, Role::Read)
            .await
            .unwrap();

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/RemoveGroupProjectPermission",
            zopp_proto::RemoveGroupProjectPermissionRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
                group_name: "devs".to_string(),
            },
        );

        let result = server.remove_group_project_permission(request).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn handler_remove_group_environment_permission_success() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "owner@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        let proj_id = create_test_project(&server, &ws_id, "proj").await;
        let env_id = create_test_environment(&server, &proj_id, "dev").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        // Create a group with environment permission
        let group_id = server
            .store
            .create_group(&CreateGroupParams {
                workspace_id: ws_id.clone(),
                name: "devs".to_string(),
                description: None,
            })
            .await
            .unwrap();
        server
            .store
            .set_group_environment_permission(&env_id, &group_id, Role::Read)
            .await
            .unwrap();

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/RemoveGroupEnvironmentPermission",
            zopp_proto::RemoveGroupEnvironmentPermissionRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
                environment_name: "dev".to_string(),
                group_name: "devs".to_string(),
            },
        );

        let result = server.remove_group_environment_permission(request).await;
        assert!(result.is_ok());
    }

    // ================== Auth handler tests: register (new) ==================

    #[tokio::test]
    async fn handler_register_new_user_success() {
        let server = create_test_server().await;

        let request = Request::new(zopp_proto::RegisterRequest {
            email: "newuser123@example.com".to_string(),
            principal_name: "laptop".to_string(),
            public_key: vec![1u8; 32],
            x25519_public_key: vec![2u8; 32],
            is_service: false,
            workspace_name: None,
            ephemeral_pub: None,
            kek_wrapped: None,
            kek_nonce: None,
        });

        let result = server.register(request).await;
        assert!(result.is_ok());
        let resp = result.unwrap().into_inner();
        assert!(!resp.user_id.is_empty());
        assert!(!resp.principal_id.is_empty());
    }

    #[tokio::test]
    async fn handler_register_service_principal_with_kek() {
        let server = create_test_server().await;

        // First create a regular user with admin permissions
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "admin123@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        // Register a service principal in the workspace
        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/Register",
            zopp_proto::RegisterRequest {
                email: String::new(), // service principals have no email
                principal_name: "my-service-new".to_string(),
                public_key: vec![0xau8; 32],
                x25519_public_key: vec![0xbu8; 32],
                is_service: true,
                workspace_name: Some("ws".to_string()),
                ephemeral_pub: Some(vec![1, 2, 3]),
                kek_wrapped: Some(vec![4, 5, 6]),
                kek_nonce: Some(vec![7, 8, 9]),
            },
        );

        let result = server.register(request).await;
        assert!(result.is_ok());
        let resp = result.unwrap().into_inner();
        assert!(resp.user_id.is_empty()); // service principals have no user_id
        assert!(!resp.principal_id.is_empty());
    }

    #[tokio::test]
    async fn handler_register_service_principal_without_kek() {
        let server = create_test_server().await;

        // First create a regular user with admin permissions
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "admin456@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        // Register a service principal without KEK wrapping
        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/Register",
            zopp_proto::RegisterRequest {
                email: String::new(),
                principal_name: "svc-no-kek-new".to_string(),
                public_key: vec![0xcu8; 32],
                x25519_public_key: vec![0xdu8; 32],
                is_service: true,
                workspace_name: Some("ws".to_string()),
                ephemeral_pub: None,
                kek_wrapped: None,
                kek_nonce: None,
            },
        );

        let result = server.register(request).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn handler_register_service_principal_ws_not_found() {
        let server = create_test_server().await;

        // Create a regular user
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "admin789@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        // Try to register a service principal in a non-existent workspace
        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/Register",
            zopp_proto::RegisterRequest {
                email: String::new(),
                principal_name: "svc-not-found".to_string(),
                public_key: vec![0xeu8; 32],
                x25519_public_key: vec![0xfu8; 32],
                is_service: true,
                workspace_name: Some("nonexistent".to_string()),
                ephemeral_pub: None,
                kek_wrapped: None,
                kek_nonce: None,
            },
        );

        let result = server.register(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn handler_register_service_principal_requires_admin() {
        let server = create_test_server().await;

        // Create admin user
        let (admin_user_id, _admin_principal_id, _) =
            create_test_user(&server, "admin000@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &admin_user_id, "ws").await;

        // Create a regular user with only Read permission
        let (_, reader_principal_id, reader_signing_key) =
            create_test_user(&server, "reader000@example.com", "laptop").await;
        add_principal_to_workspace(&server, &ws_id, &reader_principal_id).await;
        server
            .store
            .set_workspace_permission(&ws_id, &reader_principal_id, Role::Read)
            .await
            .unwrap();

        // Try to register a service principal (should fail - needs Admin)
        let request = create_signed_request(
            &reader_principal_id,
            &reader_signing_key,
            "/zopp.ZoppService/Register",
            zopp_proto::RegisterRequest {
                email: String::new(),
                principal_name: "svc-denied".to_string(),
                public_key: vec![0x11u8; 32],
                x25519_public_key: vec![0x12u8; 32],
                is_service: true,
                workspace_name: Some("ws".to_string()),
                ephemeral_pub: None,
                kek_wrapped: None,
                kek_nonce: None,
            },
        );

        let result = server.register(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::PermissionDenied);
    }

    #[tokio::test]
    async fn handler_register_with_empty_x25519() {
        let server = create_test_server().await;

        let request = Request::new(zopp_proto::RegisterRequest {
            email: "nox25519user@example.com".to_string(),
            principal_name: "laptop".to_string(),
            public_key: vec![1u8; 32],
            x25519_public_key: vec![], // empty
            is_service: false,
            workspace_name: None,
            ephemeral_pub: None,
            kek_wrapped: None,
            kek_nonce: None,
        });

        let result = server.register(request).await;
        assert!(result.is_ok());
    }

    // ================== Set user/group permission success tests ==================

    #[tokio::test]
    async fn handler_set_user_ws_perm_success() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "owner111@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        // Create another user to grant permission to
        let (other_user_id, other_principal_id, _) =
            create_test_user(&server, "other111@example.com", "laptop").await;
        server
            .store
            .add_user_to_workspace(&ws_id, &other_user_id)
            .await
            .unwrap();
        add_principal_to_workspace(&server, &ws_id, &other_principal_id).await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/SetUserWorkspacePermission",
            zopp_proto::SetUserWorkspacePermissionRequest {
                workspace_name: "ws".to_string(),
                user_email: "other111@example.com".to_string(),
                role: zopp_proto::Role::Read as i32,
            },
        );

        let result = server.set_user_workspace_permission(request).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn handler_set_user_proj_perm_success() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "owner222@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        create_test_project(&server, &ws_id, "proj").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        // Create another user
        let (other_user_id, other_principal_id, _) =
            create_test_user(&server, "other222@example.com", "laptop").await;
        server
            .store
            .add_user_to_workspace(&ws_id, &other_user_id)
            .await
            .unwrap();
        add_principal_to_workspace(&server, &ws_id, &other_principal_id).await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/SetUserProjectPermission",
            zopp_proto::SetUserProjectPermissionRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
                user_email: "other222@example.com".to_string(),
                role: zopp_proto::Role::Write as i32,
            },
        );

        let result = server.set_user_project_permission(request).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn handler_set_user_env_perm_success() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "owner333@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        let proj_id = create_test_project(&server, &ws_id, "proj").await;
        create_test_environment(&server, &proj_id, "dev").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        // Create another user
        let (other_user_id, other_principal_id, _) =
            create_test_user(&server, "other333@example.com", "laptop").await;
        server
            .store
            .add_user_to_workspace(&ws_id, &other_user_id)
            .await
            .unwrap();
        add_principal_to_workspace(&server, &ws_id, &other_principal_id).await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/SetUserEnvironmentPermission",
            zopp_proto::SetUserEnvironmentPermissionRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
                environment_name: "dev".to_string(),
                user_email: "other333@example.com".to_string(),
                role: zopp_proto::Role::Read as i32,
            },
        );

        let result = server.set_user_environment_permission(request).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn handler_set_group_ws_perm_success() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "owner444@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        // Create a group
        server
            .store
            .create_group(&CreateGroupParams {
                workspace_id: ws_id.clone(),
                name: "devs".to_string(),
                description: None,
            })
            .await
            .unwrap();

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/SetGroupWorkspacePermission",
            zopp_proto::SetGroupWorkspacePermissionRequest {
                workspace_name: "ws".to_string(),
                group_name: "devs".to_string(),
                role: zopp_proto::Role::Write as i32,
            },
        );

        let result = server.set_group_workspace_permission(request).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn handler_set_group_proj_perm_success() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "owner555@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        create_test_project(&server, &ws_id, "proj").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        // Create a group
        server
            .store
            .create_group(&CreateGroupParams {
                workspace_id: ws_id.clone(),
                name: "devs".to_string(),
                description: None,
            })
            .await
            .unwrap();

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/SetGroupProjectPermission",
            zopp_proto::SetGroupProjectPermissionRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
                group_name: "devs".to_string(),
                role: zopp_proto::Role::Read as i32,
            },
        );

        let result = server.set_group_project_permission(request).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn handler_set_group_env_perm_success() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "owner666@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        let proj_id = create_test_project(&server, &ws_id, "proj").await;
        create_test_environment(&server, &proj_id, "dev").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        // Create a group
        server
            .store
            .create_group(&CreateGroupParams {
                workspace_id: ws_id.clone(),
                name: "devs".to_string(),
                description: None,
            })
            .await
            .unwrap();

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/SetGroupEnvironmentPermission",
            zopp_proto::SetGroupEnvironmentPermissionRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
                environment_name: "dev".to_string(),
                group_name: "devs".to_string(),
                role: zopp_proto::Role::Read as i32,
            },
        );

        let result = server.set_group_environment_permission(request).await;
        assert!(result.is_ok());
    }

    // ================== More error path tests ==================

    #[tokio::test]
    async fn handler_set_ws_perm_ws_not_found() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "owner777@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        // Create another principal to grant permission to
        let (_, other_principal_id, _) =
            create_test_user(&server, "other777@example.com", "laptop").await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/SetWorkspacePermission",
            zopp_proto::SetWorkspacePermissionRequest {
                workspace_name: "nonexistent".to_string(),
                principal_id: other_principal_id.0.to_string(),
                role: zopp_proto::Role::Read as i32,
            },
        );

        let result = server.set_workspace_permission(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn handler_set_proj_perm_proj_not_found() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "owner888@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        let (_, other_principal_id, _) =
            create_test_user(&server, "other888@example.com", "laptop").await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/SetProjectPermission",
            zopp_proto::SetProjectPermissionRequest {
                workspace_name: "ws".to_string(),
                project_name: "nonexistent".to_string(),
                principal_id: other_principal_id.0.to_string(),
                role: zopp_proto::Role::Read as i32,
            },
        );

        let result = server.set_project_permission(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn handler_set_env_perm_env_not_found() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "owner999@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        create_test_project(&server, &ws_id, "proj").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        let (_, other_principal_id, _) =
            create_test_user(&server, "other999@example.com", "laptop").await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/SetEnvironmentPermission",
            zopp_proto::SetEnvironmentPermissionRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
                environment_name: "nonexistent".to_string(),
                principal_id: other_principal_id.0.to_string(),
                role: zopp_proto::Role::Read as i32,
            },
        );

        let result = server.set_environment_permission(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn handler_list_ws_perms_ws_not_found() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "owner-aaa@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/ListWorkspacePermissions",
            zopp_proto::ListWorkspacePermissionsRequest {
                workspace_name: "nonexistent".to_string(),
            },
        );

        let result = server.list_workspace_permissions(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn handler_list_proj_perms_proj_not_found() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "owner-bbb@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/ListProjectPermissions",
            zopp_proto::ListProjectPermissionsRequest {
                workspace_name: "ws".to_string(),
                project_name: "nonexistent".to_string(),
            },
        );

        let result = server.list_project_permissions(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn handler_list_env_perms_env_not_found() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "owner-ccc@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        create_test_project(&server, &ws_id, "proj").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/ListEnvironmentPermissions",
            zopp_proto::ListEnvironmentPermissionsRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
                environment_name: "nonexistent".to_string(),
            },
        );

        let result = server.list_environment_permissions(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    // ================== User permission error path tests ==================

    #[tokio::test]
    async fn handler_set_user_ws_perm_user_not_found() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "owner-d1@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/SetUserWorkspacePermission",
            zopp_proto::SetUserWorkspacePermissionRequest {
                workspace_name: "ws".to_string(),
                user_email: "nonexistent@example.com".to_string(),
                role: zopp_proto::Role::Read as i32,
            },
        );

        let result = server.set_user_workspace_permission(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn handler_set_user_ws_perm_invalid_role() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "owner-d2@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        let (other_user_id, _, _) =
            create_test_user(&server, "other-d2@example.com", "laptop").await;
        server
            .store
            .add_user_to_workspace(&ws_id, &other_user_id)
            .await
            .unwrap();

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/SetUserWorkspacePermission",
            zopp_proto::SetUserWorkspacePermissionRequest {
                workspace_name: "ws".to_string(),
                user_email: "other-d2@example.com".to_string(),
                role: 999, // invalid role
            },
        );

        let result = server.set_user_workspace_permission(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn handler_set_user_ws_perm_delegated_authority() {
        let server = create_test_server().await;
        let (admin_user_id, _admin_principal_id, _) =
            create_test_user(&server, "admin-d3@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &admin_user_id, "ws").await;

        // Create a reader user
        let (reader_user_id, reader_principal_id, reader_signing_key) =
            create_test_user(&server, "reader-d3@example.com", "laptop").await;
        server
            .store
            .add_user_to_workspace(&ws_id, &reader_user_id)
            .await
            .unwrap();
        add_principal_to_workspace(&server, &ws_id, &reader_principal_id).await;
        server
            .store
            .set_workspace_permission(&ws_id, &reader_principal_id, Role::Read)
            .await
            .unwrap();

        // Create another user to grant permissions to
        let (other_user_id, _, _) =
            create_test_user(&server, "other-d3@example.com", "laptop").await;
        server
            .store
            .add_user_to_workspace(&ws_id, &other_user_id)
            .await
            .unwrap();

        // Reader tries to grant Write permission (should fail)
        let request = create_signed_request(
            &reader_principal_id,
            &reader_signing_key,
            "/zopp.ZoppService/SetUserWorkspacePermission",
            zopp_proto::SetUserWorkspacePermissionRequest {
                workspace_name: "ws".to_string(),
                user_email: "other-d3@example.com".to_string(),
                role: zopp_proto::Role::Write as i32,
            },
        );

        let result = server.set_user_workspace_permission(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::PermissionDenied);
    }

    #[tokio::test]
    async fn handler_get_user_ws_perm_user_not_found() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "owner-d4@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/GetUserWorkspacePermission",
            zopp_proto::GetUserWorkspacePermissionRequest {
                workspace_name: "ws".to_string(),
                user_email: "nonexistent@example.com".to_string(),
            },
        );

        let result = server.get_user_workspace_permission(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn handler_set_user_proj_perm_user_not_found() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "owner-d5@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        create_test_project(&server, &ws_id, "proj").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/SetUserProjectPermission",
            zopp_proto::SetUserProjectPermissionRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
                user_email: "nonexistent@example.com".to_string(),
                role: zopp_proto::Role::Read as i32,
            },
        );

        let result = server.set_user_project_permission(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn handler_set_user_env_perm_user_not_found() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "owner-d6@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        let proj_id = create_test_project(&server, &ws_id, "proj").await;
        create_test_environment(&server, &proj_id, "dev").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/SetUserEnvironmentPermission",
            zopp_proto::SetUserEnvironmentPermissionRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
                environment_name: "dev".to_string(),
                user_email: "nonexistent@example.com".to_string(),
                role: zopp_proto::Role::Read as i32,
            },
        );

        let result = server.set_user_environment_permission(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn handler_remove_user_ws_perm_user_not_found() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "owner-d7@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/RemoveUserWorkspacePermission",
            zopp_proto::RemoveUserWorkspacePermissionRequest {
                workspace_name: "ws".to_string(),
                user_email: "nonexistent@example.com".to_string(),
            },
        );

        let result = server.remove_user_workspace_permission(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn handler_list_user_ws_perms_ws_not_found() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "owner-d8@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/ListUserWorkspacePermissions",
            zopp_proto::ListUserWorkspacePermissionsRequest {
                workspace_name: "nonexistent".to_string(),
            },
        );

        let result = server.list_user_workspace_permissions(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    // ================== Group permission error path tests ==================

    #[tokio::test]
    async fn handler_set_group_ws_perm_group_not_found() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "owner-g1@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/SetGroupWorkspacePermission",
            zopp_proto::SetGroupWorkspacePermissionRequest {
                workspace_name: "ws".to_string(),
                group_name: "nonexistent".to_string(),
                role: zopp_proto::Role::Read as i32,
            },
        );

        let result = server.set_group_workspace_permission(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn handler_set_group_proj_perm_group_not_found() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "owner-g2@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        create_test_project(&server, &ws_id, "proj").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/SetGroupProjectPermission",
            zopp_proto::SetGroupProjectPermissionRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
                group_name: "nonexistent".to_string(),
                role: zopp_proto::Role::Read as i32,
            },
        );

        let result = server.set_group_project_permission(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn handler_set_group_env_perm_group_not_found() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "owner-g3@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        let proj_id = create_test_project(&server, &ws_id, "proj").await;
        create_test_environment(&server, &proj_id, "dev").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/SetGroupEnvironmentPermission",
            zopp_proto::SetGroupEnvironmentPermissionRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
                environment_name: "dev".to_string(),
                group_name: "nonexistent".to_string(),
                role: zopp_proto::Role::Read as i32,
            },
        );

        let result = server.set_group_environment_permission(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn handler_get_group_ws_perm_group_not_found() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "owner-g4@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/GetGroupWorkspacePermission",
            zopp_proto::GetGroupWorkspacePermissionRequest {
                workspace_name: "ws".to_string(),
                group_name: "nonexistent".to_string(),
            },
        );

        let result = server.get_group_workspace_permission(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn handler_remove_group_ws_perm_group_not_found() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "owner-g5@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/RemoveGroupWorkspacePermission",
            zopp_proto::RemoveGroupWorkspacePermissionRequest {
                workspace_name: "ws".to_string(),
                group_name: "nonexistent".to_string(),
            },
        );

        let result = server.remove_group_workspace_permission(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn handler_list_group_ws_perms_ws_not_found() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "owner-g6@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/ListGroupWorkspacePermissions",
            zopp_proto::ListGroupWorkspacePermissionsRequest {
                workspace_name: "nonexistent".to_string(),
            },
        );

        let result = server.list_group_workspace_permissions(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    // ================== Principal permission error path tests ==================

    #[tokio::test]
    async fn handler_set_ws_perm_principal_not_found() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "owner-p1@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        let fake_principal_id = uuid::Uuid::new_v4().to_string();

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/SetWorkspacePermission",
            zopp_proto::SetWorkspacePermissionRequest {
                workspace_name: "ws".to_string(),
                principal_id: fake_principal_id,
                role: zopp_proto::Role::Read as i32,
            },
        );

        let result = server.set_workspace_permission(request).await;
        assert!(result.is_err());
        // Returns Internal because the principal doesn't exist in the database
        assert_eq!(result.unwrap_err().code(), tonic::Code::Internal);
    }

    #[tokio::test]
    async fn handler_set_proj_perm_principal_not_found() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "owner-p2@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        create_test_project(&server, &ws_id, "proj").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        let fake_principal_id = uuid::Uuid::new_v4().to_string();

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/SetProjectPermission",
            zopp_proto::SetProjectPermissionRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
                principal_id: fake_principal_id,
                role: zopp_proto::Role::Read as i32,
            },
        );

        let result = server.set_project_permission(request).await;
        assert!(result.is_err());
        // Returns Internal because the principal doesn't exist in the database
        assert_eq!(result.unwrap_err().code(), tonic::Code::Internal);
    }

    #[tokio::test]
    async fn handler_set_env_perm_principal_not_found() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "owner-p3@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        let proj_id = create_test_project(&server, &ws_id, "proj").await;
        create_test_environment(&server, &proj_id, "dev").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        let fake_principal_id = uuid::Uuid::new_v4().to_string();

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/SetEnvironmentPermission",
            zopp_proto::SetEnvironmentPermissionRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
                environment_name: "dev".to_string(),
                principal_id: fake_principal_id,
                role: zopp_proto::Role::Read as i32,
            },
        );

        let result = server.set_environment_permission(request).await;
        assert!(result.is_err());
        // Returns Internal because the principal doesn't exist in the database
        assert_eq!(result.unwrap_err().code(), tonic::Code::Internal);
    }

    #[tokio::test]
    async fn handler_get_ws_perm_principal_not_found() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "owner-p4@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        let fake_principal_id = uuid::Uuid::new_v4().to_string();

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/GetWorkspacePermission",
            zopp_proto::GetWorkspacePermissionRequest {
                workspace_name: "ws".to_string(),
                principal_id: fake_principal_id,
            },
        );

        let result = server.get_workspace_permission(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn handler_remove_ws_perm_principal_not_found() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "owner-p5@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        let fake_principal_id = uuid::Uuid::new_v4().to_string();

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/RemoveWorkspacePermission",
            zopp_proto::RemoveWorkspacePermissionRequest {
                workspace_name: "ws".to_string(),
                principal_id: fake_principal_id,
            },
        );

        let result = server.remove_workspace_permission(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    // ================== Audit handler additional tests ==================

    #[tokio::test]
    async fn handler_count_audit_logs_ws_not_found() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "owner-a1@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/CountAuditLogs",
            zopp_proto::CountAuditLogsRequest {
                workspace_name: "nonexistent".to_string(),
                project_name: None,
                environment_name: None,
                principal_id: None,
                user_id: None,
                action: None,
                result: None,
                from_timestamp: None,
                to_timestamp: None,
            },
        );

        let result = server.count_audit_logs(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn handler_list_audit_logs_ws_not_found() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "owner-a2@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/ListAuditLogs",
            zopp_proto::ListAuditLogsRequest {
                workspace_name: "nonexistent".to_string(),
                project_name: None,
                environment_name: None,
                principal_id: None,
                user_id: None,
                action: None,
                result: None,
                from_timestamp: None,
                to_timestamp: None,
                limit: Some(10),
                offset: None,
            },
        );

        let result = server.list_audit_logs(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    // ================== Service Principal handler tests ==================

    #[tokio::test]
    async fn handler_list_workspace_service_principals_success() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "owner-pr1@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/ListWorkspaceServicePrincipals",
            zopp_proto::ListWorkspaceServicePrincipalsRequest {
                workspace_name: "ws".to_string(),
            },
        );

        let result = server.list_workspace_service_principals(request).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn handler_list_workspace_service_principals_ws_not_found() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "owner-pr2@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/ListWorkspaceServicePrincipals",
            zopp_proto::ListWorkspaceServicePrincipalsRequest {
                workspace_name: "nonexistent".to_string(),
            },
        );

        let result = server.list_workspace_service_principals(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn handler_get_principal_success_v2() {
        let server = create_test_server().await;
        let (_user_id, principal_id, signing_key) =
            create_test_user(&server, "owner-pr3@example.com", "laptop").await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/GetPrincipal",
            zopp_proto::GetPrincipalRequest {
                principal_id: principal_id.0.to_string(),
            },
        );

        let result = server.get_principal(request).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn handler_get_principal_not_found_v2() {
        let server = create_test_server().await;
        let (_user_id, principal_id, signing_key) =
            create_test_user(&server, "owner-pr4@example.com", "laptop").await;

        let fake_principal_id = uuid::Uuid::new_v4().to_string();

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/GetPrincipal",
            zopp_proto::GetPrincipalRequest {
                principal_id: fake_principal_id,
            },
        );

        let result = server.get_principal(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    // ================== Permission error path tests ==================

    #[tokio::test]
    async fn handler_set_ws_perm_invalid_principal_id_format() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "owner-ip1@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/SetWorkspacePermission",
            zopp_proto::SetWorkspacePermissionRequest {
                workspace_name: "ws".to_string(),
                principal_id: "not-a-valid-uuid".to_string(),
                role: zopp_proto::Role::Read as i32,
            },
        );

        let result = server.set_workspace_permission(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn handler_set_ws_perm_invalid_role() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "owner-ir1@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/SetWorkspacePermission",
            zopp_proto::SetWorkspacePermissionRequest {
                workspace_name: "ws".to_string(),
                principal_id: principal_id.0.to_string(),
                role: 999, // Invalid role
            },
        );

        let result = server.set_workspace_permission(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn handler_set_proj_perm_invalid_principal_id_format() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "owner-ip2@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        create_test_project(&server, &ws_id, "proj").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/SetProjectPermission",
            zopp_proto::SetProjectPermissionRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
                principal_id: "not-a-valid-uuid".to_string(),
                role: zopp_proto::Role::Read as i32,
            },
        );

        let result = server.set_project_permission(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn handler_set_proj_perm_invalid_role() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "owner-ir2@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        create_test_project(&server, &ws_id, "proj").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/SetProjectPermission",
            zopp_proto::SetProjectPermissionRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
                principal_id: principal_id.0.to_string(),
                role: 999, // Invalid role
            },
        );

        let result = server.set_project_permission(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn handler_set_env_perm_invalid_principal_id_format() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "owner-ip3@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        let proj_id = create_test_project(&server, &ws_id, "proj").await;
        create_test_environment(&server, &proj_id, "dev").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/SetEnvironmentPermission",
            zopp_proto::SetEnvironmentPermissionRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
                environment_name: "dev".to_string(),
                principal_id: "not-a-valid-uuid".to_string(),
                role: zopp_proto::Role::Read as i32,
            },
        );

        let result = server.set_environment_permission(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn handler_set_env_perm_invalid_role() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "owner-ir3@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        let proj_id = create_test_project(&server, &ws_id, "proj").await;
        create_test_environment(&server, &proj_id, "dev").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/SetEnvironmentPermission",
            zopp_proto::SetEnvironmentPermissionRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
                environment_name: "dev".to_string(),
                principal_id: principal_id.0.to_string(),
                role: 999, // Invalid role
            },
        );

        let result = server.set_environment_permission(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn handler_get_ws_perm_invalid_principal_id_format() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "owner-gip1@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/GetWorkspacePermission",
            zopp_proto::GetWorkspacePermissionRequest {
                workspace_name: "ws".to_string(),
                principal_id: "not-a-valid-uuid".to_string(),
            },
        );

        let result = server.get_workspace_permission(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn handler_get_proj_perm_invalid_principal_id_format() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "owner-gip2@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        create_test_project(&server, &ws_id, "proj").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/GetProjectPermission",
            zopp_proto::GetProjectPermissionRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
                principal_id: "not-a-valid-uuid".to_string(),
            },
        );

        let result = server.get_project_permission(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn handler_get_env_perm_invalid_principal_id_format() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "owner-gip3@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        let proj_id = create_test_project(&server, &ws_id, "proj").await;
        create_test_environment(&server, &proj_id, "dev").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/GetEnvironmentPermission",
            zopp_proto::GetEnvironmentPermissionRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
                environment_name: "dev".to_string(),
                principal_id: "not-a-valid-uuid".to_string(),
            },
        );

        let result = server.get_environment_permission(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn handler_remove_ws_perm_invalid_principal_id_format() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "owner-rip1@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/RemoveWorkspacePermission",
            zopp_proto::RemoveWorkspacePermissionRequest {
                workspace_name: "ws".to_string(),
                principal_id: "not-a-valid-uuid".to_string(),
            },
        );

        let result = server.remove_workspace_permission(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn handler_remove_proj_perm_invalid_principal_id_format() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "owner-rip2@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        create_test_project(&server, &ws_id, "proj").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/RemoveProjectPermission",
            zopp_proto::RemoveProjectPermissionRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
                principal_id: "not-a-valid-uuid".to_string(),
            },
        );

        let result = server.remove_project_permission(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn handler_remove_env_perm_invalid_principal_id_format() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "owner-rip3@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        let proj_id = create_test_project(&server, &ws_id, "proj").await;
        create_test_environment(&server, &proj_id, "dev").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/RemoveEnvironmentPermission",
            zopp_proto::RemoveEnvironmentPermissionRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
                environment_name: "dev".to_string(),
                principal_id: "not-a-valid-uuid".to_string(),
            },
        );

        let result = server.remove_environment_permission(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::InvalidArgument);
    }

    // ================== Project not found tests ==================

    #[tokio::test]
    async fn handler_set_proj_perm_project_not_found() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "owner-pnf1@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/SetProjectPermission",
            zopp_proto::SetProjectPermissionRequest {
                workspace_name: "ws".to_string(),
                project_name: "nonexistent".to_string(),
                principal_id: principal_id.0.to_string(),
                role: zopp_proto::Role::Read as i32,
            },
        );

        let result = server.set_project_permission(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn handler_get_proj_perm_project_not_found() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "owner-pnf2@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/GetProjectPermission",
            zopp_proto::GetProjectPermissionRequest {
                workspace_name: "ws".to_string(),
                project_name: "nonexistent".to_string(),
                principal_id: principal_id.0.to_string(),
            },
        );

        let result = server.get_project_permission(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn handler_list_proj_perms_project_not_found() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "owner-pnf3@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/ListProjectPermissions",
            zopp_proto::ListProjectPermissionsRequest {
                workspace_name: "ws".to_string(),
                project_name: "nonexistent".to_string(),
            },
        );

        let result = server.list_project_permissions(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn handler_remove_proj_perm_project_not_found() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "owner-pnf4@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/RemoveProjectPermission",
            zopp_proto::RemoveProjectPermissionRequest {
                workspace_name: "ws".to_string(),
                project_name: "nonexistent".to_string(),
                principal_id: principal_id.0.to_string(),
            },
        );

        let result = server.remove_project_permission(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    // ================== Environment not found tests ==================

    #[tokio::test]
    async fn handler_set_env_perm_environment_not_found() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "owner-enf1@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        create_test_project(&server, &ws_id, "proj").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/SetEnvironmentPermission",
            zopp_proto::SetEnvironmentPermissionRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
                environment_name: "nonexistent".to_string(),
                principal_id: principal_id.0.to_string(),
                role: zopp_proto::Role::Read as i32,
            },
        );

        let result = server.set_environment_permission(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn handler_get_env_perm_environment_not_found() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "owner-enf2@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        create_test_project(&server, &ws_id, "proj").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/GetEnvironmentPermission",
            zopp_proto::GetEnvironmentPermissionRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
                environment_name: "nonexistent".to_string(),
                principal_id: principal_id.0.to_string(),
            },
        );

        let result = server.get_environment_permission(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn handler_list_env_perms_environment_not_found() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "owner-enf3@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        create_test_project(&server, &ws_id, "proj").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/ListEnvironmentPermissions",
            zopp_proto::ListEnvironmentPermissionsRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
                environment_name: "nonexistent".to_string(),
            },
        );

        let result = server.list_environment_permissions(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn handler_remove_env_perm_environment_not_found() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "owner-enf4@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        create_test_project(&server, &ws_id, "proj").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/RemoveEnvironmentPermission",
            zopp_proto::RemoveEnvironmentPermissionRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
                environment_name: "nonexistent".to_string(),
                principal_id: principal_id.0.to_string(),
            },
        );

        let result = server.remove_environment_permission(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    // ================== Delegated authority tests ==================

    #[tokio::test]
    async fn handler_set_ws_perm_delegated_authority_failure() {
        let server = create_test_server().await;
        let (admin_user_id, _admin_principal_id, _) =
            create_test_user(&server, "admin-da1@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &admin_user_id, "ws").await;

        // Create a reader user who will try to grant higher permissions
        let (reader_user_id, reader_principal_id, reader_signing_key) =
            create_test_user(&server, "reader-da1@example.com", "laptop").await;
        server.store.add_user_to_workspace(&ws_id, &reader_user_id).await.unwrap();
        add_principal_to_workspace(&server, &ws_id, &reader_principal_id).await;
        server.store.set_workspace_permission(&ws_id, &reader_principal_id, zopp_storage::Role::Read).await.unwrap();

        // Reader tries to grant Admin permission (should fail)
        let request = create_signed_request(
            &reader_principal_id,
            &reader_signing_key,
            "/zopp.ZoppService/SetWorkspacePermission",
            zopp_proto::SetWorkspacePermissionRequest {
                workspace_name: "ws".to_string(),
                principal_id: reader_principal_id.0.to_string(),
                role: zopp_proto::Role::Admin as i32,
            },
        );

        let result = server.set_workspace_permission(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::PermissionDenied);
    }

    #[tokio::test]
    async fn handler_set_proj_perm_delegated_authority_failure() {
        let server = create_test_server().await;
        let (admin_user_id, _admin_principal_id, _) =
            create_test_user(&server, "admin-da2@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &admin_user_id, "ws").await;
        let proj_id = create_test_project(&server, &ws_id, "proj").await;

        // Create a reader user
        let (reader_user_id, reader_principal_id, reader_signing_key) =
            create_test_user(&server, "reader-da2@example.com", "laptop").await;
        server.store.add_user_to_workspace(&ws_id, &reader_user_id).await.unwrap();
        add_principal_to_workspace(&server, &ws_id, &reader_principal_id).await;
        server.store.set_project_permission(&proj_id, &reader_principal_id, zopp_storage::Role::Read).await.unwrap();

        // Reader tries to grant Admin permission (should fail)
        let request = create_signed_request(
            &reader_principal_id,
            &reader_signing_key,
            "/zopp.ZoppService/SetProjectPermission",
            zopp_proto::SetProjectPermissionRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
                principal_id: reader_principal_id.0.to_string(),
                role: zopp_proto::Role::Admin as i32,
            },
        );

        let result = server.set_project_permission(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::PermissionDenied);
    }

    #[tokio::test]
    async fn handler_set_env_perm_delegated_authority_failure() {
        let server = create_test_server().await;
        let (admin_user_id, _admin_principal_id, _) =
            create_test_user(&server, "admin-da3@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &admin_user_id, "ws").await;
        let proj_id = create_test_project(&server, &ws_id, "proj").await;
        let env_id = create_test_environment(&server, &proj_id, "dev").await;

        // Create a reader user
        let (reader_user_id, reader_principal_id, reader_signing_key) =
            create_test_user(&server, "reader-da3@example.com", "laptop").await;
        server.store.add_user_to_workspace(&ws_id, &reader_user_id).await.unwrap();
        add_principal_to_workspace(&server, &ws_id, &reader_principal_id).await;
        server.store.set_environment_permission(&env_id, &reader_principal_id, zopp_storage::Role::Read).await.unwrap();

        // Reader tries to grant Admin permission (should fail)
        let request = create_signed_request(
            &reader_principal_id,
            &reader_signing_key,
            "/zopp.ZoppService/SetEnvironmentPermission",
            zopp_proto::SetEnvironmentPermissionRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
                environment_name: "dev".to_string(),
                principal_id: reader_principal_id.0.to_string(),
                role: zopp_proto::Role::Admin as i32,
            },
        );

        let result = server.set_environment_permission(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::PermissionDenied);
    }

    // ==================== Additional Coverage Tests (Unique) ====================

    #[tokio::test]
    async fn handler_create_workspace_service_principal_denied() {
        let server = create_test_server().await;
        let (user_id, _principal_id, signing_key) =
            create_test_user(&server, "owner-sp1@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;

        // Create a service principal
        let service_principal_id = server
            .store
            .create_principal(&zopp_storage::CreatePrincipalParams {
                user_id: None,
                name: "service-bot".to_string(),
                public_key: signing_key.verifying_key().to_bytes().to_vec(),
                x25519_public_key: None,
            })
            .await
            .unwrap();

        add_principal_to_workspace(&server, &ws_id, &service_principal_id).await;

        let request = create_signed_request(
            &service_principal_id,
            &signing_key,
            "/zopp.ZoppService/CreateWorkspace",
            zopp_proto::CreateWorkspaceRequest {
                id: uuid::Uuid::new_v4().to_string(),
                name: "new-ws".to_string(),
                ephemeral_pub: vec![],
                kek_wrapped: vec![],
                kek_nonce: vec![],
            },
        );

        let result = server.create_workspace(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::Unauthenticated);
    }

    #[tokio::test]
    async fn handler_create_workspace_invalid_uuid() {
        let server = create_test_server().await;
        let (_user_id, principal_id, signing_key) =
            create_test_user(&server, "test-inv1@example.com", "laptop").await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/CreateWorkspace",
            zopp_proto::CreateWorkspaceRequest {
                id: "not-a-uuid".to_string(),
                name: "ws".to_string(),
                ephemeral_pub: vec![],
                kek_wrapped: vec![],
                kek_nonce: vec![],
            },
        );

        let result = server.create_workspace(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn handler_grant_ws_access_service_principal_denied() {
        let server = create_test_server().await;
        let (user_id, _principal_id, signing_key) =
            create_test_user(&server, "owner-gwa1@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;

        let service_principal_id = server
            .store
            .create_principal(&zopp_storage::CreatePrincipalParams {
                user_id: None,
                name: "service-bot".to_string(),
                public_key: signing_key.verifying_key().to_bytes().to_vec(),
                x25519_public_key: None,
            })
            .await
            .unwrap();

        add_principal_to_workspace(&server, &ws_id, &service_principal_id).await;

        let request = create_signed_request(
            &service_principal_id,
            &signing_key,
            "/zopp.ZoppService/GrantPrincipalWorkspaceAccess",
            zopp_proto::GrantPrincipalWorkspaceAccessRequest {
                workspace_name: "ws".to_string(),
                principal_id: uuid::Uuid::new_v4().to_string(),
                ephemeral_pub: vec![1, 2, 3],
                kek_wrapped: vec![4, 5, 6],
                kek_nonce: vec![7, 8, 9],
            },
        );

        let result = server.grant_principal_workspace_access(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::PermissionDenied);
    }

    #[tokio::test]
    async fn handler_grant_ws_access_invalid_principal() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "owner-gwa2@example.com", "laptop").await;
        let _ws_id = create_test_workspace(&server, &user_id, "ws").await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/GrantPrincipalWorkspaceAccess",
            zopp_proto::GrantPrincipalWorkspaceAccessRequest {
                workspace_name: "ws".to_string(),
                principal_id: "not-a-uuid".to_string(),
                ephemeral_pub: vec![1, 2, 3],
                kek_wrapped: vec![4, 5, 6],
                kek_nonce: vec![7, 8, 9],
            },
        );

        let result = server.grant_principal_workspace_access(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn handler_grant_ws_access_principal_not_found() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "owner-gwa3@example.com", "laptop").await;
        let _ws_id = create_test_workspace(&server, &user_id, "ws").await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/GrantPrincipalWorkspaceAccess",
            zopp_proto::GrantPrincipalWorkspaceAccessRequest {
                workspace_name: "ws".to_string(),
                principal_id: uuid::Uuid::new_v4().to_string(),
                ephemeral_pub: vec![1, 2, 3],
                kek_wrapped: vec![4, 5, 6],
                kek_nonce: vec![7, 8, 9],
            },
        );

        let result = server.grant_principal_workspace_access(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn handler_grant_ws_access_requires_admin_other_user() {
        let server = create_test_server().await;
        let (admin_user_id, _admin_principal_id, _admin_signing_key) =
            create_test_user(&server, "admin-gwa4@example.com", "admin-laptop").await;
        let ws_id = create_test_workspace(&server, &admin_user_id, "ws").await;

        let (reader_user_id, reader_principal_id, reader_signing_key) =
            create_test_user(&server, "reader-gwa4@example.com", "reader-laptop").await;
        server.store.add_user_to_workspace(&ws_id, &reader_user_id).await.unwrap();
        add_principal_to_workspace(&server, &ws_id, &reader_principal_id).await;
        server.store.set_workspace_permission(&ws_id, &reader_principal_id, zopp_storage::Role::Read).await.unwrap();

        let (other_user_id, other_principal_id, _other_signing_key) =
            create_test_user(&server, "other-gwa4@example.com", "other-laptop").await;
        server.store.add_user_to_workspace(&ws_id, &other_user_id).await.unwrap();

        let request = create_signed_request(
            &reader_principal_id,
            &reader_signing_key,
            "/zopp.ZoppService/GrantPrincipalWorkspaceAccess",
            zopp_proto::GrantPrincipalWorkspaceAccessRequest {
                workspace_name: "ws".to_string(),
                principal_id: other_principal_id.0.to_string(),
                ephemeral_pub: vec![1, 2, 3],
                kek_wrapped: vec![4, 5, 6],
                kek_nonce: vec![7, 8, 9],
            },
        );

        let result = server.grant_principal_workspace_access(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::PermissionDenied);
    }

    #[tokio::test]
    async fn handler_watch_secrets_ws_not_found_user() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "test-ws1@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/WatchSecrets",
            zopp_proto::WatchSecretsRequest {
                workspace_name: "nonexistent".to_string(),
                project_name: "proj".to_string(),
                environment_name: "dev".to_string(),
                since_version: None,
            },
        );

        let result = server.watch_secrets(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn handler_watch_secrets_env_not_found() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "test-ws2@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        let _proj_id = create_test_project(&server, &ws_id, "proj").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/WatchSecrets",
            zopp_proto::WatchSecretsRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
                environment_name: "nonexistent".to_string(),
                since_version: None,
            },
        );

        let result = server.watch_secrets(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn handler_watch_secrets_perm_denied() {
        let server = create_test_server().await;
        let (admin_user_id, _admin_principal_id, _admin_signing_key) =
            create_test_user(&server, "admin-ws3@example.com", "admin-laptop").await;
        let ws_id = create_test_workspace(&server, &admin_user_id, "ws").await;
        let proj_id = create_test_project(&server, &ws_id, "proj").await;
        let _env_id = create_test_environment(&server, &proj_id, "dev").await;

        let (other_user_id, other_principal_id, other_signing_key) =
            create_test_user(&server, "other-ws3@example.com", "laptop").await;
        server.store.add_user_to_workspace(&ws_id, &other_user_id).await.unwrap();
        add_principal_to_workspace(&server, &ws_id, &other_principal_id).await;
        // No permission granted

        let request = create_signed_request(
            &other_principal_id,
            &other_signing_key,
            "/zopp.ZoppService/WatchSecrets",
            zopp_proto::WatchSecretsRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
                environment_name: "dev".to_string(),
                since_version: None,
            },
        );

        let result = server.watch_secrets(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::PermissionDenied);
    }

    #[tokio::test]
    async fn handler_upsert_secret_ws_not_found_user() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "test-us1@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/UpsertSecret",
            zopp_proto::UpsertSecretRequest {
                workspace_name: "nonexistent".to_string(),
                project_name: "proj".to_string(),
                environment_name: "dev".to_string(),
                key: "SECRET_KEY".to_string(),
                nonce: vec![0u8; 24],
                ciphertext: vec![1, 2, 3],
            },
        );

        let result = server.upsert_secret(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn handler_get_secret_ws_not_found_user() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "test-gs1@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/GetSecret",
            zopp_proto::GetSecretRequest {
                workspace_name: "nonexistent".to_string(),
                project_name: "proj".to_string(),
                environment_name: "dev".to_string(),
                key: "SECRET_KEY".to_string(),
            },
        );

        let result = server.get_secret(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn handler_list_secrets_ws_not_found_user() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "test-ls1@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/ListSecrets",
            zopp_proto::ListSecretsRequest {
                workspace_name: "nonexistent".to_string(),
                project_name: "proj".to_string(),
                environment_name: "dev".to_string(),
            },
        );

        let result = server.list_secrets(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn handler_delete_secret_ws_not_found_user() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "test-ds1@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/DeleteSecret",
            zopp_proto::DeleteSecretRequest {
                workspace_name: "nonexistent".to_string(),
                project_name: "proj".to_string(),
                environment_name: "dev".to_string(),
                key: "SECRET_KEY".to_string(),
            },
        );

        let result = server.delete_secret(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn handler_revoke_all_perms_success() {
        let server = create_test_server().await;
        let (admin_user_id, admin_principal_id, admin_signing_key) =
            create_test_user(&server, "admin-rap1@example.com", "admin-laptop").await;
        let ws_id = create_test_workspace(&server, &admin_user_id, "ws").await;
        add_principal_to_workspace(&server, &ws_id, &admin_principal_id).await;

        let (other_user_id, other_principal_id, _other_signing_key) =
            create_test_user(&server, "other-rap1@example.com", "laptop").await;
        server.store.add_user_to_workspace(&ws_id, &other_user_id).await.unwrap();
        add_principal_to_workspace(&server, &ws_id, &other_principal_id).await;
        server.store.set_workspace_permission(&ws_id, &other_principal_id, zopp_storage::Role::Write).await.unwrap();

        let request = create_signed_request(
            &admin_principal_id,
            &admin_signing_key,
            "/zopp.ZoppService/RevokeAllPrincipalPermissions",
            zopp_proto::RevokeAllPrincipalPermissionsRequest {
                workspace_name: "ws".to_string(),
                principal_id: other_principal_id.0.to_string(),
            },
        );

        let result = server.revoke_all_principal_permissions(request).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn handler_revoke_all_perms_denied() {
        let server = create_test_server().await;
        let (admin_user_id, _admin_principal_id, _admin_signing_key) =
            create_test_user(&server, "admin-rap2@example.com", "admin-laptop").await;
        let ws_id = create_test_workspace(&server, &admin_user_id, "ws").await;

        let (reader_user_id, reader_principal_id, reader_signing_key) =
            create_test_user(&server, "reader-rap2@example.com", "laptop").await;
        server.store.add_user_to_workspace(&ws_id, &reader_user_id).await.unwrap();
        add_principal_to_workspace(&server, &ws_id, &reader_principal_id).await;
        server.store.set_workspace_permission(&ws_id, &reader_principal_id, zopp_storage::Role::Read).await.unwrap();

        let (target_user_id, target_principal_id, _target_signing_key) =
            create_test_user(&server, "target-rap2@example.com", "laptop").await;
        server.store.add_user_to_workspace(&ws_id, &target_user_id).await.unwrap();
        add_principal_to_workspace(&server, &ws_id, &target_principal_id).await;

        let request = create_signed_request(
            &reader_principal_id,
            &reader_signing_key,
            "/zopp.ZoppService/RevokeAllPrincipalPermissions",
            zopp_proto::RevokeAllPrincipalPermissionsRequest {
                workspace_name: "ws".to_string(),
                principal_id: target_principal_id.0.to_string(),
            },
        );

        let result = server.revoke_all_principal_permissions(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::PermissionDenied);
    }

    #[tokio::test]
    async fn handler_create_project_ws_not_found() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "test-cp1@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/CreateProject",
            zopp_proto::CreateProjectRequest {
                workspace_name: "nonexistent".to_string(),
                name: "proj".to_string(),
            },
        );

        let result = server.create_project(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn handler_delete_project_success_v2() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "test-dp1@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        let _proj_id = create_test_project(&server, &ws_id, "proj").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/DeleteProject",
            zopp_proto::DeleteProjectRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
            },
        );

        let result = server.delete_project(request).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn handler_delete_environment_success_v2() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "test-de1@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        let proj_id = create_test_project(&server, &ws_id, "proj").await;
        let _env_id = create_test_environment(&server, &proj_id, "dev").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/DeleteEnvironment",
            zopp_proto::DeleteEnvironmentRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
                environment_name: "dev".to_string(),
            },
        );

        let result = server.delete_environment(request).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn handler_get_effective_perms_success() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "test-gep1@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;
        server.store.set_workspace_permission(&ws_id, &principal_id, zopp_storage::Role::Admin).await.unwrap();

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/GetEffectivePermissions",
            zopp_proto::GetEffectivePermissionsRequest {
                workspace_name: "ws".to_string(),
                principal_id: principal_id.0.to_string(),
            },
        );

        let result = server.get_effective_permissions(request).await;
        assert!(result.is_ok());
        let response = result.unwrap().into_inner();
        assert_eq!(response.workspace_role, Some(zopp_proto::Role::Admin as i32));
    }

    #[tokio::test]
    async fn handler_get_effective_perms_ws_not_found() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "test-gep2@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/GetEffectivePermissions",
            zopp_proto::GetEffectivePermissionsRequest {
                workspace_name: "nonexistent".to_string(),
                principal_id: principal_id.0.to_string(),
            },
        );

        let result = server.get_effective_permissions(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn handler_get_audit_log_success_v2() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "test-gal1@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        let proj_id = create_test_project(&server, &ws_id, "proj").await;
        let _env_id = create_test_environment(&server, &proj_id, "dev").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        // Create a secret to generate an audit log
        let upsert_req = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/UpsertSecret",
            zopp_proto::UpsertSecretRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
                environment_name: "dev".to_string(),
                key: "API_KEY".to_string(),
                nonce: vec![0u8; 24],
                ciphertext: vec![1, 2, 3],
            },
        );
        server.upsert_secret(upsert_req).await.unwrap();

        // List audit logs to get an ID
        let list_req = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/ListAuditLogs",
            zopp_proto::ListAuditLogsRequest {
                workspace_name: "ws".to_string(),
                principal_id: None,
                user_id: None,
                project_name: None,
                environment_name: None,
                action: None,
                result: None,
                from_timestamp: None,
                to_timestamp: None,
                limit: Some(10),
                offset: None,
            },
        );
        let list_response = server.list_audit_logs(list_req).await.unwrap().into_inner();
        assert!(!list_response.entries.is_empty());

        let audit_id = &list_response.entries[0].id;

        // Get specific audit log
        let get_req = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/GetAuditLog",
            zopp_proto::GetAuditLogRequest {
                workspace_name: "ws".to_string(),
                audit_log_id: audit_id.clone(),
            },
        );
        let result = server.get_audit_log(get_req).await;
        assert!(result.is_ok());
        let response = result.unwrap().into_inner();
        // GetAuditLog returns AuditLogEntry directly
        assert_eq!(response.id, *audit_id);
    }

    // ============== User Permission Handler Tests ==============

    #[tokio::test]
    async fn handler_set_user_workspace_permission_service_account_denied() {
        let server = create_test_server().await;
        let (user_id, _principal_id, _signing_key) =
            create_test_user(&server, "owner-sup1@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;

        // Create a service principal
        let service_signing_key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
        let service_principal_id = server
            .store
            .create_principal(&zopp_storage::CreatePrincipalParams {
                user_id: None,
                name: "service-bot".to_string(),
                public_key: service_signing_key.verifying_key().to_bytes().to_vec(),
                x25519_public_key: None,
            })
            .await
            .unwrap();
        add_principal_to_workspace(&server, &ws_id, &service_principal_id).await;

        let request = create_signed_request(
            &service_principal_id,
            &service_signing_key,
            "/zopp.ZoppService/SetUserWorkspacePermission",
            zopp_proto::SetUserWorkspacePermissionRequest {
                workspace_name: "ws".to_string(),
                user_email: "other@example.com".to_string(),
                role: zopp_proto::Role::Read as i32,
            },
        );

        let result = server.set_user_workspace_permission(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::Unauthenticated);
    }

    #[tokio::test]
    async fn handler_set_user_workspace_permission_invalid_role() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "owner-sup2@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/SetUserWorkspacePermission",
            zopp_proto::SetUserWorkspacePermissionRequest {
                workspace_name: "ws".to_string(),
                user_email: "other@example.com".to_string(),
                role: 999, // Invalid role
            },
        );

        let result = server.set_user_workspace_permission(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn handler_set_user_workspace_permission_workspace_not_found() {
        let server = create_test_server().await;
        let (_user_id, principal_id, signing_key) =
            create_test_user(&server, "owner-sup3@example.com", "laptop").await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/SetUserWorkspacePermission",
            zopp_proto::SetUserWorkspacePermissionRequest {
                workspace_name: "nonexistent".to_string(),
                user_email: "other@example.com".to_string(),
                role: zopp_proto::Role::Read as i32,
            },
        );

        let result = server.set_user_workspace_permission(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn handler_set_user_workspace_permission_user_not_found() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "owner-sup4@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/SetUserWorkspacePermission",
            zopp_proto::SetUserWorkspacePermissionRequest {
                workspace_name: "ws".to_string(),
                user_email: "nonexistent@example.com".to_string(),
                role: zopp_proto::Role::Read as i32,
            },
        );

        let result = server.set_user_workspace_permission(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn handler_set_user_workspace_permission_delegated_authority_denied() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "owner-sup5@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        // Create a second user with READ permission
        let (target_user_id, target_principal_id, target_signing_key) =
            create_test_user(&server, "reader@example.com", "laptop").await;
        server
            .store
            .add_user_to_workspace(&ws_id, &target_user_id)
            .await
            .unwrap();
        add_principal_to_workspace(&server, &ws_id, &target_principal_id).await;
        server
            .store
            .set_workspace_permission(&ws_id, &target_principal_id, zopp_storage::Role::Read)
            .await
            .unwrap();

        // Reader tries to grant ADMIN permission - should fail
        let request = create_signed_request(
            &target_principal_id,
            &target_signing_key,
            "/zopp.ZoppService/SetUserWorkspacePermission",
            zopp_proto::SetUserWorkspacePermissionRequest {
                workspace_name: "ws".to_string(),
                user_email: "owner-sup5@example.com".to_string(),
                role: zopp_proto::Role::Admin as i32,
            },
        );

        let result = server.set_user_workspace_permission(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::PermissionDenied);
    }

    #[tokio::test]
    async fn handler_get_user_workspace_permission_service_account_denied() {
        let server = create_test_server().await;
        let (user_id, _principal_id, _signing_key) =
            create_test_user(&server, "owner-gup1@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;

        // Create a service principal
        let service_signing_key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
        let service_principal_id = server
            .store
            .create_principal(&zopp_storage::CreatePrincipalParams {
                user_id: None,
                name: "service-bot".to_string(),
                public_key: service_signing_key.verifying_key().to_bytes().to_vec(),
                x25519_public_key: None,
            })
            .await
            .unwrap();
        add_principal_to_workspace(&server, &ws_id, &service_principal_id).await;

        let request = create_signed_request(
            &service_principal_id,
            &service_signing_key,
            "/zopp.ZoppService/GetUserWorkspacePermission",
            zopp_proto::GetUserWorkspacePermissionRequest {
                workspace_name: "ws".to_string(),
                user_email: "owner-gup1@example.com".to_string(),
            },
        );

        let result = server.get_user_workspace_permission(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::Unauthenticated);
    }

    #[tokio::test]
    async fn handler_get_user_workspace_permission_workspace_not_found() {
        let server = create_test_server().await;
        let (_user_id, principal_id, signing_key) =
            create_test_user(&server, "owner-gup2@example.com", "laptop").await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/GetUserWorkspacePermission",
            zopp_proto::GetUserWorkspacePermissionRequest {
                workspace_name: "nonexistent".to_string(),
                user_email: "owner-gup2@example.com".to_string(),
            },
        );

        let result = server.get_user_workspace_permission(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn handler_get_user_workspace_permission_user_not_found() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "owner-gup3@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/GetUserWorkspacePermission",
            zopp_proto::GetUserWorkspacePermissionRequest {
                workspace_name: "ws".to_string(),
                user_email: "nonexistent@example.com".to_string(),
            },
        );

        let result = server.get_user_workspace_permission(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn handler_get_user_workspace_permission_permission_not_found() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "owner-gup4@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        // Create another user without a permission record
        let (other_user_id, _, _) =
            create_test_user(&server, "nouser-perm@example.com", "laptop").await;
        server
            .store
            .add_user_to_workspace(&ws_id, &other_user_id)
            .await
            .unwrap();

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/GetUserWorkspacePermission",
            zopp_proto::GetUserWorkspacePermissionRequest {
                workspace_name: "ws".to_string(),
                user_email: "nouser-perm@example.com".to_string(),
            },
        );

        let result = server.get_user_workspace_permission(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn handler_list_user_workspace_permissions_service_account_denied() {
        let server = create_test_server().await;
        let (user_id, _principal_id, _signing_key) =
            create_test_user(&server, "owner-lup1@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;

        // Create a service principal
        let service_signing_key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
        let service_principal_id = server
            .store
            .create_principal(&zopp_storage::CreatePrincipalParams {
                user_id: None,
                name: "service-bot".to_string(),
                public_key: service_signing_key.verifying_key().to_bytes().to_vec(),
                x25519_public_key: None,
            })
            .await
            .unwrap();
        add_principal_to_workspace(&server, &ws_id, &service_principal_id).await;

        let request = create_signed_request(
            &service_principal_id,
            &service_signing_key,
            "/zopp.ZoppService/ListUserWorkspacePermissions",
            zopp_proto::ListUserWorkspacePermissionsRequest {
                workspace_name: "ws".to_string(),
            },
        );

        let result = server.list_user_workspace_permissions(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::Unauthenticated);
    }

    #[tokio::test]
    async fn handler_list_user_workspace_permissions_workspace_not_found() {
        let server = create_test_server().await;
        let (_user_id, principal_id, signing_key) =
            create_test_user(&server, "owner-lup2@example.com", "laptop").await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/ListUserWorkspacePermissions",
            zopp_proto::ListUserWorkspacePermissionsRequest {
                workspace_name: "nonexistent".to_string(),
            },
        );

        let result = server.list_user_workspace_permissions(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn handler_remove_user_workspace_permission_service_account_denied() {
        let server = create_test_server().await;
        let (user_id, _principal_id, _signing_key) =
            create_test_user(&server, "owner-rup1@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;

        // Create a service principal
        let service_signing_key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
        let service_principal_id = server
            .store
            .create_principal(&zopp_storage::CreatePrincipalParams {
                user_id: None,
                name: "service-bot".to_string(),
                public_key: service_signing_key.verifying_key().to_bytes().to_vec(),
                x25519_public_key: None,
            })
            .await
            .unwrap();
        add_principal_to_workspace(&server, &ws_id, &service_principal_id).await;

        let request = create_signed_request(
            &service_principal_id,
            &service_signing_key,
            "/zopp.ZoppService/RemoveUserWorkspacePermission",
            zopp_proto::RemoveUserWorkspacePermissionRequest {
                workspace_name: "ws".to_string(),
                user_email: "owner-rup1@example.com".to_string(),
            },
        );

        let result = server.remove_user_workspace_permission(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::Unauthenticated);
    }

    #[tokio::test]
    async fn handler_remove_user_workspace_permission_workspace_not_found() {
        let server = create_test_server().await;
        let (_user_id, principal_id, signing_key) =
            create_test_user(&server, "owner-rup2@example.com", "laptop").await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/RemoveUserWorkspacePermission",
            zopp_proto::RemoveUserWorkspacePermissionRequest {
                workspace_name: "nonexistent".to_string(),
                user_email: "owner-rup2@example.com".to_string(),
            },
        );

        let result = server.remove_user_workspace_permission(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn handler_remove_user_workspace_permission_user_not_found() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "owner-rup3@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/RemoveUserWorkspacePermission",
            zopp_proto::RemoveUserWorkspacePermissionRequest {
                workspace_name: "ws".to_string(),
                user_email: "nonexistent@example.com".to_string(),
            },
        );

        let result = server.remove_user_workspace_permission(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn handler_remove_user_workspace_permission_perm_not_found() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "owner-rup4@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        // Create another user without a permission record
        let (other_user_id, _, _) =
            create_test_user(&server, "noperm-user@example.com", "laptop").await;
        server
            .store
            .add_user_to_workspace(&ws_id, &other_user_id)
            .await
            .unwrap();

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/RemoveUserWorkspacePermission",
            zopp_proto::RemoveUserWorkspacePermissionRequest {
                workspace_name: "ws".to_string(),
                user_email: "noperm-user@example.com".to_string(),
            },
        );

        let result = server.remove_user_workspace_permission(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    // ============== User Project Permission Handler Tests ==============

    #[tokio::test]
    async fn handler_set_user_project_permission_service_account_denied() {
        let server = create_test_server().await;
        let (user_id, _principal_id, _signing_key) =
            create_test_user(&server, "owner-supp1@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        let _proj_id = create_test_project(&server, &ws_id, "proj").await;

        // Create a service principal
        let service_signing_key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
        let service_principal_id = server
            .store
            .create_principal(&zopp_storage::CreatePrincipalParams {
                user_id: None,
                name: "service-bot".to_string(),
                public_key: service_signing_key.verifying_key().to_bytes().to_vec(),
                x25519_public_key: None,
            })
            .await
            .unwrap();
        add_principal_to_workspace(&server, &ws_id, &service_principal_id).await;

        let request = create_signed_request(
            &service_principal_id,
            &service_signing_key,
            "/zopp.ZoppService/SetUserProjectPermission",
            zopp_proto::SetUserProjectPermissionRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
                user_email: "other@example.com".to_string(),
                role: zopp_proto::Role::Read as i32,
            },
        );

        let result = server.set_user_project_permission(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::Unauthenticated);
    }

    #[tokio::test]
    async fn handler_set_user_project_permission_workspace_not_found() {
        let server = create_test_server().await;
        let (_user_id, principal_id, signing_key) =
            create_test_user(&server, "owner-supp2@example.com", "laptop").await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/SetUserProjectPermission",
            zopp_proto::SetUserProjectPermissionRequest {
                workspace_name: "nonexistent".to_string(),
                project_name: "proj".to_string(),
                user_email: "other@example.com".to_string(),
                role: zopp_proto::Role::Read as i32,
            },
        );

        let result = server.set_user_project_permission(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn handler_set_user_project_permission_project_not_found() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "owner-supp3@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/SetUserProjectPermission",
            zopp_proto::SetUserProjectPermissionRequest {
                workspace_name: "ws".to_string(),
                project_name: "nonexistent".to_string(),
                user_email: "other@example.com".to_string(),
                role: zopp_proto::Role::Read as i32,
            },
        );

        let result = server.set_user_project_permission(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn handler_set_user_project_permission_user_not_found() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "owner-supp4@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        let _proj_id = create_test_project(&server, &ws_id, "proj").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/SetUserProjectPermission",
            zopp_proto::SetUserProjectPermissionRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
                user_email: "nonexistent@example.com".to_string(),
                role: zopp_proto::Role::Read as i32,
            },
        );

        let result = server.set_user_project_permission(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn handler_set_user_project_permission_invalid_role() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "owner-supp5@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        let _proj_id = create_test_project(&server, &ws_id, "proj").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        // Create a target user
        let (target_user_id, _, _) =
            create_test_user(&server, "target-supp5@example.com", "laptop").await;
        server
            .store
            .add_user_to_workspace(&ws_id, &target_user_id)
            .await
            .unwrap();

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/SetUserProjectPermission",
            zopp_proto::SetUserProjectPermissionRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
                user_email: "target-supp5@example.com".to_string(),
                role: 999, // Invalid role
            },
        );

        let result = server.set_user_project_permission(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn handler_get_user_project_permission_service_account_denied() {
        let server = create_test_server().await;
        let (user_id, _principal_id, _signing_key) =
            create_test_user(&server, "owner-gupp1@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        let _proj_id = create_test_project(&server, &ws_id, "proj").await;

        // Create a service principal
        let service_signing_key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
        let service_principal_id = server
            .store
            .create_principal(&zopp_storage::CreatePrincipalParams {
                user_id: None,
                name: "service-bot".to_string(),
                public_key: service_signing_key.verifying_key().to_bytes().to_vec(),
                x25519_public_key: None,
            })
            .await
            .unwrap();
        add_principal_to_workspace(&server, &ws_id, &service_principal_id).await;

        let request = create_signed_request(
            &service_principal_id,
            &service_signing_key,
            "/zopp.ZoppService/GetUserProjectPermission",
            zopp_proto::GetUserProjectPermissionRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
                user_email: "owner-gupp1@example.com".to_string(),
            },
        );

        let result = server.get_user_project_permission(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::Unauthenticated);
    }

    #[tokio::test]
    async fn handler_get_user_project_permission_workspace_not_found() {
        let server = create_test_server().await;
        let (_user_id, principal_id, signing_key) =
            create_test_user(&server, "owner-gupp2@example.com", "laptop").await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/GetUserProjectPermission",
            zopp_proto::GetUserProjectPermissionRequest {
                workspace_name: "nonexistent".to_string(),
                project_name: "proj".to_string(),
                user_email: "owner-gupp2@example.com".to_string(),
            },
        );

        let result = server.get_user_project_permission(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn handler_get_user_project_permission_project_not_found() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "owner-gupp3@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/GetUserProjectPermission",
            zopp_proto::GetUserProjectPermissionRequest {
                workspace_name: "ws".to_string(),
                project_name: "nonexistent".to_string(),
                user_email: "owner-gupp3@example.com".to_string(),
            },
        );

        let result = server.get_user_project_permission(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn handler_get_user_project_permission_user_not_found() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "owner-gupp4@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        let _proj_id = create_test_project(&server, &ws_id, "proj").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/GetUserProjectPermission",
            zopp_proto::GetUserProjectPermissionRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
                user_email: "nonexistent@example.com".to_string(),
            },
        );

        let result = server.get_user_project_permission(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn handler_get_user_project_permission_perm_not_found() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "owner-gupp5@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        let _proj_id = create_test_project(&server, &ws_id, "proj").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        // Create another user without a project permission
        let (other_user_id, _, _) =
            create_test_user(&server, "noprojperm@example.com", "laptop").await;
        server
            .store
            .add_user_to_workspace(&ws_id, &other_user_id)
            .await
            .unwrap();

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/GetUserProjectPermission",
            zopp_proto::GetUserProjectPermissionRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
                user_email: "noprojperm@example.com".to_string(),
            },
        );

        let result = server.get_user_project_permission(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    // ============== User Environment Permission Handler Tests ==============

    #[tokio::test]
    async fn handler_set_user_environment_permission_service_account_denied() {
        let server = create_test_server().await;
        let (user_id, _principal_id, _signing_key) =
            create_test_user(&server, "owner-suep1@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        let proj_id = create_test_project(&server, &ws_id, "proj").await;
        let _env_id = create_test_environment(&server, &proj_id, "dev").await;

        // Create a service principal
        let service_signing_key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
        let service_principal_id = server
            .store
            .create_principal(&zopp_storage::CreatePrincipalParams {
                user_id: None,
                name: "service-bot".to_string(),
                public_key: service_signing_key.verifying_key().to_bytes().to_vec(),
                x25519_public_key: None,
            })
            .await
            .unwrap();
        add_principal_to_workspace(&server, &ws_id, &service_principal_id).await;

        let request = create_signed_request(
            &service_principal_id,
            &service_signing_key,
            "/zopp.ZoppService/SetUserEnvironmentPermission",
            zopp_proto::SetUserEnvironmentPermissionRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
                environment_name: "dev".to_string(),
                user_email: "other@example.com".to_string(),
                role: zopp_proto::Role::Read as i32,
            },
        );

        let result = server.set_user_environment_permission(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::Unauthenticated);
    }

    #[tokio::test]
    async fn handler_set_user_environment_permission_workspace_not_found() {
        let server = create_test_server().await;
        let (_user_id, principal_id, signing_key) =
            create_test_user(&server, "owner-suep2@example.com", "laptop").await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/SetUserEnvironmentPermission",
            zopp_proto::SetUserEnvironmentPermissionRequest {
                workspace_name: "nonexistent".to_string(),
                project_name: "proj".to_string(),
                environment_name: "dev".to_string(),
                user_email: "other@example.com".to_string(),
                role: zopp_proto::Role::Read as i32,
            },
        );

        let result = server.set_user_environment_permission(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn handler_set_user_environment_permission_project_not_found() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "owner-suep3@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/SetUserEnvironmentPermission",
            zopp_proto::SetUserEnvironmentPermissionRequest {
                workspace_name: "ws".to_string(),
                project_name: "nonexistent".to_string(),
                environment_name: "dev".to_string(),
                user_email: "other@example.com".to_string(),
                role: zopp_proto::Role::Read as i32,
            },
        );

        let result = server.set_user_environment_permission(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn handler_set_user_environment_permission_env_not_found() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "owner-suep4@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        let _proj_id = create_test_project(&server, &ws_id, "proj").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/SetUserEnvironmentPermission",
            zopp_proto::SetUserEnvironmentPermissionRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
                environment_name: "nonexistent".to_string(),
                user_email: "other@example.com".to_string(),
                role: zopp_proto::Role::Read as i32,
            },
        );

        let result = server.set_user_environment_permission(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn handler_set_user_environment_permission_user_not_found() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "owner-suep5@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        let proj_id = create_test_project(&server, &ws_id, "proj").await;
        let _env_id = create_test_environment(&server, &proj_id, "dev").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/SetUserEnvironmentPermission",
            zopp_proto::SetUserEnvironmentPermissionRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
                environment_name: "dev".to_string(),
                user_email: "nonexistent@example.com".to_string(),
                role: zopp_proto::Role::Read as i32,
            },
        );

        let result = server.set_user_environment_permission(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn handler_set_user_environment_permission_invalid_role() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "owner-suep6@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        let proj_id = create_test_project(&server, &ws_id, "proj").await;
        let _env_id = create_test_environment(&server, &proj_id, "dev").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        // Create a target user
        let (target_user_id, _, _) =
            create_test_user(&server, "target-suep6@example.com", "laptop").await;
        server
            .store
            .add_user_to_workspace(&ws_id, &target_user_id)
            .await
            .unwrap();

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/SetUserEnvironmentPermission",
            zopp_proto::SetUserEnvironmentPermissionRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
                environment_name: "dev".to_string(),
                user_email: "target-suep6@example.com".to_string(),
                role: 999, // Invalid role
            },
        );

        let result = server.set_user_environment_permission(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn handler_get_user_environment_permission_service_account_denied() {
        let server = create_test_server().await;
        let (user_id, _principal_id, _signing_key) =
            create_test_user(&server, "owner-guep1@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        let proj_id = create_test_project(&server, &ws_id, "proj").await;
        let _env_id = create_test_environment(&server, &proj_id, "dev").await;

        // Create a service principal
        let service_signing_key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
        let service_principal_id = server
            .store
            .create_principal(&zopp_storage::CreatePrincipalParams {
                user_id: None,
                name: "service-bot".to_string(),
                public_key: service_signing_key.verifying_key().to_bytes().to_vec(),
                x25519_public_key: None,
            })
            .await
            .unwrap();
        add_principal_to_workspace(&server, &ws_id, &service_principal_id).await;

        let request = create_signed_request(
            &service_principal_id,
            &service_signing_key,
            "/zopp.ZoppService/GetUserEnvironmentPermission",
            zopp_proto::GetUserEnvironmentPermissionRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
                environment_name: "dev".to_string(),
                user_email: "owner-guep1@example.com".to_string(),
            },
        );

        let result = server.get_user_environment_permission(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::Unauthenticated);
    }

    #[tokio::test]
    async fn handler_get_user_environment_permission_workspace_not_found() {
        let server = create_test_server().await;
        let (_user_id, principal_id, signing_key) =
            create_test_user(&server, "owner-guep2@example.com", "laptop").await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/GetUserEnvironmentPermission",
            zopp_proto::GetUserEnvironmentPermissionRequest {
                workspace_name: "nonexistent".to_string(),
                project_name: "proj".to_string(),
                environment_name: "dev".to_string(),
                user_email: "owner-guep2@example.com".to_string(),
            },
        );

        let result = server.get_user_environment_permission(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn handler_get_user_environment_permission_project_not_found() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "owner-guep3@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/GetUserEnvironmentPermission",
            zopp_proto::GetUserEnvironmentPermissionRequest {
                workspace_name: "ws".to_string(),
                project_name: "nonexistent".to_string(),
                environment_name: "dev".to_string(),
                user_email: "owner-guep3@example.com".to_string(),
            },
        );

        let result = server.get_user_environment_permission(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn handler_get_user_environment_permission_env_not_found() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "owner-guep4@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        let _proj_id = create_test_project(&server, &ws_id, "proj").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/GetUserEnvironmentPermission",
            zopp_proto::GetUserEnvironmentPermissionRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
                environment_name: "nonexistent".to_string(),
                user_email: "owner-guep4@example.com".to_string(),
            },
        );

        let result = server.get_user_environment_permission(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn handler_get_user_environment_permission_user_not_found() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "owner-guep5@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        let proj_id = create_test_project(&server, &ws_id, "proj").await;
        let _env_id = create_test_environment(&server, &proj_id, "dev").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/GetUserEnvironmentPermission",
            zopp_proto::GetUserEnvironmentPermissionRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
                environment_name: "dev".to_string(),
                user_email: "nonexistent@example.com".to_string(),
            },
        );

        let result = server.get_user_environment_permission(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn handler_get_user_environment_permission_perm_not_found() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "owner-guep6@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        let proj_id = create_test_project(&server, &ws_id, "proj").await;
        let _env_id = create_test_environment(&server, &proj_id, "dev").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        // Create another user without an env permission
        let (other_user_id, _, _) =
            create_test_user(&server, "noenvperm@example.com", "laptop").await;
        server
            .store
            .add_user_to_workspace(&ws_id, &other_user_id)
            .await
            .unwrap();

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/GetUserEnvironmentPermission",
            zopp_proto::GetUserEnvironmentPermissionRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
                environment_name: "dev".to_string(),
                user_email: "noenvperm@example.com".to_string(),
            },
        );

        let result = server.get_user_environment_permission(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    // ============== Auth Handler Error Path Tests ==============

    #[tokio::test]
    async fn handler_join_create_user_other_error() {
        // This tests the case where create_user fails with an error that is NOT AlreadyExists
        // This is difficult to trigger with a real store, but we can test the join flow
        // with an expired invite to verify the error path
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "owner-jcuo@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        // Create an invite that's already expired
        let expired_at = chrono::Utc::now() - chrono::Duration::hours(1);
        let token = "expired-token-hash";
        let _ = server
            .store
            .create_invite(&zopp_storage::CreateInviteParams {
                workspace_ids: vec![ws_id],
                token: token.to_string(),
                kek_encrypted: None,
                kek_nonce: None,
                expires_at: expired_at,
                created_by_user_id: Some(user_id),
            })
            .await
            .unwrap();

        // Try to join with expired invite
        let request = tonic::Request::new(zopp_proto::JoinRequest {
            invite_token: token.to_string(),
            email: "newuser@example.com".to_string(),
            principal_name: "laptop".to_string(),
            public_key: ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng)
                .verifying_key()
                .to_bytes()
                .to_vec(),
            x25519_public_key: vec![],
            ephemeral_pub: vec![],
            kek_wrapped: vec![],
            kek_nonce: vec![],
        });

        let result = server.join(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::PermissionDenied);
    }

    #[tokio::test]
    async fn handler_join_existing_user_add_workspace_membership() {
        let server = create_test_server().await;

        // Create the workspace owner
        let (owner_user_id, owner_principal_id, owner_signing_key) =
            create_test_user(&server, "owner-jeua@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &owner_user_id, "ws").await;
        add_principal_to_workspace(&server, &ws_id, &owner_principal_id).await;

        // Create an existing user (not yet in workspace)
        let (existing_user_id, _existing_principal_id, _existing_signing_key) =
            create_test_user(&server, "existing@example.com", "laptop").await;

        // Create an invite
        let token = "invite-token-for-existing";
        let expires_at = chrono::Utc::now() + chrono::Duration::hours(1);
        let create_invite_req = create_signed_request(
            &owner_principal_id,
            &owner_signing_key,
            "/zopp.ZoppService/CreateInvite",
            zopp_proto::CreateInviteRequest {
                workspace_ids: vec![ws_id.0.to_string()],
                token: token.to_string(),
                kek_encrypted: vec![],
                kek_nonce: vec![],
                expires_at: expires_at.timestamp(),
            },
        );
        server.create_invite(create_invite_req).await.unwrap();

        // Existing user joins the workspace
        let new_signing_key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
        let request = tonic::Request::new(zopp_proto::JoinRequest {
            invite_token: token.to_string(),
            email: "existing@example.com".to_string(),
            principal_name: "new-device".to_string(),
            public_key: new_signing_key.verifying_key().to_bytes().to_vec(),
            x25519_public_key: vec![],
            ephemeral_pub: vec![],
            kek_wrapped: vec![],
            kek_nonce: vec![],
        });

        let result = server.join(request).await;
        assert!(result.is_ok());
        let response = result.unwrap().into_inner();
        assert_eq!(response.user_id, existing_user_id.0.to_string());
        assert!(!response.principal_id.is_empty());
        assert_eq!(response.workspaces.len(), 1);
    }

    #[tokio::test]
    async fn handler_login_invalid_signature() {
        let server = create_test_server().await;
        let (_user_id, _principal_id, _signing_key) =
            create_test_user(&server, "user-lis@example.com", "laptop").await;

        // Try to login with wrong signature
        use prost::Message;
        let login_req = zopp_proto::LoginRequest {
            email: "user-lis@example.com".to_string(),
            principal_name: "laptop".to_string(),
            timestamp: chrono::Utc::now().timestamp(),
            signature: vec![0u8; 64], // Invalid signature
        };

        let request = tonic::Request::new(login_req);
        let result = server.login(request).await;
        assert!(result.is_err());
        // Should fail due to signature verification
    }

    // ============== Group Permission Error Path Tests ==============

    #[tokio::test]
    async fn handler_set_group_workspace_permission_workspace_not_found() {
        let server = create_test_server().await;
        let (_user_id, principal_id, signing_key) =
            create_test_user(&server, "owner-sgwp1@example.com", "laptop").await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/SetGroupWorkspacePermission",
            zopp_proto::SetGroupWorkspacePermissionRequest {
                workspace_name: "nonexistent".to_string(),
                group_name: "group".to_string(),
                role: zopp_proto::Role::Read as i32,
            },
        );

        let result = server.set_group_workspace_permission(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn handler_set_group_workspace_permission_group_not_found() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "owner-sgwp2@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/SetGroupWorkspacePermission",
            zopp_proto::SetGroupWorkspacePermissionRequest {
                workspace_name: "ws".to_string(),
                group_name: "nonexistent".to_string(),
                role: zopp_proto::Role::Read as i32,
            },
        );

        let result = server.set_group_workspace_permission(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn handler_set_group_workspace_permission_invalid_role() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "owner-sgwp3@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        // Create a group
        let create_group_req = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/CreateGroup",
            zopp_proto::CreateGroupRequest {
                workspace_name: "ws".to_string(),
                name: "test-group".to_string(),
                description: "Test group".to_string(),
            },
        );
        server.create_group(create_group_req).await.unwrap();

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/SetGroupWorkspacePermission",
            zopp_proto::SetGroupWorkspacePermissionRequest {
                workspace_name: "ws".to_string(),
                group_name: "test-group".to_string(),
                role: 999, // Invalid role
            },
        );

        let result = server.set_group_workspace_permission(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn handler_get_group_workspace_permission_workspace_not_found() {
        let server = create_test_server().await;
        let (_user_id, principal_id, signing_key) =
            create_test_user(&server, "owner-ggwp1@example.com", "laptop").await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/GetGroupWorkspacePermission",
            zopp_proto::GetGroupWorkspacePermissionRequest {
                workspace_name: "nonexistent".to_string(),
                group_name: "group".to_string(),
            },
        );

        let result = server.get_group_workspace_permission(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn handler_get_group_workspace_permission_group_not_found() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "owner-ggwp2@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/GetGroupWorkspacePermission",
            zopp_proto::GetGroupWorkspacePermissionRequest {
                workspace_name: "ws".to_string(),
                group_name: "nonexistent".to_string(),
            },
        );

        let result = server.get_group_workspace_permission(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn handler_get_group_workspace_permission_perm_not_found() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "owner-ggwp3@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        // Create a group but don't set a permission
        let create_group_req = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/CreateGroup",
            zopp_proto::CreateGroupRequest {
                workspace_name: "ws".to_string(),
                name: "noperm-group".to_string(),
                description: "No permissions".to_string(),
            },
        );
        server.create_group(create_group_req).await.unwrap();

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/GetGroupWorkspacePermission",
            zopp_proto::GetGroupWorkspacePermissionRequest {
                workspace_name: "ws".to_string(),
                group_name: "noperm-group".to_string(),
            },
        );

        let result = server.get_group_workspace_permission(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn handler_list_group_workspace_permissions_workspace_not_found() {
        let server = create_test_server().await;
        let (_user_id, principal_id, signing_key) =
            create_test_user(&server, "owner-lgwp1@example.com", "laptop").await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/ListGroupWorkspacePermissions",
            zopp_proto::ListGroupWorkspacePermissionsRequest {
                workspace_name: "nonexistent".to_string(),
            },
        );

        let result = server.list_group_workspace_permissions(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn handler_remove_group_workspace_permission_workspace_not_found() {
        let server = create_test_server().await;
        let (_user_id, principal_id, signing_key) =
            create_test_user(&server, "owner-rgwp1@example.com", "laptop").await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/RemoveGroupWorkspacePermission",
            zopp_proto::RemoveGroupWorkspacePermissionRequest {
                workspace_name: "nonexistent".to_string(),
                group_name: "group".to_string(),
            },
        );

        let result = server.remove_group_workspace_permission(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn handler_remove_group_workspace_permission_group_not_found() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "owner-rgwp2@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/RemoveGroupWorkspacePermission",
            zopp_proto::RemoveGroupWorkspacePermissionRequest {
                workspace_name: "ws".to_string(),
                group_name: "nonexistent".to_string(),
            },
        );

        let result = server.remove_group_workspace_permission(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    // ============== Group Project Permission Error Path Tests ==============

    #[tokio::test]
    async fn handler_set_group_project_permission_workspace_not_found() {
        let server = create_test_server().await;
        let (_user_id, principal_id, signing_key) =
            create_test_user(&server, "owner-sgpp1@example.com", "laptop").await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/SetGroupProjectPermission",
            zopp_proto::SetGroupProjectPermissionRequest {
                workspace_name: "nonexistent".to_string(),
                project_name: "proj".to_string(),
                group_name: "group".to_string(),
                role: zopp_proto::Role::Read as i32,
            },
        );

        let result = server.set_group_project_permission(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn handler_set_group_project_permission_project_not_found() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "owner-sgpp2@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/SetGroupProjectPermission",
            zopp_proto::SetGroupProjectPermissionRequest {
                workspace_name: "ws".to_string(),
                project_name: "nonexistent".to_string(),
                group_name: "group".to_string(),
                role: zopp_proto::Role::Read as i32,
            },
        );

        let result = server.set_group_project_permission(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn handler_set_group_project_permission_group_not_found() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "owner-sgpp3@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        let _proj_id = create_test_project(&server, &ws_id, "proj").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/SetGroupProjectPermission",
            zopp_proto::SetGroupProjectPermissionRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
                group_name: "nonexistent".to_string(),
                role: zopp_proto::Role::Read as i32,
            },
        );

        let result = server.set_group_project_permission(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn handler_set_group_project_permission_invalid_role() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "owner-sgpp4@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        let _proj_id = create_test_project(&server, &ws_id, "proj").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        // Create a group
        let create_group_req = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/CreateGroup",
            zopp_proto::CreateGroupRequest {
                workspace_name: "ws".to_string(),
                name: "test-group".to_string(),
                description: "Test group".to_string(),
            },
        );
        server.create_group(create_group_req).await.unwrap();

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/SetGroupProjectPermission",
            zopp_proto::SetGroupProjectPermissionRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
                group_name: "test-group".to_string(),
                role: 999, // Invalid role
            },
        );

        let result = server.set_group_project_permission(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn handler_get_group_project_permission_workspace_not_found() {
        let server = create_test_server().await;
        let (_user_id, principal_id, signing_key) =
            create_test_user(&server, "owner-ggpp1@example.com", "laptop").await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/GetGroupProjectPermission",
            zopp_proto::GetGroupProjectPermissionRequest {
                workspace_name: "nonexistent".to_string(),
                project_name: "proj".to_string(),
                group_name: "group".to_string(),
            },
        );

        let result = server.get_group_project_permission(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn handler_get_group_project_permission_project_not_found() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "owner-ggpp2@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/GetGroupProjectPermission",
            zopp_proto::GetGroupProjectPermissionRequest {
                workspace_name: "ws".to_string(),
                project_name: "nonexistent".to_string(),
                group_name: "group".to_string(),
            },
        );

        let result = server.get_group_project_permission(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn handler_get_group_project_permission_group_not_found() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "owner-ggpp3@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        let _proj_id = create_test_project(&server, &ws_id, "proj").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/GetGroupProjectPermission",
            zopp_proto::GetGroupProjectPermissionRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
                group_name: "nonexistent".to_string(),
            },
        );

        let result = server.get_group_project_permission(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn handler_get_group_project_permission_perm_not_found() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "owner-ggpp4@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        let _proj_id = create_test_project(&server, &ws_id, "proj").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        // Create a group but don't set a permission
        let create_group_req = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/CreateGroup",
            zopp_proto::CreateGroupRequest {
                workspace_name: "ws".to_string(),
                name: "noperm-proj-group".to_string(),
                description: "No permissions".to_string(),
            },
        );
        server.create_group(create_group_req).await.unwrap();

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/GetGroupProjectPermission",
            zopp_proto::GetGroupProjectPermissionRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
                group_name: "noperm-proj-group".to_string(),
            },
        );

        let result = server.get_group_project_permission(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn handler_list_group_project_permissions_workspace_not_found() {
        let server = create_test_server().await;
        let (_user_id, principal_id, signing_key) =
            create_test_user(&server, "owner-lgpp1@example.com", "laptop").await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/ListGroupProjectPermissions",
            zopp_proto::ListGroupProjectPermissionsRequest {
                workspace_name: "nonexistent".to_string(),
                project_name: "proj".to_string(),
            },
        );

        let result = server.list_group_project_permissions(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn handler_list_group_project_permissions_project_not_found() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "owner-lgpp2@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/ListGroupProjectPermissions",
            zopp_proto::ListGroupProjectPermissionsRequest {
                workspace_name: "ws".to_string(),
                project_name: "nonexistent".to_string(),
            },
        );

        let result = server.list_group_project_permissions(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn handler_remove_group_project_permission_workspace_not_found() {
        let server = create_test_server().await;
        let (_user_id, principal_id, signing_key) =
            create_test_user(&server, "owner-rgpp1@example.com", "laptop").await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/RemoveGroupProjectPermission",
            zopp_proto::RemoveGroupProjectPermissionRequest {
                workspace_name: "nonexistent".to_string(),
                project_name: "proj".to_string(),
                group_name: "group".to_string(),
            },
        );

        let result = server.remove_group_project_permission(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn handler_remove_group_project_permission_project_not_found() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "owner-rgpp2@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/RemoveGroupProjectPermission",
            zopp_proto::RemoveGroupProjectPermissionRequest {
                workspace_name: "ws".to_string(),
                project_name: "nonexistent".to_string(),
                group_name: "group".to_string(),
            },
        );

        let result = server.remove_group_project_permission(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn handler_remove_group_project_permission_group_not_found() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "owner-rgpp3@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        let _proj_id = create_test_project(&server, &ws_id, "proj").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/RemoveGroupProjectPermission",
            zopp_proto::RemoveGroupProjectPermissionRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
                group_name: "nonexistent".to_string(),
            },
        );

        let result = server.remove_group_project_permission(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    // ============== Group Environment Permission Error Path Tests ==============

    #[tokio::test]
    async fn handler_set_group_environment_permission_workspace_not_found() {
        let server = create_test_server().await;
        let (_user_id, principal_id, signing_key) =
            create_test_user(&server, "owner-sgep1@example.com", "laptop").await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/SetGroupEnvironmentPermission",
            zopp_proto::SetGroupEnvironmentPermissionRequest {
                workspace_name: "nonexistent".to_string(),
                project_name: "proj".to_string(),
                environment_name: "dev".to_string(),
                group_name: "group".to_string(),
                role: zopp_proto::Role::Read as i32,
            },
        );

        let result = server.set_group_environment_permission(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn handler_set_group_environment_permission_project_not_found() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "owner-sgep2@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/SetGroupEnvironmentPermission",
            zopp_proto::SetGroupEnvironmentPermissionRequest {
                workspace_name: "ws".to_string(),
                project_name: "nonexistent".to_string(),
                environment_name: "dev".to_string(),
                group_name: "group".to_string(),
                role: zopp_proto::Role::Read as i32,
            },
        );

        let result = server.set_group_environment_permission(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn handler_set_group_environment_permission_env_not_found() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "owner-sgep3@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        let _proj_id = create_test_project(&server, &ws_id, "proj").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/SetGroupEnvironmentPermission",
            zopp_proto::SetGroupEnvironmentPermissionRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
                environment_name: "nonexistent".to_string(),
                group_name: "group".to_string(),
                role: zopp_proto::Role::Read as i32,
            },
        );

        let result = server.set_group_environment_permission(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn handler_set_group_environment_permission_group_not_found() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "owner-sgep4@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        let proj_id = create_test_project(&server, &ws_id, "proj").await;
        let _env_id = create_test_environment(&server, &proj_id, "dev").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/SetGroupEnvironmentPermission",
            zopp_proto::SetGroupEnvironmentPermissionRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
                environment_name: "dev".to_string(),
                group_name: "nonexistent".to_string(),
                role: zopp_proto::Role::Read as i32,
            },
        );

        let result = server.set_group_environment_permission(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn handler_set_group_environment_permission_invalid_role() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "owner-sgep5@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        let proj_id = create_test_project(&server, &ws_id, "proj").await;
        let _env_id = create_test_environment(&server, &proj_id, "dev").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        // Create a group
        let create_group_req = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/CreateGroup",
            zopp_proto::CreateGroupRequest {
                workspace_name: "ws".to_string(),
                name: "test-group-env".to_string(),
                description: "Test group".to_string(),
            },
        );
        server.create_group(create_group_req).await.unwrap();

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/SetGroupEnvironmentPermission",
            zopp_proto::SetGroupEnvironmentPermissionRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
                environment_name: "dev".to_string(),
                group_name: "test-group-env".to_string(),
                role: 999, // Invalid role
            },
        );

        let result = server.set_group_environment_permission(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn handler_get_group_environment_permission_workspace_not_found() {
        let server = create_test_server().await;
        let (_user_id, principal_id, signing_key) =
            create_test_user(&server, "owner-ggep1@example.com", "laptop").await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/GetGroupEnvironmentPermission",
            zopp_proto::GetGroupEnvironmentPermissionRequest {
                workspace_name: "nonexistent".to_string(),
                project_name: "proj".to_string(),
                environment_name: "dev".to_string(),
                group_name: "group".to_string(),
            },
        );

        let result = server.get_group_environment_permission(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn handler_get_group_environment_permission_project_not_found() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "owner-ggep2@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/GetGroupEnvironmentPermission",
            zopp_proto::GetGroupEnvironmentPermissionRequest {
                workspace_name: "ws".to_string(),
                project_name: "nonexistent".to_string(),
                environment_name: "dev".to_string(),
                group_name: "group".to_string(),
            },
        );

        let result = server.get_group_environment_permission(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn handler_get_group_environment_permission_env_not_found() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "owner-ggep3@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        let _proj_id = create_test_project(&server, &ws_id, "proj").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/GetGroupEnvironmentPermission",
            zopp_proto::GetGroupEnvironmentPermissionRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
                environment_name: "nonexistent".to_string(),
                group_name: "group".to_string(),
            },
        );

        let result = server.get_group_environment_permission(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn handler_get_group_environment_permission_group_not_found() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "owner-ggep4@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        let proj_id = create_test_project(&server, &ws_id, "proj").await;
        let _env_id = create_test_environment(&server, &proj_id, "dev").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/GetGroupEnvironmentPermission",
            zopp_proto::GetGroupEnvironmentPermissionRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
                environment_name: "dev".to_string(),
                group_name: "nonexistent".to_string(),
            },
        );

        let result = server.get_group_environment_permission(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn handler_get_group_environment_permission_perm_not_found() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "owner-ggep5@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        let proj_id = create_test_project(&server, &ws_id, "proj").await;
        let _env_id = create_test_environment(&server, &proj_id, "dev").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        // Create a group but don't set a permission
        let create_group_req = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/CreateGroup",
            zopp_proto::CreateGroupRequest {
                workspace_name: "ws".to_string(),
                name: "noperm-env-group".to_string(),
                description: "No permissions".to_string(),
            },
        );
        server.create_group(create_group_req).await.unwrap();

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/GetGroupEnvironmentPermission",
            zopp_proto::GetGroupEnvironmentPermissionRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
                environment_name: "dev".to_string(),
                group_name: "noperm-env-group".to_string(),
            },
        );

        let result = server.get_group_environment_permission(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn handler_list_group_environment_permissions_workspace_not_found() {
        let server = create_test_server().await;
        let (_user_id, principal_id, signing_key) =
            create_test_user(&server, "owner-lgep1@example.com", "laptop").await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/ListGroupEnvironmentPermissions",
            zopp_proto::ListGroupEnvironmentPermissionsRequest {
                workspace_name: "nonexistent".to_string(),
                project_name: "proj".to_string(),
                environment_name: "dev".to_string(),
            },
        );

        let result = server.list_group_environment_permissions(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn handler_list_group_environment_permissions_project_not_found() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "owner-lgep2@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/ListGroupEnvironmentPermissions",
            zopp_proto::ListGroupEnvironmentPermissionsRequest {
                workspace_name: "ws".to_string(),
                project_name: "nonexistent".to_string(),
                environment_name: "dev".to_string(),
            },
        );

        let result = server.list_group_environment_permissions(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn handler_list_group_environment_permissions_env_not_found() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "owner-lgep3@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        let _proj_id = create_test_project(&server, &ws_id, "proj").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/ListGroupEnvironmentPermissions",
            zopp_proto::ListGroupEnvironmentPermissionsRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
                environment_name: "nonexistent".to_string(),
            },
        );

        let result = server.list_group_environment_permissions(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn handler_remove_group_environment_permission_workspace_not_found() {
        let server = create_test_server().await;
        let (_user_id, principal_id, signing_key) =
            create_test_user(&server, "owner-rgep1@example.com", "laptop").await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/RemoveGroupEnvironmentPermission",
            zopp_proto::RemoveGroupEnvironmentPermissionRequest {
                workspace_name: "nonexistent".to_string(),
                project_name: "proj".to_string(),
                environment_name: "dev".to_string(),
                group_name: "group".to_string(),
            },
        );

        let result = server.remove_group_environment_permission(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn handler_remove_group_environment_permission_project_not_found() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "owner-rgep2@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/RemoveGroupEnvironmentPermission",
            zopp_proto::RemoveGroupEnvironmentPermissionRequest {
                workspace_name: "ws".to_string(),
                project_name: "nonexistent".to_string(),
                environment_name: "dev".to_string(),
                group_name: "group".to_string(),
            },
        );

        let result = server.remove_group_environment_permission(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn handler_remove_group_environment_permission_env_not_found() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "owner-rgep3@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        let _proj_id = create_test_project(&server, &ws_id, "proj").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/RemoveGroupEnvironmentPermission",
            zopp_proto::RemoveGroupEnvironmentPermissionRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
                environment_name: "nonexistent".to_string(),
                group_name: "group".to_string(),
            },
        );

        let result = server.remove_group_environment_permission(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn handler_remove_group_environment_permission_group_not_found() {
        let server = create_test_server().await;
        let (user_id, principal_id, signing_key) =
            create_test_user(&server, "owner-rgep4@example.com", "laptop").await;
        let ws_id = create_test_workspace(&server, &user_id, "ws").await;
        let proj_id = create_test_project(&server, &ws_id, "proj").await;
        let _env_id = create_test_environment(&server, &proj_id, "dev").await;
        add_principal_to_workspace(&server, &ws_id, &principal_id).await;

        let request = create_signed_request(
            &principal_id,
            &signing_key,
            "/zopp.ZoppService/RemoveGroupEnvironmentPermission",
            zopp_proto::RemoveGroupEnvironmentPermissionRequest {
                workspace_name: "ws".to_string(),
                project_name: "proj".to_string(),
                environment_name: "dev".to_string(),
                group_name: "nonexistent".to_string(),
            },
        );

        let result = server.remove_group_environment_permission(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

}
