//! Permission handler tests.
//!
//! Tests for permission-related gRPC handlers including permission denied scenarios.

use super::super::common::*;
use zopp_proto::zopp_service_server::ZoppService;
use zopp_storage::{Store, *};

#[tokio::test]
async fn handler_permission_denied_no_access() {
    let server = create_test_server().await;

    // Create owner with workspace
    let (owner_user_id, _owner_principal_id, _owner_signing_key) =
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
