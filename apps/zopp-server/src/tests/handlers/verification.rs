//! Email verification enforcement tests.
//!
//! Tests that verify email verification is properly enforced when required.

use super::super::common::*;
use zopp_proto::zopp_service_server::ZoppService;
use zopp_storage::{Role, Store};

#[tokio::test]
async fn unverified_principal_blocked_when_verification_required() {
    // Server with verification required
    let server = create_test_server_with_verification().await;

    // Create unverified user with principal
    let (_user_id, principal_id, signing_key) =
        create_unverified_test_user(&server, "test@example.com", "laptop").await;

    // Try to create workspace - should be blocked because principal is not verified
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

    let result = server.create_workspace(request).await;
    assert!(result.is_err(), "Unverified principal should be blocked");
    let status = result.unwrap_err();
    assert_eq!(status.code(), tonic::Code::PermissionDenied);
    assert!(
        status.message().contains("verification"),
        "Error should mention verification: {}",
        status.message()
    );
}

#[tokio::test]
async fn verified_principal_allowed_when_verification_required() {
    // Server with verification required
    let server = create_test_server_with_verification().await;

    // Create user with principal
    let (user_id, principal_id, signing_key) =
        create_test_user(&server, "test@example.com", "laptop").await;

    // Mark user as verified
    server.store.mark_user_verified(&user_id).await.unwrap();

    // Try to create workspace - should succeed because principal is verified
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

    let result = server.create_workspace(request).await;
    assert!(result.is_ok(), "Verified principal should be allowed");
}

#[tokio::test]
async fn unverified_principal_allowed_when_verification_not_required() {
    // Server without verification required (default)
    let server = create_test_server().await;

    // Create user with unverified principal
    let (_user_id, principal_id, signing_key) =
        create_test_user(&server, "test@example.com", "laptop").await;

    // Try to create workspace - should succeed because verification is not required
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

    let result = server.create_workspace(request).await;
    assert!(
        result.is_ok(),
        "Unverified principal should be allowed when verification not required"
    );
}

#[tokio::test]
async fn unverified_principal_blocked_list_workspaces() {
    // Server with verification required
    let server = create_test_server_with_verification().await;

    // Create unverified user with principal
    let (_user_id, principal_id, signing_key) =
        create_unverified_test_user(&server, "test@example.com", "laptop").await;

    // Try to list workspaces - should be blocked
    let request = create_signed_request(
        &principal_id,
        &signing_key,
        "/zopp.ZoppService/ListWorkspaces",
        zopp_proto::Empty {},
    );

    let result = server.list_workspaces(request).await;
    assert!(result.is_err(), "Unverified principal should be blocked");
    assert_eq!(result.unwrap_err().code(), tonic::Code::PermissionDenied);
}

#[tokio::test]
async fn unverified_principal_blocked_get_secret() {
    // Server with verification required
    let server = create_test_server_with_verification().await;

    // Create verified user to set up workspace/project/env
    let (user_id, _owner_principal_id, _) =
        create_test_user(&server, "owner@example.com", "owner-laptop").await;
    server.store.mark_user_verified(&user_id).await.unwrap();

    let ws_id = create_test_workspace(&server, &user_id, "test-ws").await;
    let proj_id = create_test_project(&server, &ws_id, "test-proj").await;
    let _env_id = create_test_environment(&server, &proj_id, "dev").await;

    // Create unverified principal
    let (_, unverified_principal_id, unverified_signing_key) =
        create_unverified_test_user(&server, "unverified@example.com", "unverified-laptop").await;

    // Add unverified user to workspace
    let unverified_user = server
        .store
        .get_user_by_email("unverified@example.com")
        .await
        .unwrap();
    add_user_to_workspace(&server, &ws_id, &unverified_user.id, Role::Read).await;
    add_principal_to_workspace(&server, &ws_id, &unverified_principal_id).await;

    // Try to get secret - should be blocked
    let request = create_signed_request(
        &unverified_principal_id,
        &unverified_signing_key,
        "/zopp.ZoppService/GetSecret",
        zopp_proto::GetSecretRequest {
            workspace_name: "test-ws".to_string(),
            project_name: "test-proj".to_string(),
            environment_name: "dev".to_string(),
            key: "DATABASE_URL".to_string(),
        },
    );

    let result = server.get_secret(request).await;
    assert!(result.is_err(), "Unverified principal should be blocked");
    assert_eq!(result.unwrap_err().code(), tonic::Code::PermissionDenied);
}
