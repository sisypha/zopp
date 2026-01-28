//! Auth handler tests.
//!
//! Tests for authentication-related gRPC handlers (register, etc.).

use super::super::common::*;
use tonic::Request;
use zopp_proto::zopp_service_server::ZoppService;
use zopp_storage::{Store, *};

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
