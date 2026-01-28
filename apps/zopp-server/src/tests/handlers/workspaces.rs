//! Workspace handler tests.
//!
//! Tests for workspace-related gRPC handlers.

use super::super::common::*;
use zopp_proto::zopp_service_server::ZoppService;
use zopp_storage::{Store, *};

#[tokio::test]
async fn handler_create_workspace() {
    let server = create_test_server().await;
    let (_user_id, principal_id, signing_key) =
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
    let ws_id = create_test_workspace(&server, &user_id, "test-ws").await;
    // Add principal to workspace_principals so they can see it (KEK access)
    add_principal_to_workspace(&server, &ws_id, &principal_id).await;

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
