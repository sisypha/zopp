//! Environment handler tests.
//!
//! Tests for environment-related gRPC handlers.

use super::super::common::*;
use zopp_proto::zopp_service_server::ZoppService;

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
