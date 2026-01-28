//! Secret handler tests.
//!
//! Tests for secret-related gRPC handlers.

use super::super::common::*;
use zopp_proto::zopp_service_server::ZoppService;
use zopp_storage::Store;

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
