//! Service account handler tests.
//!
//! Tests for service principal and service account related gRPC handlers.

use super::super::common::*;
use zopp_proto::zopp_service_server::ZoppService;

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
async fn handler_list_workspace_service_principals_returns_service_principals() {
    let server = create_test_server().await;
    let (user_id, principal_id, signing_key) =
        create_test_user(&server, "owner-svc@example.com", "laptop").await;
    let ws_id = create_test_workspace(&server, &user_id, "ws").await;
    add_principal_to_workspace(&server, &ws_id, &principal_id).await;

    // Create a service principal using helper
    let (svc_principal_id, _svc_signing_key) =
        create_service_principal(&server, "ci-bot").await;
    // Add service principal to workspace
    add_principal_to_workspace(&server, &ws_id, &svc_principal_id).await;

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
    let response = result.unwrap().into_inner();
    // Should find the service principal we created
    assert_eq!(response.service_principals.len(), 1);
    assert_eq!(response.service_principals[0].name, "ci-bot");
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
