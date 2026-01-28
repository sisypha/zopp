//! Principal handler tests.
//!
//! Tests for principal-related gRPC handlers.

use super::super::common::*;
use zopp_proto::zopp_service_server::ZoppService;

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
