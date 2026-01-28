//! Effective permissions handler tests.
//!
//! Tests for the GetEffectivePermissions gRPC handler.

use super::super::common::*;
use zopp_proto::zopp_service_server::ZoppService;
use zopp_storage::{Store, *};

#[tokio::test]
async fn handler_get_effective_permissions_requires_admin_or_self() {
    let server = create_test_server().await;
    let (user_id, owner_principal_id, _signing_key) =
        create_test_user(&server, "owner-gep-rbac@example.com", "laptop").await;
    let ws_id = create_test_workspace(&server, &user_id, "ws").await;
    add_principal_to_workspace(&server, &ws_id, &owner_principal_id).await;
    server
        .store
        .set_workspace_permission(&ws_id, &owner_principal_id, Role::Admin)
        .await
        .unwrap();

    // Create another user with READ permission (not ADMIN)
    let (other_user_id, other_principal_id, other_signing_key) =
        create_test_user(&server, "other-gep-rbac@example.com", "laptop").await;
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

    // Other user tries to get effective permissions for owner - should be denied
    let request = create_signed_request(
        &other_principal_id,
        &other_signing_key,
        "/zopp.ZoppService/GetEffectivePermissions",
        zopp_proto::GetEffectivePermissionsRequest {
            workspace_name: "ws".to_string(),
            principal_id: owner_principal_id.0.to_string(),
        },
    );

    let result = server.get_effective_permissions(request).await;
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code(), tonic::Code::PermissionDenied);

    // Other user can get their own effective permissions
    let self_request = create_signed_request(
        &other_principal_id,
        &other_signing_key,
        "/zopp.ZoppService/GetEffectivePermissions",
        zopp_proto::GetEffectivePermissionsRequest {
            workspace_name: "ws".to_string(),
            principal_id: other_principal_id.0.to_string(),
        },
    );

    let result = server.get_effective_permissions(self_request).await;
    assert!(
        result.is_ok(),
        "User should be able to query their own effective permissions"
    );
}
