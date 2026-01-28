//! RBAC enforcement tests.
//!
//! Tests for role-based access control enforcement in gRPC handlers.

use super::super::common::*;
use zopp_proto::zopp_service_server::ZoppService;
use zopp_storage::{Store, *};

#[tokio::test]
async fn handler_list_groups_requires_read_permission() {
    let server = create_test_server().await;
    let (user_id, _principal_id, _signing_key) =
        create_test_user(&server, "owner-lg-rbac@example.com", "laptop").await;
    let ws_id = create_test_workspace(&server, &user_id, "ws").await;

    // Create another user without any permission
    let (other_user_id, other_principal_id, other_signing_key) =
        create_test_user(&server, "other-lg-rbac@example.com", "laptop").await;
    server
        .store
        .add_user_to_workspace(&ws_id, &other_user_id)
        .await
        .unwrap();
    add_principal_to_workspace(&server, &ws_id, &other_principal_id).await;
    // No RBAC permission granted

    let request = create_signed_request(
        &other_principal_id,
        &other_signing_key,
        "/zopp.ZoppService/ListGroups",
        zopp_proto::ListGroupsRequest {
            workspace_name: "ws".to_string(),
        },
    );

    let result = server.list_groups(request).await;
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code(), tonic::Code::PermissionDenied);
}

#[tokio::test]
async fn handler_get_group_requires_read_permission() {
    let server = create_test_server().await;
    let (user_id, principal_id, signing_key) =
        create_test_user(&server, "owner-gg-rbac@example.com", "laptop").await;
    let ws_id = create_test_workspace(&server, &user_id, "ws").await;
    add_principal_to_workspace(&server, &ws_id, &principal_id).await;
    server
        .store
        .set_workspace_permission(&ws_id, &principal_id, Role::Admin)
        .await
        .unwrap();

    // Create a group
    let create_request = create_signed_request(
        &principal_id,
        &signing_key,
        "/zopp.ZoppService/CreateGroup",
        zopp_proto::CreateGroupRequest {
            workspace_name: "ws".to_string(),
            name: "test-group".to_string(),
            description: "".to_string(),
        },
    );
    server.create_group(create_request).await.unwrap();

    // Create another user without any permission
    let (other_user_id, other_principal_id, other_signing_key) =
        create_test_user(&server, "other-gg-rbac@example.com", "laptop").await;
    server
        .store
        .add_user_to_workspace(&ws_id, &other_user_id)
        .await
        .unwrap();
    add_principal_to_workspace(&server, &ws_id, &other_principal_id).await;
    // No RBAC permission granted

    let request = create_signed_request(
        &other_principal_id,
        &other_signing_key,
        "/zopp.ZoppService/GetGroup",
        zopp_proto::GetGroupRequest {
            workspace_name: "ws".to_string(),
            group_name: "test-group".to_string(),
        },
    );

    let result = server.get_group(request).await;
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code(), tonic::Code::PermissionDenied);
}

#[tokio::test]
async fn handler_list_group_members_requires_read_permission() {
    let server = create_test_server().await;
    let (user_id, principal_id, signing_key) =
        create_test_user(&server, "owner-lgm-rbac@example.com", "laptop").await;
    let ws_id = create_test_workspace(&server, &user_id, "ws").await;
    add_principal_to_workspace(&server, &ws_id, &principal_id).await;
    server
        .store
        .set_workspace_permission(&ws_id, &principal_id, Role::Admin)
        .await
        .unwrap();

    // Create a group
    let create_request = create_signed_request(
        &principal_id,
        &signing_key,
        "/zopp.ZoppService/CreateGroup",
        zopp_proto::CreateGroupRequest {
            workspace_name: "ws".to_string(),
            name: "test-group".to_string(),
            description: "".to_string(),
        },
    );
    server.create_group(create_request).await.unwrap();

    // Create another user without any permission
    let (other_user_id, other_principal_id, other_signing_key) =
        create_test_user(&server, "other-lgm-rbac@example.com", "laptop").await;
    server
        .store
        .add_user_to_workspace(&ws_id, &other_user_id)
        .await
        .unwrap();
    add_principal_to_workspace(&server, &ws_id, &other_principal_id).await;
    // No RBAC permission granted

    let request = create_signed_request(
        &other_principal_id,
        &other_signing_key,
        "/zopp.ZoppService/ListGroupMembers",
        zopp_proto::ListGroupMembersRequest {
            workspace_name: "ws".to_string(),
            group_name: "test-group".to_string(),
        },
    );

    let result = server.list_group_members(request).await;
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code(), tonic::Code::PermissionDenied);
}

#[tokio::test]
async fn handler_list_user_groups_requires_read_permission() {
    let server = create_test_server().await;
    let (user_id, _principal_id, _signing_key) =
        create_test_user(&server, "owner-lug-rbac@example.com", "laptop").await;
    let ws_id = create_test_workspace(&server, &user_id, "ws").await;

    // Create another user without any permission
    let (other_user_id, other_principal_id, other_signing_key) =
        create_test_user(&server, "other-lug-rbac@example.com", "laptop").await;
    server
        .store
        .add_user_to_workspace(&ws_id, &other_user_id)
        .await
        .unwrap();
    add_principal_to_workspace(&server, &ws_id, &other_principal_id).await;
    // No RBAC permission granted

    let request = create_signed_request(
        &other_principal_id,
        &other_signing_key,
        "/zopp.ZoppService/ListUserGroups",
        zopp_proto::ListUserGroupsRequest {
            workspace_name: "ws".to_string(),
            user_email: "owner-lug-rbac@example.com".to_string(),
        },
    );

    let result = server.list_user_groups(request).await;
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code(), tonic::Code::PermissionDenied);
}

#[tokio::test]
async fn handler_list_workspace_service_principals_requires_admin() {
    let server = create_test_server().await;
    let (user_id, _principal_id, _signing_key) =
        create_test_user(&server, "owner-lwsp-rbac@example.com", "laptop").await;
    let ws_id = create_test_workspace(&server, &user_id, "ws").await;

    // Create another user with READ permission (not ADMIN)
    let (other_user_id, other_principal_id, other_signing_key) =
        create_test_user(&server, "other-lwsp-rbac@example.com", "laptop").await;
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
        &other_principal_id,
        &other_signing_key,
        "/zopp.ZoppService/ListWorkspaceServicePrincipals",
        zopp_proto::ListWorkspaceServicePrincipalsRequest {
            workspace_name: "ws".to_string(),
        },
    );

    let result = server.list_workspace_service_principals(request).await;
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code(), tonic::Code::PermissionDenied);
}
