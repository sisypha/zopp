//! Group handler tests.
//!
//! Tests for group-related gRPC handlers.

use super::super::common::*;
use zopp_proto::zopp_service_server::ZoppService;
use zopp_storage::{Role, Store};

#[tokio::test]
async fn handler_group_create_and_list() {
    let server = create_test_server().await;
    let (user_id, principal_id, signing_key) =
        create_test_user(&server, "test@example.com", "laptop").await;

    let _ws_id = create_test_workspace(&server, &user_id, "ws").await;

    // Create group
    let request = create_signed_request(
        &principal_id,
        &signing_key,
        "/zopp.ZoppService/CreateGroup",
        zopp_proto::CreateGroupRequest {
            workspace_name: "ws".to_string(),
            name: "developers".to_string(),
            description: "Dev team".to_string(),
        },
    );

    let response = server.create_group(request).await.unwrap().into_inner();
    assert_eq!(response.name, "developers");

    // List groups
    let list_request = create_signed_request(
        &principal_id,
        &signing_key,
        "/zopp.ZoppService/ListGroups",
        zopp_proto::ListGroupsRequest {
            workspace_name: "ws".to_string(),
        },
    );

    let list_response = server.list_groups(list_request).await.unwrap().into_inner();
    assert_eq!(list_response.groups.len(), 1);
    assert_eq!(list_response.groups[0].name, "developers");
}

#[tokio::test]
async fn handler_group_add_member() {
    let server = create_test_server().await;
    let (user_id, principal_id, signing_key) =
        create_test_user(&server, "admin@example.com", "admin").await;

    let ws_id = create_test_workspace(&server, &user_id, "ws").await;

    // Create a group using test helper
    let _group_id = create_test_group(&server, &ws_id, "team").await;

    // Create another user to add
    let (member_user_id, _, _) = create_test_user(&server, "member@example.com", "member").await;

    // Grant workspace access first
    server
        .store
        .set_user_workspace_permission(&ws_id, &member_user_id, Role::Read)
        .await
        .unwrap();

    // Add member to group
    let request = create_signed_request(
        &principal_id,
        &signing_key,
        "/zopp.ZoppService/AddGroupMember",
        zopp_proto::AddGroupMemberRequest {
            workspace_name: "ws".to_string(),
            group_name: "team".to_string(),
            user_email: "member@example.com".to_string(),
        },
    );

    server.add_group_member(request).await.unwrap();

    // List members
    let list_request = create_signed_request(
        &principal_id,
        &signing_key,
        "/zopp.ZoppService/ListGroupMembers",
        zopp_proto::ListGroupMembersRequest {
            workspace_name: "ws".to_string(),
            group_name: "team".to_string(),
        },
    );

    let response = server
        .list_group_members(list_request)
        .await
        .unwrap()
        .into_inner();
    assert_eq!(response.members.len(), 1);
}
