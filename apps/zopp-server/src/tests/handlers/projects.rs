//! Project handler tests.
//!
//! Tests for project-related gRPC handlers.

use super::super::common::*;
use zopp_proto::zopp_service_server::ZoppService;

#[tokio::test]
async fn handler_create_project() {
    let server = create_test_server().await;
    let (user_id, principal_id, signing_key) =
        create_test_user(&server, "test@example.com", "laptop").await;

    create_test_workspace(&server, &user_id, "ws").await;

    let request = create_signed_request(
        &principal_id,
        &signing_key,
        "/zopp.ZoppService/CreateProject",
        zopp_proto::CreateProjectRequest {
            workspace_name: "ws".to_string(),
            name: "my-project".to_string(),
        },
    );

    let response = server.create_project(request).await.unwrap().into_inner();
    assert_eq!(response.name, "my-project");
}

#[tokio::test]
async fn handler_list_projects() {
    let server = create_test_server().await;
    let (user_id, principal_id, signing_key) =
        create_test_user(&server, "test@example.com", "laptop").await;

    let ws_id = create_test_workspace(&server, &user_id, "ws").await;
    create_test_project(&server, &ws_id, "proj1").await;
    create_test_project(&server, &ws_id, "proj2").await;

    let request = create_signed_request(
        &principal_id,
        &signing_key,
        "/zopp.ZoppService/ListProjects",
        zopp_proto::ListProjectsRequest {
            workspace_name: "ws".to_string(),
        },
    );

    let response = server.list_projects(request).await.unwrap().into_inner();
    assert_eq!(response.projects.len(), 2);
}

#[tokio::test]
async fn handler_get_project() {
    let server = create_test_server().await;
    let (user_id, principal_id, signing_key) =
        create_test_user(&server, "test@example.com", "laptop").await;

    let ws_id = create_test_workspace(&server, &user_id, "ws").await;
    create_test_project(&server, &ws_id, "my-proj").await;

    let request = create_signed_request(
        &principal_id,
        &signing_key,
        "/zopp.ZoppService/GetProject",
        zopp_proto::GetProjectRequest {
            workspace_name: "ws".to_string(),
            project_name: "my-proj".to_string(),
        },
    );

    let response = server.get_project(request).await.unwrap().into_inner();
    assert_eq!(response.name, "my-proj");
}

#[tokio::test]
async fn handler_delete_project() {
    let server = create_test_server().await;
    let (user_id, principal_id, signing_key) =
        create_test_user(&server, "test@example.com", "laptop").await;

    let ws_id = create_test_workspace(&server, &user_id, "ws").await;
    create_test_project(&server, &ws_id, "to-delete").await;

    let request = create_signed_request(
        &principal_id,
        &signing_key,
        "/zopp.ZoppService/DeleteProject",
        zopp_proto::DeleteProjectRequest {
            workspace_name: "ws".to_string(),
            project_name: "to-delete".to_string(),
        },
    );

    server.delete_project(request).await.unwrap();

    // Verify deletion
    let list_request = create_signed_request(
        &principal_id,
        &signing_key,
        "/zopp.ZoppService/ListProjects",
        zopp_proto::ListProjectsRequest {
            workspace_name: "ws".to_string(),
        },
    );
    let response = server
        .list_projects(list_request)
        .await
        .unwrap()
        .into_inner();
    assert_eq!(response.projects.len(), 0);
}
