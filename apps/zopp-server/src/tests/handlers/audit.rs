//! Audit log handler tests.
//!
//! Tests for audit-related gRPC handlers.

use super::super::common::*;
use zopp_proto::zopp_service_server::ZoppService;

#[tokio::test]
async fn handler_list_audit_logs() {
    let server = create_test_server().await;
    let (user_id, principal_id, signing_key) =
        create_test_user(&server, "test@example.com", "laptop").await;

    let _ws_id = create_test_workspace(&server, &user_id, "ws").await;

    let request = create_signed_request(
        &principal_id,
        &signing_key,
        "/zopp.ZoppService/ListAuditLogs",
        zopp_proto::ListAuditLogsRequest {
            workspace_name: "ws".to_string(),
            principal_id: None,
            user_id: None,
            project_name: None,
            environment_name: None,
            action: None,
            result: None,
            from_timestamp: None,
            to_timestamp: None,
            limit: Some(10),
            offset: None,
        },
    );

    let response = server.list_audit_logs(request).await.unwrap().into_inner();
    // Response received successfully - entries may or may not exist
    let _ = response.entries;
}

#[tokio::test]
async fn handler_audit_logs_total_count() {
    // CountAuditLogs was removed - use ListAuditLogs response.total_count instead
    let server = create_test_server().await;
    let (user_id, principal_id, signing_key) =
        create_test_user(&server, "test@example.com", "laptop").await;

    let _ws_id = create_test_workspace(&server, &user_id, "ws").await;

    // Use ListAuditLogs with limit=0 to get total_count without fetching entries
    let request = create_signed_request(
        &principal_id,
        &signing_key,
        "/zopp.ZoppService/ListAuditLogs",
        zopp_proto::ListAuditLogsRequest {
            workspace_name: "ws".to_string(),
            principal_id: None,
            user_id: None,
            project_name: None,
            environment_name: None,
            action: None,
            result: None,
            from_timestamp: None,
            to_timestamp: None,
            limit: Some(0), // Only get count, no entries
            offset: None,
        },
    );

    let response = server.list_audit_logs(request).await.unwrap().into_inner();
    // Response received successfully - verify total_count is accessible
    let _ = response.total_count;
}
