//! Audit log commands: list, get, count

use crate::config::PrincipalConfig;
use crate::grpc::{add_auth_metadata, setup_client};

#[cfg(test)]
use crate::client::MockAuditClient;

use zopp_proto::{AuditLogEntry, AuditLogList, CountAuditLogsResponse};

/// Inner implementation for audit list that accepts a trait-bounded client.
pub async fn audit_list_inner<C>(
    client: &mut C,
    principal: &PrincipalConfig,
    workspace_name: &str,
    action: Option<&str>,
    result: Option<&str>,
    limit: Option<u32>,
) -> Result<AuditLogList, Box<dyn std::error::Error>>
where
    C: crate::client::AuditClient,
{
    let mut request = tonic::Request::new(zopp_proto::ListAuditLogsRequest {
        workspace_name: workspace_name.to_string(),
        principal_id: None,
        user_id: None,
        project_name: None,
        environment_name: None,
        action: action.map(|s| s.to_string()),
        result: result.map(|s| s.to_string()),
        from_timestamp: None,
        to_timestamp: None,
        limit,
        offset: None,
    });
    add_auth_metadata(&mut request, principal, "/zopp.ZoppService/ListAuditLogs")?;

    let response = client.list_audit_logs(request).await?.into_inner();
    Ok(response)
}

/// Print audit list results.
pub fn print_audit_list(response: &AuditLogList) {
    if response.entries.is_empty() {
        println!("No audit log entries found.");
    } else {
        println!(
            "Audit logs ({} of {} total):\n",
            response.entries.len(),
            response.total_count
        );
        for entry in &response.entries {
            print_audit_entry_summary(entry);
        }
    }
}

/// Print a summary of an audit log entry.
pub fn print_audit_entry_summary(entry: &AuditLogEntry) {
    println!("ID:        {}", entry.id);
    println!("Timestamp: {}", entry.timestamp);
    println!("Action:    {}", entry.action);
    println!("Resource:  {} ({})", entry.resource_type, entry.resource_id);
    println!("Result:    {}", entry.result);
    if let Some(reason) = &entry.reason {
        println!("Reason:    {}", reason);
    }
    println!();
}

/// Inner implementation for audit get that accepts a trait-bounded client.
pub async fn audit_get_inner<C>(
    client: &mut C,
    principal: &PrincipalConfig,
    workspace_name: &str,
    audit_log_id: &str,
) -> Result<AuditLogEntry, Box<dyn std::error::Error>>
where
    C: crate::client::AuditClient,
{
    let mut request = tonic::Request::new(zopp_proto::GetAuditLogRequest {
        workspace_name: workspace_name.to_string(),
        audit_log_id: audit_log_id.to_string(),
    });
    add_auth_metadata(&mut request, principal, "/zopp.ZoppService/GetAuditLog")?;

    let entry = client.get_audit_log(request).await?.into_inner();
    Ok(entry)
}

/// Print full audit log entry details.
pub fn print_audit_entry_details(entry: &AuditLogEntry) {
    println!("ID:           {}", entry.id);
    println!("Timestamp:    {}", entry.timestamp);
    println!("Principal ID: {}", entry.principal_id);
    if let Some(user_id) = &entry.user_id {
        println!("User ID:      {}", user_id);
    }
    println!("Action:       {}", entry.action);
    println!(
        "Resource:     {} ({})",
        entry.resource_type, entry.resource_id
    );
    if let Some(workspace_id) = &entry.workspace_id {
        println!("Workspace:    {}", workspace_id);
    }
    if let Some(project_id) = &entry.project_id {
        println!("Project:      {}", project_id);
    }
    if let Some(environment_id) = &entry.environment_id {
        println!("Environment:  {}", environment_id);
    }
    println!("Result:       {}", entry.result);
    if let Some(reason) = &entry.reason {
        println!("Reason:       {}", reason);
    }
    if let Some(details) = &entry.details {
        println!("Details:      {}", details);
    }
    if let Some(client_ip) = &entry.client_ip {
        println!("Client IP:    {}", client_ip);
    }
}

/// Inner implementation for audit count that accepts a trait-bounded client.
pub async fn audit_count_inner<C>(
    client: &mut C,
    principal: &PrincipalConfig,
    workspace_name: &str,
    action: Option<&str>,
    result: Option<&str>,
) -> Result<CountAuditLogsResponse, Box<dyn std::error::Error>>
where
    C: crate::client::AuditClient,
{
    let mut request = tonic::Request::new(zopp_proto::CountAuditLogsRequest {
        workspace_name: workspace_name.to_string(),
        principal_id: None,
        user_id: None,
        project_name: None,
        environment_name: None,
        action: action.map(|s| s.to_string()),
        result: result.map(|s| s.to_string()),
        from_timestamp: None,
        to_timestamp: None,
    });
    add_auth_metadata(&mut request, principal, "/zopp.ZoppService/CountAuditLogs")?;

    let response = client.count_audit_logs(request).await?.into_inner();
    Ok(response)
}

/// Print audit count result.
pub fn print_audit_count(response: &CountAuditLogsResponse) {
    println!("Total audit log entries: {}", response.count);
}

pub async fn cmd_audit_list(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    workspace_name: &str,
    action: Option<&str>,
    result: Option<&str>,
    limit: Option<u32>,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, principal) = setup_client(server, tls_ca_cert).await?;
    let response = audit_list_inner(
        &mut client,
        &principal,
        workspace_name,
        action,
        result,
        limit,
    )
    .await?;
    print_audit_list(&response);
    Ok(())
}

pub async fn cmd_audit_get(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    workspace_name: &str,
    audit_log_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, principal) = setup_client(server, tls_ca_cert).await?;
    let entry = audit_get_inner(&mut client, &principal, workspace_name, audit_log_id).await?;
    print_audit_entry_details(&entry);
    Ok(())
}

pub async fn cmd_audit_count(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    workspace_name: &str,
    action: Option<&str>,
    result: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, principal) = setup_client(server, tls_ca_cert).await?;
    let response =
        audit_count_inner(&mut client, &principal, workspace_name, action, result).await?;
    print_audit_count(&response);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tonic::{Response, Status};

    fn create_test_principal() -> PrincipalConfig {
        PrincipalConfig {
            id: "test-principal-id".to_string(),
            name: "test-principal".to_string(),
            private_key: "0".repeat(64),
            public_key: "1".repeat(64),
            x25519_private_key: Some("2".repeat(64)),
            x25519_public_key: Some("3".repeat(64)),
        }
    }

    fn create_test_audit_entry() -> AuditLogEntry {
        AuditLogEntry {
            id: "audit-1".to_string(),
            timestamp: "2024-01-01T00:00:00Z".to_string(),
            principal_id: "principal-1".to_string(),
            user_id: Some("user-1".to_string()),
            action: "secret.read".to_string(),
            resource_type: "secret".to_string(),
            resource_id: "secret-1".to_string(),
            workspace_id: Some("ws-1".to_string()),
            project_id: Some("proj-1".to_string()),
            environment_id: Some("env-1".to_string()),
            result: "success".to_string(),
            reason: None,
            details: Some("Read secret API_KEY".to_string()),
            client_ip: Some("127.0.0.1".to_string()),
        }
    }

    #[tokio::test]
    async fn test_audit_list_inner_success() {
        let mut mock = MockAuditClient::new();

        mock.expect_list_audit_logs().returning(|_| {
            Ok(Response::new(AuditLogList {
                entries: vec![
                    AuditLogEntry {
                        id: "audit-1".to_string(),
                        timestamp: "2024-01-01T00:00:00Z".to_string(),
                        principal_id: "principal-1".to_string(),
                        user_id: None,
                        action: "secret.read".to_string(),
                        resource_type: "secret".to_string(),
                        resource_id: "secret-1".to_string(),
                        workspace_id: None,
                        project_id: None,
                        environment_id: None,
                        result: "success".to_string(),
                        reason: None,
                        details: None,
                        client_ip: None,
                    },
                    AuditLogEntry {
                        id: "audit-2".to_string(),
                        timestamp: "2024-01-01T00:01:00Z".to_string(),
                        principal_id: "principal-1".to_string(),
                        user_id: None,
                        action: "secret.write".to_string(),
                        resource_type: "secret".to_string(),
                        resource_id: "secret-2".to_string(),
                        workspace_id: None,
                        project_id: None,
                        environment_id: None,
                        result: "success".to_string(),
                        reason: None,
                        details: None,
                        client_ip: None,
                    },
                ],
                total_count: 2,
            }))
        });

        let principal = create_test_principal();
        let result =
            audit_list_inner(&mut mock, &principal, "my-workspace", None, None, None).await;

        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(response.entries.len(), 2);
        assert_eq!(response.total_count, 2);
    }

    #[tokio::test]
    async fn test_audit_list_inner_empty() {
        let mut mock = MockAuditClient::new();

        mock.expect_list_audit_logs().returning(|_| {
            Ok(Response::new(AuditLogList {
                entries: vec![],
                total_count: 0,
            }))
        });

        let principal = create_test_principal();
        let result =
            audit_list_inner(&mut mock, &principal, "my-workspace", None, None, None).await;

        assert!(result.is_ok());
        let response = result.unwrap();
        assert!(response.entries.is_empty());
    }

    #[tokio::test]
    async fn test_audit_list_inner_permission_denied() {
        let mut mock = MockAuditClient::new();

        mock.expect_list_audit_logs()
            .returning(|_| Err(Status::permission_denied("Not authorized")));

        let principal = create_test_principal();
        let result =
            audit_list_inner(&mut mock, &principal, "my-workspace", None, None, None).await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_audit_get_inner_success() {
        let mut mock = MockAuditClient::new();

        mock.expect_get_audit_log().returning(|_| {
            Ok(Response::new(AuditLogEntry {
                id: "audit-1".to_string(),
                timestamp: "2024-01-01T00:00:00Z".to_string(),
                principal_id: "principal-1".to_string(),
                user_id: Some("user-1".to_string()),
                action: "secret.read".to_string(),
                resource_type: "secret".to_string(),
                resource_id: "secret-1".to_string(),
                workspace_id: Some("ws-1".to_string()),
                project_id: Some("proj-1".to_string()),
                environment_id: Some("env-1".to_string()),
                result: "success".to_string(),
                reason: None,
                details: Some("Read secret".to_string()),
                client_ip: Some("127.0.0.1".to_string()),
            }))
        });

        let principal = create_test_principal();
        let result = audit_get_inner(&mut mock, &principal, "my-workspace", "audit-1").await;

        assert!(result.is_ok());
        let entry = result.unwrap();
        assert_eq!(entry.id, "audit-1");
        assert_eq!(entry.action, "secret.read");
    }

    #[tokio::test]
    async fn test_audit_get_inner_not_found() {
        let mut mock = MockAuditClient::new();

        mock.expect_get_audit_log()
            .returning(|_| Err(Status::not_found("Audit log not found")));

        let principal = create_test_principal();
        let result = audit_get_inner(&mut mock, &principal, "my-workspace", "nonexistent").await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_audit_count_inner_success() {
        let mut mock = MockAuditClient::new();

        mock.expect_count_audit_logs()
            .returning(|_| Ok(Response::new(CountAuditLogsResponse { count: 42 })));

        let principal = create_test_principal();
        let result = audit_count_inner(&mut mock, &principal, "my-workspace", None, None).await;

        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(response.count, 42);
    }

    #[tokio::test]
    async fn test_audit_count_inner_with_filter() {
        let mut mock = MockAuditClient::new();

        mock.expect_count_audit_logs()
            .returning(|_| Ok(Response::new(CountAuditLogsResponse { count: 10 })));

        let principal = create_test_principal();
        let result = audit_count_inner(
            &mut mock,
            &principal,
            "my-workspace",
            Some("secret.read"),
            Some("success"),
        )
        .await;

        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(response.count, 10);
    }

    #[tokio::test]
    async fn test_audit_count_inner_permission_denied() {
        let mut mock = MockAuditClient::new();

        mock.expect_count_audit_logs()
            .returning(|_| Err(Status::permission_denied("Not authorized")));

        let principal = create_test_principal();
        let result = audit_count_inner(&mut mock, &principal, "my-workspace", None, None).await;

        assert!(result.is_err());
    }

    #[test]
    fn test_print_audit_list_empty() {
        let response = AuditLogList {
            entries: vec![],
            total_count: 0,
        };
        print_audit_list(&response);
    }

    #[test]
    fn test_print_audit_list_with_entries() {
        let response = AuditLogList {
            entries: vec![AuditLogEntry {
                id: "audit-1".to_string(),
                timestamp: "2024-01-01T00:00:00Z".to_string(),
                principal_id: "principal-1".to_string(),
                user_id: None,
                action: "secret.read".to_string(),
                resource_type: "secret".to_string(),
                resource_id: "secret-1".to_string(),
                workspace_id: None,
                project_id: None,
                environment_id: None,
                result: "success".to_string(),
                reason: Some("Test reason".to_string()),
                details: None,
                client_ip: None,
            }],
            total_count: 1,
        };
        print_audit_list(&response);
    }

    #[test]
    fn test_print_audit_entry_details() {
        let entry = create_test_audit_entry();
        print_audit_entry_details(&entry);
    }

    #[test]
    fn test_print_audit_entry_details_minimal() {
        let entry = AuditLogEntry {
            id: "audit-1".to_string(),
            timestamp: "2024-01-01T00:00:00Z".to_string(),
            principal_id: "principal-1".to_string(),
            user_id: None,
            action: "secret.read".to_string(),
            resource_type: "secret".to_string(),
            resource_id: "secret-1".to_string(),
            workspace_id: None,
            project_id: None,
            environment_id: None,
            result: "success".to_string(),
            reason: None,
            details: None,
            client_ip: None,
        };
        print_audit_entry_details(&entry);
    }

    #[test]
    fn test_print_audit_count() {
        let response = CountAuditLogsResponse { count: 42 };
        print_audit_count(&response);
    }
}
