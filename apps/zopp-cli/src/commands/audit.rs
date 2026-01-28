//! Audit log commands: list, get, count

use crate::grpc::{add_auth_metadata, setup_client};

pub async fn cmd_audit_list(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    workspace_name: &str,
    action: Option<&str>,
    result: Option<&str>,
    limit: Option<u32>,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, principal, secrets) = setup_client(server, tls_ca_cert).await?;

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
    add_auth_metadata(
        &mut request,
        &principal,
        &secrets,
        "/zopp.ZoppService/ListAuditLogs",
    )?;

    let response = client.list_audit_logs(request).await?.into_inner();

    if response.entries.is_empty() {
        println!("No audit log entries found.");
    } else {
        println!(
            "Audit logs ({} of {} total):\n",
            response.entries.len(),
            response.total_count
        );
        for entry in response.entries {
            println!("ID:        {}", entry.id);
            println!("Timestamp: {}", entry.timestamp);
            println!("Action:    {}", entry.action);
            println!("Resource:  {} ({})", entry.resource_type, entry.resource_id);
            println!("Result:    {}", entry.result);
            if let Some(reason) = entry.reason {
                println!("Reason:    {}", reason);
            }
            println!();
        }
    }

    Ok(())
}

pub async fn cmd_audit_get(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    workspace_name: &str,
    audit_log_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, principal, secrets) = setup_client(server, tls_ca_cert).await?;

    let mut request = tonic::Request::new(zopp_proto::GetAuditLogRequest {
        workspace_name: workspace_name.to_string(),
        audit_log_id: audit_log_id.to_string(),
    });
    add_auth_metadata(
        &mut request,
        &principal,
        &secrets,
        "/zopp.ZoppService/GetAuditLog",
    )?;

    let entry = client.get_audit_log(request).await?.into_inner();

    println!("ID:           {}", entry.id);
    println!("Timestamp:    {}", entry.timestamp);
    println!("Principal ID: {}", entry.principal_id);
    if let Some(user_id) = entry.user_id {
        println!("User ID:      {}", user_id);
    }
    println!("Action:       {}", entry.action);
    println!(
        "Resource:     {} ({})",
        entry.resource_type, entry.resource_id
    );
    if let Some(workspace_id) = entry.workspace_id {
        println!("Workspace:    {}", workspace_id);
    }
    if let Some(project_id) = entry.project_id {
        println!("Project:      {}", project_id);
    }
    if let Some(environment_id) = entry.environment_id {
        println!("Environment:  {}", environment_id);
    }
    println!("Result:       {}", entry.result);
    if let Some(reason) = entry.reason {
        println!("Reason:       {}", reason);
    }
    if let Some(details) = entry.details {
        println!("Details:      {}", details);
    }
    if let Some(client_ip) = entry.client_ip {
        println!("Client IP:    {}", client_ip);
    }

    Ok(())
}

pub async fn cmd_audit_count(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    workspace_name: &str,
    action: Option<&str>,
    result: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, principal, secrets) = setup_client(server, tls_ca_cert).await?;

    // Use ListAuditLogs with limit=0 to get total_count (CountAuditLogs was removed)
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
        limit: Some(0), // Just get the count, not the entries
        offset: None,
    });
    add_auth_metadata(
        &mut request,
        &principal,
        &secrets,
        "/zopp.ZoppService/ListAuditLogs",
    )?;

    let response = client.list_audit_logs(request).await?.into_inner();

    println!("Total audit log entries: {}", response.total_count);

    Ok(())
}
