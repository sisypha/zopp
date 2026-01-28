//! Audit log handlers: list, get
//! Note: CountAuditLogs was removed - use ListAuditLogs with limit=0 to get total_count

use chrono::DateTime;
use tonic::{Request, Response, Status};
use zopp_audit::{AuditLog, AuditLogFilter, AuditLogId};
use zopp_proto::{AuditLogEntry, AuditLogList, GetAuditLogRequest, ListAuditLogsRequest};
use zopp_storage::{PrincipalId, Role, Store, UserId};

use crate::server::{extract_signature, ZoppServer};

/// Maximum number of audit log entries that can be returned in a single request.
/// This prevents memory exhaustion from unbounded queries.
const MAX_AUDIT_LOG_LIMIT: u32 = 1000;

pub async fn list_audit_logs(
    server: &ZoppServer,
    request: Request<ListAuditLogsRequest>,
) -> Result<Response<AuditLogList>, Status> {
    let (principal_id, timestamp, signature, request_hash) = extract_signature(&request)?;
    let req_for_verify = request.get_ref().clone();
    let principal = server
        .verify_signature_and_get_principal(
            &principal_id,
            timestamp,
            &signature,
            "/zopp.ZoppService/ListAuditLogs",
            &req_for_verify,
            &request_hash,
        )
        .await?;

    let req = request.into_inner();

    // Look up workspace by name
    let workspace = if let Some(user_id) = &principal.user_id {
        server
            .store
            .get_workspace_by_name(user_id, &req.workspace_name)
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::NotFound => {
                    Status::not_found("Workspace not found or access denied")
                }
                _ => Status::internal(format!("Failed to get workspace: {}", e)),
            })?
    } else {
        server
            .store
            .get_workspace_by_name_for_principal(&principal_id, &req.workspace_name)
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::NotFound => {
                    Status::not_found("Workspace not found or access denied")
                }
                _ => Status::internal(format!("Failed to get workspace: {}", e)),
            })?
    };

    // Check permission - only Admin can view audit logs
    server
        .check_permission_workspace_only(&principal_id, &workspace.id, Role::Admin)
        .await?;

    // Build filter
    let mut filter = AuditLogFilter::new().workspace_id(workspace.id);

    if let Some(pid) = req.principal_id {
        let pid = uuid::Uuid::parse_str(&pid)
            .map(PrincipalId)
            .map_err(|_| Status::invalid_argument("Invalid principal_id format"))?;
        filter = filter.principal_id(pid);
    }

    if let Some(uid) = req.user_id {
        let uid = uuid::Uuid::parse_str(&uid)
            .map(UserId)
            .map_err(|_| Status::invalid_argument("Invalid user_id format"))?;
        filter = filter.user_id(uid);
    }

    if let Some(action) = req.action {
        let action: zopp_audit::AuditAction = action
            .parse()
            .map_err(|_| Status::invalid_argument("Invalid action"))?;
        filter = filter.action(action);
    }

    if let Some(result) = req.result {
        let result: zopp_audit::AuditResult = result
            .parse()
            .map_err(|_| Status::invalid_argument("Invalid result"))?;
        filter = filter.result(result);
    }

    if let Some(from) = req.from_timestamp {
        let from = DateTime::parse_from_rfc3339(&from)
            .map_err(|_| Status::invalid_argument("Invalid from_timestamp format"))?
            .with_timezone(&chrono::Utc);
        filter = filter.from(from);
    }

    if let Some(to) = req.to_timestamp {
        let to = DateTime::parse_from_rfc3339(&to)
            .map_err(|_| Status::invalid_argument("Invalid to_timestamp format"))?
            .with_timezone(&chrono::Utc);
        filter = filter.to(to);
    }

    // Apply limit with enforcement of maximum
    let limit = req
        .limit
        .map(|l| l.min(MAX_AUDIT_LOG_LIMIT))
        .unwrap_or(MAX_AUDIT_LOG_LIMIT);
    filter = filter.limit(limit);

    if let Some(offset) = req.offset {
        filter = filter.offset(offset);
    }

    // Get total count for pagination
    let count_filter = filter.clone();
    let total_count = server
        .store
        .count(count_filter)
        .await
        .map_err(|e| Status::internal(format!("Failed to count audit logs: {}", e)))?;

    // Query audit logs
    let events = server
        .store
        .query(filter)
        .await
        .map_err(|e| Status::internal(format!("Failed to query audit logs: {}", e)))?;

    let entries = events
        .into_iter()
        .map(|e| AuditLogEntry {
            id: e.id.0.to_string(),
            timestamp: e.timestamp.to_rfc3339(),
            principal_id: e.principal_id.to_string(),
            user_id: e.user_id.map(|u| u.to_string()),
            action: e.action.to_string(),
            resource_type: e.resource_type,
            resource_id: e.resource_id,
            workspace_id: e.workspace_id.map(|w| w.to_string()),
            project_id: e.project_id.map(|p| p.to_string()),
            environment_id: e.environment_id.map(|e| e.to_string()),
            result: e.result.to_string(),
            reason: e.reason,
            details: e.details.map(|d| d.to_string()),
            client_ip: e.client_ip,
        })
        .collect();

    Ok(Response::new(AuditLogList {
        entries,
        total_count,
    }))
}

pub async fn get_audit_log(
    server: &ZoppServer,
    request: Request<GetAuditLogRequest>,
) -> Result<Response<AuditLogEntry>, Status> {
    let (principal_id, timestamp, signature, request_hash) = extract_signature(&request)?;
    let req_for_verify = request.get_ref().clone();
    let principal = server
        .verify_signature_and_get_principal(
            &principal_id,
            timestamp,
            &signature,
            "/zopp.ZoppService/GetAuditLog",
            &req_for_verify,
            &request_hash,
        )
        .await?;

    let req = request.into_inner();

    // Look up workspace by name
    let workspace = if let Some(user_id) = &principal.user_id {
        server
            .store
            .get_workspace_by_name(user_id, &req.workspace_name)
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::NotFound => {
                    Status::not_found("Workspace not found or access denied")
                }
                _ => Status::internal(format!("Failed to get workspace: {}", e)),
            })?
    } else {
        server
            .store
            .get_workspace_by_name_for_principal(&principal_id, &req.workspace_name)
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::NotFound => {
                    Status::not_found("Workspace not found or access denied")
                }
                _ => Status::internal(format!("Failed to get workspace: {}", e)),
            })?
    };

    // Check permission - only Admin can view audit logs
    server
        .check_permission_workspace_only(&principal_id, &workspace.id, Role::Admin)
        .await?;

    // Parse audit log ID
    let audit_log_id = uuid::Uuid::parse_str(&req.audit_log_id)
        .map(AuditLogId)
        .map_err(|_| Status::invalid_argument("Invalid audit_log_id format"))?;

    // Get audit log
    let event = server.store.get(audit_log_id).await.map_err(|e| match e {
        zopp_audit::AuditLogError::NotFound(_) => Status::not_found("Audit log not found"),
        _ => Status::internal(format!("Failed to get audit log: {}", e)),
    })?;

    // Verify the audit log belongs to this workspace
    if event
        .workspace_id
        .map(|w| w != workspace.id.0)
        .unwrap_or(true)
    {
        return Err(Status::not_found("Audit log not found"));
    }

    Ok(Response::new(AuditLogEntry {
        id: event.id.0.to_string(),
        timestamp: event.timestamp.to_rfc3339(),
        principal_id: event.principal_id.to_string(),
        user_id: event.user_id.map(|u| u.to_string()),
        action: event.action.to_string(),
        resource_type: event.resource_type,
        resource_id: event.resource_id,
        workspace_id: event.workspace_id.map(|w| w.to_string()),
        project_id: event.project_id.map(|p| p.to_string()),
        environment_id: event.environment_id.map(|e| e.to_string()),
        result: event.result.to_string(),
        reason: event.reason,
        details: event.details.map(|d| d.to_string()),
        client_ip: event.client_ip,
    }))
}

// CountAuditLogs was removed - use ListAuditLogs with limit=0 to get total_count
