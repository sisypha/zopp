-- Audit logs table for tracking all auditable actions in the system
CREATE TABLE audit_logs (
    id TEXT PRIMARY KEY NOT NULL,
    timestamp TEXT NOT NULL,
    principal_id TEXT NOT NULL,
    user_id TEXT,
    action TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    workspace_id TEXT,
    project_id TEXT,
    environment_id TEXT,
    result TEXT NOT NULL,
    reason TEXT,
    details TEXT,
    client_ip TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Indexes for common query patterns
CREATE INDEX idx_audit_logs_timestamp ON audit_logs(timestamp DESC);
CREATE INDEX idx_audit_logs_principal_id ON audit_logs(principal_id);
CREATE INDEX idx_audit_logs_user_id ON audit_logs(user_id) WHERE user_id IS NOT NULL;
CREATE INDEX idx_audit_logs_workspace_id ON audit_logs(workspace_id) WHERE workspace_id IS NOT NULL;
CREATE INDEX idx_audit_logs_action ON audit_logs(action);
CREATE INDEX idx_audit_logs_result ON audit_logs(result);

-- Composite index for workspace + time range queries (common for compliance)
CREATE INDEX idx_audit_logs_workspace_timestamp ON audit_logs(workspace_id, timestamp DESC) WHERE workspace_id IS NOT NULL;
