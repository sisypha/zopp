-- Audit logs table for tracking all auditable actions in the system
CREATE TABLE audit_logs (
    id UUID PRIMARY KEY NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL,
    principal_id UUID NOT NULL,
    user_id UUID,
    action TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    workspace_id UUID,
    project_id UUID,
    environment_id UUID,
    result TEXT NOT NULL,
    reason TEXT,
    details JSONB,
    client_ip TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
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

-- GIN index for JSONB details column (enables efficient JSON queries)
CREATE INDEX idx_audit_logs_details ON audit_logs USING GIN (details) WHERE details IS NOT NULL;
