-- RBAC migration for SQLite
-- Adds roles and permissions at workspace/project/environment levels

-- Role enum (stored as TEXT in SQLite)
-- Values: 'admin', 'write', 'read'

-- Workspace-level permissions (principal has role on entire workspace)
CREATE TABLE IF NOT EXISTS workspace_permissions (
  workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  principal_id TEXT NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
  role TEXT NOT NULL CHECK (role IN ('admin', 'write', 'read')),
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
  PRIMARY KEY (workspace_id, principal_id)
);

-- Project-level permissions (principal has role on specific project)
CREATE TABLE IF NOT EXISTS project_permissions (
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  principal_id TEXT NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
  role TEXT NOT NULL CHECK (role IN ('admin', 'write', 'read')),
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
  PRIMARY KEY (project_id, principal_id)
);

-- Environment-level permissions (principal has role on specific environment)
CREATE TABLE IF NOT EXISTS environment_permissions (
  environment_id TEXT NOT NULL REFERENCES environments(id) ON DELETE CASCADE,
  principal_id TEXT NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
  role TEXT NOT NULL CHECK (role IN ('admin', 'write', 'read')),
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
  PRIMARY KEY (environment_id, principal_id)
);

-- Indexes for efficient permission lookups
CREATE INDEX idx_workspace_permissions_principal ON workspace_permissions(principal_id);
CREATE INDEX idx_project_permissions_principal ON project_permissions(principal_id);
CREATE INDEX idx_environment_permissions_principal ON environment_permissions(principal_id);
