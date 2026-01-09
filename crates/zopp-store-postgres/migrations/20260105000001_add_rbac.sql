-- RBAC migration for PostgreSQL
-- Adds roles and permissions at workspace/project/environment levels

-- Role enum type
CREATE TYPE role AS ENUM ('admin', 'write', 'read');

-- Workspace-level permissions (principal has role on entire workspace)
CREATE TABLE IF NOT EXISTS workspace_permissions (
  workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  principal_id UUID NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
  role role NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (workspace_id, principal_id)
);

-- Project-level permissions (principal has role on specific project)
CREATE TABLE IF NOT EXISTS project_permissions (
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  principal_id UUID NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
  role role NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (project_id, principal_id)
);

-- Environment-level permissions (principal has role on specific environment)
CREATE TABLE IF NOT EXISTS environment_permissions (
  environment_id UUID NOT NULL REFERENCES environments(id) ON DELETE CASCADE,
  principal_id UUID NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
  role role NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (environment_id, principal_id)
);

-- Indexes for efficient permission lookups
CREATE INDEX idx_workspace_permissions_principal ON workspace_permissions(principal_id);
CREATE INDEX idx_project_permissions_principal ON project_permissions(principal_id);
CREATE INDEX idx_environment_permissions_principal ON environment_permissions(principal_id);
