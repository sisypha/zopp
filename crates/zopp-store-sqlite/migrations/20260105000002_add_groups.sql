-- Groups migration for SQLite
-- Adds groups and group membership tables

-- Groups table (scoped to workspace)
CREATE TABLE IF NOT EXISTS groups (
  id TEXT PRIMARY KEY NOT NULL,
  workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  description TEXT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
  UNIQUE(workspace_id, name)
);

-- Group membership (users belong to groups)
CREATE TABLE IF NOT EXISTS group_members (
  group_id TEXT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
  PRIMARY KEY (group_id, user_id)
);

-- Group permissions at workspace level
CREATE TABLE IF NOT EXISTS group_workspace_permissions (
  workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  group_id TEXT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
  role TEXT NOT NULL CHECK (role IN ('admin', 'write', 'read')),
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
  PRIMARY KEY (workspace_id, group_id)
);

-- Group permissions at project level
CREATE TABLE IF NOT EXISTS group_project_permissions (
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  group_id TEXT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
  role TEXT NOT NULL CHECK (role IN ('admin', 'write', 'read')),
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
  PRIMARY KEY (project_id, group_id)
);

-- Group permissions at environment level
CREATE TABLE IF NOT EXISTS group_environment_permissions (
  environment_id TEXT NOT NULL REFERENCES environments(id) ON DELETE CASCADE,
  group_id TEXT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
  role TEXT NOT NULL CHECK (role IN ('admin', 'write', 'read')),
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
  PRIMARY KEY (environment_id, group_id)
);

-- Indexes for efficient lookups
CREATE INDEX idx_groups_workspace ON groups(workspace_id);
CREATE INDEX idx_group_members_user ON group_members(user_id);
CREATE INDEX idx_group_members_group ON group_members(group_id);
CREATE INDEX idx_group_workspace_permissions_group ON group_workspace_permissions(group_id);
CREATE INDEX idx_group_project_permissions_group ON group_project_permissions(group_id);
CREATE INDEX idx_group_environment_permissions_group ON group_environment_permissions(group_id);
