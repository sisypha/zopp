-- User-level permissions (separate from principal-level)
-- Users get permissions, principals can only RESTRICT (not expand)

CREATE TABLE user_workspace_permissions (
    workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role TEXT NOT NULL CHECK (role IN ('admin', 'write', 'read')),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    PRIMARY KEY (workspace_id, user_id)
);

CREATE TABLE user_project_permissions (
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role TEXT NOT NULL CHECK (role IN ('admin', 'write', 'read')),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    PRIMARY KEY (project_id, user_id)
);

CREATE TABLE user_environment_permissions (
    environment_id TEXT NOT NULL REFERENCES environments(id) ON DELETE CASCADE,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role TEXT NOT NULL CHECK (role IN ('admin', 'write', 'read')),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    PRIMARY KEY (environment_id, user_id)
);

-- Indexes for efficient lookups
CREATE INDEX idx_user_workspace_permissions_user ON user_workspace_permissions(user_id);
CREATE INDEX idx_user_project_permissions_user ON user_project_permissions(user_id);
CREATE INDEX idx_user_environment_permissions_user ON user_environment_permissions(user_id);
