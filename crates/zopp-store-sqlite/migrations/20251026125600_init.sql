PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY NOT NULL,     -- UUID string
  email TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now')),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now'))
);

CREATE TRIGGER IF NOT EXISTS users_updated_at AFTER UPDATE ON users
BEGIN
  UPDATE users SET updated_at = strftime('%Y-%m-%d %H:%M:%f', 'now') WHERE id = NEW.id;
END;

CREATE TABLE IF NOT EXISTS principals (
  id TEXT PRIMARY KEY NOT NULL,     -- UUID string
  user_id TEXT REFERENCES users(id) ON DELETE CASCADE,  -- NULL for service accounts
  name TEXT NOT NULL,               -- Unique per user, not globally
  public_key BLOB NOT NULL,
  x25519_public_key BLOB,           -- X25519 for encryption (ECDH)
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now')),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now'))
);

-- Principal names are unique per user (alice can have "laptop", bob can also have "laptop")
CREATE UNIQUE INDEX principals_user_name_unique ON principals(user_id, name) WHERE user_id IS NOT NULL;

CREATE TRIGGER IF NOT EXISTS principals_updated_at AFTER UPDATE ON principals
BEGIN
  UPDATE principals SET updated_at = strftime('%Y-%m-%d %H:%M:%f', 'now') WHERE id = NEW.id;
END;

CREATE TABLE IF NOT EXISTS workspaces (
  id TEXT PRIMARY KEY NOT NULL,     -- UUID string
  name TEXT NOT NULL UNIQUE,        -- Globally unique workspace names
  owner_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  kdf_salt BLOB NOT NULL,
  kdf_m_cost_kib INTEGER NOT NULL,
  kdf_t_cost INTEGER NOT NULL,
  kdf_p_cost INTEGER NOT NULL,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now')),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now'))
);

CREATE TRIGGER IF NOT EXISTS workspaces_updated_at AFTER UPDATE ON workspaces
BEGIN
  UPDATE workspaces SET updated_at = strftime('%Y-%m-%d %H:%M:%f', 'now') WHERE id = NEW.id;
END;

CREATE TABLE IF NOT EXISTS workspace_members (
  workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now')),
  PRIMARY KEY (workspace_id, user_id)
);

CREATE TABLE IF NOT EXISTS workspace_principals (
  workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  principal_id TEXT NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
  ephemeral_pub BLOB NOT NULL,  -- Ephemeral X25519 public key for KEK wrapping
  kek_wrapped BLOB NOT NULL,     -- Workspace KEK wrapped for this principal
  kek_nonce BLOB NOT NULL,       -- 24-byte nonce for KEK wrapping
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now')),
  PRIMARY KEY (workspace_id, principal_id)
);

CREATE TABLE IF NOT EXISTS invites (
  id TEXT PRIMARY KEY NOT NULL,     -- UUID string
  token TEXT NOT NULL UNIQUE,
  kek_encrypted BLOB,               -- Workspace KEK encrypted with invite secret
  kek_nonce BLOB,                   -- 24-byte nonce for KEK encryption
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now')),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now')),
  expires_at TEXT NOT NULL,
  created_by_user_id TEXT REFERENCES users(id) ON DELETE CASCADE,  -- NULL for server-created invites
  revoked INTEGER NOT NULL DEFAULT 0  -- boolean: 0 = active, 1 = revoked
);

CREATE TRIGGER IF NOT EXISTS invites_updated_at AFTER UPDATE ON invites
BEGIN
  UPDATE invites SET updated_at = strftime('%Y-%m-%d %H:%M:%f', 'now') WHERE id = NEW.id;
END;

CREATE TABLE IF NOT EXISTS invite_workspaces (
  invite_id TEXT NOT NULL REFERENCES invites(id) ON DELETE CASCADE,
  workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now')),
  PRIMARY KEY (invite_id, workspace_id)
);

CREATE TABLE IF NOT EXISTS projects (
  id TEXT PRIMARY KEY NOT NULL,     -- UUID string
  workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now')),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now')),
  UNIQUE(workspace_id, name)
);

CREATE TRIGGER IF NOT EXISTS projects_updated_at AFTER UPDATE ON projects
BEGIN
  UPDATE projects SET updated_at = strftime('%Y-%m-%d %H:%M:%f', 'now') WHERE id = NEW.id;
END;

CREATE TABLE IF NOT EXISTS environments (
  id TEXT PRIMARY KEY NOT NULL,     -- UUID string
  workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  dek_wrapped BLOB NOT NULL,
  dek_nonce BLOB NOT NULL,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now')),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now')),
  UNIQUE(workspace_id, project_id, name)
);

CREATE TRIGGER IF NOT EXISTS environments_updated_at AFTER UPDATE ON environments
BEGIN
  UPDATE environments SET updated_at = strftime('%Y-%m-%d %H:%M:%f', 'now') WHERE id = NEW.id;
END;

CREATE TABLE IF NOT EXISTS secrets (
  id TEXT PRIMARY KEY NOT NULL,     -- UUID string
  workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  env_id TEXT NOT NULL REFERENCES environments(id) ON DELETE CASCADE,
  key_name TEXT NOT NULL,
  nonce BLOB NOT NULL,
  ciphertext BLOB NOT NULL,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now')),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now')),
  UNIQUE(workspace_id, env_id, key_name)
);

CREATE TRIGGER IF NOT EXISTS secrets_updated_at AFTER UPDATE ON secrets
BEGIN
  UPDATE secrets SET updated_at = strftime('%Y-%m-%d %H:%M:%f', 'now') WHERE id = NEW.id;
END;
