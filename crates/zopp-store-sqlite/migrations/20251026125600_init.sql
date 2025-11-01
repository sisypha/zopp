PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS workspaces (
  id TEXT PRIMARY KEY NOT NULL,     -- UUID string
  kdf_salt BLOB NOT NULL,
  kdf_m_cost_kib INTEGER NOT NULL,
  kdf_t_cost INTEGER NOT NULL,
  kdf_p_cost INTEGER NOT NULL,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS projects (
  id TEXT PRIMARY KEY NOT NULL,     -- UUID string
  workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  UNIQUE(workspace_id, name)
);

CREATE TABLE IF NOT EXISTS environments (
  id TEXT PRIMARY KEY NOT NULL,     -- UUID string
  workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  dek_wrapped BLOB NOT NULL,
  dek_nonce BLOB NOT NULL,
  UNIQUE(workspace_id, project_id, name)
);

CREATE TABLE IF NOT EXISTS secrets (
  id TEXT PRIMARY KEY NOT NULL,     -- UUID string
  workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  env_id TEXT NOT NULL REFERENCES environments(id) ON DELETE CASCADE,
  key_name TEXT NOT NULL,
  nonce BLOB NOT NULL,
  ciphertext BLOB NOT NULL,
  created_at INTEGER NOT NULL,
  UNIQUE(workspace_id, env_id, key_name)
);
