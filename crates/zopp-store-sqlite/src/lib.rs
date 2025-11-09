use chrono::{DateTime, Utc};
use sqlx::{SqlitePool, sqlite::SqlitePoolOptions};
use uuid::Uuid;
use zopp_storage::{
    CreateEnvParams, CreateInviteParams, CreatePrincipalParams, CreateProjectParams,
    CreateUserParams, CreateWorkspaceParams, EnvName, Environment, EnvironmentId, Invite, InviteId,
    Principal, PrincipalId, ProjectName, SecretRow, Store, StoreError, Transaction, User, UserId,
    Workspace, WorkspaceId,
};

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

pub struct SqliteStore {
    pool: SqlitePool,
}

pub struct SqliteTxn;
impl Transaction for SqliteTxn {
    fn commit(self) -> Result<(), StoreError> {
        Ok(())
    }
    fn rollback(self) -> Result<(), StoreError> {
        Ok(())
    }
}

impl SqliteStore {
    /// `~/.zopp/store.db` (creates dir with 0700 perms on unix)
    pub async fn open_default() -> Result<Self, StoreError> {
        let dir = dirs::home_dir()
            .ok_or_else(|| StoreError::Backend("no home dir".into()))?
            .join(".zopp");
        std::fs::create_dir_all(&dir).map_err(|e| StoreError::Backend(e.to_string()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
                .map_err(|e| StoreError::Backend(e.to_string()))?;
        }
        let path = dir.join("store.db");
        let url = format!("sqlite://{}", path.to_string_lossy());
        Self::open(&url).await
    }

    pub async fn open_in_memory() -> Result<Self, StoreError> {
        Self::open("sqlite::memory:").await
    }

    pub async fn open(url: &str) -> Result<Self, StoreError> {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect(url)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))?;

        MIGRATOR
            .run(&pool)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))?;

        Ok(Self { pool })
    }
}

#[async_trait::async_trait]
impl Store for SqliteStore {
    type Txn = SqliteTxn;

    async fn begin_txn(&self) -> Result<Self::Txn, StoreError> {
        Ok(SqliteTxn)
    }

    // ───────────────────────────── Users ─────────────────────────────

    async fn create_user(
        &self,
        params: &CreateUserParams,
    ) -> Result<(UserId, Option<PrincipalId>), StoreError> {
        let user_id = Uuid::now_v7();
        let user_id_str = user_id.to_string();

        // Use transaction if we need to create principal or add to workspaces
        let needs_tx = params.principal.is_some() || !params.workspace_ids.is_empty();

        if needs_tx {
            let mut tx = self
                .pool
                .begin()
                .await
                .map_err(|e| StoreError::Backend(e.to_string()))?;

            // Create user
            sqlx::query!(
                "INSERT INTO users(id, email) VALUES(?, ?)",
                user_id_str,
                params.email
            )
            .execute(&mut *tx)
            .await
            .map_err(|e| {
                let s = e.to_string();
                if s.contains("UNIQUE") {
                    StoreError::AlreadyExists
                } else {
                    StoreError::Backend(s)
                }
            })?;

            // Create principal if provided
            let principal_id = if let Some(principal_data) = &params.principal {
                let principal_id = Uuid::now_v7();
                let principal_id_str = principal_id.to_string();

                sqlx::query!(
                    "INSERT INTO principals(id, user_id, name, public_key) VALUES(?, ?, ?, ?)",
                    principal_id_str,
                    user_id_str,
                    principal_data.name,
                    principal_data.public_key
                )
                .execute(&mut *tx)
                .await
                .map_err(|e| StoreError::Backend(e.to_string()))?;

                Some(PrincipalId(principal_id))
            } else {
                None
            };

            // Add user to workspaces (user-level membership)
            for workspace_id in &params.workspace_ids {
                let ws_id = workspace_id.0.to_string();
                sqlx::query!(
                    "INSERT INTO workspace_members(workspace_id, user_id) VALUES(?, ?)",
                    ws_id,
                    user_id_str
                )
                .execute(&mut *tx)
                .await
                .map_err(|e| StoreError::Backend(e.to_string()))?;
            }

            tx.commit()
                .await
                .map_err(|e| StoreError::Backend(e.to_string()))?;

            Ok((UserId(user_id), principal_id))
        } else {
            // Simple case: just create user
            sqlx::query!(
                "INSERT INTO users(id, email) VALUES(?, ?)",
                user_id_str,
                params.email
            )
            .execute(&self.pool)
            .await
            .map_err(|e| {
                let s = e.to_string();
                if s.contains("UNIQUE") {
                    StoreError::AlreadyExists
                } else {
                    StoreError::Backend(s)
                }
            })?;

            Ok((UserId(user_id), None))
        }
    }

    async fn get_user_by_email(&self, email: &str) -> Result<User, StoreError> {
        let row = sqlx::query!(
            r#"SELECT id, email,
               created_at as "created_at: DateTime<Utc>",
               updated_at as "updated_at: DateTime<Utc>"
               FROM users WHERE email = ?"#,
            email
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;

        match row {
            None => Err(StoreError::NotFound),
            Some(row) => {
                let id =
                    Uuid::try_parse(&row.id).map_err(|e| StoreError::Backend(e.to_string()))?;
                Ok(User {
                    id: UserId(id),
                    email: row.email,
                    created_at: row.created_at,
                    updated_at: row.updated_at,
                })
            }
        }
    }

    async fn get_user_by_id(&self, user_id: &UserId) -> Result<User, StoreError> {
        let user_id_str = user_id.0.to_string();
        let row = sqlx::query!(
            r#"SELECT id, email,
               created_at as "created_at: DateTime<Utc>",
               updated_at as "updated_at: DateTime<Utc>"
               FROM users WHERE id = ?"#,
            user_id_str
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;

        match row {
            None => Err(StoreError::NotFound),
            Some(row) => {
                let id =
                    Uuid::try_parse(&row.id).map_err(|e| StoreError::Backend(e.to_string()))?;
                Ok(User {
                    id: UserId(id),
                    email: row.email,
                    created_at: row.created_at,
                    updated_at: row.updated_at,
                })
            }
        }
    }

    // ───────────────────────────── Principals ─────────────────────────────

    async fn create_principal(
        &self,
        params: &CreatePrincipalParams,
    ) -> Result<PrincipalId, StoreError> {
        let principal_id = Uuid::now_v7();
        let principal_id_str = principal_id.to_string();
        let user_id_str = params.user_id.as_ref().map(|id| id.0.to_string());

        sqlx::query!(
            "INSERT INTO principals(id, user_id, name, public_key) VALUES(?, ?, ?, ?)",
            principal_id_str,
            user_id_str,
            params.name,
            params.public_key
        )
        .execute(&self.pool)
        .await
        .map_err(|e| {
            let s = e.to_string();
            if s.contains("UNIQUE") {
                StoreError::AlreadyExists
            } else {
                StoreError::Backend(s)
            }
        })?;
        Ok(PrincipalId(principal_id))
    }

    async fn get_principal(&self, principal_id: &PrincipalId) -> Result<Principal, StoreError> {
        let principal_id_str = principal_id.0.to_string();
        let row = sqlx::query!(
            r#"SELECT id, user_id, name, public_key,
               created_at as "created_at: DateTime<Utc>",
               updated_at as "updated_at: DateTime<Utc>"
               FROM principals WHERE id = ?"#,
            principal_id_str
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;

        match row {
            None => Err(StoreError::NotFound),
            Some(row) => {
                let id =
                    Uuid::try_parse(&row.id).map_err(|e| StoreError::Backend(e.to_string()))?;
                let user_id = row
                    .user_id
                    .as_ref()
                    .map(|id| Uuid::try_parse(id).map(UserId))
                    .transpose()
                    .map_err(|e| StoreError::Backend(e.to_string()))?;
                Ok(Principal {
                    id: PrincipalId(id),
                    user_id,
                    name: row.name,
                    public_key: row.public_key,
                    created_at: row.created_at,
                    updated_at: row.updated_at,
                })
            }
        }
    }

    async fn rename_principal(
        &self,
        principal_id: &PrincipalId,
        new_name: &str,
    ) -> Result<(), StoreError> {
        let principal_id_str = principal_id.0.to_string();
        let result = sqlx::query!(
            "UPDATE principals SET name = ? WHERE id = ?",
            new_name,
            principal_id_str
        )
        .execute(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;

        if result.rows_affected() == 0 {
            Err(StoreError::NotFound)
        } else {
            Ok(())
        }
    }

    async fn list_principals(&self, user_id: &UserId) -> Result<Vec<Principal>, StoreError> {
        let user_id_str = user_id.0.to_string();
        let rows = sqlx::query!(
            r#"SELECT id, user_id, name, public_key,
               created_at as "created_at: DateTime<Utc>",
               updated_at as "updated_at: DateTime<Utc>"
               FROM principals WHERE user_id = ?"#,
            user_id_str
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;

        let mut principals = Vec::with_capacity(rows.len());
        for row in rows {
            let id = Uuid::try_parse(&row.id).map_err(|e| StoreError::Backend(e.to_string()))?;
            let user_id = row
                .user_id
                .as_ref()
                .map(|id| Uuid::try_parse(id).map(UserId))
                .transpose()
                .map_err(|e| StoreError::Backend(e.to_string()))?;
            principals.push(Principal {
                id: PrincipalId(id),
                user_id,
                name: row.name,
                public_key: row.public_key,
                created_at: row.created_at,
                updated_at: row.updated_at,
            });
        }
        Ok(principals)
    }

    // ───────────────────────────── Invites ─────────────────────────────

    async fn create_invite(&self, params: &CreateInviteParams) -> Result<Invite, StoreError> {
        let invite_id = Uuid::now_v7();
        let invite_id_str = invite_id.to_string();

        // Generate cryptographically secure random token (32 bytes = 256 bits)
        use rand_core::RngCore;
        let mut token_bytes = [0u8; 32];
        rand_core::OsRng.fill_bytes(&mut token_bytes);
        let token = hex::encode(token_bytes);

        let created_by_user_id_str = params
            .created_by_user_id
            .as_ref()
            .map(|id| id.0.to_string());

        sqlx::query!(
            "INSERT INTO invites(id, token, expires_at, created_by_user_id) VALUES(?, ?, ?, ?)",
            invite_id_str,
            token,
            params.expires_at,
            created_by_user_id_str
        )
        .execute(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;

        // Insert workspace associations
        for ws_id in &params.workspace_ids {
            let ws_id_str = ws_id.0.to_string();
            sqlx::query!(
                "INSERT INTO invite_workspaces(invite_id, workspace_id) VALUES(?, ?)",
                invite_id_str,
                ws_id_str
            )
            .execute(&self.pool)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))?;
        }

        // Fetch the created invite to get the database-set timestamps
        let row = sqlx::query!(
            r#"SELECT created_at as "created_at: DateTime<Utc>",
               updated_at as "updated_at: DateTime<Utc>"
               FROM invites WHERE id = ?"#,
            invite_id_str
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;

        Ok(Invite {
            id: InviteId(invite_id),
            token,
            workspace_ids: params.workspace_ids.clone(),
            created_at: row.created_at,
            updated_at: row.updated_at,
            expires_at: params.expires_at,
            created_by_user_id: params.created_by_user_id.clone(),
        })
    }

    async fn get_invite_by_token(&self, token: &str) -> Result<Invite, StoreError> {
        let row = sqlx::query!(
            r#"SELECT id, token,
               created_at as "created_at: DateTime<Utc>",
               updated_at as "updated_at: DateTime<Utc>",
               expires_at as "expires_at: DateTime<Utc>",
               created_by_user_id, revoked
               FROM invites WHERE token = ?"#,
            token
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;

        match row {
            None => Err(StoreError::NotFound),
            Some(row) => {
                if row.revoked != 0 {
                    return Err(StoreError::NotFound); // Treat revoked as not found
                }

                let id =
                    Uuid::try_parse(&row.id).map_err(|e| StoreError::Backend(e.to_string()))?;
                let created_by_user_id = row
                    .created_by_user_id
                    .as_ref()
                    .map(|id| Uuid::try_parse(id).map(UserId))
                    .transpose()
                    .map_err(|e| StoreError::Backend(e.to_string()))?;

                // Get workspace IDs
                let invite_id_str = row.id;
                let ws_rows = sqlx::query!(
                    "SELECT workspace_id FROM invite_workspaces WHERE invite_id = ?",
                    invite_id_str
                )
                .fetch_all(&self.pool)
                .await
                .map_err(|e| StoreError::Backend(e.to_string()))?;

                let mut workspace_ids = Vec::new();
                for ws_row in ws_rows {
                    let ws_id = Uuid::try_parse(&ws_row.workspace_id)
                        .map_err(|e| StoreError::Backend(e.to_string()))?;
                    workspace_ids.push(WorkspaceId(ws_id));
                }

                Ok(Invite {
                    id: InviteId(id),
                    token: row.token,
                    workspace_ids,
                    created_at: row.created_at,
                    updated_at: row.updated_at,
                    expires_at: row.expires_at,
                    created_by_user_id,
                })
            }
        }
    }

    async fn list_invites(&self, user_id: Option<&UserId>) -> Result<Vec<Invite>, StoreError> {
        let user_id_str = user_id.map(|id| id.0.to_string());

        // Query for either user-created invites or server invites (where created_by_user_id IS NULL)
        let rows = sqlx::query!(
            r#"SELECT id, token,
               created_at as "created_at: DateTime<Utc>",
               updated_at as "updated_at: DateTime<Utc>",
               expires_at as "expires_at: DateTime<Utc>",
               created_by_user_id, revoked
               FROM invites
               WHERE revoked = 0 AND (
                   (? IS NOT NULL AND created_by_user_id = ?) OR
                   (? IS NULL AND created_by_user_id IS NULL)
               )"#,
            user_id_str,
            user_id_str,
            user_id_str
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;

        let mut invites = Vec::new();
        for row in rows {
            let id = Uuid::try_parse(&row.id).map_err(|e| StoreError::Backend(e.to_string()))?;
            let created_by_user_id = row
                .created_by_user_id
                .as_ref()
                .map(|id| Uuid::try_parse(id).map(UserId))
                .transpose()
                .map_err(|e| StoreError::Backend(e.to_string()))?;

            // Get workspace IDs
            let ws_rows = sqlx::query!(
                "SELECT workspace_id FROM invite_workspaces WHERE invite_id = ?",
                row.id
            )
            .fetch_all(&self.pool)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))?;

            let mut workspace_ids = Vec::new();
            for ws_row in ws_rows {
                let ws_id = Uuid::try_parse(&ws_row.workspace_id)
                    .map_err(|e| StoreError::Backend(e.to_string()))?;
                workspace_ids.push(WorkspaceId(ws_id));
            }

            invites.push(Invite {
                id: InviteId(id),
                token: row.token,
                workspace_ids,
                created_at: row.created_at,
                updated_at: row.updated_at,
                expires_at: row.expires_at,
                created_by_user_id,
            });
        }
        Ok(invites)
    }

    async fn revoke_invite(&self, invite_id: &InviteId) -> Result<(), StoreError> {
        let invite_id_str = invite_id.0.to_string();
        let result = sqlx::query!("UPDATE invites SET revoked = 1 WHERE id = ?", invite_id_str)
            .execute(&self.pool)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))?;

        if result.rows_affected() == 0 {
            Err(StoreError::NotFound)
        } else {
            Ok(())
        }
    }

    // ───────────────────────────── Workspaces ─────────────────────────────

    async fn create_workspace(
        &self,
        params: &CreateWorkspaceParams,
    ) -> Result<WorkspaceId, StoreError> {
        let ws_id = Uuid::now_v7();
        let ws_id_str = ws_id.to_string();
        let owner_user_id_str = params.owner_user_id.0.to_string();
        let m_cost = params.m_cost_kib as i64;
        let t_cost = params.t_cost as i64;
        let p_cost = params.p_cost as i64;

        sqlx::query!(
            "INSERT INTO workspaces(id, name, owner_user_id, kdf_salt, kdf_m_cost_kib, kdf_t_cost, kdf_p_cost)
             VALUES(?, ?, ?, ?, ?, ?, ?)",
            ws_id_str,
            params.name,
            owner_user_id_str,
            params.kdf_salt,
            m_cost,
            t_cost,
            p_cost
        )
        .execute(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;
        Ok(WorkspaceId(ws_id))
    }

    async fn list_workspaces(&self, user_id: &UserId) -> Result<Vec<Workspace>, StoreError> {
        let user_id_str = user_id.0.to_string();

        // Get all workspaces where user is a member
        let rows = sqlx::query!(
            r#"SELECT w.id, w.name, w.owner_user_id, w.kdf_salt, w.kdf_m_cost_kib, w.kdf_t_cost, w.kdf_p_cost,
               w.created_at as "created_at: DateTime<Utc>",
               w.updated_at as "updated_at: DateTime<Utc>"
               FROM workspaces w
               JOIN workspace_members wm ON w.id = wm.workspace_id
               WHERE wm.user_id = ?"#,
            user_id_str
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;

        let mut workspaces = Vec::new();
        for row in rows {
            let id = Uuid::try_parse(&row.id).map_err(|e| StoreError::Backend(e.to_string()))?;
            let owner_user_id = Uuid::try_parse(&row.owner_user_id)
                .map_err(|e| StoreError::Backend(e.to_string()))?;
            workspaces.push(Workspace {
                id: WorkspaceId(id),
                name: row.name,
                owner_user_id: UserId(owner_user_id),
                kdf_salt: row.kdf_salt,
                m_cost_kib: row.kdf_m_cost_kib as u32,
                t_cost: row.kdf_t_cost as u32,
                p_cost: row.kdf_p_cost as u32,
                created_at: row.created_at,
                updated_at: row.updated_at,
            });
        }
        Ok(workspaces)
    }

    async fn get_workspace(&self, ws: &WorkspaceId) -> Result<Workspace, StoreError> {
        let ws_id = ws.0.to_string();
        let row = sqlx::query!(
            r#"SELECT id, name, owner_user_id, kdf_salt, kdf_m_cost_kib, kdf_t_cost, kdf_p_cost,
               created_at as "created_at: DateTime<Utc>",
               updated_at as "updated_at: DateTime<Utc>"
               FROM workspaces WHERE id = ?"#,
            ws_id
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;

        match row {
            None => Err(StoreError::NotFound),
            Some(row) => {
                let id =
                    Uuid::try_parse(&row.id).map_err(|e| StoreError::Backend(e.to_string()))?;
                let owner_user_id = Uuid::try_parse(&row.owner_user_id)
                    .map_err(|e| StoreError::Backend(e.to_string()))?;
                Ok(Workspace {
                    id: WorkspaceId(id),
                    name: row.name,
                    owner_user_id: UserId(owner_user_id),
                    kdf_salt: row.kdf_salt,
                    m_cost_kib: row.kdf_m_cost_kib as u32,
                    t_cost: row.kdf_t_cost as u32,
                    p_cost: row.kdf_p_cost as u32,
                    created_at: row.created_at,
                    updated_at: row.updated_at,
                })
            }
        }
    }

    async fn add_principal_to_workspace(
        &self,
        workspace_id: &WorkspaceId,
        principal_id: &PrincipalId,
    ) -> Result<(), StoreError> {
        let ws_id = workspace_id.0.to_string();
        let p_id = principal_id.0.to_string();

        sqlx::query!(
            "INSERT INTO workspace_principals(workspace_id, principal_id) VALUES(?, ?)",
            ws_id,
            p_id
        )
        .execute(&self.pool)
        .await
        .map_err(|e| match e {
            sqlx::Error::Database(ref db_err) if db_err.is_unique_violation() => {
                StoreError::AlreadyExists
            }
            _ => StoreError::Backend(e.to_string()),
        })?;
        Ok(())
    }

    async fn add_user_to_workspace(
        &self,
        workspace_id: &WorkspaceId,
        user_id: &UserId,
    ) -> Result<(), StoreError> {
        let ws_id = workspace_id.0.to_string();
        let u_id = user_id.0.to_string();

        sqlx::query!(
            "INSERT INTO workspace_members(workspace_id, user_id) VALUES(?, ?)",
            ws_id,
            u_id
        )
        .execute(&self.pool)
        .await
        .map_err(|e| match e {
            sqlx::Error::Database(ref db_err) if db_err.is_unique_violation() => {
                StoreError::AlreadyExists
            }
            _ => StoreError::Backend(e.to_string()),
        })?;
        Ok(())
    }

    // ───────────────────────────── Projects ───────────────────────────────

    async fn create_project(
        &self,
        params: &CreateProjectParams,
    ) -> Result<zopp_storage::ProjectId, StoreError> {
        let id = Uuid::now_v7();
        let id_str = id.to_string();
        let ws_id = params.workspace_id.0.to_string();

        sqlx::query!(
            "INSERT INTO projects(id, workspace_id, name) VALUES(?, ?, ?)",
            id_str,
            ws_id,
            params.name
        )
        .execute(&self.pool)
        .await
        .map_err(|e| {
            let s = e.to_string();
            if s.contains("UNIQUE") {
                StoreError::AlreadyExists
            } else {
                StoreError::Backend(s)
            }
        })?;
        Ok(zopp_storage::ProjectId(id))
    }

    async fn list_projects(
        &self,
        workspace_id: &WorkspaceId,
    ) -> Result<Vec<zopp_storage::Project>, StoreError> {
        let ws_id = workspace_id.0.to_string();

        let rows = sqlx::query!(
            r#"SELECT id, workspace_id, name,
               created_at as "created_at: DateTime<Utc>",
               updated_at as "updated_at: DateTime<Utc>"
               FROM projects WHERE workspace_id = ? ORDER BY created_at DESC"#,
            ws_id
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;

        let projects = rows
            .into_iter()
            .map(|row| {
                Ok(zopp_storage::Project {
                    id: zopp_storage::ProjectId(
                        Uuid::parse_str(&row.id).map_err(|e| StoreError::Backend(e.to_string()))?,
                    ),
                    workspace_id: zopp_storage::WorkspaceId(
                        Uuid::parse_str(&row.workspace_id)
                            .map_err(|e| StoreError::Backend(e.to_string()))?,
                    ),
                    name: row.name,
                    created_at: row.created_at,
                    updated_at: row.updated_at,
                })
            })
            .collect::<Result<Vec<_>, StoreError>>()?;

        Ok(projects)
    }

    async fn get_project(
        &self,
        project_id: &zopp_storage::ProjectId,
    ) -> Result<zopp_storage::Project, StoreError> {
        let id_str = project_id.0.to_string();

        let row = sqlx::query!(
            r#"SELECT id, workspace_id, name,
               created_at as "created_at: DateTime<Utc>",
               updated_at as "updated_at: DateTime<Utc>"
               FROM projects WHERE id = ?"#,
            id_str
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?
        .ok_or(StoreError::NotFound)?;

        Ok(zopp_storage::Project {
            id: zopp_storage::ProjectId(
                Uuid::parse_str(&row.id).map_err(|e| StoreError::Backend(e.to_string()))?,
            ),
            workspace_id: zopp_storage::WorkspaceId(
                Uuid::parse_str(&row.workspace_id)
                    .map_err(|e| StoreError::Backend(e.to_string()))?,
            ),
            name: row.name,
            created_at: row.created_at,
            updated_at: row.updated_at,
        })
    }

    async fn delete_project(&self, project_id: &zopp_storage::ProjectId) -> Result<(), StoreError> {
        let id_str = project_id.0.to_string();

        let result = sqlx::query!("DELETE FROM projects WHERE id = ?", id_str)
            .execute(&self.pool)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(StoreError::NotFound);
        }

        Ok(())
    }

    // ──────────────────────────── Environments ────────────────────────────

    async fn create_env(&self, params: &CreateEnvParams) -> Result<EnvironmentId, StoreError> {
        let env_id = Uuid::now_v7();
        let env_id_str = env_id.to_string();
        let proj_id_str = params.project_id.0.to_string();

        // Get project to determine workspace_id
        let proj_row = sqlx::query!(
            "SELECT workspace_id FROM projects WHERE id = ?",
            proj_id_str
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?
        .ok_or(StoreError::NotFound)?;

        let ws_id = proj_row.workspace_id;

        sqlx::query!(
            "INSERT INTO environments(id, workspace_id, project_id, name, dek_wrapped, dek_nonce)
             VALUES(?, ?, ?, ?, ?, ?)",
            env_id_str,
            ws_id,
            proj_id_str,
            params.name,
            params.dek_wrapped,
            params.dek_nonce
        )
        .execute(&self.pool)
        .await
        .map_err(|e| {
            let s = e.to_string();
            if s.contains("UNIQUE") {
                StoreError::AlreadyExists
            } else {
                StoreError::Backend(s)
            }
        })?;

        Ok(EnvironmentId(env_id))
    }

    async fn list_environments(
        &self,
        project_id: &zopp_storage::ProjectId,
    ) -> Result<Vec<Environment>, StoreError> {
        let proj_id_str = project_id.0.to_string();

        let rows = sqlx::query!(
            r#"SELECT id, project_id, name, dek_wrapped, dek_nonce,
               created_at as "created_at: DateTime<Utc>",
               updated_at as "updated_at: DateTime<Utc>"
               FROM environments WHERE project_id = ? ORDER BY created_at DESC"#,
            proj_id_str
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;

        let environments = rows
            .into_iter()
            .map(|row| {
                Ok(Environment {
                    id: EnvironmentId(
                        Uuid::parse_str(&row.id).map_err(|e| StoreError::Backend(e.to_string()))?,
                    ),
                    project_id: zopp_storage::ProjectId(
                        Uuid::parse_str(&row.project_id)
                            .map_err(|e| StoreError::Backend(e.to_string()))?,
                    ),
                    name: row.name,
                    dek_wrapped: row.dek_wrapped,
                    dek_nonce: row.dek_nonce,
                    created_at: row.created_at,
                    updated_at: row.updated_at,
                })
            })
            .collect::<Result<Vec<_>, StoreError>>()?;

        Ok(environments)
    }

    async fn get_environment(&self, env_id: &EnvironmentId) -> Result<Environment, StoreError> {
        let env_id_str = env_id.0.to_string();

        let row = sqlx::query!(
            r#"SELECT id, project_id, name, dek_wrapped, dek_nonce,
               created_at as "created_at: DateTime<Utc>",
               updated_at as "updated_at: DateTime<Utc>"
               FROM environments WHERE id = ?"#,
            env_id_str
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?
        .ok_or(StoreError::NotFound)?;

        Ok(Environment {
            id: EnvironmentId(
                Uuid::parse_str(&row.id).map_err(|e| StoreError::Backend(e.to_string()))?,
            ),
            project_id: zopp_storage::ProjectId(
                Uuid::parse_str(&row.project_id).map_err(|e| StoreError::Backend(e.to_string()))?,
            ),
            name: row.name,
            dek_wrapped: row.dek_wrapped,
            dek_nonce: row.dek_nonce,
            created_at: row.created_at,
            updated_at: row.updated_at,
        })
    }

    async fn delete_environment(&self, env_id: &EnvironmentId) -> Result<(), StoreError> {
        let env_id_str = env_id.0.to_string();

        let result = sqlx::query!("DELETE FROM environments WHERE id = ?", env_id_str)
            .execute(&self.pool)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(StoreError::NotFound);
        }

        Ok(())
    }

    async fn get_env_wrap(
        &self,
        ws: &WorkspaceId,
        project: &ProjectName,
        env: &EnvName,
    ) -> Result<(Vec<u8>, Vec<u8>), StoreError> {
        let ws_id = ws.0.to_string();
        let proj_name = &project.0;
        let env_name = &env.0;

        let row = sqlx::query!(
            "SELECT e.dek_wrapped, e.dek_nonce
             FROM environments e
             JOIN projects p ON p.id = e.project_id
             WHERE e.workspace_id = ? AND p.workspace_id = ? AND p.name = ? AND e.name = ?",
            ws_id,
            ws_id,
            proj_name,
            env_name
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;

        match row {
            Some(row) => Ok((row.dek_wrapped, row.dek_nonce)),
            None => Err(StoreError::NotFound),
        }
    }

    // ────────────────────────────── Secrets ───────────────────────────────

    async fn upsert_secret(
        &self,
        env_id: &EnvironmentId,
        key: &str,
        nonce: &[u8],
        ciphertext: &[u8],
    ) -> Result<(), StoreError> {
        let env_id_str = env_id.0.to_string();

        // Get environment to determine workspace_id
        let env_row = sqlx::query!(
            "SELECT workspace_id FROM environments WHERE id = ?",
            env_id_str
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?
        .ok_or(StoreError::NotFound)?;

        let ws_id = env_row.workspace_id;
        let secret_id = Uuid::now_v7().to_string();

        sqlx::query!(
            "INSERT INTO secrets(id, workspace_id, env_id, key_name, nonce, ciphertext)
             VALUES(?, ?, ?, ?, ?, ?)
             ON CONFLICT(workspace_id, env_id, key_name)
             DO UPDATE SET nonce = excluded.nonce, ciphertext = excluded.ciphertext",
            secret_id,
            ws_id,
            env_id_str,
            key,
            nonce,
            ciphertext
        )
        .execute(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;

        Ok(())
    }

    async fn get_secret(&self, env_id: &EnvironmentId, key: &str) -> Result<SecretRow, StoreError> {
        let env_id_str = env_id.0.to_string();

        let row = sqlx::query!(
            "SELECT nonce, ciphertext FROM secrets WHERE env_id = ? AND key_name = ?",
            env_id_str,
            key
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;

        match row {
            None => Err(StoreError::NotFound),
            Some(row) => Ok(SecretRow {
                nonce: row.nonce,
                ciphertext: row.ciphertext,
            }),
        }
    }

    async fn list_secret_keys(&self, env_id: &EnvironmentId) -> Result<Vec<String>, StoreError> {
        let env_id_str = env_id.0.to_string();

        let rows = sqlx::query!(
            "SELECT key_name FROM secrets WHERE env_id = ? ORDER BY key_name",
            env_id_str
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;

        Ok(rows.into_iter().map(|row| row.key_name).collect())
    }

    async fn delete_secret(&self, env_id: &EnvironmentId, key: &str) -> Result<(), StoreError> {
        let env_id_str = env_id.0.to_string();

        let result = sqlx::query!(
            "DELETE FROM secrets WHERE env_id = ? AND key_name = ?",
            env_id_str,
            key
        )
        .execute(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(StoreError::NotFound);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zopp_storage::{CreateWorkspaceParams, EnvName, ProjectName, StoreError, UserId};

    fn workspace_params(owner_user_id: UserId) -> CreateWorkspaceParams {
        CreateWorkspaceParams {
            name: "test-workspace".to_string(),
            owner_user_id,
            kdf_salt: b"abcdef0123456789".to_vec(),
            m_cost_kib: 1024,
            t_cost: 2,
            p_cost: 1,
        }
    }

    #[tokio::test]
    async fn workspace_params_roundtrip() {
        let s = SqliteStore::open_in_memory().await.unwrap();
        let (user_id, _) = s
            .create_user(&CreateUserParams {
                email: "test@example.com".to_string(),
                principal: None,
                workspace_ids: vec![],
            })
            .await
            .unwrap();
        let ws = s
            .create_workspace(&workspace_params(user_id))
            .await
            .unwrap();
        let got = s.get_workspace(&ws).await.unwrap();
        assert_eq!(
            got.kdf_salt,
            workspace_params(got.owner_user_id.clone()).kdf_salt
        );
        assert_eq!(got.m_cost_kib, 1024);
        assert_eq!(got.t_cost, 2);
        assert_eq!(got.p_cost, 1);
    }

    #[tokio::test]
    async fn duplicate_project_maps_to_alreadyexists() {
        let s = SqliteStore::open_in_memory().await.unwrap();
        let (user_id, _) = s
            .create_user(&CreateUserParams {
                email: "test@example.com".to_string(),
                principal: None,
                workspace_ids: vec![],
            })
            .await
            .unwrap();
        let ws = s
            .create_workspace(&workspace_params(user_id))
            .await
            .unwrap();
        let name = ProjectName("app".into());

        s.create_project(&CreateProjectParams {
            workspace_id: ws.clone(),
            name: name.0.clone(),
        })
        .await
        .unwrap();
        let err = s
            .create_project(&CreateProjectParams {
                workspace_id: ws,
                name: name.0,
            })
            .await
            .unwrap_err();

        matches!(err, StoreError::AlreadyExists);
    }

    #[tokio::test]
    async fn workspace_scoping_isolation() {
        let s = SqliteStore::open_in_memory().await.unwrap();
        let (user_id, _) = s
            .create_user(&CreateUserParams {
                email: "test@example.com".to_string(),
                principal: None,
                workspace_ids: vec![],
            })
            .await
            .unwrap();
        let ws1 = s
            .create_workspace(&workspace_params(user_id.clone()))
            .await
            .unwrap();
        let ws2 = s
            .create_workspace(&workspace_params(user_id))
            .await
            .unwrap();

        let p = ProjectName("app".into());
        let e = EnvName("prod".into());

        let project_id1 = s
            .create_project(&CreateProjectParams {
                workspace_id: ws1.clone(),
                name: p.0.clone(),
            })
            .await
            .unwrap();
        let env_id1 = s
            .create_env(&CreateEnvParams {
                project_id: project_id1,
                name: e.0.clone(),
                dek_wrapped: vec![1],
                dek_nonce: vec![9; 24],
            })
            .await
            .unwrap();

        let project_id2 = s
            .create_project(&CreateProjectParams {
                workspace_id: ws2.clone(),
                name: p.0.clone(),
            })
            .await
            .unwrap();
        let env_id2 = s
            .create_env(&CreateEnvParams {
                project_id: project_id2,
                name: e.0.clone(),
                dek_wrapped: vec![2],
                dek_nonce: vec![9; 24],
            })
            .await
            .unwrap();

        // only insert secret into env1
        s.upsert_secret(&env_id1, "TOKEN", &[7; 24], &[1; 8])
            .await
            .unwrap();

        // env2 must NOT be able to see env1's secret
        let err = s.get_secret(&env_id2, "TOKEN").await.unwrap_err();
        matches!(err, StoreError::NotFound);
    }

    #[tokio::test]
    async fn list_secret_keys_returns_sorted() {
        let s = SqliteStore::open_in_memory().await.unwrap();
        let (user_id, _) = s
            .create_user(&CreateUserParams {
                email: "test@example.com".to_string(),
                principal: None,
                workspace_ids: vec![],
            })
            .await
            .unwrap();
        let ws = s
            .create_workspace(&workspace_params(user_id))
            .await
            .unwrap();

        let p = ProjectName("app".into());
        let e = EnvName("prod".into());
        let project_id = s
            .create_project(&CreateProjectParams {
                workspace_id: ws.clone(),
                name: p.0.clone(),
            })
            .await
            .unwrap();
        let env_id = s
            .create_env(&CreateEnvParams {
                project_id,
                name: e.0.clone(),
                dek_wrapped: vec![1],
                dek_nonce: vec![9; 24],
            })
            .await
            .unwrap();

        s.upsert_secret(&env_id, "z_last", &[7; 24], &[1])
            .await
            .unwrap();
        s.upsert_secret(&env_id, "a_first", &[7; 24], &[1])
            .await
            .unwrap();
        s.upsert_secret(&env_id, "m_middle", &[7; 24], &[1])
            .await
            .unwrap();

        let keys = s.list_secret_keys(&env_id).await.unwrap();
        assert_eq!(keys, vec!["a_first", "m_middle", "z_last"]);
    }

    #[tokio::test]
    async fn create_env_requires_existing_project() {
        let s = SqliteStore::open_in_memory().await.unwrap();
        let (user_id, _) = s
            .create_user(&CreateUserParams {
                email: "test@example.com".to_string(),
                principal: None,
                workspace_ids: vec![],
            })
            .await
            .unwrap();
        let _ws = s
            .create_workspace(&workspace_params(user_id))
            .await
            .unwrap();

        // Non-existent project ID → creating env should fail with NotFound
        let fake_project_id = zopp_storage::ProjectId(uuid::Uuid::new_v4());
        let err = s
            .create_env(&CreateEnvParams {
                project_id: fake_project_id,
                name: "prod".to_string(),
                dek_wrapped: vec![1],
                dek_nonce: vec![9; 24],
            })
            .await
            .unwrap_err();
        matches!(err, StoreError::NotFound);
    }

    #[tokio::test]
    async fn duplicate_env_maps_to_alreadyexists() {
        let s = SqliteStore::open_in_memory().await.unwrap();
        let (user_id, _) = s
            .create_user(&CreateUserParams {
                email: "test@example.com".to_string(),
                principal: None,
                workspace_ids: vec![],
            })
            .await
            .unwrap();
        let ws = s
            .create_workspace(&workspace_params(user_id))
            .await
            .unwrap();
        let p = ProjectName("app".into());
        let e = EnvName("prod".into());

        let project_id = s
            .create_project(&CreateProjectParams {
                workspace_id: ws.clone(),
                name: p.0.clone(),
            })
            .await
            .unwrap();
        s.create_env(&CreateEnvParams {
            project_id: project_id.clone(),
            name: e.0.clone(),
            dek_wrapped: vec![1],
            dek_nonce: vec![9; 24],
        })
        .await
        .unwrap();
        let err = s
            .create_env(&CreateEnvParams {
                project_id,
                name: e.0,
                dek_wrapped: vec![1],
                dek_nonce: vec![9; 24],
            })
            .await
            .unwrap_err();
        matches!(err, StoreError::AlreadyExists);
    }

    #[tokio::test]
    async fn upsert_secret_overwrites_value_and_nonce() {
        let s = SqliteStore::open_in_memory().await.unwrap();
        let (user_id, _) = s
            .create_user(&CreateUserParams {
                email: "test@example.com".to_string(),
                principal: None,
                workspace_ids: vec![],
            })
            .await
            .unwrap();
        let ws = s
            .create_workspace(&workspace_params(user_id))
            .await
            .unwrap();

        let p = ProjectName("app".into());
        let e = EnvName("prod".into());
        let project_id = s
            .create_project(&CreateProjectParams {
                workspace_id: ws.clone(),
                name: p.0.clone(),
            })
            .await
            .unwrap();
        let env_id = s
            .create_env(&CreateEnvParams {
                project_id,
                name: e.0.clone(),
                dek_wrapped: vec![1],
                dek_nonce: vec![9; 24],
            })
            .await
            .unwrap();

        s.upsert_secret(&env_id, "API", &[1; 24], &[10; 4])
            .await
            .unwrap();
        let a = s.get_secret(&env_id, "API").await.unwrap();

        s.upsert_secret(&env_id, "API", &[2; 24], &[20; 6])
            .await
            .unwrap();
        let b = s.get_secret(&env_id, "API").await.unwrap();

        assert_ne!(a.nonce, b.nonce);
        assert_ne!(a.ciphertext, b.ciphertext);
        assert_eq!(b.nonce, vec![2; 24]);
        assert_eq!(b.ciphertext, vec![20; 6]);
    }

    #[tokio::test]
    async fn get_env_wrap_scoped_by_workspace() {
        let s = SqliteStore::open_in_memory().await.unwrap();
        let (user_id, _) = s
            .create_user(&CreateUserParams {
                email: "test@example.com".to_string(),
                principal: None,
                workspace_ids: vec![],
            })
            .await
            .unwrap();
        let ws1 = s
            .create_workspace(&workspace_params(user_id.clone()))
            .await
            .unwrap();
        let ws2 = s
            .create_workspace(&workspace_params(user_id))
            .await
            .unwrap();

        let p = ProjectName("app".into());
        let e = EnvName("prod".into());

        let project_id1 = s
            .create_project(&CreateProjectParams {
                workspace_id: ws1.clone(),
                name: p.0.clone(),
            })
            .await
            .unwrap();
        s.create_env(&CreateEnvParams {
            project_id: project_id1,
            name: e.0.clone(),
            dek_wrapped: b"wrap1".to_vec(),
            dek_nonce: vec![9; 24],
        })
        .await
        .unwrap();

        let project_id2 = s
            .create_project(&CreateProjectParams {
                workspace_id: ws2.clone(),
                name: p.0.clone(),
            })
            .await
            .unwrap();
        s.create_env(&CreateEnvParams {
            project_id: project_id2,
            name: e.0.clone(),
            dek_wrapped: b"wrap2".to_vec(),
            dek_nonce: vec![8; 24],
        })
        .await
        .unwrap();

        let (w1, n1) = s.get_env_wrap(&ws1, &p, &e).await.unwrap();
        let (w2, n2) = s.get_env_wrap(&ws2, &p, &e).await.unwrap();

        assert_eq!(w1, b"wrap1");
        assert_eq!(n1, vec![9; 24]);
        assert_eq!(w2, b"wrap2");
        assert_eq!(n2, vec![8; 24]);
    }

    #[tokio::test]
    async fn update_changes_updated_at_but_not_created_at() {
        let s = SqliteStore::open_in_memory().await.unwrap();
        let (user_id, _) = s
            .create_user(&CreateUserParams {
                email: "test@example.com".to_string(),
                principal: None,
                workspace_ids: vec![],
            })
            .await
            .unwrap();

        // Create a principal
        let principal_id = s
            .create_principal(&CreatePrincipalParams {
                user_id: Some(user_id.clone()),
                name: "old-name".to_string(),
                public_key: vec![1, 2, 3],
            })
            .await
            .unwrap();

        let initial = s.get_principal(&principal_id).await.unwrap();

        // Sleep to ensure time passes (SQLite timestamps have millisecond precision)
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;

        // Update the principal
        s.rename_principal(&principal_id, "new-name").await.unwrap();

        let after_update = s.get_principal(&principal_id).await.unwrap();

        // created_at should never change
        assert_eq!(initial.created_at, after_update.created_at);
        // updated_at should be newer after an update
        assert!(after_update.updated_at > initial.updated_at);
        // The actual update should have worked
        assert_eq!(after_update.name, "new-name");
    }

    #[tokio::test]
    async fn unicode_keys_and_names_roundtrip() {
        let s = SqliteStore::open_in_memory().await.unwrap();
        let (user_id, _) = s
            .create_user(&CreateUserParams {
                email: "test@example.com".to_string(),
                principal: None,
                workspace_ids: vec![],
            })
            .await
            .unwrap();
        let ws = s
            .create_workspace(&workspace_params(user_id))
            .await
            .unwrap();

        let p = ProjectName("🚀-プロジェクト".into());
        let e = EnvName("生产".into());
        let k = "🔑-секрет";

        let project_id = s
            .create_project(&CreateProjectParams {
                workspace_id: ws.clone(),
                name: p.0.clone(),
            })
            .await
            .unwrap();
        let env_id = s
            .create_env(&CreateEnvParams {
                project_id,
                name: e.0.clone(),
                dek_wrapped: vec![1, 2, 3],
                dek_nonce: vec![9; 24],
            })
            .await
            .unwrap();
        s.upsert_secret(&env_id, k, &[7; 24], &[1, 2, 3, 4])
            .await
            .unwrap();

        let row = s.get_secret(&env_id, k).await.unwrap();
        assert_eq!(row.ciphertext, vec![1, 2, 3, 4]);

        let keys = s.list_secret_keys(&env_id).await.unwrap();
        assert_eq!(keys, vec![k]);
    }
}
