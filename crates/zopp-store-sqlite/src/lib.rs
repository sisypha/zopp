use chrono::{DateTime, Utc};
use sqlx::{sqlite::SqlitePoolOptions, SqlitePool};
use std::str::FromStr;
use uuid::Uuid;
use zopp_audit::{
    AuditAction, AuditEvent, AuditLog, AuditLogError, AuditLogFilter, AuditLogId, AuditResult,
};
use zopp_storage::{
    AddWorkspacePrincipalParams, CreateEnvParams, CreateInviteParams, CreatePrincipalExportParams,
    CreatePrincipalParams, CreateProjectParams, CreateUserParams, CreateWorkspaceParams, EnvName,
    Environment, EnvironmentId, EnvironmentPermission, Invite, InviteId, Principal,
    PrincipalExport, PrincipalExportId, PrincipalId, ProjectName, ProjectPermission, Role,
    SecretRow, Store, StoreError, User, UserEnvironmentPermission, UserId, UserProjectPermission,
    UserWorkspacePermission, Workspace, WorkspaceId, WorkspacePermission, WorkspacePrincipal,
};

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

pub struct SqliteStore {
    pool: SqlitePool,
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
    // ───────────────────────────── Users ─────────────────────────────

    async fn create_user(
        &self,
        params: &CreateUserParams,
    ) -> Result<(UserId, Option<PrincipalId>), StoreError> {
        // Use transaction if we need to create principal or add to workspaces
        let needs_tx = params.principal.is_some() || !params.workspace_ids.is_empty();

        if needs_tx {
            let mut tx = self
                .pool
                .begin()
                .await
                .map_err(|e| StoreError::Backend(e.to_string()))?;

            // First try to get existing user
            let existing_user = sqlx::query!("SELECT id FROM users WHERE email = ?", params.email)
                .fetch_optional(&mut *tx)
                .await
                .map_err(|e| StoreError::Backend(e.to_string()))?;

            let actual_user_id_str = if let Some(existing) = existing_user {
                // User already exists, use their ID
                existing.id
            } else {
                // Create new user
                let user_id = Uuid::now_v7();
                let user_id_str = user_id.to_string();
                sqlx::query!(
                    "INSERT INTO users(id, email) VALUES(?, ?)",
                    user_id_str,
                    params.email
                )
                .execute(&mut *tx)
                .await
                .map_err(|e| StoreError::Backend(e.to_string()))?;
                user_id_str
            };

            // Create principal if provided
            let principal_id = if let Some(principal_data) = &params.principal {
                let principal_id = Uuid::now_v7();
                let principal_id_str = principal_id.to_string();

                // Service principals have NULL user_id
                let user_id_for_principal = if principal_data.is_service {
                    None
                } else {
                    Some(actual_user_id_str.clone())
                };

                sqlx::query!(
                    "INSERT INTO principals(id, user_id, name, public_key, x25519_public_key) VALUES(?, ?, ?, ?, ?)",
                    principal_id_str,
                    user_id_for_principal,
                    principal_data.name,
                    principal_data.public_key,
                    principal_data.x25519_public_key
                )
                .execute(&mut *tx)
                .await
                .map_err(|e| StoreError::Backend(e.to_string()))?;

                Some(PrincipalId(principal_id))
            } else {
                None
            };

            // Add user to workspaces (user-level membership)
            // Use INSERT OR IGNORE to handle the case where user is already a member
            for workspace_id in &params.workspace_ids {
                let ws_id = workspace_id.0.to_string();
                sqlx::query!(
                    "INSERT OR IGNORE INTO workspace_members(workspace_id, user_id) VALUES(?, ?)",
                    ws_id,
                    actual_user_id_str
                )
                .execute(&mut *tx)
                .await
                .map_err(|e| StoreError::Backend(e.to_string()))?;
            }

            tx.commit()
                .await
                .map_err(|e| StoreError::Backend(e.to_string()))?;

            // Parse the actual user_id
            let actual_user_id = Uuid::parse_str(&actual_user_id_str)
                .map_err(|e| StoreError::Backend(e.to_string()))?;

            Ok((UserId(actual_user_id), principal_id))
        } else {
            // Simple case: just create user
            let user_id = Uuid::now_v7();
            let user_id_str = user_id.to_string();

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
            "INSERT INTO principals(id, user_id, name, public_key, x25519_public_key) VALUES(?, ?, ?, ?, ?)",
            principal_id_str,
            user_id_str,
            params.name,
            params.public_key,
            params.x25519_public_key
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
            r#"SELECT id, user_id, name, public_key, x25519_public_key,
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
                    x25519_public_key: row.x25519_public_key,
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
            r#"SELECT id, user_id, name, public_key, x25519_public_key,
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
                x25519_public_key: row.x25519_public_key,
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

        let created_by_user_id_str = params
            .created_by_user_id
            .as_ref()
            .map(|id| id.0.to_string());

        sqlx::query!(
            "INSERT INTO invites(id, token, expires_at, created_by_user_id, kek_encrypted, kek_nonce) VALUES(?, ?, ?, ?, ?, ?)",
            invite_id_str,
            params.token,
            params.expires_at,
            created_by_user_id_str,
            params.kek_encrypted,
            params.kek_nonce
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
            token: params.token.clone(),
            workspace_ids: params.workspace_ids.clone(),
            kek_encrypted: params.kek_encrypted.clone(),
            kek_nonce: params.kek_nonce.clone(),
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
               created_by_user_id, revoked, kek_encrypted, kek_nonce
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
                    kek_encrypted: row.kek_encrypted,
                    kek_nonce: row.kek_nonce,
                    created_at: row.created_at,
                    updated_at: row.updated_at,
                    expires_at: row.expires_at,
                    created_by_user_id,
                })
            }
        }
    }

    async fn list_invites(&self, user_id: Option<UserId>) -> Result<Vec<Invite>, StoreError> {
        let user_id_str = user_id.map(|id| id.0.to_string());

        // Query for either user-created invites or server invites (where created_by_user_id IS NULL)
        let rows = sqlx::query!(
            r#"SELECT id, token,
               created_at as "created_at: DateTime<Utc>",
               updated_at as "updated_at: DateTime<Utc>",
               expires_at as "expires_at: DateTime<Utc>",
               created_by_user_id, revoked, kek_encrypted, kek_nonce
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
                kek_encrypted: row.kek_encrypted,
                kek_nonce: row.kek_nonce,
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

    // ───────────────────────────── Principal Exports ──────────────────────────

    async fn create_principal_export(
        &self,
        params: &CreatePrincipalExportParams,
    ) -> Result<PrincipalExport, StoreError> {
        let export_id = uuid::Uuid::now_v7();
        let export_id_str = export_id.to_string();
        let user_id_str = params.user_id.0.to_string();
        let principal_id_str = params.principal_id.0.to_string();

        let row = sqlx::query!(
            r#"INSERT INTO principal_exports(id, export_code, token_hash, user_id, principal_id, encrypted_data, salt, nonce, expires_at)
               VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)
               RETURNING created_at as "created_at: DateTime<Utc>""#,
            export_id_str,
            params.export_code,
            params.token_hash,
            user_id_str,
            principal_id_str,
            params.encrypted_data,
            params.salt,
            params.nonce,
            params.expires_at
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;

        Ok(PrincipalExport {
            id: PrincipalExportId(export_id),
            export_code: params.export_code.clone(),
            token_hash: params.token_hash.clone(),
            user_id: params.user_id.clone(),
            principal_id: params.principal_id.clone(),
            encrypted_data: params.encrypted_data.clone(),
            salt: params.salt.clone(),
            nonce: params.nonce.clone(),
            expires_at: params.expires_at,
            created_at: row.created_at,
            consumed: false,
            failed_attempts: 0,
        })
    }

    async fn get_principal_export_by_code(
        &self,
        export_code: &str,
    ) -> Result<PrincipalExport, StoreError> {
        let row = sqlx::query!(
            r#"SELECT id as "id!", export_code as "export_code!", token_hash as "token_hash!",
               user_id as "user_id!", principal_id as "principal_id!",
               encrypted_data as "encrypted_data!", salt as "salt!", nonce as "nonce!",
               expires_at as "expires_at!: DateTime<Utc>",
               created_at as "created_at!: DateTime<Utc>",
               consumed as "consumed!", failed_attempts as "failed_attempts!"
               FROM principal_exports
               WHERE export_code = ? AND consumed = 0 AND expires_at > CURRENT_TIMESTAMP"#,
            export_code
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;

        match row {
            None => Err(StoreError::NotFound),
            Some(row) => {
                let id =
                    Uuid::try_parse(&row.id).map_err(|e| StoreError::Backend(e.to_string()))?;
                let user_id = Uuid::try_parse(&row.user_id)
                    .map_err(|e| StoreError::Backend(e.to_string()))?;
                let principal_id = Uuid::try_parse(&row.principal_id)
                    .map_err(|e| StoreError::Backend(e.to_string()))?;

                Ok(PrincipalExport {
                    id: PrincipalExportId(id),
                    export_code: row.export_code,
                    token_hash: row.token_hash,
                    user_id: UserId(user_id),
                    principal_id: PrincipalId(principal_id),
                    encrypted_data: row.encrypted_data,
                    salt: row.salt,
                    nonce: row.nonce,
                    expires_at: row.expires_at,
                    created_at: row.created_at,
                    consumed: row.consumed,
                    failed_attempts: row.failed_attempts as i32,
                })
            }
        }
    }

    async fn consume_principal_export(
        &self,
        export_id: &PrincipalExportId,
    ) -> Result<(), StoreError> {
        let export_id_str = export_id.0.to_string();
        let result = sqlx::query!(
            "UPDATE principal_exports SET consumed = 1 WHERE id = ? AND consumed = 0",
            export_id_str
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

    async fn increment_export_failed_attempts(
        &self,
        export_id: &PrincipalExportId,
    ) -> Result<i32, StoreError> {
        let export_id_str = export_id.0.to_string();
        let row = sqlx::query!(
            r#"UPDATE principal_exports SET failed_attempts = failed_attempts + 1
               WHERE id = ?
               RETURNING failed_attempts as "failed_attempts!""#,
            export_id_str
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;

        match row {
            None => Err(StoreError::NotFound),
            Some(row) => Ok(row.failed_attempts as i32),
        }
    }

    async fn delete_principal_export(
        &self,
        export_id: &PrincipalExportId,
    ) -> Result<(), StoreError> {
        let export_id_str = export_id.0.to_string();
        let result = sqlx::query!("DELETE FROM principal_exports WHERE id = ?", export_id_str)
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
        let ws_id_str = params.id.0.to_string();
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
        Ok(params.id.clone())
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

    async fn get_workspace_by_name(
        &self,
        user_id: &UserId,
        name: &str,
    ) -> Result<Workspace, StoreError> {
        let user_id_str = user_id.0.to_string();
        let row = sqlx::query!(
            r#"SELECT w.id, w.name, w.owner_user_id, w.kdf_salt, w.kdf_m_cost_kib, w.kdf_t_cost, w.kdf_p_cost,
               w.created_at as "created_at: DateTime<Utc>",
               w.updated_at as "updated_at: DateTime<Utc>"
               FROM workspaces w
               LEFT JOIN workspace_members wm ON w.id = wm.workspace_id
               WHERE w.name = ? AND (w.owner_user_id = ? OR wm.user_id = ?)
               LIMIT 1"#,
            name,
            user_id_str,
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

    async fn get_workspace_by_name_for_principal(
        &self,
        principal_id: &PrincipalId,
        name: &str,
    ) -> Result<Workspace, StoreError> {
        let principal_id_str = principal_id.0.to_string();
        let row = sqlx::query!(
            r#"SELECT w.id, w.name, w.owner_user_id, w.kdf_salt, w.kdf_m_cost_kib, w.kdf_t_cost, w.kdf_p_cost,
               w.created_at as "created_at: DateTime<Utc>",
               w.updated_at as "updated_at: DateTime<Utc>"
               FROM workspaces w
               INNER JOIN workspace_principals wp ON w.id = wp.workspace_id
               WHERE w.name = ? AND wp.principal_id = ?
               LIMIT 1"#,
            name,
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

    async fn add_workspace_principal(
        &self,
        params: &AddWorkspacePrincipalParams,
    ) -> Result<(), StoreError> {
        let ws_id = params.workspace_id.0.to_string();
        let p_id = params.principal_id.0.to_string();

        sqlx::query!(
            "INSERT INTO workspace_principals(workspace_id, principal_id, ephemeral_pub, kek_wrapped, kek_nonce) VALUES(?, ?, ?, ?, ?)",
            ws_id,
            p_id,
            params.ephemeral_pub,
            params.kek_wrapped,
            params.kek_nonce
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

    async fn get_workspace_principal(
        &self,
        workspace_id: &WorkspaceId,
        principal_id: &PrincipalId,
    ) -> Result<WorkspacePrincipal, StoreError> {
        let ws_id = workspace_id.0.to_string();
        let p_id = principal_id.0.to_string();

        let row = sqlx::query!(
            r#"SELECT workspace_id, principal_id, ephemeral_pub, kek_wrapped, kek_nonce,
               created_at as "created_at: DateTime<Utc>"
               FROM workspace_principals WHERE workspace_id = ? AND principal_id = ?"#,
            ws_id,
            p_id
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;

        match row {
            None => Err(StoreError::NotFound),
            Some(row) => {
                let workspace_id = Uuid::try_parse(&row.workspace_id)
                    .map_err(|e| StoreError::Backend(e.to_string()))?;
                let principal_id = Uuid::try_parse(&row.principal_id)
                    .map_err(|e| StoreError::Backend(e.to_string()))?;
                Ok(WorkspacePrincipal {
                    workspace_id: WorkspaceId(workspace_id),
                    principal_id: PrincipalId(principal_id),
                    ephemeral_pub: row.ephemeral_pub,
                    kek_wrapped: row.kek_wrapped,
                    kek_nonce: row.kek_nonce,
                    created_at: row.created_at,
                })
            }
        }
    }

    async fn list_workspace_principals(
        &self,
        workspace_id: &WorkspaceId,
    ) -> Result<Vec<WorkspacePrincipal>, StoreError> {
        let ws_id = workspace_id.0.to_string();

        let rows = sqlx::query!(
            r#"SELECT workspace_id, principal_id, ephemeral_pub, kek_wrapped, kek_nonce,
               created_at as "created_at: DateTime<Utc>"
               FROM workspace_principals WHERE workspace_id = ?"#,
            ws_id
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;

        let mut principals = Vec::with_capacity(rows.len());
        for row in rows {
            let workspace_id = Uuid::try_parse(&row.workspace_id)
                .map_err(|e| StoreError::Backend(e.to_string()))?;
            let principal_id = Uuid::try_parse(&row.principal_id)
                .map_err(|e| StoreError::Backend(e.to_string()))?;
            principals.push(WorkspacePrincipal {
                workspace_id: WorkspaceId(workspace_id),
                principal_id: PrincipalId(principal_id),
                ephemeral_pub: row.ephemeral_pub,
                kek_wrapped: row.kek_wrapped,
                kek_nonce: row.kek_nonce,
                created_at: row.created_at,
            });
        }
        Ok(principals)
    }

    async fn remove_workspace_principal(
        &self,
        workspace_id: &WorkspaceId,
        principal_id: &PrincipalId,
    ) -> Result<(), StoreError> {
        let ws_id = workspace_id.0.to_string();
        let p_id = principal_id.0.to_string();

        sqlx::query!(
            "DELETE FROM workspace_principals WHERE workspace_id = ? AND principal_id = ?",
            ws_id,
            p_id
        )
        .execute(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;

        Ok(())
    }

    async fn remove_all_project_permissions_for_principal(
        &self,
        workspace_id: &WorkspaceId,
        principal_id: &PrincipalId,
    ) -> Result<u32, StoreError> {
        let ws_id = workspace_id.0.to_string();
        let p_id = principal_id.0.to_string();

        // Delete all project permissions for this principal in projects belonging to this workspace
        let result = sqlx::query!(
            r#"DELETE FROM project_permissions
               WHERE principal_id = ?
               AND project_id IN (SELECT id FROM projects WHERE workspace_id = ?)"#,
            p_id,
            ws_id
        )
        .execute(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;

        Ok(result.rows_affected() as u32)
    }

    async fn remove_all_environment_permissions_for_principal(
        &self,
        workspace_id: &WorkspaceId,
        principal_id: &PrincipalId,
    ) -> Result<u32, StoreError> {
        let ws_id = workspace_id.0.to_string();
        let p_id = principal_id.0.to_string();

        // Delete all environment permissions for this principal in environments belonging to projects in this workspace
        let result = sqlx::query!(
            r#"DELETE FROM environment_permissions
               WHERE principal_id = ?
               AND environment_id IN (
                   SELECT e.id FROM environments e
                   JOIN projects p ON e.project_id = p.id
                   WHERE p.workspace_id = ?
               )"#,
            p_id,
            ws_id
        )
        .execute(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;

        Ok(result.rows_affected() as u32)
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

    async fn get_project_by_name(
        &self,
        workspace_id: &WorkspaceId,
        name: &str,
    ) -> Result<zopp_storage::Project, StoreError> {
        let ws_id_str = workspace_id.0.to_string();

        let row = sqlx::query!(
            r#"SELECT id, workspace_id, name,
               created_at as "created_at: DateTime<Utc>",
               updated_at as "updated_at: DateTime<Utc>"
               FROM projects WHERE workspace_id = ? AND name = ?"#,
            ws_id_str,
            name
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
            r#"SELECT id, project_id, name, dek_wrapped, dek_nonce, version,
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
                    version: row.version,
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
            r#"SELECT id, project_id, name, dek_wrapped, dek_nonce, version,
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
            version: row.version,
            created_at: row.created_at,
            updated_at: row.updated_at,
        })
    }

    async fn get_environment_by_name(
        &self,
        project_id: &zopp_storage::ProjectId,
        name: &str,
    ) -> Result<Environment, StoreError> {
        let proj_id_str = project_id.0.to_string();

        let row = sqlx::query!(
            r#"SELECT id, project_id, name, dek_wrapped, dek_nonce, version,
               created_at as "created_at: DateTime<Utc>",
               updated_at as "updated_at: DateTime<Utc>"
               FROM environments WHERE project_id = ? AND name = ?"#,
            proj_id_str,
            name
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
            version: row.version,
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
    ) -> Result<i64, StoreError> {
        let env_id_str = env_id.0.to_string();

        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))?;

        // Get environment to determine workspace_id
        let env_row = sqlx::query!(
            "SELECT workspace_id FROM environments WHERE id = ?",
            env_id_str
        )
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?
        .ok_or(StoreError::NotFound)?;

        let ws_id = env_row.workspace_id;
        let secret_id = Uuid::now_v7().to_string();

        // Insert/update the secret
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
        .execute(&mut *tx)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;

        // Increment environment version
        let result = sqlx::query!(
            "UPDATE environments SET version = version + 1 WHERE id = ? RETURNING version",
            env_id_str
        )
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;

        tx.commit()
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))?;

        Ok(result.version)
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

    async fn delete_secret(&self, env_id: &EnvironmentId, key: &str) -> Result<i64, StoreError> {
        let env_id_str = env_id.0.to_string();

        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))?;

        let result = sqlx::query!(
            "DELETE FROM secrets WHERE env_id = ? AND key_name = ?",
            env_id_str,
            key
        )
        .execute(&mut *tx)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(StoreError::NotFound);
        }

        // Increment environment version
        let version_result = sqlx::query!(
            "UPDATE environments SET version = version + 1 WHERE id = ? RETURNING version",
            env_id_str
        )
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;

        tx.commit()
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))?;

        Ok(version_result.version)
    }

    // ────────────────────────────── RBAC Permissions ───────────────────────────────

    async fn set_workspace_permission(
        &self,
        workspace_id: &WorkspaceId,
        principal_id: &PrincipalId,
        role: Role,
    ) -> Result<(), StoreError> {
        let ws_id = workspace_id.0.to_string();
        let p_id = principal_id.0.to_string();
        let role_str = role.as_str();

        sqlx::query!(
            "INSERT INTO workspace_permissions(workspace_id, principal_id, role) VALUES(?, ?, ?)
             ON CONFLICT(workspace_id, principal_id) DO UPDATE SET role = excluded.role",
            ws_id,
            p_id,
            role_str
        )
        .execute(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;

        Ok(())
    }

    async fn get_workspace_permission(
        &self,
        workspace_id: &WorkspaceId,
        principal_id: &PrincipalId,
    ) -> Result<Role, StoreError> {
        let ws_id = workspace_id.0.to_string();
        let p_id = principal_id.0.to_string();

        let row = sqlx::query!(
            "SELECT role FROM workspace_permissions WHERE workspace_id = ? AND principal_id = ?",
            ws_id,
            p_id
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?
        .ok_or(StoreError::NotFound)?;

        Role::from_str(&row.role).map_err(|e| StoreError::Backend(format!("invalid role: {}", e)))
    }

    async fn list_workspace_permissions_for_principal(
        &self,
        principal_id: &PrincipalId,
    ) -> Result<Vec<WorkspacePermission>, StoreError> {
        let p_id = principal_id.0.to_string();

        let rows = sqlx::query!(
            r#"SELECT workspace_id, principal_id, role,
               created_at as "created_at: DateTime<Utc>"
               FROM workspace_permissions WHERE principal_id = ?"#,
            p_id
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;

        let mut perms = Vec::with_capacity(rows.len());
        for row in rows {
            let workspace_id = Uuid::try_parse(&row.workspace_id)
                .map_err(|e| StoreError::Backend(e.to_string()))?;
            let principal_id = Uuid::try_parse(&row.principal_id)
                .map_err(|e| StoreError::Backend(e.to_string()))?;
            let role = Role::from_str(&row.role)
                .map_err(|e| StoreError::Backend(format!("invalid role in database: {}", e)))?;

            perms.push(WorkspacePermission {
                workspace_id: WorkspaceId(workspace_id),
                principal_id: PrincipalId(principal_id),
                role,
                created_at: row.created_at,
            });
        }
        Ok(perms)
    }

    async fn list_workspace_permissions(
        &self,
        workspace_id: &WorkspaceId,
    ) -> Result<Vec<WorkspacePermission>, StoreError> {
        let ws_id = workspace_id.0.to_string();

        let rows = sqlx::query!(
            r#"SELECT workspace_id, principal_id, role,
               created_at as "created_at: DateTime<Utc>"
               FROM workspace_permissions WHERE workspace_id = ?"#,
            ws_id
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;

        let mut perms = Vec::with_capacity(rows.len());
        for row in rows {
            let workspace_id = Uuid::try_parse(&row.workspace_id)
                .map_err(|e| StoreError::Backend(e.to_string()))?;
            let principal_id = Uuid::try_parse(&row.principal_id)
                .map_err(|e| StoreError::Backend(e.to_string()))?;
            let role = Role::from_str(&row.role)
                .map_err(|e| StoreError::Backend(format!("invalid role in database: {}", e)))?;

            perms.push(WorkspacePermission {
                workspace_id: WorkspaceId(workspace_id),
                principal_id: PrincipalId(principal_id),
                role,
                created_at: row.created_at,
            });
        }
        Ok(perms)
    }

    async fn remove_workspace_permission(
        &self,
        workspace_id: &WorkspaceId,
        principal_id: &PrincipalId,
    ) -> Result<(), StoreError> {
        let ws_id = workspace_id.0.to_string();
        let p_id = principal_id.0.to_string();

        let result = sqlx::query!(
            "DELETE FROM workspace_permissions WHERE workspace_id = ? AND principal_id = ?",
            ws_id,
            p_id
        )
        .execute(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(StoreError::NotFound);
        }

        Ok(())
    }

    async fn set_project_permission(
        &self,
        project_id: &zopp_storage::ProjectId,
        principal_id: &PrincipalId,
        role: Role,
    ) -> Result<(), StoreError> {
        let proj_id = project_id.0.to_string();
        let p_id = principal_id.0.to_string();
        let role_str = role.as_str();

        sqlx::query!(
            "INSERT INTO project_permissions(project_id, principal_id, role) VALUES(?, ?, ?)
             ON CONFLICT(project_id, principal_id) DO UPDATE SET role = excluded.role",
            proj_id,
            p_id,
            role_str
        )
        .execute(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;

        Ok(())
    }

    async fn get_project_permission(
        &self,
        project_id: &zopp_storage::ProjectId,
        principal_id: &PrincipalId,
    ) -> Result<Role, StoreError> {
        let proj_id = project_id.0.to_string();
        let p_id = principal_id.0.to_string();

        let row = sqlx::query!(
            "SELECT role FROM project_permissions WHERE project_id = ? AND principal_id = ?",
            proj_id,
            p_id
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?
        .ok_or(StoreError::NotFound)?;

        Role::from_str(&row.role).map_err(|e| StoreError::Backend(format!("invalid role: {}", e)))
    }

    async fn list_project_permissions_for_principal(
        &self,
        principal_id: &PrincipalId,
    ) -> Result<Vec<ProjectPermission>, StoreError> {
        let p_id = principal_id.0.to_string();

        let rows = sqlx::query!(
            r#"SELECT project_id, principal_id, role,
               created_at as "created_at: DateTime<Utc>"
               FROM project_permissions WHERE principal_id = ?"#,
            p_id
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;

        let mut perms = Vec::with_capacity(rows.len());
        for row in rows {
            let project_id =
                Uuid::try_parse(&row.project_id).map_err(|e| StoreError::Backend(e.to_string()))?;
            let principal_id = Uuid::try_parse(&row.principal_id)
                .map_err(|e| StoreError::Backend(e.to_string()))?;
            let role = Role::from_str(&row.role)
                .map_err(|e| StoreError::Backend(format!("invalid role in database: {}", e)))?;

            perms.push(ProjectPermission {
                project_id: zopp_storage::ProjectId(project_id),
                principal_id: PrincipalId(principal_id),
                role,
                created_at: row.created_at,
            });
        }
        Ok(perms)
    }

    async fn list_project_permissions(
        &self,
        project_id: &zopp_storage::ProjectId,
    ) -> Result<Vec<ProjectPermission>, StoreError> {
        let proj_id = project_id.0.to_string();

        let rows = sqlx::query!(
            r#"SELECT project_id, principal_id, role,
               created_at as "created_at: DateTime<Utc>"
               FROM project_permissions WHERE project_id = ?"#,
            proj_id
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;

        let mut perms = Vec::with_capacity(rows.len());
        for row in rows {
            let project_id =
                Uuid::try_parse(&row.project_id).map_err(|e| StoreError::Backend(e.to_string()))?;
            let principal_id = Uuid::try_parse(&row.principal_id)
                .map_err(|e| StoreError::Backend(e.to_string()))?;
            let role = Role::from_str(&row.role)
                .map_err(|e| StoreError::Backend(format!("invalid role in database: {}", e)))?;

            perms.push(ProjectPermission {
                project_id: zopp_storage::ProjectId(project_id),
                principal_id: PrincipalId(principal_id),
                role,
                created_at: row.created_at,
            });
        }
        Ok(perms)
    }

    async fn remove_project_permission(
        &self,
        project_id: &zopp_storage::ProjectId,
        principal_id: &PrincipalId,
    ) -> Result<(), StoreError> {
        let proj_id = project_id.0.to_string();
        let p_id = principal_id.0.to_string();

        let result = sqlx::query!(
            "DELETE FROM project_permissions WHERE project_id = ? AND principal_id = ?",
            proj_id,
            p_id
        )
        .execute(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(StoreError::NotFound);
        }

        Ok(())
    }

    async fn set_environment_permission(
        &self,
        environment_id: &EnvironmentId,
        principal_id: &PrincipalId,
        role: Role,
    ) -> Result<(), StoreError> {
        let env_id = environment_id.0.to_string();
        let p_id = principal_id.0.to_string();
        let role_str = role.as_str();

        sqlx::query!(
            "INSERT INTO environment_permissions(environment_id, principal_id, role) VALUES(?, ?, ?)
             ON CONFLICT(environment_id, principal_id) DO UPDATE SET role = excluded.role",
            env_id,
            p_id,
            role_str
        )
        .execute(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;

        Ok(())
    }

    async fn get_environment_permission(
        &self,
        environment_id: &EnvironmentId,
        principal_id: &PrincipalId,
    ) -> Result<Role, StoreError> {
        let env_id = environment_id.0.to_string();
        let p_id = principal_id.0.to_string();

        let row = sqlx::query!(
            "SELECT role FROM environment_permissions WHERE environment_id = ? AND principal_id = ?",
            env_id,
            p_id
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?
        .ok_or(StoreError::NotFound)?;

        Role::from_str(&row.role).map_err(|e| StoreError::Backend(format!("invalid role: {}", e)))
    }

    async fn list_environment_permissions_for_principal(
        &self,
        principal_id: &PrincipalId,
    ) -> Result<Vec<EnvironmentPermission>, StoreError> {
        let p_id = principal_id.0.to_string();

        let rows = sqlx::query!(
            r#"SELECT environment_id, principal_id, role,
               created_at as "created_at: DateTime<Utc>"
               FROM environment_permissions WHERE principal_id = ?"#,
            p_id
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;

        let mut perms = Vec::with_capacity(rows.len());
        for row in rows {
            let environment_id = Uuid::try_parse(&row.environment_id)
                .map_err(|e| StoreError::Backend(e.to_string()))?;
            let principal_id = Uuid::try_parse(&row.principal_id)
                .map_err(|e| StoreError::Backend(e.to_string()))?;
            let role = Role::from_str(&row.role)
                .map_err(|e| StoreError::Backend(format!("invalid role in database: {}", e)))?;

            perms.push(EnvironmentPermission {
                environment_id: EnvironmentId(environment_id),
                principal_id: PrincipalId(principal_id),
                role,
                created_at: row.created_at,
            });
        }
        Ok(perms)
    }

    async fn list_environment_permissions(
        &self,
        environment_id: &EnvironmentId,
    ) -> Result<Vec<EnvironmentPermission>, StoreError> {
        let env_id = environment_id.0.to_string();

        let rows = sqlx::query!(
            r#"SELECT environment_id, principal_id, role,
               created_at as "created_at: DateTime<Utc>"
               FROM environment_permissions WHERE environment_id = ?"#,
            env_id
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;

        let mut perms = Vec::with_capacity(rows.len());
        for row in rows {
            let environment_id = Uuid::try_parse(&row.environment_id)
                .map_err(|e| StoreError::Backend(e.to_string()))?;
            let principal_id = Uuid::try_parse(&row.principal_id)
                .map_err(|e| StoreError::Backend(e.to_string()))?;
            let role = Role::from_str(&row.role)
                .map_err(|e| StoreError::Backend(format!("invalid role in database: {}", e)))?;

            perms.push(EnvironmentPermission {
                environment_id: EnvironmentId(environment_id),
                principal_id: PrincipalId(principal_id),
                role,
                created_at: row.created_at,
            });
        }
        Ok(perms)
    }

    async fn remove_environment_permission(
        &self,
        environment_id: &EnvironmentId,
        principal_id: &PrincipalId,
    ) -> Result<(), StoreError> {
        let env_id = environment_id.0.to_string();
        let p_id = principal_id.0.to_string();

        let result = sqlx::query!(
            "DELETE FROM environment_permissions WHERE environment_id = ? AND principal_id = ?",
            env_id,
            p_id
        )
        .execute(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(StoreError::NotFound);
        }

        Ok(())
    }

    // ────────────────────────────────────── Groups ────────────────────────────────────────

    async fn create_group(
        &self,
        params: &zopp_storage::CreateGroupParams,
    ) -> Result<zopp_storage::GroupId, StoreError> {
        let group_id = Uuid::now_v7();
        let group_id_str = group_id.to_string();
        let ws_id = params.workspace_id.0.to_string();

        sqlx::query!(
            "INSERT INTO groups(id, workspace_id, name, description) VALUES(?, ?, ?, ?)",
            group_id_str,
            ws_id,
            params.name,
            params.description
        )
        .execute(&self.pool)
        .await
        .map_err(|e| {
            if e.to_string().contains("UNIQUE") {
                StoreError::AlreadyExists
            } else {
                StoreError::Backend(e.to_string())
            }
        })?;

        Ok(zopp_storage::GroupId(group_id))
    }

    async fn get_group(
        &self,
        group_id: &zopp_storage::GroupId,
    ) -> Result<zopp_storage::Group, StoreError> {
        let g_id = group_id.0.to_string();

        let row = sqlx::query!(
            "SELECT id as \"id!\", workspace_id as \"workspace_id!\", name as \"name!\", description, created_at as \"created_at!\", updated_at as \"updated_at!\" FROM groups WHERE id = ?",
            g_id
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?
        .ok_or(StoreError::NotFound)?;

        Ok(zopp_storage::Group {
            id: zopp_storage::GroupId(Uuid::parse_str(&row.id).unwrap()),
            workspace_id: WorkspaceId(Uuid::parse_str(&row.workspace_id).unwrap()),
            name: row.name,
            description: row.description,
            created_at: DateTime::parse_from_rfc3339(&row.created_at)
                .unwrap()
                .with_timezone(&Utc),
            updated_at: DateTime::parse_from_rfc3339(&row.updated_at)
                .unwrap()
                .with_timezone(&Utc),
        })
    }

    async fn get_group_by_name(
        &self,
        workspace_id: &WorkspaceId,
        name: &str,
    ) -> Result<zopp_storage::Group, StoreError> {
        let ws_id = workspace_id.0.to_string();

        let row = sqlx::query!(
            "SELECT id as \"id!\", workspace_id as \"workspace_id!\", name as \"name!\", description, created_at as \"created_at!\", updated_at as \"updated_at!\" FROM groups WHERE workspace_id = ? AND name = ?",
            ws_id,
            name
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?
        .ok_or(StoreError::NotFound)?;

        Ok(zopp_storage::Group {
            id: zopp_storage::GroupId(Uuid::parse_str(&row.id).unwrap()),
            workspace_id: WorkspaceId(Uuid::parse_str(&row.workspace_id).unwrap()),
            name: row.name,
            description: row.description,
            created_at: DateTime::parse_from_rfc3339(&row.created_at)
                .unwrap()
                .with_timezone(&Utc),
            updated_at: DateTime::parse_from_rfc3339(&row.updated_at)
                .unwrap()
                .with_timezone(&Utc),
        })
    }

    async fn list_groups(
        &self,
        workspace_id: &WorkspaceId,
    ) -> Result<Vec<zopp_storage::Group>, StoreError> {
        let ws_id = workspace_id.0.to_string();

        let rows = sqlx::query!(
            "SELECT id as \"id!\", workspace_id as \"workspace_id!\", name as \"name!\", description, created_at as \"created_at!\", updated_at as \"updated_at!\" FROM groups WHERE workspace_id = ? ORDER BY name",
            ws_id
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;

        Ok(rows
            .into_iter()
            .map(|row| zopp_storage::Group {
                id: zopp_storage::GroupId(Uuid::parse_str(&row.id).unwrap()),
                workspace_id: WorkspaceId(Uuid::parse_str(&row.workspace_id).unwrap()),
                name: row.name,
                description: row.description,
                created_at: DateTime::parse_from_rfc3339(&row.created_at)
                    .unwrap()
                    .with_timezone(&Utc),
                updated_at: DateTime::parse_from_rfc3339(&row.updated_at)
                    .unwrap()
                    .with_timezone(&Utc),
            })
            .collect())
    }

    async fn update_group(
        &self,
        group_id: &zopp_storage::GroupId,
        name: &str,
        description: Option<String>,
    ) -> Result<(), StoreError> {
        let g_id = group_id.0.to_string();

        let result = sqlx::query!(
            "UPDATE groups SET name = ?, description = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now') WHERE id = ?",
            name,
            description,
            g_id
        )
        .execute(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(StoreError::NotFound);
        }

        Ok(())
    }

    async fn delete_group(&self, group_id: &zopp_storage::GroupId) -> Result<(), StoreError> {
        let g_id = group_id.0.to_string();

        let result = sqlx::query!("DELETE FROM groups WHERE id = ?", g_id)
            .execute(&self.pool)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(StoreError::NotFound);
        }

        Ok(())
    }

    async fn add_group_member(
        &self,
        group_id: &zopp_storage::GroupId,
        user_id: &UserId,
    ) -> Result<(), StoreError> {
        let g_id = group_id.0.to_string();
        let u_id = user_id.0.to_string();

        sqlx::query!(
            "INSERT INTO group_members(group_id, user_id) VALUES(?, ?)",
            g_id,
            u_id
        )
        .execute(&self.pool)
        .await
        .map_err(|e| {
            if e.to_string().contains("UNIQUE") {
                StoreError::AlreadyExists
            } else {
                StoreError::Backend(e.to_string())
            }
        })?;

        Ok(())
    }

    async fn remove_group_member(
        &self,
        group_id: &zopp_storage::GroupId,
        user_id: &UserId,
    ) -> Result<(), StoreError> {
        let g_id = group_id.0.to_string();
        let u_id = user_id.0.to_string();

        let result = sqlx::query!(
            "DELETE FROM group_members WHERE group_id = ? AND user_id = ?",
            g_id,
            u_id
        )
        .execute(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(StoreError::NotFound);
        }

        Ok(())
    }

    async fn list_group_members(
        &self,
        group_id: &zopp_storage::GroupId,
    ) -> Result<Vec<zopp_storage::GroupMember>, StoreError> {
        let g_id = group_id.0.to_string();

        let rows = sqlx::query!(
            "SELECT group_id, user_id, created_at FROM group_members WHERE group_id = ?",
            g_id
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;

        Ok(rows
            .into_iter()
            .map(|row| zopp_storage::GroupMember {
                group_id: zopp_storage::GroupId(Uuid::parse_str(&row.group_id).unwrap()),
                user_id: UserId(Uuid::parse_str(&row.user_id).unwrap()),
                created_at: DateTime::parse_from_rfc3339(&row.created_at)
                    .unwrap()
                    .with_timezone(&Utc),
            })
            .collect())
    }

    async fn list_user_groups(
        &self,
        user_id: &UserId,
    ) -> Result<Vec<zopp_storage::Group>, StoreError> {
        let u_id = user_id.0.to_string();

        let rows = sqlx::query!(
            "SELECT g.id as \"id!\", g.workspace_id as \"workspace_id!\", g.name as \"name!\", g.description, g.created_at as \"created_at!\", g.updated_at as \"updated_at!\"
             FROM groups g
             INNER JOIN group_members gm ON g.id = gm.group_id
             WHERE gm.user_id = ?
             ORDER BY g.name",
            u_id
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;

        Ok(rows
            .into_iter()
            .map(|row| zopp_storage::Group {
                id: zopp_storage::GroupId(Uuid::parse_str(&row.id).unwrap()),
                workspace_id: WorkspaceId(Uuid::parse_str(&row.workspace_id).unwrap()),
                name: row.name,
                description: row.description,
                created_at: DateTime::parse_from_rfc3339(&row.created_at)
                    .unwrap()
                    .with_timezone(&Utc),
                updated_at: DateTime::parse_from_rfc3339(&row.updated_at)
                    .unwrap()
                    .with_timezone(&Utc),
            })
            .collect())
    }

    async fn set_group_workspace_permission(
        &self,
        workspace_id: &WorkspaceId,
        group_id: &zopp_storage::GroupId,
        role: Role,
    ) -> Result<(), StoreError> {
        let ws_id = workspace_id.0.to_string();
        let g_id = group_id.0.to_string();
        let role_str = role.as_str();

        sqlx::query!(
            "INSERT INTO group_workspace_permissions(workspace_id, group_id, role) VALUES(?, ?, ?)
             ON CONFLICT(workspace_id, group_id) DO UPDATE SET role = excluded.role",
            ws_id,
            g_id,
            role_str
        )
        .execute(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;

        Ok(())
    }

    async fn get_group_workspace_permission(
        &self,
        workspace_id: &WorkspaceId,
        group_id: &zopp_storage::GroupId,
    ) -> Result<Role, StoreError> {
        let ws_id = workspace_id.0.to_string();
        let g_id = group_id.0.to_string();

        let row = sqlx::query!(
            "SELECT role FROM group_workspace_permissions WHERE workspace_id = ? AND group_id = ?",
            ws_id,
            g_id
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?
        .ok_or(StoreError::NotFound)?;

        Role::from_str(&row.role).map_err(|_| StoreError::Backend("Invalid role".to_string()))
    }

    async fn list_group_workspace_permissions(
        &self,
        workspace_id: &WorkspaceId,
    ) -> Result<Vec<zopp_storage::GroupWorkspacePermission>, StoreError> {
        let ws_id = workspace_id.0.to_string();

        let rows = sqlx::query!(
            "SELECT workspace_id, group_id, role, created_at FROM group_workspace_permissions WHERE workspace_id = ?",
            ws_id
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;

        let mut perms = Vec::with_capacity(rows.len());
        for row in rows {
            let role = Role::from_str(&row.role)
                .map_err(|e| StoreError::Backend(format!("invalid role in database: {}", e)))?;
            perms.push(zopp_storage::GroupWorkspacePermission {
                workspace_id: WorkspaceId(
                    Uuid::parse_str(&row.workspace_id)
                        .map_err(|e| StoreError::Backend(format!("invalid workspace_id: {}", e)))?,
                ),
                group_id: zopp_storage::GroupId(
                    Uuid::parse_str(&row.group_id)
                        .map_err(|e| StoreError::Backend(format!("invalid group_id: {}", e)))?,
                ),
                role,
                created_at: DateTime::parse_from_rfc3339(&row.created_at)
                    .map_err(|e| StoreError::Backend(format!("invalid created_at: {}", e)))?
                    .with_timezone(&Utc),
            });
        }
        Ok(perms)
    }

    async fn remove_group_workspace_permission(
        &self,
        workspace_id: &WorkspaceId,
        group_id: &zopp_storage::GroupId,
    ) -> Result<(), StoreError> {
        let ws_id = workspace_id.0.to_string();
        let g_id = group_id.0.to_string();

        let result = sqlx::query!(
            "DELETE FROM group_workspace_permissions WHERE workspace_id = ? AND group_id = ?",
            ws_id,
            g_id
        )
        .execute(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(StoreError::NotFound);
        }

        Ok(())
    }

    async fn set_group_project_permission(
        &self,
        project_id: &zopp_storage::ProjectId,
        group_id: &zopp_storage::GroupId,
        role: Role,
    ) -> Result<(), StoreError> {
        let proj_id = project_id.0.to_string();
        let g_id = group_id.0.to_string();
        let role_str = role.as_str();

        sqlx::query!(
            "INSERT INTO group_project_permissions(project_id, group_id, role) VALUES(?, ?, ?)
             ON CONFLICT(project_id, group_id) DO UPDATE SET role = excluded.role",
            proj_id,
            g_id,
            role_str
        )
        .execute(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;

        Ok(())
    }

    async fn get_group_project_permission(
        &self,
        project_id: &zopp_storage::ProjectId,
        group_id: &zopp_storage::GroupId,
    ) -> Result<Role, StoreError> {
        let proj_id = project_id.0.to_string();
        let g_id = group_id.0.to_string();

        let row = sqlx::query!(
            "SELECT role FROM group_project_permissions WHERE project_id = ? AND group_id = ?",
            proj_id,
            g_id
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?
        .ok_or(StoreError::NotFound)?;

        Role::from_str(&row.role).map_err(|_| StoreError::Backend("Invalid role".to_string()))
    }

    async fn list_group_project_permissions(
        &self,
        project_id: &zopp_storage::ProjectId,
    ) -> Result<Vec<zopp_storage::GroupProjectPermission>, StoreError> {
        let proj_id = project_id.0.to_string();

        let rows = sqlx::query!(
            "SELECT project_id, group_id, role, created_at FROM group_project_permissions WHERE project_id = ?",
            proj_id
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;

        let mut perms = Vec::with_capacity(rows.len());
        for row in rows {
            let role = Role::from_str(&row.role)
                .map_err(|e| StoreError::Backend(format!("invalid role in database: {}", e)))?;
            perms.push(zopp_storage::GroupProjectPermission {
                project_id: zopp_storage::ProjectId(
                    Uuid::parse_str(&row.project_id)
                        .map_err(|e| StoreError::Backend(format!("invalid project_id: {}", e)))?,
                ),
                group_id: zopp_storage::GroupId(
                    Uuid::parse_str(&row.group_id)
                        .map_err(|e| StoreError::Backend(format!("invalid group_id: {}", e)))?,
                ),
                role,
                created_at: DateTime::parse_from_rfc3339(&row.created_at)
                    .map_err(|e| StoreError::Backend(format!("invalid created_at: {}", e)))?
                    .with_timezone(&Utc),
            });
        }
        Ok(perms)
    }

    async fn remove_group_project_permission(
        &self,
        project_id: &zopp_storage::ProjectId,
        group_id: &zopp_storage::GroupId,
    ) -> Result<(), StoreError> {
        let proj_id = project_id.0.to_string();
        let g_id = group_id.0.to_string();

        let result = sqlx::query!(
            "DELETE FROM group_project_permissions WHERE project_id = ? AND group_id = ?",
            proj_id,
            g_id
        )
        .execute(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(StoreError::NotFound);
        }

        Ok(())
    }

    async fn set_group_environment_permission(
        &self,
        environment_id: &EnvironmentId,
        group_id: &zopp_storage::GroupId,
        role: Role,
    ) -> Result<(), StoreError> {
        let env_id = environment_id.0.to_string();
        let g_id = group_id.0.to_string();
        let role_str = role.as_str();

        sqlx::query!(
            "INSERT INTO group_environment_permissions(environment_id, group_id, role) VALUES(?, ?, ?)
             ON CONFLICT(environment_id, group_id) DO UPDATE SET role = excluded.role",
            env_id,
            g_id,
            role_str
        )
        .execute(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;

        Ok(())
    }

    async fn get_group_environment_permission(
        &self,
        environment_id: &EnvironmentId,
        group_id: &zopp_storage::GroupId,
    ) -> Result<Role, StoreError> {
        let env_id = environment_id.0.to_string();
        let g_id = group_id.0.to_string();

        let row = sqlx::query!(
            "SELECT role FROM group_environment_permissions WHERE environment_id = ? AND group_id = ?",
            env_id,
            g_id
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?
        .ok_or(StoreError::NotFound)?;

        Role::from_str(&row.role).map_err(|_| StoreError::Backend("Invalid role".to_string()))
    }

    async fn list_group_environment_permissions(
        &self,
        environment_id: &EnvironmentId,
    ) -> Result<Vec<zopp_storage::GroupEnvironmentPermission>, StoreError> {
        let env_id = environment_id.0.to_string();

        let rows = sqlx::query!(
            "SELECT environment_id, group_id, role, created_at FROM group_environment_permissions WHERE environment_id = ?",
            env_id
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;

        let mut perms = Vec::with_capacity(rows.len());
        for row in rows {
            let role = Role::from_str(&row.role)
                .map_err(|e| StoreError::Backend(format!("invalid role in database: {}", e)))?;
            perms.push(zopp_storage::GroupEnvironmentPermission {
                environment_id: EnvironmentId(
                    Uuid::parse_str(&row.environment_id).map_err(|e| {
                        StoreError::Backend(format!("invalid environment_id: {}", e))
                    })?,
                ),
                group_id: zopp_storage::GroupId(
                    Uuid::parse_str(&row.group_id)
                        .map_err(|e| StoreError::Backend(format!("invalid group_id: {}", e)))?,
                ),
                role,
                created_at: DateTime::parse_from_rfc3339(&row.created_at)
                    .map_err(|e| StoreError::Backend(format!("invalid created_at: {}", e)))?
                    .with_timezone(&Utc),
            });
        }
        Ok(perms)
    }

    async fn remove_group_environment_permission(
        &self,
        environment_id: &EnvironmentId,
        group_id: &zopp_storage::GroupId,
    ) -> Result<(), StoreError> {
        let env_id = environment_id.0.to_string();
        let g_id = group_id.0.to_string();

        let result = sqlx::query!(
            "DELETE FROM group_environment_permissions WHERE environment_id = ? AND group_id = ?",
            env_id,
            g_id
        )
        .execute(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(StoreError::NotFound);
        }

        Ok(())
    }

    // ────────────────────────────────────── User Permissions ──────────────────────────────────────

    async fn set_user_workspace_permission(
        &self,
        workspace_id: &WorkspaceId,
        user_id: &UserId,
        role: Role,
    ) -> Result<(), StoreError> {
        let ws_id = workspace_id.0.to_string();
        let u_id = user_id.0.to_string();
        let role_str = role.as_str();

        sqlx::query!(
            "INSERT INTO user_workspace_permissions(workspace_id, user_id, role) VALUES(?, ?, ?)
             ON CONFLICT(workspace_id, user_id) DO UPDATE SET role = excluded.role, updated_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now')",
            ws_id,
            u_id,
            role_str
        )
        .execute(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;

        Ok(())
    }

    async fn get_user_workspace_permission(
        &self,
        workspace_id: &WorkspaceId,
        user_id: &UserId,
    ) -> Result<Role, StoreError> {
        let ws_id = workspace_id.0.to_string();
        let u_id = user_id.0.to_string();

        let row = sqlx::query!(
            "SELECT role FROM user_workspace_permissions WHERE workspace_id = ? AND user_id = ?",
            ws_id,
            u_id
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?
        .ok_or(StoreError::NotFound)?;

        Role::from_str(&row.role).map_err(|_| StoreError::Backend("Invalid role".to_string()))
    }

    async fn list_user_workspace_permissions(
        &self,
        workspace_id: &WorkspaceId,
    ) -> Result<Vec<UserWorkspacePermission>, StoreError> {
        let ws_id = workspace_id.0.to_string();

        let rows = sqlx::query!(
            "SELECT workspace_id, user_id, role, created_at FROM user_workspace_permissions WHERE workspace_id = ?",
            ws_id
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;

        let mut perms = Vec::with_capacity(rows.len());
        for row in rows {
            let role = Role::from_str(&row.role)
                .map_err(|e| StoreError::Backend(format!("invalid role in database: {}", e)))?;
            perms.push(UserWorkspacePermission {
                workspace_id: WorkspaceId(
                    Uuid::parse_str(&row.workspace_id)
                        .map_err(|e| StoreError::Backend(format!("invalid workspace_id: {}", e)))?,
                ),
                user_id: UserId(
                    Uuid::parse_str(&row.user_id)
                        .map_err(|e| StoreError::Backend(format!("invalid user_id: {}", e)))?,
                ),
                role,
                created_at: DateTime::parse_from_rfc3339(&row.created_at)
                    .map_err(|e| StoreError::Backend(format!("invalid created_at: {}", e)))?
                    .with_timezone(&Utc),
            });
        }
        Ok(perms)
    }

    async fn remove_user_workspace_permission(
        &self,
        workspace_id: &WorkspaceId,
        user_id: &UserId,
    ) -> Result<(), StoreError> {
        let ws_id = workspace_id.0.to_string();
        let u_id = user_id.0.to_string();

        let result = sqlx::query!(
            "DELETE FROM user_workspace_permissions WHERE workspace_id = ? AND user_id = ?",
            ws_id,
            u_id
        )
        .execute(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(StoreError::NotFound);
        }

        Ok(())
    }

    async fn set_user_project_permission(
        &self,
        project_id: &zopp_storage::ProjectId,
        user_id: &UserId,
        role: Role,
    ) -> Result<(), StoreError> {
        let proj_id = project_id.0.to_string();
        let u_id = user_id.0.to_string();
        let role_str = role.as_str();

        sqlx::query!(
            "INSERT INTO user_project_permissions(project_id, user_id, role) VALUES(?, ?, ?)
             ON CONFLICT(project_id, user_id) DO UPDATE SET role = excluded.role, updated_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now')",
            proj_id,
            u_id,
            role_str
        )
        .execute(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;

        Ok(())
    }

    async fn get_user_project_permission(
        &self,
        project_id: &zopp_storage::ProjectId,
        user_id: &UserId,
    ) -> Result<Role, StoreError> {
        let proj_id = project_id.0.to_string();
        let u_id = user_id.0.to_string();

        let row = sqlx::query!(
            "SELECT role FROM user_project_permissions WHERE project_id = ? AND user_id = ?",
            proj_id,
            u_id
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?
        .ok_or(StoreError::NotFound)?;

        Role::from_str(&row.role).map_err(|_| StoreError::Backend("Invalid role".to_string()))
    }

    async fn list_user_project_permissions(
        &self,
        project_id: &zopp_storage::ProjectId,
    ) -> Result<Vec<UserProjectPermission>, StoreError> {
        let proj_id = project_id.0.to_string();

        let rows = sqlx::query!(
            "SELECT project_id, user_id, role, created_at FROM user_project_permissions WHERE project_id = ?",
            proj_id
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;

        let mut perms = Vec::with_capacity(rows.len());
        for row in rows {
            let role = Role::from_str(&row.role)
                .map_err(|e| StoreError::Backend(format!("invalid role in database: {}", e)))?;
            perms.push(UserProjectPermission {
                project_id: zopp_storage::ProjectId(
                    Uuid::parse_str(&row.project_id)
                        .map_err(|e| StoreError::Backend(format!("invalid project_id: {}", e)))?,
                ),
                user_id: UserId(
                    Uuid::parse_str(&row.user_id)
                        .map_err(|e| StoreError::Backend(format!("invalid user_id: {}", e)))?,
                ),
                role,
                created_at: DateTime::parse_from_rfc3339(&row.created_at)
                    .map_err(|e| StoreError::Backend(format!("invalid created_at: {}", e)))?
                    .with_timezone(&Utc),
            });
        }
        Ok(perms)
    }

    async fn remove_user_project_permission(
        &self,
        project_id: &zopp_storage::ProjectId,
        user_id: &UserId,
    ) -> Result<(), StoreError> {
        let proj_id = project_id.0.to_string();
        let u_id = user_id.0.to_string();

        let result = sqlx::query!(
            "DELETE FROM user_project_permissions WHERE project_id = ? AND user_id = ?",
            proj_id,
            u_id
        )
        .execute(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(StoreError::NotFound);
        }

        Ok(())
    }

    async fn set_user_environment_permission(
        &self,
        environment_id: &EnvironmentId,
        user_id: &UserId,
        role: Role,
    ) -> Result<(), StoreError> {
        let env_id = environment_id.0.to_string();
        let u_id = user_id.0.to_string();
        let role_str = role.as_str();

        sqlx::query!(
            "INSERT INTO user_environment_permissions(environment_id, user_id, role) VALUES(?, ?, ?)
             ON CONFLICT(environment_id, user_id) DO UPDATE SET role = excluded.role, updated_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now')",
            env_id,
            u_id,
            role_str
        )
        .execute(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;

        Ok(())
    }

    async fn get_user_environment_permission(
        &self,
        environment_id: &EnvironmentId,
        user_id: &UserId,
    ) -> Result<Role, StoreError> {
        let env_id = environment_id.0.to_string();
        let u_id = user_id.0.to_string();

        let row = sqlx::query!(
            "SELECT role FROM user_environment_permissions WHERE environment_id = ? AND user_id = ?",
            env_id,
            u_id
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?
        .ok_or(StoreError::NotFound)?;

        Role::from_str(&row.role).map_err(|_| StoreError::Backend("Invalid role".to_string()))
    }

    async fn list_user_environment_permissions(
        &self,
        environment_id: &EnvironmentId,
    ) -> Result<Vec<UserEnvironmentPermission>, StoreError> {
        let env_id = environment_id.0.to_string();

        let rows = sqlx::query!(
            "SELECT environment_id, user_id, role, created_at FROM user_environment_permissions WHERE environment_id = ?",
            env_id
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;

        let mut perms = Vec::with_capacity(rows.len());
        for row in rows {
            let role = Role::from_str(&row.role)
                .map_err(|e| StoreError::Backend(format!("invalid role in database: {}", e)))?;
            perms.push(UserEnvironmentPermission {
                environment_id: EnvironmentId(
                    Uuid::parse_str(&row.environment_id).map_err(|e| {
                        StoreError::Backend(format!("invalid environment_id: {}", e))
                    })?,
                ),
                user_id: UserId(
                    Uuid::parse_str(&row.user_id)
                        .map_err(|e| StoreError::Backend(format!("invalid user_id: {}", e)))?,
                ),
                role,
                created_at: DateTime::parse_from_rfc3339(&row.created_at)
                    .map_err(|e| StoreError::Backend(format!("invalid created_at: {}", e)))?
                    .with_timezone(&Utc),
            });
        }
        Ok(perms)
    }

    async fn remove_user_environment_permission(
        &self,
        environment_id: &EnvironmentId,
        user_id: &UserId,
    ) -> Result<(), StoreError> {
        let env_id = environment_id.0.to_string();
        let u_id = user_id.0.to_string();

        let result = sqlx::query!(
            "DELETE FROM user_environment_permissions WHERE environment_id = ? AND user_id = ?",
            env_id,
            u_id
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

// ────────────────────────────────────── Audit Log ──────────────────────────────────────

#[async_trait::async_trait]
impl AuditLog for SqliteStore {
    async fn record(&self, event: AuditEvent) -> Result<(), AuditLogError> {
        let id = event.id.0.to_string();
        let timestamp = event.timestamp.to_rfc3339();
        let principal_id = event.principal_id.to_string();
        let user_id = event.user_id.map(|u| u.to_string());
        let action = event.action.to_string();
        let workspace_id = event.workspace_id.map(|w| w.to_string());
        let project_id = event.project_id.map(|p| p.to_string());
        let environment_id = event.environment_id.map(|e| e.to_string());
        let result = event.result.to_string();
        let details = event.details.map(|d| d.to_string());

        sqlx::query!(
            r#"INSERT INTO audit_logs (
                id, timestamp, principal_id, user_id, action,
                resource_type, resource_id, workspace_id, project_id, environment_id,
                result, reason, details, client_ip
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"#,
            id,
            timestamp,
            principal_id,
            user_id,
            action,
            event.resource_type,
            event.resource_id,
            workspace_id,
            project_id,
            environment_id,
            result,
            event.reason,
            details,
            event.client_ip
        )
        .execute(&self.pool)
        .await
        .map_err(|e| AuditLogError::Database(e.to_string()))?;

        Ok(())
    }

    async fn query(&self, filter: AuditLogFilter) -> Result<Vec<AuditEvent>, AuditLogError> {
        // Build the query dynamically based on filters
        // For simplicity, we'll use a base query and filter in Rust for complex cases
        // In production, you'd want to build proper parameterized queries

        let limit = filter.limit.unwrap_or(100) as i64;
        let offset = filter.offset.unwrap_or(0) as i64;

        // Convert filter parameters to strings
        let principal_id = filter.principal_id.map(|p| p.0.to_string());
        let user_id = filter.user_id.map(|u| u.0.to_string());
        let workspace_id = filter.workspace_id.map(|w| w.0.to_string());
        let project_id = filter.project_id.map(|p| p.0.to_string());
        let environment_id = filter.environment_id.map(|e| e.0.to_string());
        let action = filter.action.map(|a| a.to_string());
        let result = filter.result.map(|r| r.to_string());
        let from = filter.from.map(|f| f.to_rfc3339());
        let to = filter.to.map(|t| t.to_rfc3339());

        let rows = sqlx::query!(
            r#"SELECT id, timestamp, principal_id, user_id, action,
                      resource_type, resource_id, workspace_id, project_id, environment_id,
                      result, reason, details, client_ip
               FROM audit_logs
               WHERE (? IS NULL OR principal_id = ?)
                 AND (? IS NULL OR user_id = ?)
                 AND (? IS NULL OR workspace_id = ?)
                 AND (? IS NULL OR project_id = ?)
                 AND (? IS NULL OR environment_id = ?)
                 AND (? IS NULL OR action = ?)
                 AND (? IS NULL OR result = ?)
                 AND (? IS NULL OR timestamp >= ?)
                 AND (? IS NULL OR timestamp < ?)
               ORDER BY timestamp DESC
               LIMIT ? OFFSET ?"#,
            principal_id,
            principal_id,
            user_id,
            user_id,
            workspace_id,
            workspace_id,
            project_id,
            project_id,
            environment_id,
            environment_id,
            action,
            action,
            result,
            result,
            from,
            from,
            to,
            to,
            limit,
            offset
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| AuditLogError::Database(e.to_string()))?;

        let mut events = Vec::with_capacity(rows.len());
        for row in rows {
            let id =
                Uuid::parse_str(&row.id).map_err(|e| AuditLogError::Database(e.to_string()))?;
            let principal_id = Uuid::parse_str(&row.principal_id)
                .map_err(|e| AuditLogError::Database(e.to_string()))?;
            let user_id = row
                .user_id
                .map(|u| Uuid::parse_str(&u))
                .transpose()
                .map_err(|e| AuditLogError::Database(e.to_string()))?;
            let workspace_id = row
                .workspace_id
                .map(|w| Uuid::parse_str(&w))
                .transpose()
                .map_err(|e| AuditLogError::Database(e.to_string()))?;
            let project_id = row
                .project_id
                .map(|p| Uuid::parse_str(&p))
                .transpose()
                .map_err(|e| AuditLogError::Database(e.to_string()))?;
            let environment_id = row
                .environment_id
                .map(|e| Uuid::parse_str(&e))
                .transpose()
                .map_err(|e| AuditLogError::Database(e.to_string()))?;
            let timestamp = DateTime::parse_from_rfc3339(&row.timestamp)
                .map_err(|e| AuditLogError::Database(e.to_string()))?
                .with_timezone(&Utc);
            let action: AuditAction = row
                .action
                .parse()
                .map_err(|e: String| AuditLogError::Database(e))?;
            let result: AuditResult = row
                .result
                .parse()
                .map_err(|e: String| AuditLogError::Database(e))?;
            let details = row
                .details
                .map(|d| serde_json::from_str(&d))
                .transpose()
                .map_err(|e| AuditLogError::Database(e.to_string()))?;

            events.push(AuditEvent {
                id: AuditLogId(id),
                timestamp,
                principal_id,
                user_id,
                action,
                resource_type: row.resource_type,
                resource_id: row.resource_id,
                workspace_id,
                project_id,
                environment_id,
                result,
                reason: row.reason,
                details,
                client_ip: row.client_ip,
            });
        }

        Ok(events)
    }

    async fn get(&self, id: AuditLogId) -> Result<AuditEvent, AuditLogError> {
        let id_str = id.0.to_string();

        let row = sqlx::query!(
            r#"SELECT id, timestamp, principal_id, user_id, action,
                      resource_type, resource_id, workspace_id, project_id, environment_id,
                      result, reason, details, client_ip
               FROM audit_logs WHERE id = ?"#,
            id_str
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AuditLogError::Database(e.to_string()))?;

        let row = row.ok_or(AuditLogError::NotFound(id))?;

        let uuid_id =
            Uuid::parse_str(&row.id).map_err(|e| AuditLogError::Database(e.to_string()))?;
        let principal_id = Uuid::parse_str(&row.principal_id)
            .map_err(|e| AuditLogError::Database(e.to_string()))?;
        let user_id = row
            .user_id
            .map(|u| Uuid::parse_str(&u))
            .transpose()
            .map_err(|e| AuditLogError::Database(e.to_string()))?;
        let workspace_id = row
            .workspace_id
            .map(|w| Uuid::parse_str(&w))
            .transpose()
            .map_err(|e| AuditLogError::Database(e.to_string()))?;
        let project_id = row
            .project_id
            .map(|p| Uuid::parse_str(&p))
            .transpose()
            .map_err(|e| AuditLogError::Database(e.to_string()))?;
        let environment_id = row
            .environment_id
            .map(|e| Uuid::parse_str(&e))
            .transpose()
            .map_err(|e| AuditLogError::Database(e.to_string()))?;
        let timestamp = DateTime::parse_from_rfc3339(&row.timestamp)
            .map_err(|e| AuditLogError::Database(e.to_string()))?
            .with_timezone(&Utc);
        let action: AuditAction = row
            .action
            .parse()
            .map_err(|e: String| AuditLogError::Database(e))?;
        let result: AuditResult = row
            .result
            .parse()
            .map_err(|e: String| AuditLogError::Database(e))?;
        let details = row
            .details
            .map(|d| serde_json::from_str(&d))
            .transpose()
            .map_err(|e| AuditLogError::Database(e.to_string()))?;

        Ok(AuditEvent {
            id: AuditLogId(uuid_id),
            timestamp,
            principal_id,
            user_id,
            action,
            resource_type: row.resource_type,
            resource_id: row.resource_id,
            workspace_id,
            project_id,
            environment_id,
            result,
            reason: row.reason,
            details,
            client_ip: row.client_ip,
        })
    }

    async fn count(&self, filter: AuditLogFilter) -> Result<u64, AuditLogError> {
        // Convert filter parameters to strings
        let principal_id = filter.principal_id.map(|p| p.0.to_string());
        let user_id = filter.user_id.map(|u| u.0.to_string());
        let workspace_id = filter.workspace_id.map(|w| w.0.to_string());
        let project_id = filter.project_id.map(|p| p.0.to_string());
        let environment_id = filter.environment_id.map(|e| e.0.to_string());
        let action = filter.action.map(|a| a.to_string());
        let result = filter.result.map(|r| r.to_string());
        let from = filter.from.map(|f| f.to_rfc3339());
        let to = filter.to.map(|t| t.to_rfc3339());

        let row = sqlx::query!(
            r#"SELECT COUNT(*) as count
               FROM audit_logs
               WHERE (? IS NULL OR principal_id = ?)
                 AND (? IS NULL OR user_id = ?)
                 AND (? IS NULL OR workspace_id = ?)
                 AND (? IS NULL OR project_id = ?)
                 AND (? IS NULL OR environment_id = ?)
                 AND (? IS NULL OR action = ?)
                 AND (? IS NULL OR result = ?)
                 AND (? IS NULL OR timestamp >= ?)
                 AND (? IS NULL OR timestamp < ?)"#,
            principal_id,
            principal_id,
            user_id,
            user_id,
            workspace_id,
            workspace_id,
            project_id,
            project_id,
            environment_id,
            environment_id,
            action,
            action,
            result,
            result,
            from,
            from,
            to,
            to
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|e| AuditLogError::Database(e.to_string()))?;

        Ok(row.count as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zopp_storage::{
        CreatePrincipalData, CreateWorkspaceParams, EnvName, ProjectName, StoreError, UserId,
        WorkspaceId,
    };

    fn workspace_params(owner_user_id: UserId, name: &str) -> CreateWorkspaceParams {
        CreateWorkspaceParams {
            id: WorkspaceId(uuid::Uuid::now_v7()),
            name: name.to_string(),
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
            .create_workspace(&workspace_params(user_id, "test-workspace"))
            .await
            .unwrap();
        let got = s.get_workspace(&ws).await.unwrap();
        assert_eq!(
            got.kdf_salt,
            workspace_params(got.owner_user_id.clone(), "test-workspace").kdf_salt
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
            .create_workspace(&workspace_params(user_id, "test-workspace"))
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
            .create_workspace(&workspace_params(user_id.clone(), "test-workspace-1"))
            .await
            .unwrap();
        let ws2 = s
            .create_workspace(&workspace_params(user_id, "test-workspace-2"))
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
            .create_workspace(&workspace_params(user_id, "test-workspace"))
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
            .create_workspace(&workspace_params(user_id, "test-workspace"))
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
            .create_workspace(&workspace_params(user_id, "test-workspace"))
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
            .create_workspace(&workspace_params(user_id, "test-workspace"))
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
            .create_workspace(&workspace_params(user_id.clone(), "test-workspace-1"))
            .await
            .unwrap();
        let ws2 = s
            .create_workspace(&workspace_params(user_id, "test-workspace-2"))
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
                x25519_public_key: None,
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
            .create_workspace(&workspace_params(user_id, "test-workspace"))
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

    #[tokio::test]
    async fn rbac_permissions_roundtrip() {
        use zopp_storage::Role;

        let s = SqliteStore::open_in_memory().await.unwrap();
        let (user_id, principal_id) = s
            .create_user(&CreateUserParams {
                email: "test@example.com".to_string(),
                principal: Some(zopp_storage::CreatePrincipalData {
                    name: "test-principal".to_string(),
                    public_key: vec![1, 2, 3],
                    x25519_public_key: None,
                    is_service: false,
                }),
                workspace_ids: vec![],
            })
            .await
            .unwrap();
        let principal_id = principal_id.unwrap();

        let ws = s
            .create_workspace(&workspace_params(user_id.clone(), "test-workspace"))
            .await
            .unwrap();

        let project_id = s
            .create_project(&CreateProjectParams {
                workspace_id: ws.clone(),
                name: "test-project".to_string(),
            })
            .await
            .unwrap();

        let env_id = s
            .create_env(&CreateEnvParams {
                project_id: project_id.clone(),
                name: "test-env".to_string(),
                dek_wrapped: vec![1],
                dek_nonce: vec![9; 24],
            })
            .await
            .unwrap();

        // Test workspace permissions
        s.set_workspace_permission(&ws, &principal_id, Role::Admin)
            .await
            .unwrap();
        let role = s
            .get_workspace_permission(&ws, &principal_id)
            .await
            .unwrap();
        assert_eq!(role, Role::Admin);

        // Update workspace permission
        s.set_workspace_permission(&ws, &principal_id, Role::Read)
            .await
            .unwrap();
        let role = s
            .get_workspace_permission(&ws, &principal_id)
            .await
            .unwrap();
        assert_eq!(role, Role::Read);

        // Test project permissions
        s.set_project_permission(&project_id, &principal_id, Role::Write)
            .await
            .unwrap();
        let role = s
            .get_project_permission(&project_id, &principal_id)
            .await
            .unwrap();
        assert_eq!(role, Role::Write);

        // Test environment permissions
        s.set_environment_permission(&env_id, &principal_id, Role::Read)
            .await
            .unwrap();
        let role = s
            .get_environment_permission(&env_id, &principal_id)
            .await
            .unwrap();
        assert_eq!(role, Role::Read);

        // Test listing permissions
        let ws_perms = s
            .list_workspace_permissions_for_principal(&principal_id)
            .await
            .unwrap();
        assert_eq!(ws_perms.len(), 1);
        assert_eq!(ws_perms[0].role, Role::Read);

        let proj_perms = s
            .list_project_permissions_for_principal(&principal_id)
            .await
            .unwrap();
        assert_eq!(proj_perms.len(), 1);
        assert_eq!(proj_perms[0].role, Role::Write);

        let env_perms = s
            .list_environment_permissions_for_principal(&principal_id)
            .await
            .unwrap();
        assert_eq!(env_perms.len(), 1);
        assert_eq!(env_perms[0].role, Role::Read);

        // Test remove permissions
        s.remove_workspace_permission(&ws, &principal_id)
            .await
            .unwrap();
        let err = s
            .get_workspace_permission(&ws, &principal_id)
            .await
            .unwrap_err();
        matches!(err, StoreError::NotFound);
    }

    #[tokio::test]
    async fn secret_crud_operations() {
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
            .create_workspace(&workspace_params(user_id.clone(), "test-workspace"))
            .await
            .unwrap();
        let project_id = s
            .create_project(&CreateProjectParams {
                workspace_id: ws.clone(),
                name: "test-project".to_string(),
            })
            .await
            .unwrap();
        let env_id = s
            .create_env(&CreateEnvParams {
                project_id: project_id.clone(),
                name: "dev".to_string(),
                dek_wrapped: vec![4, 5, 6],
                dek_nonce: vec![
                    7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
                ],
            })
            .await
            .unwrap();

        // Insert a secret
        let nonce = vec![0u8; 24];
        let ciphertext = vec![1u8, 2, 3, 4, 5];
        let version = s
            .upsert_secret(&env_id, "API_KEY", &nonce, &ciphertext)
            .await
            .unwrap();
        assert_eq!(version, 1);

        // Get the secret
        let secret = s.get_secret(&env_id, "API_KEY").await.unwrap();
        assert_eq!(secret.nonce, nonce);
        assert_eq!(secret.ciphertext, ciphertext);

        // Update the secret
        let new_ciphertext = vec![10u8, 20, 30];
        let version2 = s
            .upsert_secret(&env_id, "API_KEY", &nonce, &new_ciphertext)
            .await
            .unwrap();
        assert_eq!(version2, 2);

        // List secret keys
        let keys = s.list_secret_keys(&env_id).await.unwrap();
        assert_eq!(keys, vec!["API_KEY".to_string()]);

        // Delete the secret
        let del_version = s.delete_secret(&env_id, "API_KEY").await.unwrap();
        assert_eq!(del_version, 3);

        // Get should fail now
        let err = s.get_secret(&env_id, "API_KEY").await.unwrap_err();
        assert!(matches!(err, StoreError::NotFound));
    }

    #[tokio::test]
    async fn user_operations() {
        let s = SqliteStore::open_in_memory().await.unwrap();
        let (user_id, _) = s
            .create_user(&CreateUserParams {
                email: "user@example.com".to_string(),
                principal: None,
                workspace_ids: vec![],
            })
            .await
            .unwrap();

        // Get user by email
        let user = s.get_user_by_email("user@example.com").await.unwrap();
        assert_eq!(user.id, user_id);
        assert_eq!(user.email, "user@example.com");

        // Get user by id
        let user2 = s.get_user_by_id(&user_id).await.unwrap();
        assert_eq!(user2.email, "user@example.com");

        // User not found
        let err = s
            .get_user_by_email("notfound@example.com")
            .await
            .unwrap_err();
        matches!(err, StoreError::NotFound);
    }

    #[tokio::test]
    async fn invite_operations() {
        let s = SqliteStore::open_in_memory().await.unwrap();
        let (user_id, _) = s
            .create_user(&CreateUserParams {
                email: "inviter@example.com".to_string(),
                principal: None,
                workspace_ids: vec![],
            })
            .await
            .unwrap();
        let ws = s
            .create_workspace(&workspace_params(user_id.clone(), "test-workspace"))
            .await
            .unwrap();

        // Create an invite
        let invite = s
            .create_invite(&CreateInviteParams {
                workspace_ids: vec![ws.clone()],
                token: "test-token".to_string(),
                kek_encrypted: Some(vec![1, 2, 3]),
                kek_nonce: Some(vec![0u8; 24]),
                expires_at: chrono::Utc::now() + chrono::Duration::hours(24),
                created_by_user_id: Some(user_id.clone()),
            })
            .await
            .unwrap();

        // Get invite by token
        let got = s.get_invite_by_token("test-token").await.unwrap();
        assert_eq!(got.id, invite.id);

        // List invites
        let invites = s.list_invites(Some(user_id.clone())).await.unwrap();
        assert_eq!(invites.len(), 1);

        // Revoke invite
        s.revoke_invite(&invite.id).await.unwrap();
        let err = s.get_invite_by_token("test-token").await.unwrap_err();
        matches!(err, StoreError::NotFound);
    }

    #[tokio::test]
    async fn project_and_environment_delete() {
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
            .create_workspace(&workspace_params(user_id.clone(), "test-workspace"))
            .await
            .unwrap();
        let project_id = s
            .create_project(&CreateProjectParams {
                workspace_id: ws.clone(),
                name: "test-project".to_string(),
            })
            .await
            .unwrap();
        let env_id = s
            .create_env(&CreateEnvParams {
                project_id: project_id.clone(),
                name: "dev".to_string(),
                dek_wrapped: vec![4, 5, 6],
                dek_nonce: vec![
                    7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
                ],
            })
            .await
            .unwrap();

        // Delete environment
        s.delete_environment(&env_id).await.unwrap();
        let err = s.get_environment(&env_id).await.unwrap_err();
        matches!(err, StoreError::NotFound);

        // Delete project
        s.delete_project(&project_id).await.unwrap();
        let err = s.get_project(&project_id).await.unwrap_err();
        matches!(err, StoreError::NotFound);
    }

    #[tokio::test]
    async fn user_permission_operations() {
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
            .create_workspace(&workspace_params(user_id.clone(), "test-workspace"))
            .await
            .unwrap();
        s.add_user_to_workspace(&ws, &user_id).await.unwrap();

        let project_id = s
            .create_project(&CreateProjectParams {
                workspace_id: ws.clone(),
                name: "test-project".to_string(),
            })
            .await
            .unwrap();
        let env_id = s
            .create_env(&CreateEnvParams {
                project_id: project_id.clone(),
                name: "dev".to_string(),
                dek_wrapped: vec![4, 5, 6],
                dek_nonce: vec![
                    7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
                ],
            })
            .await
            .unwrap();

        // Set user workspace permission
        s.set_user_workspace_permission(&ws, &user_id, Role::Admin)
            .await
            .unwrap();
        let role = s
            .get_user_workspace_permission(&ws, &user_id)
            .await
            .unwrap();
        assert_eq!(role, Role::Admin);

        // Set user project permission
        s.set_user_project_permission(&project_id, &user_id, Role::Write)
            .await
            .unwrap();
        let role = s
            .get_user_project_permission(&project_id, &user_id)
            .await
            .unwrap();
        assert_eq!(role, Role::Write);

        // Set user environment permission
        s.set_user_environment_permission(&env_id, &user_id, Role::Read)
            .await
            .unwrap();
        let role = s
            .get_user_environment_permission(&env_id, &user_id)
            .await
            .unwrap();
        assert_eq!(role, Role::Read);

        // List user permissions at each level
        let ws_perms = s.list_user_workspace_permissions(&ws).await.unwrap();
        assert_eq!(ws_perms.len(), 1);
        assert_eq!(ws_perms[0].role, Role::Admin);

        let proj_perms = s.list_user_project_permissions(&project_id).await.unwrap();
        assert_eq!(proj_perms.len(), 1);
        assert_eq!(proj_perms[0].role, Role::Write);

        let env_perms = s.list_user_environment_permissions(&env_id).await.unwrap();
        assert_eq!(env_perms.len(), 1);
        assert_eq!(env_perms[0].role, Role::Read);

        // Remove user permissions
        s.remove_user_workspace_permission(&ws, &user_id)
            .await
            .unwrap();
        let err = s
            .get_user_workspace_permission(&ws, &user_id)
            .await
            .unwrap_err();
        matches!(err, StoreError::NotFound);
    }

    #[tokio::test]
    async fn workspace_principal_operations() {
        let s = SqliteStore::open_in_memory().await.unwrap();
        let (user_id, principal_id) = s
            .create_user(&CreateUserParams {
                email: "test@example.com".to_string(),
                principal: Some(CreatePrincipalData {
                    name: "laptop".to_string(),
                    public_key: vec![1, 2, 3, 4],
                    x25519_public_key: Some(vec![5, 6, 7, 8]),
                    is_service: false,
                }),
                workspace_ids: vec![],
            })
            .await
            .unwrap();
        let principal_id = principal_id.unwrap();

        let ws = s
            .create_workspace(&workspace_params(user_id.clone(), "test-workspace"))
            .await
            .unwrap();

        // Add workspace principal
        s.add_workspace_principal(&AddWorkspacePrincipalParams {
            workspace_id: ws.clone(),
            principal_id: principal_id.clone(),
            ephemeral_pub: vec![10, 20, 30],
            kek_wrapped: vec![40, 50, 60],
            kek_nonce: vec![0u8; 24],
        })
        .await
        .unwrap();

        // Get workspace principal
        let wp = s.get_workspace_principal(&ws, &principal_id).await.unwrap();
        assert_eq!(wp.ephemeral_pub, vec![10, 20, 30]);
        assert_eq!(wp.kek_wrapped, vec![40, 50, 60]);

        // List workspace principals
        let principals = s.list_workspace_principals(&ws).await.unwrap();
        assert_eq!(principals.len(), 1);

        // Remove workspace principal
        s.remove_workspace_principal(&ws, &principal_id)
            .await
            .unwrap();
        let err = s
            .get_workspace_principal(&ws, &principal_id)
            .await
            .unwrap_err();
        matches!(err, StoreError::NotFound);
    }
}
