use sqlx::{PgPool, postgres::PgPoolOptions};
use uuid::Uuid;
use zopp_storage::{
    AddWorkspacePrincipalParams, CreateEnvParams, CreateInviteParams, CreatePrincipalParams,
    CreateProjectParams, CreateUserParams, CreateWorkspaceParams, EnvName, Environment,
    EnvironmentId, Invite, InviteId, Principal, PrincipalId, ProjectName, SecretRow, Store,
    StoreError, User, UserId, Workspace, WorkspaceId, WorkspacePrincipal,
};

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

pub struct PostgresStore {
    pool: PgPool,
}

impl PostgresStore {
    pub async fn open(url: &str) -> Result<Self, StoreError> {
        let pool = PgPoolOptions::new()
            .max_connections(10)
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
impl Store for PostgresStore {
    // ───────────────────────────── Users ─────────────────────────────

    async fn create_user(
        &self,
        params: &CreateUserParams,
    ) -> Result<(UserId, Option<PrincipalId>), StoreError> {
        let needs_tx = params.principal.is_some() || !params.workspace_ids.is_empty();

        if needs_tx {
            let mut tx = self
                .pool
                .begin()
                .await
                .map_err(|e| StoreError::Backend(e.to_string()))?;

            let existing_user = sqlx::query!("SELECT id FROM users WHERE email = $1", params.email)
                .fetch_optional(&mut *tx)
                .await
                .map_err(|e| StoreError::Backend(e.to_string()))?;

            let actual_user_id = if let Some(existing) = existing_user {
                existing.id
            } else {
                let user_id = Uuid::now_v7();
                sqlx::query!(
                    "INSERT INTO users(id, email) VALUES($1, $2)",
                    user_id,
                    params.email
                )
                .execute(&mut *tx)
                .await
                .map_err(|e| StoreError::Backend(e.to_string()))?;
                user_id
            };

            let principal_id = if let Some(principal_data) = &params.principal {
                let principal_id = Uuid::now_v7();

                let user_id_for_principal = if principal_data.is_service {
                    None
                } else {
                    Some(actual_user_id)
                };

                sqlx::query!(
                    "INSERT INTO principals(id, user_id, name, public_key, x25519_public_key) VALUES($1, $2, $3, $4, $5)",
                    principal_id,
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

            for workspace_id in &params.workspace_ids {
                sqlx::query!(
                    "INSERT INTO workspace_members(workspace_id, user_id) VALUES($1, $2)",
                    workspace_id.0,
                    actual_user_id
                )
                .execute(&mut *tx)
                .await
                .map_err(|e| StoreError::Backend(e.to_string()))?;
            }

            tx.commit()
                .await
                .map_err(|e| StoreError::Backend(e.to_string()))?;

            Ok((UserId(actual_user_id), principal_id))
        } else {
            let user_id = Uuid::now_v7();

            sqlx::query!(
                "INSERT INTO users(id, email) VALUES($1, $2)",
                user_id,
                params.email
            )
            .execute(&self.pool)
            .await
            .map_err(|e| {
                let s = e.to_string();
                if s.contains("duplicate key") || s.contains("unique constraint") {
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
            r#"SELECT id, email, created_at, updated_at FROM users WHERE email = $1"#,
            email
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?
        .ok_or(StoreError::NotFound)?;

        Ok(User {
            id: UserId(row.id),
            email: row.email,
            created_at: row.created_at,
            updated_at: row.updated_at,
        })
    }

    async fn get_user_by_id(&self, user_id: &UserId) -> Result<User, StoreError> {
        let row = sqlx::query!(
            r#"SELECT id, email, created_at, updated_at FROM users WHERE id = $1"#,
            user_id.0
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?
        .ok_or(StoreError::NotFound)?;

        Ok(User {
            id: UserId(row.id),
            email: row.email,
            created_at: row.created_at,
            updated_at: row.updated_at,
        })
    }

    // ───────────────────────────── Principals ─────────────────────────────

    async fn create_principal(
        &self,
        params: &CreatePrincipalParams,
    ) -> Result<PrincipalId, StoreError> {
        let principal_id = Uuid::now_v7();
        let user_id = params.user_id.as_ref().map(|id| id.0);

        sqlx::query!(
            "INSERT INTO principals(id, user_id, name, public_key, x25519_public_key) VALUES($1, $2, $3, $4, $5)",
            principal_id,
            user_id,
            params.name,
            params.public_key,
            params.x25519_public_key
        )
        .execute(&self.pool)
        .await
        .map_err(|e| {
            let s = e.to_string();
            if s.contains("duplicate key") || s.contains("unique constraint") {
                StoreError::AlreadyExists
            } else {
                StoreError::Backend(s)
            }
        })?;
        Ok(PrincipalId(principal_id))
    }

    async fn get_principal(&self, principal_id: &PrincipalId) -> Result<Principal, StoreError> {
        let row = sqlx::query!(
            r#"SELECT id, user_id, name, public_key, x25519_public_key, created_at, updated_at
               FROM principals WHERE id = $1"#,
            principal_id.0
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?
        .ok_or(StoreError::NotFound)?;

        Ok(Principal {
            id: PrincipalId(row.id),
            user_id: row.user_id.map(UserId),
            name: row.name,
            public_key: row.public_key,
            x25519_public_key: row.x25519_public_key,
            created_at: row.created_at,
            updated_at: row.updated_at,
        })
    }

    async fn rename_principal(
        &self,
        principal_id: &PrincipalId,
        new_name: &str,
    ) -> Result<(), StoreError> {
        let result = sqlx::query!(
            "UPDATE principals SET name = $1 WHERE id = $2",
            new_name,
            principal_id.0
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
        let rows = sqlx::query!(
            r#"SELECT id, user_id, name, public_key, x25519_public_key, created_at, updated_at
               FROM principals WHERE user_id = $1"#,
            user_id.0
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;

        Ok(rows
            .into_iter()
            .map(|row| Principal {
                id: PrincipalId(row.id),
                user_id: row.user_id.map(UserId),
                name: row.name,
                public_key: row.public_key,
                x25519_public_key: row.x25519_public_key,
                created_at: row.created_at,
                updated_at: row.updated_at,
            })
            .collect())
    }

    // ───────────────────────────── Invites ─────────────────────────────

    async fn create_invite(&self, params: &CreateInviteParams) -> Result<Invite, StoreError> {
        let invite_id = Uuid::now_v7();
        let created_by_user_id = params.created_by_user_id.as_ref().map(|id| id.0);

        let row = sqlx::query!(
            r#"INSERT INTO invites(id, token, expires_at, created_by_user_id, kek_encrypted, kek_nonce)
               VALUES($1, $2, $3, $4, $5, $6)
               RETURNING created_at, updated_at"#,
            invite_id,
            params.token,
            params.expires_at,
            created_by_user_id,
            params.kek_encrypted,
            params.kek_nonce
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;

        for ws_id in &params.workspace_ids {
            sqlx::query!(
                "INSERT INTO invite_workspaces(invite_id, workspace_id) VALUES($1, $2)",
                invite_id,
                ws_id.0
            )
            .execute(&self.pool)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))?;
        }

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
            r#"SELECT id, token, created_at, updated_at, expires_at, created_by_user_id, revoked, kek_encrypted, kek_nonce
               FROM invites WHERE token = $1"#,
            token
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?
        .ok_or(StoreError::NotFound)?;

        if row.revoked {
            return Err(StoreError::NotFound);
        }

        let ws_rows = sqlx::query!(
            "SELECT workspace_id FROM invite_workspaces WHERE invite_id = $1",
            row.id
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;

        let workspace_ids = ws_rows
            .into_iter()
            .map(|r| WorkspaceId(r.workspace_id))
            .collect();

        Ok(Invite {
            id: InviteId(row.id),
            token: row.token,
            workspace_ids,
            kek_encrypted: row.kek_encrypted,
            kek_nonce: row.kek_nonce,
            created_at: row.created_at,
            updated_at: row.updated_at,
            expires_at: row.expires_at,
            created_by_user_id: row.created_by_user_id.map(UserId),
        })
    }

    async fn list_invites(&self, user_id: Option<&UserId>) -> Result<Vec<Invite>, StoreError> {
        let user_id_opt = user_id.map(|id| id.0);

        let rows = sqlx::query!(
            r#"SELECT id, token, created_at, updated_at, expires_at, created_by_user_id, revoked, kek_encrypted, kek_nonce
               FROM invites
               WHERE revoked = FALSE AND (
                   ($1::UUID IS NOT NULL AND created_by_user_id = $1) OR
                   ($1::UUID IS NULL AND created_by_user_id IS NULL)
               )"#,
            user_id_opt
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;

        let mut invites = Vec::new();
        for row in rows {
            let ws_rows = sqlx::query!(
                "SELECT workspace_id FROM invite_workspaces WHERE invite_id = $1",
                row.id
            )
            .fetch_all(&self.pool)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))?;

            let workspace_ids = ws_rows
                .into_iter()
                .map(|r| WorkspaceId(r.workspace_id))
                .collect();

            invites.push(Invite {
                id: InviteId(row.id),
                token: row.token,
                workspace_ids,
                kek_encrypted: row.kek_encrypted,
                kek_nonce: row.kek_nonce,
                created_at: row.created_at,
                updated_at: row.updated_at,
                expires_at: row.expires_at,
                created_by_user_id: row.created_by_user_id.map(UserId),
            });
        }
        Ok(invites)
    }

    async fn revoke_invite(&self, invite_id: &InviteId) -> Result<(), StoreError> {
        let result = sqlx::query!(
            "UPDATE invites SET revoked = TRUE WHERE id = $1",
            invite_id.0
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

    // ───────────────────────────── Workspaces ─────────────────────────────

    async fn create_workspace(
        &self,
        params: &CreateWorkspaceParams,
    ) -> Result<WorkspaceId, StoreError> {
        let m_cost = params.m_cost_kib as i32;
        let t_cost = params.t_cost as i32;
        let p_cost = params.p_cost as i32;

        sqlx::query!(
            "INSERT INTO workspaces(id, name, owner_user_id, kdf_salt, kdf_m_cost_kib, kdf_t_cost, kdf_p_cost)
             VALUES($1, $2, $3, $4, $5, $6, $7)",
            params.id.0,
            params.name,
            params.owner_user_id.0,
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
        let rows = sqlx::query!(
            r#"SELECT w.id, w.name, w.owner_user_id, w.kdf_salt, w.kdf_m_cost_kib, w.kdf_t_cost, w.kdf_p_cost,
               w.created_at, w.updated_at
               FROM workspaces w
               JOIN workspace_members wm ON w.id = wm.workspace_id
               WHERE wm.user_id = $1"#,
            user_id.0
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;

        Ok(rows
            .into_iter()
            .map(|row| Workspace {
                id: WorkspaceId(row.id),
                name: row.name,
                owner_user_id: UserId(row.owner_user_id),
                kdf_salt: row.kdf_salt,
                m_cost_kib: row.kdf_m_cost_kib as u32,
                t_cost: row.kdf_t_cost as u32,
                p_cost: row.kdf_p_cost as u32,
                created_at: row.created_at,
                updated_at: row.updated_at,
            })
            .collect())
    }

    async fn get_workspace(&self, ws: &WorkspaceId) -> Result<Workspace, StoreError> {
        let row = sqlx::query!(
            r#"SELECT id, name, owner_user_id, kdf_salt, kdf_m_cost_kib, kdf_t_cost, kdf_p_cost,
               created_at, updated_at
               FROM workspaces WHERE id = $1"#,
            ws.0
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?
        .ok_or(StoreError::NotFound)?;

        Ok(Workspace {
            id: WorkspaceId(row.id),
            name: row.name,
            owner_user_id: UserId(row.owner_user_id),
            kdf_salt: row.kdf_salt,
            m_cost_kib: row.kdf_m_cost_kib as u32,
            t_cost: row.kdf_t_cost as u32,
            p_cost: row.kdf_p_cost as u32,
            created_at: row.created_at,
            updated_at: row.updated_at,
        })
    }

    async fn get_workspace_by_name(
        &self,
        user_id: &UserId,
        name: &str,
    ) -> Result<Workspace, StoreError> {
        let row = sqlx::query!(
            r#"SELECT w.id, w.name, w.owner_user_id, w.kdf_salt, w.kdf_m_cost_kib, w.kdf_t_cost, w.kdf_p_cost,
               w.created_at, w.updated_at
               FROM workspaces w
               LEFT JOIN workspace_members wm ON w.id = wm.workspace_id
               WHERE w.name = $1 AND (w.owner_user_id = $2 OR wm.user_id = $2)
               LIMIT 1"#,
            name,
            user_id.0
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?
        .ok_or(StoreError::NotFound)?;

        Ok(Workspace {
            id: WorkspaceId(row.id),
            name: row.name,
            owner_user_id: UserId(row.owner_user_id),
            kdf_salt: row.kdf_salt,
            m_cost_kib: row.kdf_m_cost_kib as u32,
            t_cost: row.kdf_t_cost as u32,
            p_cost: row.kdf_p_cost as u32,
            created_at: row.created_at,
            updated_at: row.updated_at,
        })
    }

    async fn get_workspace_by_name_for_principal(
        &self,
        principal_id: &PrincipalId,
        name: &str,
    ) -> Result<Workspace, StoreError> {
        let row = sqlx::query!(
            r#"SELECT w.id, w.name, w.owner_user_id, w.kdf_salt, w.kdf_m_cost_kib, w.kdf_t_cost, w.kdf_p_cost,
               w.created_at, w.updated_at
               FROM workspaces w
               INNER JOIN workspace_principals wp ON w.id = wp.workspace_id
               WHERE w.name = $1 AND wp.principal_id = $2
               LIMIT 1"#,
            name,
            principal_id.0
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?
        .ok_or(StoreError::NotFound)?;

        Ok(Workspace {
            id: WorkspaceId(row.id),
            name: row.name,
            owner_user_id: UserId(row.owner_user_id),
            kdf_salt: row.kdf_salt,
            m_cost_kib: row.kdf_m_cost_kib as u32,
            t_cost: row.kdf_t_cost as u32,
            p_cost: row.kdf_p_cost as u32,
            created_at: row.created_at,
            updated_at: row.updated_at,
        })
    }

    async fn add_workspace_principal(
        &self,
        params: &AddWorkspacePrincipalParams,
    ) -> Result<(), StoreError> {
        sqlx::query!(
            "INSERT INTO workspace_principals(workspace_id, principal_id, ephemeral_pub, kek_wrapped, kek_nonce) VALUES($1, $2, $3, $4, $5)",
            params.workspace_id.0,
            params.principal_id.0,
            params.ephemeral_pub,
            params.kek_wrapped,
            params.kek_nonce
        )
        .execute(&self.pool)
        .await
        .map_err(|e| {
            let s = e.to_string();
            if s.contains("duplicate key") || s.contains("unique constraint") {
                StoreError::AlreadyExists
            } else {
                StoreError::Backend(s)
            }
        })?;
        Ok(())
    }

    async fn get_workspace_principal(
        &self,
        workspace_id: &WorkspaceId,
        principal_id: &PrincipalId,
    ) -> Result<WorkspacePrincipal, StoreError> {
        let row = sqlx::query!(
            r#"SELECT workspace_id, principal_id, ephemeral_pub, kek_wrapped, kek_nonce, created_at
               FROM workspace_principals WHERE workspace_id = $1 AND principal_id = $2"#,
            workspace_id.0,
            principal_id.0
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?
        .ok_or(StoreError::NotFound)?;

        Ok(WorkspacePrincipal {
            workspace_id: WorkspaceId(row.workspace_id),
            principal_id: PrincipalId(row.principal_id),
            ephemeral_pub: row.ephemeral_pub,
            kek_wrapped: row.kek_wrapped,
            kek_nonce: row.kek_nonce,
            created_at: row.created_at,
        })
    }

    async fn list_workspace_principals(
        &self,
        workspace_id: &WorkspaceId,
    ) -> Result<Vec<WorkspacePrincipal>, StoreError> {
        let rows = sqlx::query!(
            r#"SELECT workspace_id, principal_id, ephemeral_pub, kek_wrapped, kek_nonce, created_at
               FROM workspace_principals WHERE workspace_id = $1"#,
            workspace_id.0
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;

        Ok(rows
            .into_iter()
            .map(|row| WorkspacePrincipal {
                workspace_id: WorkspaceId(row.workspace_id),
                principal_id: PrincipalId(row.principal_id),
                ephemeral_pub: row.ephemeral_pub,
                kek_wrapped: row.kek_wrapped,
                kek_nonce: row.kek_nonce,
                created_at: row.created_at,
            })
            .collect())
    }

    async fn add_user_to_workspace(
        &self,
        workspace_id: &WorkspaceId,
        user_id: &UserId,
    ) -> Result<(), StoreError> {
        sqlx::query!(
            "INSERT INTO workspace_members(workspace_id, user_id) VALUES($1, $2)",
            workspace_id.0,
            user_id.0
        )
        .execute(&self.pool)
        .await
        .map_err(|e| {
            let s = e.to_string();
            if s.contains("duplicate key") || s.contains("unique constraint") {
                StoreError::AlreadyExists
            } else {
                StoreError::Backend(s)
            }
        })?;
        Ok(())
    }

    // ───────────────────────────── Projects ───────────────────────────────

    async fn create_project(
        &self,
        params: &CreateProjectParams,
    ) -> Result<zopp_storage::ProjectId, StoreError> {
        let id = Uuid::now_v7();

        sqlx::query!(
            "INSERT INTO projects(id, workspace_id, name) VALUES($1, $2, $3)",
            id,
            params.workspace_id.0,
            params.name
        )
        .execute(&self.pool)
        .await
        .map_err(|e| {
            let s = e.to_string();
            if s.contains("duplicate key") || s.contains("unique constraint") {
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
        let rows = sqlx::query!(
            r#"SELECT id, workspace_id, name, created_at, updated_at
               FROM projects WHERE workspace_id = $1 ORDER BY created_at DESC"#,
            workspace_id.0
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;

        Ok(rows
            .into_iter()
            .map(|row| zopp_storage::Project {
                id: zopp_storage::ProjectId(row.id),
                workspace_id: WorkspaceId(row.workspace_id),
                name: row.name,
                created_at: row.created_at,
                updated_at: row.updated_at,
            })
            .collect())
    }

    async fn get_project(
        &self,
        project_id: &zopp_storage::ProjectId,
    ) -> Result<zopp_storage::Project, StoreError> {
        let row = sqlx::query!(
            r#"SELECT id, workspace_id, name, created_at, updated_at
               FROM projects WHERE id = $1"#,
            project_id.0
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?
        .ok_or(StoreError::NotFound)?;

        Ok(zopp_storage::Project {
            id: zopp_storage::ProjectId(row.id),
            workspace_id: WorkspaceId(row.workspace_id),
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
        let row = sqlx::query!(
            r#"SELECT id, workspace_id, name, created_at, updated_at
               FROM projects WHERE workspace_id = $1 AND name = $2"#,
            workspace_id.0,
            name
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?
        .ok_or(StoreError::NotFound)?;

        Ok(zopp_storage::Project {
            id: zopp_storage::ProjectId(row.id),
            workspace_id: WorkspaceId(row.workspace_id),
            name: row.name,
            created_at: row.created_at,
            updated_at: row.updated_at,
        })
    }

    async fn delete_project(&self, project_id: &zopp_storage::ProjectId) -> Result<(), StoreError> {
        let result = sqlx::query!("DELETE FROM projects WHERE id = $1", project_id.0)
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

        let proj_row = sqlx::query!(
            "SELECT workspace_id FROM projects WHERE id = $1",
            params.project_id.0
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?
        .ok_or(StoreError::NotFound)?;

        sqlx::query!(
            "INSERT INTO environments(id, workspace_id, project_id, name, dek_wrapped, dek_nonce)
             VALUES($1, $2, $3, $4, $5, $6)",
            env_id,
            proj_row.workspace_id,
            params.project_id.0,
            params.name,
            params.dek_wrapped,
            params.dek_nonce
        )
        .execute(&self.pool)
        .await
        .map_err(|e| {
            let s = e.to_string();
            if s.contains("duplicate key") || s.contains("unique constraint") {
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
        let rows = sqlx::query!(
            r#"SELECT id, project_id, name, dek_wrapped, dek_nonce, version, created_at, updated_at
               FROM environments WHERE project_id = $1 ORDER BY created_at DESC"#,
            project_id.0
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;

        Ok(rows
            .into_iter()
            .map(|row| Environment {
                id: EnvironmentId(row.id),
                project_id: zopp_storage::ProjectId(row.project_id),
                name: row.name,
                dek_wrapped: row.dek_wrapped,
                dek_nonce: row.dek_nonce,
                version: row.version,
                created_at: row.created_at,
                updated_at: row.updated_at,
            })
            .collect())
    }

    async fn get_environment(&self, env_id: &EnvironmentId) -> Result<Environment, StoreError> {
        let row = sqlx::query!(
            r#"SELECT id, project_id, name, dek_wrapped, dek_nonce, version, created_at, updated_at
               FROM environments WHERE id = $1"#,
            env_id.0
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?
        .ok_or(StoreError::NotFound)?;

        Ok(Environment {
            id: EnvironmentId(row.id),
            project_id: zopp_storage::ProjectId(row.project_id),
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
        let row = sqlx::query!(
            r#"SELECT id, project_id, name, dek_wrapped, dek_nonce, version, created_at, updated_at
               FROM environments WHERE project_id = $1 AND name = $2"#,
            project_id.0,
            name
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?
        .ok_or(StoreError::NotFound)?;

        Ok(Environment {
            id: EnvironmentId(row.id),
            project_id: zopp_storage::ProjectId(row.project_id),
            name: row.name,
            dek_wrapped: row.dek_wrapped,
            dek_nonce: row.dek_nonce,
            version: row.version,
            created_at: row.created_at,
            updated_at: row.updated_at,
        })
    }

    async fn delete_environment(&self, env_id: &EnvironmentId) -> Result<(), StoreError> {
        let result = sqlx::query!("DELETE FROM environments WHERE id = $1", env_id.0)
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
        let row = sqlx::query!(
            "SELECT e.dek_wrapped, e.dek_nonce
             FROM environments e
             JOIN projects p ON p.id = e.project_id
             WHERE e.workspace_id = $1 AND p.workspace_id = $1 AND p.name = $2 AND e.name = $3",
            ws.0,
            project.0,
            env.0
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?
        .ok_or(StoreError::NotFound)?;

        Ok((row.dek_wrapped, row.dek_nonce))
    }

    // ────────────────────────────── Secrets ───────────────────────────────

    async fn upsert_secret(
        &self,
        env_id: &EnvironmentId,
        key: &str,
        nonce: &[u8],
        ciphertext: &[u8],
    ) -> Result<i64, StoreError> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))?;

        let env_row = sqlx::query!(
            "SELECT workspace_id FROM environments WHERE id = $1",
            env_id.0
        )
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?
        .ok_or(StoreError::NotFound)?;

        let secret_id = Uuid::now_v7();

        sqlx::query!(
            "INSERT INTO secrets(id, workspace_id, env_id, key_name, nonce, ciphertext)
             VALUES($1, $2, $3, $4, $5, $6)
             ON CONFLICT(workspace_id, env_id, key_name)
             DO UPDATE SET nonce = EXCLUDED.nonce, ciphertext = EXCLUDED.ciphertext",
            secret_id,
            env_row.workspace_id,
            env_id.0,
            key,
            nonce,
            ciphertext
        )
        .execute(&mut *tx)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;

        let result = sqlx::query!(
            "UPDATE environments SET version = version + 1 WHERE id = $1 RETURNING version",
            env_id.0
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
        let row = sqlx::query!(
            "SELECT nonce, ciphertext FROM secrets WHERE env_id = $1 AND key_name = $2",
            env_id.0,
            key
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?
        .ok_or(StoreError::NotFound)?;

        Ok(SecretRow {
            nonce: row.nonce,
            ciphertext: row.ciphertext,
        })
    }

    async fn list_secret_keys(&self, env_id: &EnvironmentId) -> Result<Vec<String>, StoreError> {
        let rows = sqlx::query!(
            "SELECT key_name FROM secrets WHERE env_id = $1 ORDER BY key_name",
            env_id.0
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;

        Ok(rows.into_iter().map(|row| row.key_name).collect())
    }

    async fn delete_secret(&self, env_id: &EnvironmentId, key: &str) -> Result<i64, StoreError> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))?;

        let result = sqlx::query!(
            "DELETE FROM secrets WHERE env_id = $1 AND key_name = $2",
            env_id.0,
            key
        )
        .execute(&mut *tx)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(StoreError::NotFound);
        }

        let version_result = sqlx::query!(
            "UPDATE environments SET version = version + 1 WHERE id = $1 RETURNING version",
            env_id.0
        )
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;

        tx.commit()
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))?;

        Ok(version_result.version)
    }
}

#[cfg(test)]
mod tests;
