use sqlx::{postgres::PgPoolOptions, PgPool};
use std::str::FromStr;
use uuid::Uuid;
use zopp_storage::{
    AddWorkspacePrincipalParams, CreateEnvParams, CreateInviteParams, CreatePrincipalParams,
    CreateProjectParams, CreateUserParams, CreateWorkspaceParams, EnvName, Environment,
    EnvironmentId, EnvironmentPermission, Invite, InviteId, Principal, PrincipalId, ProjectName,
    ProjectPermission, Role, SecretRow, Store, StoreError, User, UserEnvironmentPermission, UserId,
    UserProjectPermission, UserWorkspacePermission, Workspace, WorkspaceId, WorkspacePermission,
    WorkspacePrincipal,
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

    async fn remove_workspace_principal(
        &self,
        workspace_id: &WorkspaceId,
        principal_id: &PrincipalId,
    ) -> Result<(), StoreError> {
        sqlx::query!(
            "DELETE FROM workspace_principals WHERE workspace_id = $1 AND principal_id = $2",
            workspace_id.0,
            principal_id.0
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
        // Delete all project permissions for this principal in projects belonging to this workspace
        let result = sqlx::query!(
            r#"DELETE FROM project_permissions
               WHERE principal_id = $1
               AND project_id IN (SELECT id FROM projects WHERE workspace_id = $2)"#,
            principal_id.0,
            workspace_id.0
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
        // Delete all environment permissions for this principal in environments belonging to projects in this workspace
        let result = sqlx::query!(
            r#"DELETE FROM environment_permissions
               WHERE principal_id = $1
               AND environment_id IN (
                   SELECT e.id FROM environments e
                   JOIN projects p ON e.project_id = p.id
                   WHERE p.workspace_id = $2
               )"#,
            principal_id.0,
            workspace_id.0
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

    // ────────────────────────────── RBAC Permissions ───────────────────────────────

    async fn set_workspace_permission(
        &self,
        workspace_id: &WorkspaceId,
        principal_id: &PrincipalId,
        role: Role,
    ) -> Result<(), StoreError> {
        let role_str = role.as_str();

        sqlx::query!(
            "INSERT INTO workspace_permissions(workspace_id, principal_id, role) VALUES($1, $2, $3::text::role)
             ON CONFLICT(workspace_id, principal_id) DO UPDATE SET role = EXCLUDED.role",
            workspace_id.0,
            principal_id.0,
            role_str as _
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
        let row = sqlx::query!(
            "SELECT role as \"role: String\" FROM workspace_permissions WHERE workspace_id = $1 AND principal_id = $2",
            workspace_id.0,
            principal_id.0
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?
        .ok_or(StoreError::NotFound)?;

        Role::from_str(&row.role)
            .map_err(|e| StoreError::Backend(format!("invalid role in database: {}", e)))
    }

    async fn list_workspace_permissions_for_principal(
        &self,
        principal_id: &PrincipalId,
    ) -> Result<Vec<WorkspacePermission>, StoreError> {
        let rows = sqlx::query!(
            "SELECT workspace_id, principal_id, role as \"role: String\", created_at
             FROM workspace_permissions WHERE principal_id = $1",
            principal_id.0
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;

        let mut perms = Vec::with_capacity(rows.len());
        for row in rows {
            let role = Role::from_str(&row.role)
                .map_err(|e| StoreError::Backend(format!("invalid role in database: {}", e)))?;

            perms.push(WorkspacePermission {
                workspace_id: WorkspaceId(row.workspace_id),
                principal_id: PrincipalId(row.principal_id),
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
        let rows = sqlx::query!(
            "SELECT workspace_id, principal_id, role as \"role: String\", created_at
             FROM workspace_permissions WHERE workspace_id = $1",
            workspace_id.0
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;

        let mut perms = Vec::with_capacity(rows.len());
        for row in rows {
            let role = Role::from_str(&row.role)
                .map_err(|e| StoreError::Backend(format!("invalid role in database: {}", e)))?;

            perms.push(WorkspacePermission {
                workspace_id: WorkspaceId(row.workspace_id),
                principal_id: PrincipalId(row.principal_id),
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
        let result = sqlx::query!(
            "DELETE FROM workspace_permissions WHERE workspace_id = $1 AND principal_id = $2",
            workspace_id.0,
            principal_id.0
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
        let role_str = role.as_str();

        sqlx::query!(
            "INSERT INTO project_permissions(project_id, principal_id, role) VALUES($1, $2, $3::text::role)
             ON CONFLICT(project_id, principal_id) DO UPDATE SET role = EXCLUDED.role",
            project_id.0,
            principal_id.0,
            role_str as _
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
        let row = sqlx::query!(
            "SELECT role as \"role: String\" FROM project_permissions WHERE project_id = $1 AND principal_id = $2",
            project_id.0,
            principal_id.0
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?
        .ok_or(StoreError::NotFound)?;

        Role::from_str(&row.role)
            .map_err(|e| StoreError::Backend(format!("invalid role in database: {}", e)))
    }

    async fn list_project_permissions_for_principal(
        &self,
        principal_id: &PrincipalId,
    ) -> Result<Vec<ProjectPermission>, StoreError> {
        let rows = sqlx::query!(
            "SELECT project_id, principal_id, role as \"role: String\", created_at
             FROM project_permissions WHERE principal_id = $1",
            principal_id.0
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;

        let mut perms = Vec::with_capacity(rows.len());
        for row in rows {
            let role = Role::from_str(&row.role)
                .map_err(|e| StoreError::Backend(format!("invalid role in database: {}", e)))?;

            perms.push(ProjectPermission {
                project_id: zopp_storage::ProjectId(row.project_id),
                principal_id: PrincipalId(row.principal_id),
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
        let rows = sqlx::query!(
            "SELECT project_id, principal_id, role as \"role: String\", created_at
             FROM project_permissions WHERE project_id = $1",
            project_id.0
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;

        let mut perms = Vec::with_capacity(rows.len());
        for row in rows {
            let role = Role::from_str(&row.role)
                .map_err(|e| StoreError::Backend(format!("invalid role in database: {}", e)))?;

            perms.push(ProjectPermission {
                project_id: zopp_storage::ProjectId(row.project_id),
                principal_id: PrincipalId(row.principal_id),
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
        let result = sqlx::query!(
            "DELETE FROM project_permissions WHERE project_id = $1 AND principal_id = $2",
            project_id.0,
            principal_id.0
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
        let role_str = role.as_str();

        sqlx::query!(
            "INSERT INTO environment_permissions(environment_id, principal_id, role) VALUES($1, $2, $3::text::role)
             ON CONFLICT(environment_id, principal_id) DO UPDATE SET role = EXCLUDED.role",
            environment_id.0,
            principal_id.0,
            role_str as _
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
        let row = sqlx::query!(
            "SELECT role as \"role: String\" FROM environment_permissions WHERE environment_id = $1 AND principal_id = $2",
            environment_id.0,
            principal_id.0
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?
        .ok_or(StoreError::NotFound)?;

        Role::from_str(&row.role)
            .map_err(|e| StoreError::Backend(format!("invalid role in database: {}", e)))
    }

    async fn list_environment_permissions_for_principal(
        &self,
        principal_id: &PrincipalId,
    ) -> Result<Vec<EnvironmentPermission>, StoreError> {
        let rows = sqlx::query!(
            "SELECT environment_id, principal_id, role as \"role: String\", created_at
             FROM environment_permissions WHERE principal_id = $1",
            principal_id.0
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;

        let mut perms = Vec::with_capacity(rows.len());
        for row in rows {
            let role = Role::from_str(&row.role)
                .map_err(|e| StoreError::Backend(format!("invalid role in database: {}", e)))?;

            perms.push(EnvironmentPermission {
                environment_id: EnvironmentId(row.environment_id),
                principal_id: PrincipalId(row.principal_id),
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
        let rows = sqlx::query!(
            "SELECT environment_id, principal_id, role as \"role: String\", created_at
             FROM environment_permissions WHERE environment_id = $1",
            environment_id.0
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;

        let mut perms = Vec::with_capacity(rows.len());
        for row in rows {
            let role = Role::from_str(&row.role)
                .map_err(|e| StoreError::Backend(format!("invalid role in database: {}", e)))?;

            perms.push(EnvironmentPermission {
                environment_id: EnvironmentId(row.environment_id),
                principal_id: PrincipalId(row.principal_id),
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
        let result = sqlx::query!(
            "DELETE FROM environment_permissions WHERE environment_id = $1 AND principal_id = $2",
            environment_id.0,
            principal_id.0
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

        sqlx::query!(
            "INSERT INTO groups(id, workspace_id, name, description) VALUES($1, $2, $3, $4)",
            group_id,
            params.workspace_id.0,
            params.name,
            params.description
        )
        .execute(&self.pool)
        .await
        .map_err(|e| {
            if e.to_string().contains("duplicate key") {
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
        let row = sqlx::query!(
            "SELECT id, workspace_id, name, description, created_at, updated_at FROM groups WHERE id = $1",
            group_id.0
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?
        .ok_or(StoreError::NotFound)?;

        Ok(zopp_storage::Group {
            id: zopp_storage::GroupId(row.id),
            workspace_id: WorkspaceId(row.workspace_id),
            name: row.name,
            description: row.description,
            created_at: row.created_at,
            updated_at: row.updated_at,
        })
    }

    async fn get_group_by_name(
        &self,
        workspace_id: &WorkspaceId,
        name: &str,
    ) -> Result<zopp_storage::Group, StoreError> {
        let row = sqlx::query!(
            "SELECT id, workspace_id, name, description, created_at, updated_at FROM groups WHERE workspace_id = $1 AND name = $2",
            workspace_id.0,
            name
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?
        .ok_or(StoreError::NotFound)?;

        Ok(zopp_storage::Group {
            id: zopp_storage::GroupId(row.id),
            workspace_id: WorkspaceId(row.workspace_id),
            name: row.name,
            description: row.description,
            created_at: row.created_at,
            updated_at: row.updated_at,
        })
    }

    async fn list_groups(
        &self,
        workspace_id: &WorkspaceId,
    ) -> Result<Vec<zopp_storage::Group>, StoreError> {
        let rows = sqlx::query!(
            "SELECT id, workspace_id, name, description, created_at, updated_at FROM groups WHERE workspace_id = $1 ORDER BY name",
            workspace_id.0
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;

        Ok(rows
            .into_iter()
            .map(|row| zopp_storage::Group {
                id: zopp_storage::GroupId(row.id),
                workspace_id: WorkspaceId(row.workspace_id),
                name: row.name,
                description: row.description,
                created_at: row.created_at,
                updated_at: row.updated_at,
            })
            .collect())
    }

    async fn update_group(
        &self,
        group_id: &zopp_storage::GroupId,
        name: &str,
        description: Option<&str>,
    ) -> Result<(), StoreError> {
        let result = sqlx::query!(
            "UPDATE groups SET name = $1, description = $2, updated_at = NOW() WHERE id = $3",
            name,
            description,
            group_id.0
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
        let result = sqlx::query!("DELETE FROM groups WHERE id = $1", group_id.0)
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
        sqlx::query!(
            "INSERT INTO group_members(group_id, user_id) VALUES($1, $2)",
            group_id.0,
            user_id.0
        )
        .execute(&self.pool)
        .await
        .map_err(|e| {
            if e.to_string().contains("duplicate key") {
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
        let result = sqlx::query!(
            "DELETE FROM group_members WHERE group_id = $1 AND user_id = $2",
            group_id.0,
            user_id.0
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
        let rows = sqlx::query!(
            "SELECT group_id, user_id, created_at FROM group_members WHERE group_id = $1",
            group_id.0
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;

        Ok(rows
            .into_iter()
            .map(|row| zopp_storage::GroupMember {
                group_id: zopp_storage::GroupId(row.group_id),
                user_id: UserId(row.user_id),
                created_at: row.created_at,
            })
            .collect())
    }

    async fn list_user_groups(
        &self,
        user_id: &UserId,
    ) -> Result<Vec<zopp_storage::Group>, StoreError> {
        let rows = sqlx::query!(
            "SELECT g.id, g.workspace_id, g.name, g.description, g.created_at, g.updated_at
             FROM groups g
             INNER JOIN group_members gm ON g.id = gm.group_id
             WHERE gm.user_id = $1
             ORDER BY g.name",
            user_id.0
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;

        Ok(rows
            .into_iter()
            .map(|row| zopp_storage::Group {
                id: zopp_storage::GroupId(row.id),
                workspace_id: WorkspaceId(row.workspace_id),
                name: row.name,
                description: row.description,
                created_at: row.created_at,
                updated_at: row.updated_at,
            })
            .collect())
    }

    async fn set_group_workspace_permission(
        &self,
        workspace_id: &WorkspaceId,
        group_id: &zopp_storage::GroupId,
        role: Role,
    ) -> Result<(), StoreError> {
        let role_str = role.as_str();

        sqlx::query!(
            "INSERT INTO group_workspace_permissions(workspace_id, group_id, role) VALUES($1, $2, $3::text::role)
             ON CONFLICT(workspace_id, group_id) DO UPDATE SET role = EXCLUDED.role",
            workspace_id.0,
            group_id.0,
            role_str as _
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
        let row = sqlx::query!(
            "SELECT role as \"role: String\" FROM group_workspace_permissions WHERE workspace_id = $1 AND group_id = $2",
            workspace_id.0,
            group_id.0
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
        let rows = sqlx::query!(
            "SELECT workspace_id, group_id, role as \"role: String\", created_at FROM group_workspace_permissions WHERE workspace_id = $1",
            workspace_id.0
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;

        let mut perms = Vec::with_capacity(rows.len());
        for row in rows {
            let role = Role::from_str(&row.role)
                .map_err(|e| StoreError::Backend(format!("invalid role in database: {}", e)))?;
            perms.push(zopp_storage::GroupWorkspacePermission {
                workspace_id: WorkspaceId(row.workspace_id),
                group_id: zopp_storage::GroupId(row.group_id),
                role,
                created_at: row.created_at,
            });
        }
        Ok(perms)
    }

    async fn remove_group_workspace_permission(
        &self,
        workspace_id: &WorkspaceId,
        group_id: &zopp_storage::GroupId,
    ) -> Result<(), StoreError> {
        let result = sqlx::query!(
            "DELETE FROM group_workspace_permissions WHERE workspace_id = $1 AND group_id = $2",
            workspace_id.0,
            group_id.0
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
        let role_str = role.as_str();

        sqlx::query!(
            "INSERT INTO group_project_permissions(project_id, group_id, role) VALUES($1, $2, $3::text::role)
             ON CONFLICT(project_id, group_id) DO UPDATE SET role = EXCLUDED.role",
            project_id.0,
            group_id.0,
            role_str as _
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
        let row = sqlx::query!(
            "SELECT role as \"role: String\" FROM group_project_permissions WHERE project_id = $1 AND group_id = $2",
            project_id.0,
            group_id.0
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
        let rows = sqlx::query!(
            "SELECT project_id, group_id, role as \"role: String\", created_at FROM group_project_permissions WHERE project_id = $1",
            project_id.0
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;

        let mut perms = Vec::with_capacity(rows.len());
        for row in rows {
            let role = Role::from_str(&row.role)
                .map_err(|e| StoreError::Backend(format!("invalid role in database: {}", e)))?;
            perms.push(zopp_storage::GroupProjectPermission {
                project_id: zopp_storage::ProjectId(row.project_id),
                group_id: zopp_storage::GroupId(row.group_id),
                role,
                created_at: row.created_at,
            });
        }
        Ok(perms)
    }

    async fn remove_group_project_permission(
        &self,
        project_id: &zopp_storage::ProjectId,
        group_id: &zopp_storage::GroupId,
    ) -> Result<(), StoreError> {
        let result = sqlx::query!(
            "DELETE FROM group_project_permissions WHERE project_id = $1 AND group_id = $2",
            project_id.0,
            group_id.0
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
        let role_str = role.as_str();

        sqlx::query!(
            "INSERT INTO group_environment_permissions(environment_id, group_id, role) VALUES($1, $2, $3::text::role)
             ON CONFLICT(environment_id, group_id) DO UPDATE SET role = EXCLUDED.role",
            environment_id.0,
            group_id.0,
            role_str as _
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
        let row = sqlx::query!(
            "SELECT role as \"role: String\" FROM group_environment_permissions WHERE environment_id = $1 AND group_id = $2",
            environment_id.0,
            group_id.0
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
        let rows = sqlx::query!(
            "SELECT environment_id, group_id, role as \"role: String\", created_at FROM group_environment_permissions WHERE environment_id = $1",
            environment_id.0
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;

        let mut perms = Vec::with_capacity(rows.len());
        for row in rows {
            let role = Role::from_str(&row.role)
                .map_err(|e| StoreError::Backend(format!("invalid role in database: {}", e)))?;
            perms.push(zopp_storage::GroupEnvironmentPermission {
                environment_id: EnvironmentId(row.environment_id),
                group_id: zopp_storage::GroupId(row.group_id),
                role,
                created_at: row.created_at,
            });
        }
        Ok(perms)
    }

    async fn remove_group_environment_permission(
        &self,
        environment_id: &EnvironmentId,
        group_id: &zopp_storage::GroupId,
    ) -> Result<(), StoreError> {
        let result = sqlx::query!(
            "DELETE FROM group_environment_permissions WHERE environment_id = $1 AND group_id = $2",
            environment_id.0,
            group_id.0
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
        let role_str = role.as_str();

        sqlx::query!(
            "INSERT INTO user_workspace_permissions(workspace_id, user_id, role) VALUES($1, $2, $3::text::role)
             ON CONFLICT(workspace_id, user_id) DO UPDATE SET role = EXCLUDED.role, updated_at = NOW()",
            workspace_id.0,
            user_id.0,
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
        let row = sqlx::query!(
            "SELECT role as \"role: String\" FROM user_workspace_permissions WHERE workspace_id = $1 AND user_id = $2",
            workspace_id.0,
            user_id.0
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
        let rows = sqlx::query!(
            "SELECT workspace_id, user_id, role as \"role: String\", created_at FROM user_workspace_permissions WHERE workspace_id = $1",
            workspace_id.0
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;

        let mut perms = Vec::with_capacity(rows.len());
        for row in rows {
            let role = Role::from_str(&row.role)
                .map_err(|e| StoreError::Backend(format!("invalid role in database: {}", e)))?;
            perms.push(UserWorkspacePermission {
                workspace_id: WorkspaceId(row.workspace_id),
                user_id: UserId(row.user_id),
                role,
                created_at: row.created_at,
            });
        }
        Ok(perms)
    }

    async fn remove_user_workspace_permission(
        &self,
        workspace_id: &WorkspaceId,
        user_id: &UserId,
    ) -> Result<(), StoreError> {
        let result = sqlx::query!(
            "DELETE FROM user_workspace_permissions WHERE workspace_id = $1 AND user_id = $2",
            workspace_id.0,
            user_id.0
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
        let role_str = role.as_str();

        sqlx::query!(
            "INSERT INTO user_project_permissions(project_id, user_id, role) VALUES($1, $2, $3::text::role)
             ON CONFLICT(project_id, user_id) DO UPDATE SET role = EXCLUDED.role, updated_at = NOW()",
            project_id.0,
            user_id.0,
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
        let row = sqlx::query!(
            "SELECT role as \"role: String\" FROM user_project_permissions WHERE project_id = $1 AND user_id = $2",
            project_id.0,
            user_id.0
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
        let rows = sqlx::query!(
            "SELECT project_id, user_id, role as \"role: String\", created_at FROM user_project_permissions WHERE project_id = $1",
            project_id.0
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;

        let mut perms = Vec::with_capacity(rows.len());
        for row in rows {
            let role = Role::from_str(&row.role)
                .map_err(|e| StoreError::Backend(format!("invalid role in database: {}", e)))?;
            perms.push(UserProjectPermission {
                project_id: zopp_storage::ProjectId(row.project_id),
                user_id: UserId(row.user_id),
                role,
                created_at: row.created_at,
            });
        }
        Ok(perms)
    }

    async fn remove_user_project_permission(
        &self,
        project_id: &zopp_storage::ProjectId,
        user_id: &UserId,
    ) -> Result<(), StoreError> {
        let result = sqlx::query!(
            "DELETE FROM user_project_permissions WHERE project_id = $1 AND user_id = $2",
            project_id.0,
            user_id.0
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
        let role_str = role.as_str();

        sqlx::query!(
            "INSERT INTO user_environment_permissions(environment_id, user_id, role) VALUES($1, $2, $3::text::role)
             ON CONFLICT(environment_id, user_id) DO UPDATE SET role = EXCLUDED.role, updated_at = NOW()",
            environment_id.0,
            user_id.0,
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
        let row = sqlx::query!(
            "SELECT role as \"role: String\" FROM user_environment_permissions WHERE environment_id = $1 AND user_id = $2",
            environment_id.0,
            user_id.0
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
        let rows = sqlx::query!(
            "SELECT environment_id, user_id, role as \"role: String\", created_at FROM user_environment_permissions WHERE environment_id = $1",
            environment_id.0
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;

        let mut perms = Vec::with_capacity(rows.len());
        for row in rows {
            let role = Role::from_str(&row.role)
                .map_err(|e| StoreError::Backend(format!("invalid role in database: {}", e)))?;
            perms.push(UserEnvironmentPermission {
                environment_id: EnvironmentId(row.environment_id),
                user_id: UserId(row.user_id),
                role,
                created_at: row.created_at,
            });
        }
        Ok(perms)
    }

    async fn remove_user_environment_permission(
        &self,
        environment_id: &EnvironmentId,
        user_id: &UserId,
    ) -> Result<(), StoreError> {
        let result = sqlx::query!(
            "DELETE FROM user_environment_permissions WHERE environment_id = $1 AND user_id = $2",
            environment_id.0,
            user_id.0
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
mod tests;
