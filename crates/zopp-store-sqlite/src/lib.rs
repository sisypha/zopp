use chrono::Utc;
use sqlx::{SqlitePool, sqlite::SqlitePoolOptions};
use uuid::Uuid;
use zopp_storage::{
    EnvName, ProjectName, SecretRow, Store, StoreError, Transaction, WorkspaceId, WorkspaceParams,
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

    // ───────────────────────────── Workspaces ─────────────────────────────

    async fn create_workspace(&self, p: &WorkspaceParams) -> Result<WorkspaceId, StoreError> {
        let ws_id = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO workspaces(id,kdf_salt,kdf_m_cost_kib,kdf_t_cost,kdf_p_cost,created_at)
             VALUES(?,?,?,?,?,?)",
        )
        .bind(ws_id.to_string())
        .bind(&p.kdf_salt)
        .bind(p.m_cost_kib as i64)
        .bind(p.t_cost as i64)
        .bind(p.p_cost as i64)
        .bind(Utc::now().timestamp())
        .execute(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;
        Ok(WorkspaceId(ws_id))
    }

    async fn list_workspaces(&self) -> Result<Vec<WorkspaceId>, StoreError> {
        let rows = sqlx::query_as::<_, (String,)>("SELECT id FROM workspaces")
            .fetch_all(&self.pool)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))?;
        let mut out = Vec::with_capacity(rows.len());
        for (id_str,) in rows {
            let id = Uuid::try_parse(&id_str).map_err(|e| StoreError::Backend(e.to_string()))?;
            out.push(WorkspaceId(id));
        }
        Ok(out)
    }

    async fn get_workspace(&self, ws: &WorkspaceId) -> Result<WorkspaceParams, StoreError> {
        let row = sqlx::query_as::<_, (Vec<u8>, i64, i64, i64)>(
            "SELECT kdf_salt,kdf_m_cost_kib,kdf_t_cost,kdf_p_cost FROM workspaces WHERE id=?",
        )
        .bind(ws.0.to_string())
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;

        match row {
            None => Err(StoreError::NotFound),
            Some((salt, m, t, p)) => Ok(WorkspaceParams {
                kdf_salt: salt,
                m_cost_kib: m as u32,
                t_cost: t as u32,
                p_cost: p as u32,
            }),
        }
    }

    // ───────────────────────────── Projects ───────────────────────────────

    async fn create_project(&self, ws: &WorkspaceId, name: &ProjectName) -> Result<(), StoreError> {
        let id = Uuid::now_v7().to_string();
        sqlx::query("INSERT INTO projects(id,workspace_id,name) VALUES(?,?,?)")
            .bind(&id)
            .bind(ws.0.to_string())
            .bind(&name.0)
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
        Ok(())
    }

    // ──────────────────────────── Environments ────────────────────────────

    async fn create_env(
        &self,
        ws: &WorkspaceId,
        project: &ProjectName,
        env: &EnvName,
        dek_wrapped: &[u8],
        dek_nonce: &[u8],
    ) -> Result<(), StoreError> {
        // find project id inside this workspace
        let proj_id: Option<(String,)> =
            sqlx::query_as("SELECT id FROM projects WHERE workspace_id=? AND name=?")
                .bind(ws.0.to_string())
                .bind(&project.0)
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| StoreError::Backend(e.to_string()))?;

        let proj_id = match proj_id {
            Some((id,)) => id,
            None => return Err(StoreError::NotFound),
        };

        let env_id = Uuid::now_v7().to_string();
        sqlx::query(
            "INSERT INTO environments(id,workspace_id,project_id,name,dek_wrapped,dek_nonce)
             VALUES(?,?,?,?,?,?)",
        )
        .bind(&env_id)
        .bind(ws.0.to_string())
        .bind(proj_id)
        .bind(&env.0)
        .bind(dek_wrapped)
        .bind(dek_nonce)
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

        Ok(())
    }

    async fn get_env_wrap(
        &self,
        ws: &WorkspaceId,
        project: &ProjectName,
        env: &EnvName,
    ) -> Result<(Vec<u8>, Vec<u8>), StoreError> {
        let row = sqlx::query_as::<_, (Vec<u8>, Vec<u8>)>(
            "SELECT e.dek_wrapped, e.dek_nonce
             FROM environments e
             JOIN projects p ON p.id=e.project_id
             WHERE e.workspace_id=? AND p.workspace_id=? AND p.name=? AND e.name=?",
        )
        .bind(ws.0.to_string())
        .bind(ws.0.to_string())
        .bind(&project.0)
        .bind(&env.0)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;

        row.ok_or(StoreError::NotFound)
    }

    // ────────────────────────────── Secrets ───────────────────────────────

    async fn upsert_secret(
        &self,
        ws: &WorkspaceId,
        project: &ProjectName,
        env: &EnvName,
        key: &str,
        nonce: &[u8],
        ciphertext: &[u8],
    ) -> Result<(), StoreError> {
        // find env id within workspace & project
        let env_id: Option<(String,)> = sqlx::query_as(
            "SELECT e.id
               FROM environments e
               JOIN projects p ON p.id=e.project_id
              WHERE e.workspace_id=? AND p.workspace_id=? AND p.name=? AND e.name=?",
        )
        .bind(ws.0.to_string())
        .bind(ws.0.to_string())
        .bind(&project.0)
        .bind(&env.0)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;

        let env_id = match env_id {
            Some((id,)) => id,
            None => return Err(StoreError::NotFound),
        };

        let secret_id = Uuid::now_v7().to_string();

        sqlx::query(
            "INSERT INTO secrets(id,workspace_id,env_id,key_name,nonce,ciphertext,created_at)
             VALUES(?,?,?,?,?,?,?)
             ON CONFLICT(workspace_id,env_id,key_name)
             DO UPDATE SET nonce=excluded.nonce,
                           ciphertext=excluded.ciphertext,
                           created_at=excluded.created_at",
        )
        .bind(&secret_id)
        .bind(ws.0.to_string())
        .bind(env_id)
        .bind(key)
        .bind(nonce)
        .bind(ciphertext)
        .bind(Utc::now().timestamp())
        .execute(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;

        Ok(())
    }

    async fn get_secret(
        &self,
        ws: &WorkspaceId,
        project: &ProjectName,
        env: &EnvName,
        key: &str,
    ) -> Result<SecretRow, StoreError> {
        let row = sqlx::query_as::<_, (Vec<u8>, Vec<u8>)>(
            "SELECT s.nonce, s.ciphertext
               FROM secrets s
               JOIN environments e ON e.id=s.env_id
               JOIN projects p ON p.id=e.project_id
              WHERE s.workspace_id=?
                AND e.workspace_id=?
                AND p.workspace_id=?
                AND p.name=? AND e.name=? AND s.key_name=?",
        )
        .bind(ws.0.to_string())
        .bind(ws.0.to_string())
        .bind(ws.0.to_string())
        .bind(&project.0)
        .bind(&env.0)
        .bind(key)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;

        match row {
            None => Err(StoreError::NotFound),
            Some((nonce, ciphertext)) => Ok(SecretRow { nonce, ciphertext }),
        }
    }

    async fn list_secret_keys(
        &self,
        ws: &WorkspaceId,
        project: &ProjectName,
        env: &EnvName,
    ) -> Result<Vec<String>, StoreError> {
        let rows = sqlx::query_as::<_, (String,)>(
            "SELECT s.key_name
               FROM secrets s
               JOIN environments e ON e.id=s.env_id
               JOIN projects p ON p.id=e.project_id
              WHERE s.workspace_id=?
                AND e.workspace_id=?
                AND p.workspace_id=?
                AND p.name=? AND e.name=?
              ORDER BY s.key_name",
        )
        .bind(ws.0.to_string())
        .bind(ws.0.to_string())
        .bind(ws.0.to_string())
        .bind(&project.0)
        .bind(&env.0)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;

        Ok(rows.into_iter().map(|(k,)| k).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zopp_storage::{EnvName, ProjectName, StoreError, WorkspaceParams};

    fn params() -> WorkspaceParams {
        WorkspaceParams {
            kdf_salt: b"abcdef0123456789".to_vec(),
            m_cost_kib: 1024,
            t_cost: 2,
            p_cost: 1,
        }
    }

    #[tokio::test]
    async fn workspace_params_roundtrip() {
        let s = SqliteStore::open_in_memory().await.unwrap();
        let ws = s.create_workspace(&params()).await.unwrap();
        let got = s.get_workspace(&ws).await.unwrap();
        assert_eq!(got.kdf_salt, params().kdf_salt);
        assert_eq!(got.m_cost_kib, params().m_cost_kib);
        assert_eq!(got.t_cost, params().t_cost);
        assert_eq!(got.p_cost, params().p_cost);
    }

    #[tokio::test]
    async fn duplicate_project_maps_to_alreadyexists() {
        let s = SqliteStore::open_in_memory().await.unwrap();
        let ws = s.create_workspace(&params()).await.unwrap();
        let name = ProjectName("app".into());

        s.create_project(&ws, &name).await.unwrap();
        let err = s.create_project(&ws, &name).await.unwrap_err();

        matches!(err, StoreError::AlreadyExists);
    }

    #[tokio::test]
    async fn workspace_scoping_isolation() {
        let s = SqliteStore::open_in_memory().await.unwrap();
        let ws1 = s.create_workspace(&params()).await.unwrap();
        let ws2 = s.create_workspace(&params()).await.unwrap();

        let p = ProjectName("app".into());
        let e = EnvName("prod".into());

        s.create_project(&ws1, &p).await.unwrap();
        s.create_env(&ws1, &p, &e, &[1], &[9; 24]).await.unwrap();

        s.create_project(&ws2, &p).await.unwrap();
        s.create_env(&ws2, &p, &e, &[2], &[9; 24]).await.unwrap();

        // only insert secret into ws1
        s.upsert_secret(&ws1, &p, &e, "TOKEN", &[7; 24], &[1; 8])
            .await
            .unwrap();

        // ws2 must NOT be able to see ws1's secret
        let err = s.get_secret(&ws2, &p, &e, "TOKEN").await.unwrap_err();
        matches!(err, StoreError::NotFound);
    }

    #[tokio::test]
    async fn list_secret_keys_returns_sorted() {
        let s = SqliteStore::open_in_memory().await.unwrap();
        let ws = s.create_workspace(&params()).await.unwrap();

        let p = ProjectName("app".into());
        let e = EnvName("prod".into());
        s.create_project(&ws, &p).await.unwrap();
        s.create_env(&ws, &p, &e, &[1], &[9; 24]).await.unwrap();

        s.upsert_secret(&ws, &p, &e, "z_last", &[7; 24], &[1])
            .await
            .unwrap();
        s.upsert_secret(&ws, &p, &e, "a_first", &[7; 24], &[1])
            .await
            .unwrap();
        s.upsert_secret(&ws, &p, &e, "m_middle", &[7; 24], &[1])
            .await
            .unwrap();

        let keys = s.list_secret_keys(&ws, &p, &e).await.unwrap();
        assert_eq!(keys, vec!["a_first", "m_middle", "z_last"]);
    }

    #[tokio::test]
    async fn create_env_requires_existing_project() {
        let s = SqliteStore::open_in_memory().await.unwrap();
        let ws = s.create_workspace(&params()).await.unwrap();

        // No project "app" yet → creating env should fail with NotFound
        let err = s
            .create_env(
                &ws,
                &ProjectName("app".into()),
                &EnvName("prod".into()),
                &[1],
                &[9; 24],
            )
            .await
            .unwrap_err();
        matches!(err, StoreError::NotFound);
    }

    #[tokio::test]
    async fn duplicate_env_maps_to_alreadyexists() {
        let s = SqliteStore::open_in_memory().await.unwrap();
        let ws = s.create_workspace(&params()).await.unwrap();
        let p = ProjectName("app".into());
        let e = EnvName("prod".into());

        s.create_project(&ws, &p).await.unwrap();
        s.create_env(&ws, &p, &e, &[1], &[9; 24]).await.unwrap();
        let err = s.create_env(&ws, &p, &e, &[1], &[9; 24]).await.unwrap_err();
        matches!(err, StoreError::AlreadyExists);
    }

    #[tokio::test]
    async fn upsert_secret_overwrites_value_and_nonce() {
        let s = SqliteStore::open_in_memory().await.unwrap();
        let ws = s.create_workspace(&params()).await.unwrap();

        let p = ProjectName("app".into());
        let e = EnvName("prod".into());
        s.create_project(&ws, &p).await.unwrap();
        s.create_env(&ws, &p, &e, &[1], &[9; 24]).await.unwrap();

        s.upsert_secret(&ws, &p, &e, "API", &[1; 24], &[10; 4])
            .await
            .unwrap();
        let a = s.get_secret(&ws, &p, &e, "API").await.unwrap();

        s.upsert_secret(&ws, &p, &e, "API", &[2; 24], &[20; 6])
            .await
            .unwrap();
        let b = s.get_secret(&ws, &p, &e, "API").await.unwrap();

        assert_ne!(a.nonce, b.nonce);
        assert_ne!(a.ciphertext, b.ciphertext);
        assert_eq!(b.nonce, vec![2; 24]);
        assert_eq!(b.ciphertext, vec![20; 6]);
    }

    #[tokio::test]
    async fn get_env_wrap_scoped_by_workspace() {
        let s = SqliteStore::open_in_memory().await.unwrap();
        let ws1 = s.create_workspace(&params()).await.unwrap();
        let ws2 = s.create_workspace(&params()).await.unwrap();

        let p = ProjectName("app".into());
        let e = EnvName("prod".into());

        s.create_project(&ws1, &p).await.unwrap();
        s.create_env(&ws1, &p, &e, b"wrap1", &[9; 24])
            .await
            .unwrap();

        s.create_project(&ws2, &p).await.unwrap();
        s.create_env(&ws2, &p, &e, b"wrap2", &[8; 24])
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
    async fn list_workspaces_includes_new_workspace() {
        let s = SqliteStore::open_in_memory().await.unwrap();
        let ws = s.create_workspace(&params()).await.unwrap();
        let all = s.list_workspaces().await.unwrap();
        assert!(all.iter().any(|id| id == &ws));
    }

    #[tokio::test]
    async fn unicode_keys_and_names_roundtrip() {
        let s = SqliteStore::open_in_memory().await.unwrap();
        let ws = s.create_workspace(&params()).await.unwrap();

        let p = ProjectName("🚀-プロジェクト".into());
        let e = EnvName("生产".into());
        let k = "🔑-секрет";

        s.create_project(&ws, &p).await.unwrap();
        s.create_env(&ws, &p, &e, &[1, 2, 3], &[9; 24])
            .await
            .unwrap();
        s.upsert_secret(&ws, &p, &e, k, &[7; 24], &[1, 2, 3, 4])
            .await
            .unwrap();

        let row = s.get_secret(&ws, &p, &e, k).await.unwrap();
        assert_eq!(row.ciphertext, vec![1, 2, 3, 4]);

        let keys = s.list_secret_keys(&ws, &p, &e).await.unwrap();
        assert_eq!(keys, vec![k]);
    }
}
