//! Storage abstraction for zopp.
//!
//! Backend crates (e.g., zopp-store-sqlite, zopp-store-postgres) implement this trait so
//! `zopp-core` doesn’t depend on any specific database engine or schema details.

use thiserror::Error;
use uuid::Uuid;

/// Uniform error type for all storage backends.
#[derive(Debug, Error)]
pub enum StoreError {
    #[error("not found")]
    NotFound,
    #[error("already exists")]
    AlreadyExists,
    #[error("conflict")]
    Conflict,
    #[error("backend error: {0}")]
    Backend(String),
}

/// Strongly-typed identifiers & names (avoid mixing strings arbitrarily).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct WorkspaceId(pub Uuid);

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ProjectName(pub String);

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct EnvName(pub String);

/// Workspace-wide KDF parameters (persisted by the store).
#[derive(Clone, Debug)]
pub struct WorkspaceParams {
    pub kdf_salt: Vec<u8>, // >= 16 bytes
    pub m_cost_kib: u32,   // memory cost (KiB)
    pub t_cost: u32,       // iterations
    pub p_cost: u32,       // parallelism
}

/// Encrypted secret row (nonce + ciphertext); no plaintext in storage.
#[derive(Clone, Debug)]
pub struct SecretRow {
    pub nonce: Vec<u8>,      // 24 bytes (XChaCha20 nonce)
    pub ciphertext: Vec<u8>, // AEAD ciphertext
}

/// Optional explicit transaction interface.
/// For simple backends you can stub this out and let methods be atomic.
pub trait Transaction {
    fn commit(self) -> Result<(), StoreError>;
    fn rollback(self) -> Result<(), StoreError>;
}

/// The storage trait `zopp-core` depends on.
///
/// All methods that act on project/env/secrets are **scoped by workspace**.
#[async_trait::async_trait]
pub trait Store {
    type Txn: Transaction;

    // ─────────────────────────────── Lifecycle  ───────────────────────────────

    /// Optional explicit transaction (backends may ignore if not needed).
    async fn begin_txn(&self) -> Result<Self::Txn, StoreError>;

    // ───────────────────────────────────── Workspaces ─────────────────────────────────────

    /// Create a new workspace (returns its generated ID).
    async fn create_workspace(&self, params: &WorkspaceParams) -> Result<WorkspaceId, StoreError>;

    /// List all workspace IDs present in this store.
    async fn list_workspaces(&self) -> Result<Vec<WorkspaceId>, StoreError>;

    /// Fetch KDF parameters for a workspace.
    async fn get_workspace(&self, ws: &WorkspaceId) -> Result<WorkspaceParams, StoreError>;

    // ───────────────────────────────────── Projects ───────────────────────────────────────

    /// Create a project within a workspace.
    async fn create_project(&self, ws: &WorkspaceId, name: &ProjectName) -> Result<(), StoreError>;

    // ─────────────────────────────────────── Environments ─────────────────────────────────────

    /// Create an environment within a project, storing the wrapped DEK + its nonce.
    async fn create_env(
        &self,
        ws: &WorkspaceId,
        project: &ProjectName,
        env: &EnvName,
        dek_wrapped: &[u8], // wrapped DEK (by master/device key, depending on mode)
        dek_nonce: &[u8],   // 24-byte nonce used in wrapping
    ) -> Result<(), StoreError>;

    /// Fetch the (wrapped_dek, dek_nonce) pair for an environment so core can unwrap it.
    async fn get_env_wrap(
        &self,
        ws: &WorkspaceId,
        project: &ProjectName,
        env: &EnvName,
    ) -> Result<(Vec<u8>, Vec<u8>), StoreError>;

    // ────────────────────────────────────── Secrets ───────────────────────────────────────

    /// Upsert a secret value (AEAD ciphertext + nonce) for (workspace, project, env, key).
    async fn upsert_secret(
        &self,
        ws: &WorkspaceId,
        project: &ProjectName,
        env: &EnvName,
        key: &str,
        nonce: &[u8],      // per-value 24B nonce
        ciphertext: &[u8], // AEAD ciphertext under DEK
    ) -> Result<(), StoreError>;

    /// Fetch a secret row (nonce + ciphertext).
    async fn get_secret(
        &self,
        ws: &WorkspaceId,
        project: &ProjectName,
        env: &EnvName,
        key: &str,
    ) -> Result<SecretRow, StoreError>;

    /// List all secret keys for (workspace, project, env).
    async fn list_secret_keys(
        &self,
        ws: &WorkspaceId,
        project: &ProjectName,
        env: &EnvName,
    ) -> Result<Vec<String>, StoreError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    // Tiny compile-time smoke test for trait object usage.
    struct NoopTxn;
    impl Transaction for NoopTxn {
        fn commit(self) -> Result<(), StoreError> {
            Ok(())
        }
        fn rollback(self) -> Result<(), StoreError> {
            Ok(())
        }
    }

    struct NoopStore;
    #[async_trait::async_trait]
    impl Store for NoopStore {
        type Txn = NoopTxn;

        async fn begin_txn(&self) -> Result<Self::Txn, StoreError> {
            Ok(NoopTxn)
        }

        async fn create_workspace(&self, _p: &WorkspaceParams) -> Result<WorkspaceId, StoreError> {
            Ok(WorkspaceId(Uuid::new_v4()))
        }
        async fn list_workspaces(&self) -> Result<Vec<WorkspaceId>, StoreError> {
            Ok(vec![])
        }
        async fn get_workspace(&self, _ws: &WorkspaceId) -> Result<WorkspaceParams, StoreError> {
            Err(StoreError::NotFound)
        }

        async fn create_project(
            &self,
            _ws: &WorkspaceId,
            _name: &ProjectName,
        ) -> Result<(), StoreError> {
            Ok(())
        }

        async fn create_env(
            &self,
            _ws: &WorkspaceId,
            _project: &ProjectName,
            _env: &EnvName,
            _dek_wrapped: &[u8],
            _dek_nonce: &[u8],
        ) -> Result<(), StoreError> {
            Ok(())
        }

        async fn get_env_wrap(
            &self,
            _ws: &WorkspaceId,
            _project: &ProjectName,
            _env: &EnvName,
        ) -> Result<(Vec<u8>, Vec<u8>), StoreError> {
            Err(StoreError::NotFound)
        }

        async fn upsert_secret(
            &self,
            _ws: &WorkspaceId,
            _project: &ProjectName,
            _env: &EnvName,
            _key: &str,
            _nonce: &[u8],
            _ciphertext: &[u8],
        ) -> Result<(), StoreError> {
            Ok(())
        }

        async fn get_secret(
            &self,
            _ws: &WorkspaceId,
            _project: &ProjectName,
            _env: &EnvName,
            _key: &str,
        ) -> Result<SecretRow, StoreError> {
            Err(StoreError::NotFound)
        }

        async fn list_secret_keys(
            &self,
            _ws: &WorkspaceId,
            _project: &ProjectName,
            _env: &EnvName,
        ) -> Result<Vec<String>, StoreError> {
            Ok(vec![])
        }
    }

    #[tokio::test]
    async fn trait_smoke() {
        let s = NoopStore;
        let _txn = s.begin_txn().await.unwrap();

        let ws = s
            .create_workspace(&WorkspaceParams {
                kdf_salt: b"0123456789abcdef".to_vec(),
                m_cost_kib: 64 * 1024,
                t_cost: 3,
                p_cost: 1,
            })
            .await
            .unwrap();

        // We can call workspace-scoped methods without compile errors.
        let _ = s.create_project(&ws, &ProjectName("p1".into())).await;
        let _ = s.list_workspaces().await.unwrap();
    }
}
