use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use zopp_config::PrincipalConfig;

/// Operator credentials - wraps a standard PrincipalConfig and caches KEKs and DEKs
#[derive(Clone)]
pub struct OperatorCredentials {
    pub principal: PrincipalConfig,
    /// Cached workspace KEKs (workspace_name -> KEK bytes)
    kek_cache: Arc<RwLock<HashMap<String, [u8; 32]>>>,
    /// Cached environment DEKs (workspace/project/environment -> DEK bytes)
    dek_cache: Arc<RwLock<HashMap<String, [u8; 32]>>>,
}

impl OperatorCredentials {
    /// Create from a PrincipalConfig
    pub fn new(principal: PrincipalConfig) -> Self {
        Self {
            principal,
            kek_cache: Arc::new(RwLock::new(HashMap::new())),
            dek_cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Cache a KEK for a workspace
    pub async fn cache_kek(&self, workspace: &str, kek: [u8; 32]) {
        self.kek_cache
            .write()
            .await
            .insert(workspace.to_string(), kek);
    }

    /// Get cached KEK for a workspace
    pub async fn get_cached_kek(&self, workspace: &str) -> Option<[u8; 32]> {
        self.kek_cache.read().await.get(workspace).copied()
    }

    /// Cache a DEK for an environment
    pub async fn cache_dek(
        &self,
        workspace: &str,
        project: &str,
        environment: &str,
        dek: [u8; 32],
    ) {
        let key = format!("{}/{}/{}", workspace, project, environment);
        self.dek_cache.write().await.insert(key, dek);
    }

    /// Get cached DEK for an environment
    pub async fn get_cached_dek(
        &self,
        workspace: &str,
        project: &str,
        environment: &str,
    ) -> Option<[u8; 32]> {
        let key = format!("{}/{}/{}", workspace, project, environment);
        self.dek_cache.read().await.get(&key).copied()
    }
}
