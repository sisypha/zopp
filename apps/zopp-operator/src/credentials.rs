//! Operator credential management.
//!
//! This module handles loading principal credentials for the operator.
//! Credentials can be loaded from environment variables or a config file.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::info;
use zopp_config::PrincipalConfig;

/// Errors that can occur when loading credentials.
#[derive(Error, Debug)]
pub enum CredentialError {
    #[error("Missing environment variable: {0}")]
    MissingEnvVar(String),

    #[error("Config file error: {0}")]
    ConfigFile(String),

    #[error("No credentials found: set ZOPP_PRINCIPAL_ID env vars or provide --credentials file")]
    NoCredentials,
}

/// Environment variable names for credentials.
pub mod env_vars {
    pub const PRINCIPAL_ID: &str = "ZOPP_PRINCIPAL_ID";
    pub const PRINCIPAL_NAME: &str = "ZOPP_PRINCIPAL_NAME";
    pub const PRIVATE_KEY: &str = "ZOPP_PRIVATE_KEY";
    pub const PUBLIC_KEY: &str = "ZOPP_PUBLIC_KEY";
    pub const X25519_PRIVATE_KEY: &str = "ZOPP_X25519_PRIVATE_KEY";
    pub const X25519_PUBLIC_KEY: &str = "ZOPP_X25519_PUBLIC_KEY";
}

/// Operator credentials - wraps a standard PrincipalConfig and caches DEKs
#[derive(Clone, Debug)]
pub struct OperatorCredentials {
    pub principal: PrincipalConfig,
    /// Cached environment DEKs (workspace/project/environment -> DEK bytes)
    dek_cache: Arc<RwLock<HashMap<String, [u8; 32]>>>,
}

impl OperatorCredentials {
    /// Create from a PrincipalConfig
    pub fn new(principal: PrincipalConfig) -> Self {
        Self {
            principal,
            dek_cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Load credentials from environment variables or file.
    ///
    /// Priority:
    /// 1. Environment variables (if ZOPP_PRINCIPAL_ID is set)
    /// 2. Config file (if path provided or default exists)
    ///
    /// Returns an error if no credentials can be loaded.
    pub fn load(file_path: Option<PathBuf>) -> Result<Self, CredentialError> {
        // Try environment variables first
        if std::env::var(env_vars::PRINCIPAL_ID).is_ok() {
            info!("Loading credentials from environment variables");
            return Self::from_env();
        }

        // Fall back to file-based config
        Self::from_file(file_path)
    }

    /// Load credentials from environment variables.
    pub fn from_env() -> Result<Self, CredentialError> {
        let principal_id = std::env::var(env_vars::PRINCIPAL_ID)
            .map_err(|_| CredentialError::MissingEnvVar(env_vars::PRINCIPAL_ID.to_string()))?;

        let principal_name = std::env::var(env_vars::PRINCIPAL_NAME)
            .map_err(|_| CredentialError::MissingEnvVar(env_vars::PRINCIPAL_NAME.to_string()))?;

        let private_key = std::env::var(env_vars::PRIVATE_KEY)
            .map_err(|_| CredentialError::MissingEnvVar(env_vars::PRIVATE_KEY.to_string()))?;

        let public_key = std::env::var(env_vars::PUBLIC_KEY)
            .map_err(|_| CredentialError::MissingEnvVar(env_vars::PUBLIC_KEY.to_string()))?;

        let x25519_private_key = std::env::var(env_vars::X25519_PRIVATE_KEY).map_err(|_| {
            CredentialError::MissingEnvVar(env_vars::X25519_PRIVATE_KEY.to_string())
        })?;

        let x25519_public_key = std::env::var(env_vars::X25519_PUBLIC_KEY)
            .map_err(|_| CredentialError::MissingEnvVar(env_vars::X25519_PUBLIC_KEY.to_string()))?;

        let principal = PrincipalConfig {
            id: principal_id,
            name: principal_name,
            private_key,
            public_key,
            x25519_private_key: Some(x25519_private_key),
            x25519_public_key: Some(x25519_public_key),
        };

        info!(
            "Loaded credentials from env for principal: {} ({})",
            principal.name, principal.id
        );

        Ok(Self::new(principal))
    }

    /// Load credentials from a config file.
    pub fn from_file(path: Option<PathBuf>) -> Result<Self, CredentialError> {
        let config_path = path.unwrap_or_else(zopp_config::CliConfig::default_path);

        if !config_path.exists() {
            return Err(CredentialError::NoCredentials);
        }

        info!("Loading credentials from file: {:?}", config_path);

        let config = zopp_config::CliConfig::load_from(&config_path)
            .map_err(|e| CredentialError::ConfigFile(e.to_string()))?;

        let principal = config
            .get_current_principal()
            .map_err(|e| CredentialError::ConfigFile(e.to_string()))?
            .clone();

        info!(
            "Loaded credentials from file for principal: {} ({})",
            principal.name, principal.id
        );

        Ok(Self::new(principal))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_env_var_names() {
        assert_eq!(env_vars::PRINCIPAL_ID, "ZOPP_PRINCIPAL_ID");
        assert_eq!(env_vars::PRINCIPAL_NAME, "ZOPP_PRINCIPAL_NAME");
        assert_eq!(env_vars::PRIVATE_KEY, "ZOPP_PRIVATE_KEY");
        assert_eq!(env_vars::PUBLIC_KEY, "ZOPP_PUBLIC_KEY");
        assert_eq!(env_vars::X25519_PRIVATE_KEY, "ZOPP_X25519_PRIVATE_KEY");
        assert_eq!(env_vars::X25519_PUBLIC_KEY, "ZOPP_X25519_PUBLIC_KEY");
    }

    #[test]
    fn test_from_env_missing_var() {
        // Clear any existing env vars
        std::env::remove_var(env_vars::PRINCIPAL_ID);

        let result = OperatorCredentials::from_env();
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            CredentialError::MissingEnvVar(_)
        ));
    }

    #[test]
    fn test_from_file_missing() {
        let result =
            OperatorCredentials::from_file(Some(PathBuf::from("/nonexistent/path/config.json")));
        assert!(result.is_err());
    }
}
