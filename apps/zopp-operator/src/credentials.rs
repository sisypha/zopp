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
#[derive(Clone)]
pub struct OperatorCredentials {
    pub principal: PrincipalConfig,
    /// Cached environment DEKs (workspace/project/environment -> DEK bytes)
    dek_cache: Arc<RwLock<HashMap<String, [u8; 32]>>>,
}

// Manual Debug implementation to avoid exposing private keys in logs
impl std::fmt::Debug for OperatorCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OperatorCredentials")
            .field("principal_id", &self.principal.id)
            .field("principal_name", &self.principal.name)
            .field("private_key", &"[REDACTED]")
            .field("public_key", &self.principal.public_key)
            .field("x25519_private_key", &"[REDACTED]")
            .field(
                "x25519_public_key",
                &self
                    .principal
                    .x25519_public_key
                    .as_deref()
                    .unwrap_or("[NOT SET]"),
            )
            .field("dek_cache_size", &"[LOCKED]")
            .finish()
    }
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
            user_id: None, // Service principals don't have user identity
            email: None,   // Service principals don't have user identity
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
    use serial_test::serial;

    #[test]
    fn test_env_var_names() {
        assert_eq!(env_vars::PRINCIPAL_ID, "ZOPP_PRINCIPAL_ID");
        assert_eq!(env_vars::PRINCIPAL_NAME, "ZOPP_PRINCIPAL_NAME");
        assert_eq!(env_vars::PRIVATE_KEY, "ZOPP_PRIVATE_KEY");
        assert_eq!(env_vars::PUBLIC_KEY, "ZOPP_PUBLIC_KEY");
        assert_eq!(env_vars::X25519_PRIVATE_KEY, "ZOPP_X25519_PRIVATE_KEY");
        assert_eq!(env_vars::X25519_PUBLIC_KEY, "ZOPP_X25519_PUBLIC_KEY");
    }

    // Tests that modify environment variables must run serially to avoid race conditions
    #[test]
    #[serial]
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

    fn create_test_credentials() -> OperatorCredentials {
        let principal = PrincipalConfig {
            id: "test-id".to_string(),
            name: "test-principal".to_string(),
            user_id: None,               // Service principals don't have user identity
            email: None,                 // Service principals don't have user identity
            private_key: "0".repeat(64), // 32 bytes in hex
            public_key: "1".repeat(64),
            x25519_private_key: Some("2".repeat(64)),
            x25519_public_key: Some("3".repeat(64)),
        };
        OperatorCredentials::new(principal)
    }

    #[tokio::test]
    async fn test_dek_cache_store_and_retrieve() {
        let creds = create_test_credentials();
        let dek = [42u8; 32];

        // Cache should be empty initially
        let cached = creds.get_cached_dek("ws", "proj", "env").await;
        assert!(cached.is_none());

        // Cache a DEK
        creds.cache_dek("ws", "proj", "env", dek).await;

        // Should be retrievable
        let cached = creds.get_cached_dek("ws", "proj", "env").await;
        assert!(cached.is_some());
        assert_eq!(cached.unwrap(), dek);
    }

    #[tokio::test]
    async fn test_dek_cache_different_environments() {
        let creds = create_test_credentials();
        let dek1 = [1u8; 32];
        let dek2 = [2u8; 32];

        // Cache DEKs for different environments
        creds.cache_dek("ws", "proj", "dev", dek1).await;
        creds.cache_dek("ws", "proj", "prod", dek2).await;

        // Each should return the correct DEK
        assert_eq!(
            creds.get_cached_dek("ws", "proj", "dev").await.unwrap(),
            dek1
        );
        assert_eq!(
            creds.get_cached_dek("ws", "proj", "prod").await.unwrap(),
            dek2
        );

        // Non-existent environment should return None
        assert!(creds
            .get_cached_dek("ws", "proj", "staging")
            .await
            .is_none());
    }

    #[tokio::test]
    async fn test_dek_cache_overwrite() {
        let creds = create_test_credentials();
        let dek1 = [1u8; 32];
        let dek2 = [2u8; 32];

        // Cache a DEK
        creds.cache_dek("ws", "proj", "env", dek1).await;
        assert_eq!(
            creds.get_cached_dek("ws", "proj", "env").await.unwrap(),
            dek1
        );

        // Overwrite with new DEK
        creds.cache_dek("ws", "proj", "env", dek2).await;
        assert_eq!(
            creds.get_cached_dek("ws", "proj", "env").await.unwrap(),
            dek2
        );
    }

    #[test]
    fn test_credentials_debug_redacts_secrets() {
        let creds = create_test_credentials();
        let debug_str = format!("{:?}", creds);

        // Should contain non-sensitive info
        assert!(debug_str.contains("test-id"));
        assert!(debug_str.contains("test-principal"));

        // Should NOT contain private keys in the debug output
        assert!(debug_str.contains("[REDACTED]"));
        assert!(!debug_str.contains(&"0".repeat(64))); // ed25519 private key value
        assert!(!debug_str.contains(&"2".repeat(64))); // x25519 private key value
    }

    #[test]
    #[serial]
    fn test_from_env_success() {
        // Set all required environment variables
        std::env::set_var(env_vars::PRINCIPAL_ID, "test-id");
        std::env::set_var(env_vars::PRINCIPAL_NAME, "test-principal");
        std::env::set_var(env_vars::PRIVATE_KEY, "0".repeat(64));
        std::env::set_var(env_vars::PUBLIC_KEY, "1".repeat(64));
        std::env::set_var(env_vars::X25519_PRIVATE_KEY, "2".repeat(64));
        std::env::set_var(env_vars::X25519_PUBLIC_KEY, "3".repeat(64));

        let result = OperatorCredentials::from_env();
        assert!(result.is_ok());

        let creds = result.unwrap();
        assert_eq!(creds.principal.id, "test-id");
        assert_eq!(creds.principal.name, "test-principal");
        // Service principals don't have user identity
        assert!(creds.principal.user_id.is_none());
        assert!(creds.principal.email.is_none());

        // Clean up environment variables
        std::env::remove_var(env_vars::PRINCIPAL_ID);
        std::env::remove_var(env_vars::PRINCIPAL_NAME);
        std::env::remove_var(env_vars::PRIVATE_KEY);
        std::env::remove_var(env_vars::PUBLIC_KEY);
        std::env::remove_var(env_vars::X25519_PRIVATE_KEY);
        std::env::remove_var(env_vars::X25519_PUBLIC_KEY);
    }

    #[test]
    #[serial]
    fn test_from_env_missing_principal_name() {
        std::env::set_var(env_vars::PRINCIPAL_ID, "test-id");
        std::env::remove_var(env_vars::PRINCIPAL_NAME);

        let result = OperatorCredentials::from_env();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, CredentialError::MissingEnvVar(_)));
        if let CredentialError::MissingEnvVar(name) = err {
            assert_eq!(name, env_vars::PRINCIPAL_NAME);
        }

        std::env::remove_var(env_vars::PRINCIPAL_ID);
    }

    #[test]
    #[serial]
    fn test_from_env_missing_private_key() {
        std::env::set_var(env_vars::PRINCIPAL_ID, "test-id");
        std::env::set_var(env_vars::PRINCIPAL_NAME, "test");
        std::env::remove_var(env_vars::PRIVATE_KEY);

        let result = OperatorCredentials::from_env();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, CredentialError::MissingEnvVar(_)));
        if let CredentialError::MissingEnvVar(name) = err {
            assert_eq!(name, env_vars::PRIVATE_KEY);
        }

        std::env::remove_var(env_vars::PRINCIPAL_ID);
        std::env::remove_var(env_vars::PRINCIPAL_NAME);
    }

    #[test]
    #[serial]
    fn test_from_env_missing_public_key() {
        std::env::set_var(env_vars::PRINCIPAL_ID, "test-id");
        std::env::set_var(env_vars::PRINCIPAL_NAME, "test");
        std::env::set_var(env_vars::PRIVATE_KEY, "a".repeat(64));
        std::env::remove_var(env_vars::PUBLIC_KEY);

        let result = OperatorCredentials::from_env();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, CredentialError::MissingEnvVar(_)));
        if let CredentialError::MissingEnvVar(name) = err {
            assert_eq!(name, env_vars::PUBLIC_KEY);
        }

        std::env::remove_var(env_vars::PRINCIPAL_ID);
        std::env::remove_var(env_vars::PRINCIPAL_NAME);
        std::env::remove_var(env_vars::PRIVATE_KEY);
    }

    #[test]
    #[serial]
    fn test_from_env_missing_x25519_private_key() {
        std::env::set_var(env_vars::PRINCIPAL_ID, "test-id");
        std::env::set_var(env_vars::PRINCIPAL_NAME, "test");
        std::env::set_var(env_vars::PRIVATE_KEY, "a".repeat(64));
        std::env::set_var(env_vars::PUBLIC_KEY, "b".repeat(64));
        std::env::remove_var(env_vars::X25519_PRIVATE_KEY);

        let result = OperatorCredentials::from_env();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, CredentialError::MissingEnvVar(_)));
        if let CredentialError::MissingEnvVar(name) = err {
            assert_eq!(name, env_vars::X25519_PRIVATE_KEY);
        }

        std::env::remove_var(env_vars::PRINCIPAL_ID);
        std::env::remove_var(env_vars::PRINCIPAL_NAME);
        std::env::remove_var(env_vars::PRIVATE_KEY);
        std::env::remove_var(env_vars::PUBLIC_KEY);
    }

    #[test]
    #[serial]
    fn test_from_env_missing_x25519_public_key() {
        std::env::set_var(env_vars::PRINCIPAL_ID, "test-id");
        std::env::set_var(env_vars::PRINCIPAL_NAME, "test");
        std::env::set_var(env_vars::PRIVATE_KEY, "a".repeat(64));
        std::env::set_var(env_vars::PUBLIC_KEY, "b".repeat(64));
        std::env::set_var(env_vars::X25519_PRIVATE_KEY, "c".repeat(64));
        std::env::remove_var(env_vars::X25519_PUBLIC_KEY);

        let result = OperatorCredentials::from_env();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, CredentialError::MissingEnvVar(_)));
        if let CredentialError::MissingEnvVar(name) = err {
            assert_eq!(name, env_vars::X25519_PUBLIC_KEY);
        }

        std::env::remove_var(env_vars::PRINCIPAL_ID);
        std::env::remove_var(env_vars::PRINCIPAL_NAME);
        std::env::remove_var(env_vars::PRIVATE_KEY);
        std::env::remove_var(env_vars::PUBLIC_KEY);
        std::env::remove_var(env_vars::X25519_PRIVATE_KEY);
    }

    #[test]
    #[serial]
    fn test_load_prefers_env_over_file() {
        // Set environment variables
        std::env::set_var(env_vars::PRINCIPAL_ID, "env-id");
        std::env::set_var(env_vars::PRINCIPAL_NAME, "env-principal");
        std::env::set_var(env_vars::PRIVATE_KEY, "0".repeat(64));
        std::env::set_var(env_vars::PUBLIC_KEY, "1".repeat(64));
        std::env::set_var(env_vars::X25519_PRIVATE_KEY, "2".repeat(64));
        std::env::set_var(env_vars::X25519_PUBLIC_KEY, "3".repeat(64));

        // Even if file path is provided, env vars take precedence
        let result = OperatorCredentials::load(Some(PathBuf::from("/nonexistent/path")));
        assert!(result.is_ok());

        let creds = result.unwrap();
        assert_eq!(creds.principal.id, "env-id");

        // Clean up
        std::env::remove_var(env_vars::PRINCIPAL_ID);
        std::env::remove_var(env_vars::PRINCIPAL_NAME);
        std::env::remove_var(env_vars::PRIVATE_KEY);
        std::env::remove_var(env_vars::PUBLIC_KEY);
        std::env::remove_var(env_vars::X25519_PRIVATE_KEY);
        std::env::remove_var(env_vars::X25519_PUBLIC_KEY);
    }

    #[test]
    #[serial]
    fn test_load_falls_back_to_file_when_no_env() {
        // Ensure no env vars are set
        std::env::remove_var(env_vars::PRINCIPAL_ID);

        // Should try file-based loading (which will fail with NoCredentials for nonexistent file)
        let result = OperatorCredentials::load(Some(PathBuf::from("/nonexistent/path")));
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            CredentialError::NoCredentials
        ));
    }

    #[test]
    fn test_credentials_new() {
        let principal = PrincipalConfig {
            id: "id".to_string(),
            name: "name".to_string(),
            user_id: None, // Service principals don't have user identity
            email: None,   // Service principals don't have user identity
            private_key: "priv".to_string(),
            public_key: "pub".to_string(),
            x25519_private_key: None,
            x25519_public_key: None,
        };

        let creds = OperatorCredentials::new(principal.clone());
        assert_eq!(creds.principal.id, principal.id);
        assert_eq!(creds.principal.name, principal.name);
    }

    #[test]
    fn test_credentials_debug_no_x25519_keys() {
        let principal = PrincipalConfig {
            id: "test-id".to_string(),
            name: "test-principal".to_string(),
            user_id: None, // Service principals don't have user identity
            email: None,   // Service principals don't have user identity
            private_key: "0".repeat(64),
            public_key: "1".repeat(64),
            x25519_private_key: None,
            x25519_public_key: None,
        };
        let creds = OperatorCredentials::new(principal);
        let debug_str = format!("{:?}", creds);

        // Should show [NOT SET] for missing x25519 public key
        assert!(debug_str.contains("[NOT SET]"));
    }

    #[test]
    fn test_credential_error_display() {
        let err1 = CredentialError::MissingEnvVar("TEST_VAR".to_string());
        assert_eq!(err1.to_string(), "Missing environment variable: TEST_VAR");

        let err2 = CredentialError::ConfigFile("File not found".to_string());
        assert_eq!(err2.to_string(), "Config file error: File not found");

        let err3 = CredentialError::NoCredentials;
        assert!(err3.to_string().contains("No credentials found"));
    }
}
