use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("Config file not found. Run 'zopp join' or 'zopp login' first.")]
    NotFound,
    #[error("Failed to read config: {0}")]
    Read(#[from] std::io::Error),
    #[error("Failed to parse config: {0}")]
    Parse(#[from] serde_json::Error),
    #[error("No principals configured")]
    NoPrincipals,
    #[error("Principal '{0}' not found")]
    PrincipalNotFound(String),
}

/// Main user configuration stored in ~/.zopp/config.json
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CliConfig {
    pub user_id: String,
    pub email: String,
    pub principals: Vec<PrincipalConfig>,
    #[serde(default)]
    pub current_principal: Option<String>, // Name of current principal
}

/// Principal (device) configuration with cryptographic keys
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PrincipalConfig {
    pub id: String,
    pub name: String,
    pub private_key: String, // Ed25519 private key (hex-encoded)
    pub public_key: String,  // Ed25519 public key (hex-encoded)
    #[serde(default)]
    pub x25519_private_key: Option<String>, // X25519 private key (hex-encoded)
    #[serde(default)]
    pub x25519_public_key: Option<String>, // X25519 public key (hex-encoded)
}

impl CliConfig {
    /// Load config from default path (~/.zopp/config.json)
    pub fn load() -> Result<Self, ConfigError> {
        Self::load_from(Self::default_path())
    }

    /// Load config from custom path
    pub fn load_from<P: AsRef<Path>>(path: P) -> Result<Self, ConfigError> {
        let contents = std::fs::read_to_string(path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                ConfigError::NotFound
            } else {
                ConfigError::Read(e)
            }
        })?;
        Ok(serde_json::from_str(&contents)?)
    }

    /// Save config to default path
    pub fn save(&self) -> Result<(), ConfigError> {
        self.save_to(Self::default_path())
    }

    /// Save config to custom path
    pub fn save_to<P: AsRef<Path>>(&self, path: P) -> Result<(), ConfigError> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, serde_json::to_string_pretty(&self)?)?;
        Ok(())
    }

    /// Get default config path (~/.zopp/config.json)
    pub fn default_path() -> PathBuf {
        dirs::home_dir()
            .expect("Failed to get home directory")
            .join(".zopp")
            .join("config.json")
    }

    /// Get the current active principal
    pub fn get_current_principal(&self) -> Result<&PrincipalConfig, ConfigError> {
        let principal_name = self
            .current_principal
            .as_ref()
            .or_else(|| self.principals.first().map(|p| &p.name))
            .ok_or(ConfigError::NoPrincipals)?;

        self.principals
            .iter()
            .find(|p| &p.name == principal_name)
            .ok_or_else(|| ConfigError::PrincipalNotFound(principal_name.clone()))
    }

    /// Get a principal by name
    pub fn get_principal(&self, name: &str) -> Result<&PrincipalConfig, ConfigError> {
        self.principals
            .iter()
            .find(|p| p.name == name)
            .ok_or_else(|| ConfigError::PrincipalNotFound(name.to_string()))
    }
}

impl PrincipalConfig {
    /// Get Ed25519 private key as bytes (32 bytes)
    pub fn get_private_key_bytes(&self) -> Result<[u8; 32], String> {
        let bytes = hex::decode(&self.private_key)
            .map_err(|e| format!("Invalid private key hex: {}", e))?;
        bytes
            .try_into()
            .map_err(|_| "Private key must be exactly 32 bytes".to_string())
    }

    /// Get Ed25519 public key as bytes (32 bytes)
    pub fn get_public_key_bytes(&self) -> Result<[u8; 32], String> {
        let bytes =
            hex::decode(&self.public_key).map_err(|e| format!("Invalid public key hex: {}", e))?;
        bytes
            .try_into()
            .map_err(|_| "Public key must be exactly 32 bytes".to_string())
    }

    /// Get X25519 private key as bytes (32 bytes) if present
    pub fn get_x25519_private_key_bytes(&self) -> Result<Option<[u8; 32]>, String> {
        match &self.x25519_private_key {
            Some(key) => {
                let bytes = hex::decode(key)
                    .map_err(|e| format!("Invalid x25519 private key hex: {}", e))?;
                let arr: [u8; 32] = bytes
                    .try_into()
                    .map_err(|_| "X25519 private key must be exactly 32 bytes".to_string())?;
                Ok(Some(arr))
            }
            None => Ok(None),
        }
    }

    /// Get X25519 public key as bytes (32 bytes) if present
    pub fn get_x25519_public_key_bytes(&self) -> Result<Option<[u8; 32]>, String> {
        match &self.x25519_public_key {
            Some(key) => {
                let bytes = hex::decode(key)
                    .map_err(|e| format!("Invalid x25519 public key hex: {}", e))?;
                let arr: [u8; 32] = bytes
                    .try_into()
                    .map_err(|_| "X25519 public key must be exactly 32 bytes".to_string())?;
                Ok(Some(arr))
            }
            None => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cli_config_roundtrip() {
        let config = CliConfig {
            user_id: "user-123".to_string(),
            email: "test@example.com".to_string(),
            principals: vec![PrincipalConfig {
                id: "principal-123".to_string(),
                name: "test-device".to_string(),
                private_key: "abcd1234".to_string(),
                public_key: "efgh5678".to_string(),
                x25519_private_key: Some("x25519priv".to_string()),
                x25519_public_key: Some("x25519pub".to_string()),
            }],
            current_principal: Some("test-device".to_string()),
        };

        let json = serde_json::to_string_pretty(&config).unwrap();
        let parsed: CliConfig = serde_json::from_str(&json).unwrap();

        assert_eq!(config.user_id, parsed.user_id);
        assert_eq!(config.email, parsed.email);
        assert_eq!(config.principals.len(), parsed.principals.len());
    }

    #[test]
    fn test_get_current_principal() {
        let config = CliConfig {
            user_id: "user-123".to_string(),
            email: "test@example.com".to_string(),
            principals: vec![
                PrincipalConfig {
                    id: "p1".to_string(),
                    name: "device1".to_string(),
                    private_key: "key1".to_string(),
                    public_key: "pub1".to_string(),
                    x25519_private_key: None,
                    x25519_public_key: None,
                },
                PrincipalConfig {
                    id: "p2".to_string(),
                    name: "device2".to_string(),
                    private_key: "key2".to_string(),
                    public_key: "pub2".to_string(),
                    x25519_private_key: None,
                    x25519_public_key: None,
                },
            ],
            current_principal: Some("device2".to_string()),
        };

        let current = config.get_current_principal().unwrap();
        assert_eq!(current.name, "device2");
        assert_eq!(current.id, "p2");
    }

    #[test]
    fn test_get_current_principal_fallback_to_first() {
        let config = CliConfig {
            user_id: "user-123".to_string(),
            email: "test@example.com".to_string(),
            principals: vec![PrincipalConfig {
                id: "p1".to_string(),
                name: "device1".to_string(),
                private_key: "key1".to_string(),
                public_key: "pub1".to_string(),
                x25519_private_key: None,
                x25519_public_key: None,
            }],
            current_principal: None, // No current set, should fallback to first
        };

        let current = config.get_current_principal().unwrap();
        assert_eq!(current.name, "device1");
    }

    #[test]
    fn test_get_current_principal_no_principals() {
        let config = CliConfig {
            user_id: "user-123".to_string(),
            email: "test@example.com".to_string(),
            principals: vec![],
            current_principal: None,
        };

        let err = config.get_current_principal().unwrap_err();
        assert!(matches!(err, ConfigError::NoPrincipals));
    }

    #[test]
    fn test_get_current_principal_not_found() {
        let config = CliConfig {
            user_id: "user-123".to_string(),
            email: "test@example.com".to_string(),
            principals: vec![PrincipalConfig {
                id: "p1".to_string(),
                name: "device1".to_string(),
                private_key: "key1".to_string(),
                public_key: "pub1".to_string(),
                x25519_private_key: None,
                x25519_public_key: None,
            }],
            current_principal: Some("nonexistent".to_string()),
        };

        let err = config.get_current_principal().unwrap_err();
        assert!(matches!(err, ConfigError::PrincipalNotFound(_)));
    }

    #[test]
    fn test_get_principal() {
        let config = CliConfig {
            user_id: "user-123".to_string(),
            email: "test@example.com".to_string(),
            principals: vec![PrincipalConfig {
                id: "p1".to_string(),
                name: "device1".to_string(),
                private_key: "key1".to_string(),
                public_key: "pub1".to_string(),
                x25519_private_key: None,
                x25519_public_key: None,
            }],
            current_principal: None,
        };

        let p = config.get_principal("device1").unwrap();
        assert_eq!(p.id, "p1");

        let err = config.get_principal("nonexistent").unwrap_err();
        assert!(matches!(err, ConfigError::PrincipalNotFound(_)));
    }

    #[test]
    fn test_load_from_file_not_found() {
        let result = CliConfig::load_from("/nonexistent/path/config.json");
        assert!(matches!(result, Err(ConfigError::NotFound)));
    }

    #[test]
    fn test_save_and_load_roundtrip() {
        let temp_dir = std::env::temp_dir();
        let config_path = temp_dir.join("zopp_test_config.json");

        let config = CliConfig {
            user_id: "user-456".to_string(),
            email: "roundtrip@example.com".to_string(),
            principals: vec![PrincipalConfig {
                id: "p1".to_string(),
                name: "saved-device".to_string(),
                private_key: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                    .to_string(),
                public_key: "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
                    .to_string(),
                x25519_private_key: None,
                x25519_public_key: None,
            }],
            current_principal: Some("saved-device".to_string()),
        };

        // Save
        config.save_to(&config_path).unwrap();

        // Load
        let loaded = CliConfig::load_from(&config_path).unwrap();
        assert_eq!(loaded.user_id, "user-456");
        assert_eq!(loaded.email, "roundtrip@example.com");
        assert_eq!(loaded.principals.len(), 1);
        assert_eq!(loaded.principals[0].name, "saved-device");

        // Cleanup
        std::fs::remove_file(&config_path).ok();
    }

    #[test]
    fn test_load_from_invalid_json() {
        let temp_dir = std::env::temp_dir();
        let config_path = temp_dir.join("zopp_test_invalid.json");

        std::fs::write(&config_path, "not valid json").unwrap();

        let result = CliConfig::load_from(&config_path);
        assert!(matches!(result, Err(ConfigError::Parse(_))));

        std::fs::remove_file(&config_path).ok();
    }

    #[test]
    fn test_principal_key_bytes() {
        // Valid 32-byte hex keys
        let p = PrincipalConfig {
            id: "p1".to_string(),
            name: "test".to_string(),
            private_key: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                .to_string(),
            public_key: "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
                .to_string(),
            x25519_private_key: Some(
                "1111111111111111111111111111111111111111111111111111111111111111".to_string(),
            ),
            x25519_public_key: Some(
                "2222222222222222222222222222222222222222222222222222222222222222".to_string(),
            ),
        };

        let priv_key = p.get_private_key_bytes().unwrap();
        assert_eq!(priv_key.len(), 32);

        let pub_key = p.get_public_key_bytes().unwrap();
        assert_eq!(pub_key.len(), 32);

        let x_priv = p.get_x25519_private_key_bytes().unwrap();
        assert!(x_priv.is_some());
        assert_eq!(x_priv.unwrap().len(), 32);

        let x_pub = p.get_x25519_public_key_bytes().unwrap();
        assert!(x_pub.is_some());
        assert_eq!(x_pub.unwrap().len(), 32);
    }

    #[test]
    fn test_principal_key_bytes_none() {
        let p = PrincipalConfig {
            id: "p1".to_string(),
            name: "test".to_string(),
            private_key: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                .to_string(),
            public_key: "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
                .to_string(),
            x25519_private_key: None,
            x25519_public_key: None,
        };

        assert!(p.get_x25519_private_key_bytes().unwrap().is_none());
        assert!(p.get_x25519_public_key_bytes().unwrap().is_none());
    }

    #[test]
    fn test_principal_key_bytes_invalid_hex() {
        let p = PrincipalConfig {
            id: "p1".to_string(),
            name: "test".to_string(),
            private_key: "not_hex".to_string(),
            public_key: "also_not_hex".to_string(),
            x25519_private_key: Some("invalid".to_string()),
            x25519_public_key: Some("invalid".to_string()),
        };

        assert!(p.get_private_key_bytes().is_err());
        assert!(p.get_public_key_bytes().is_err());
        assert!(p.get_x25519_private_key_bytes().is_err());
        assert!(p.get_x25519_public_key_bytes().is_err());
    }

    #[test]
    fn test_principal_key_bytes_wrong_length() {
        let p = PrincipalConfig {
            id: "p1".to_string(),
            name: "test".to_string(),
            private_key: "0123456789abcdef".to_string(), // Too short
            public_key: "0123456789abcdef".to_string(),
            x25519_private_key: Some("0123456789abcdef".to_string()),
            x25519_public_key: Some("0123456789abcdef".to_string()),
        };

        assert!(p.get_private_key_bytes().is_err());
        assert!(p.get_public_key_bytes().is_err());
        assert!(p.get_x25519_private_key_bytes().is_err());
        assert!(p.get_x25519_public_key_bytes().is_err());
    }

    #[test]
    fn test_config_error_display() {
        assert_eq!(
            format!("{}", ConfigError::NotFound),
            "Config file not found. Run 'zopp join' or 'zopp login' first."
        );
        assert_eq!(
            format!("{}", ConfigError::NoPrincipals),
            "No principals configured"
        );
        assert_eq!(
            format!("{}", ConfigError::PrincipalNotFound("test".to_string())),
            "Principal 'test' not found"
        );
    }
}
