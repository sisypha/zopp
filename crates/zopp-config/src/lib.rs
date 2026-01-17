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
    pub principals: Vec<PrincipalConfig>,
    #[serde(default)]
    pub current_principal: Option<String>, // Name of current principal
}

/// Principal (device) configuration with cryptographic keys
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PrincipalConfig {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub user_id: Option<String>, // Only for human principals (CLI users)
    #[serde(default)]
    pub email: Option<String>, // Only for human principals (CLI users)
    pub private_key: String,   // Ed25519 private key (hex-encoded)
    pub public_key: String,    // Ed25519 public key (hex-encoded)
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
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_cli_config_roundtrip() {
        let config = CliConfig {
            principals: vec![PrincipalConfig {
                id: "principal-123".to_string(),
                name: "test-device".to_string(),
                user_id: Some("user-123".to_string()),
                email: Some("test@example.com".to_string()),
                private_key: "abcd1234".to_string(),
                public_key: "efgh5678".to_string(),
                x25519_private_key: Some("x25519priv".to_string()),
                x25519_public_key: Some("x25519pub".to_string()),
            }],
            current_principal: Some("test-device".to_string()),
        };

        let json = serde_json::to_string_pretty(&config).unwrap();
        let parsed: CliConfig = serde_json::from_str(&json).unwrap();

        assert_eq!(config.principals.len(), parsed.principals.len());
        assert_eq!(config.principals[0].user_id, parsed.principals[0].user_id);
        assert_eq!(config.principals[0].email, parsed.principals[0].email);
    }

    #[test]
    fn test_get_current_principal() {
        let config = CliConfig {
            principals: vec![
                PrincipalConfig {
                    id: "p1".to_string(),
                    name: "device1".to_string(),
                    user_id: Some("user-123".to_string()),
                    email: Some("test@example.com".to_string()),
                    private_key: "key1".to_string(),
                    public_key: "pub1".to_string(),
                    x25519_private_key: None,
                    x25519_public_key: None,
                },
                PrincipalConfig {
                    id: "p2".to_string(),
                    name: "device2".to_string(),
                    user_id: Some("user-123".to_string()),
                    email: Some("test@example.com".to_string()),
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
    fn test_get_current_principal_falls_back_to_first() {
        let config = CliConfig {
            principals: vec![
                PrincipalConfig {
                    id: "p1".to_string(),
                    name: "device1".to_string(),
                    user_id: Some("user-123".to_string()),
                    email: Some("test@example.com".to_string()),
                    private_key: "key1".to_string(),
                    public_key: "pub1".to_string(),
                    x25519_private_key: None,
                    x25519_public_key: None,
                },
                PrincipalConfig {
                    id: "p2".to_string(),
                    name: "device2".to_string(),
                    user_id: Some("user-123".to_string()),
                    email: Some("test@example.com".to_string()),
                    private_key: "key2".to_string(),
                    public_key: "pub2".to_string(),
                    x25519_private_key: None,
                    x25519_public_key: None,
                },
            ],
            current_principal: None, // No current principal set
        };

        // Should fall back to first principal
        let current = config.get_current_principal().unwrap();
        assert_eq!(current.name, "device1");
        assert_eq!(current.id, "p1");
    }

    #[test]
    fn test_get_current_principal_no_principals() {
        let config = CliConfig {
            principals: vec![],
            current_principal: None,
        };

        let result = config.get_current_principal();
        assert!(matches!(result, Err(ConfigError::NoPrincipals)));
    }

    #[test]
    fn test_get_current_principal_not_found() {
        let config = CliConfig {
            principals: vec![PrincipalConfig {
                id: "p1".to_string(),
                name: "device1".to_string(),
                user_id: Some("user-123".to_string()),
                email: Some("test@example.com".to_string()),
                private_key: "key1".to_string(),
                public_key: "pub1".to_string(),
                x25519_private_key: None,
                x25519_public_key: None,
            }],
            current_principal: Some("nonexistent".to_string()),
        };

        let result = config.get_current_principal();
        assert!(matches!(result, Err(ConfigError::PrincipalNotFound(_))));
    }

    #[test]
    fn test_get_principal_by_name() {
        let config = CliConfig {
            principals: vec![
                PrincipalConfig {
                    id: "p1".to_string(),
                    name: "device1".to_string(),
                    user_id: Some("user-123".to_string()),
                    email: Some("test@example.com".to_string()),
                    private_key: "key1".to_string(),
                    public_key: "pub1".to_string(),
                    x25519_private_key: None,
                    x25519_public_key: None,
                },
                PrincipalConfig {
                    id: "p2".to_string(),
                    name: "device2".to_string(),
                    user_id: Some("user-123".to_string()),
                    email: Some("test@example.com".to_string()),
                    private_key: "key2".to_string(),
                    public_key: "pub2".to_string(),
                    x25519_private_key: None,
                    x25519_public_key: None,
                },
            ],
            current_principal: None,
        };

        let p1 = config.get_principal("device1").unwrap();
        assert_eq!(p1.id, "p1");

        let p2 = config.get_principal("device2").unwrap();
        assert_eq!(p2.id, "p2");
    }

    #[test]
    fn test_get_principal_not_found() {
        let config = CliConfig {
            principals: vec![],
            current_principal: None,
        };

        let result = config.get_principal("nonexistent");
        assert!(
            matches!(result, Err(ConfigError::PrincipalNotFound(name)) if name == "nonexistent")
        );
    }

    #[test]
    fn test_load_from_file() {
        let config = CliConfig {
            principals: vec![PrincipalConfig {
                id: "p1".to_string(),
                name: "laptop".to_string(),
                user_id: Some("user-456".to_string()),
                email: Some("test@example.com".to_string()),
                private_key: "aabbccdd".to_string(),
                public_key: "11223344".to_string(),
                x25519_private_key: Some("x25519priv".to_string()),
                x25519_public_key: Some("x25519pub".to_string()),
            }],
            current_principal: Some("laptop".to_string()),
        };

        let mut temp_file = NamedTempFile::new().unwrap();
        write!(
            temp_file,
            "{}",
            serde_json::to_string_pretty(&config).unwrap()
        )
        .unwrap();

        let loaded = CliConfig::load_from(temp_file.path()).unwrap();
        assert_eq!(
            loaded.principals[0].user_id,
            Some("user-456".to_string())
        );
        assert_eq!(
            loaded.principals[0].email,
            Some("test@example.com".to_string())
        );
        assert_eq!(loaded.principals.len(), 1);
        assert_eq!(loaded.principals[0].name, "laptop");
    }

    #[test]
    fn test_load_from_nonexistent_file() {
        let result = CliConfig::load_from("/nonexistent/path/config.json");
        assert!(matches!(result, Err(ConfigError::NotFound)));
    }

    #[test]
    fn test_load_from_invalid_json() {
        let mut temp_file = NamedTempFile::new().unwrap();
        write!(temp_file, "{{ invalid json }}").unwrap();

        let result = CliConfig::load_from(temp_file.path());
        assert!(matches!(result, Err(ConfigError::Parse(_))));
    }

    #[test]
    fn test_save_to_file() {
        let config = CliConfig {
            principals: vec![PrincipalConfig {
                id: "p1".to_string(),
                name: "phone".to_string(),
                user_id: Some("user-789".to_string()),
                email: Some("save@example.com".to_string()),
                private_key: "deadbeef".to_string(),
                public_key: "cafebabe".to_string(),
                x25519_private_key: None,
                x25519_public_key: None,
            }],
            current_principal: None,
        };

        let temp_file = NamedTempFile::new().unwrap();
        config.save_to(temp_file.path()).unwrap();

        let loaded = CliConfig::load_from(temp_file.path()).unwrap();
        assert_eq!(
            loaded.principals[0].user_id,
            Some("user-789".to_string())
        );
        assert_eq!(
            loaded.principals[0].email,
            Some("save@example.com".to_string())
        );
    }

    #[test]
    fn test_save_to_creates_parent_dirs() {
        let config = CliConfig {
            principals: vec![],
            current_principal: None,
        };

        let temp_dir = tempfile::tempdir().unwrap();
        let nested_path = temp_dir
            .path()
            .join("nested")
            .join("dir")
            .join("config.json");

        config.save_to(&nested_path).unwrap();

        assert!(nested_path.exists());
        let loaded = CliConfig::load_from(&nested_path).unwrap();
        assert!(loaded.principals.is_empty());
    }

    #[test]
    fn test_principal_get_private_key_bytes() {
        // 32 bytes hex encoded = 64 hex chars
        let private_key_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let principal = PrincipalConfig {
            id: "p1".to_string(),
            name: "test".to_string(),
            user_id: Some("user-123".to_string()),
            email: Some("test@example.com".to_string()),
            private_key: private_key_hex.to_string(),
            public_key: private_key_hex.to_string(),
            x25519_private_key: None,
            x25519_public_key: None,
        };

        let bytes = principal.get_private_key_bytes().unwrap();
        assert_eq!(bytes.len(), 32);
        assert_eq!(bytes[0], 0x01);
        assert_eq!(bytes[1], 0x23);
    }

    #[test]
    fn test_principal_get_private_key_bytes_invalid_hex() {
        let principal = PrincipalConfig {
            id: "p1".to_string(),
            name: "test".to_string(),
            user_id: Some("user-123".to_string()),
            email: Some("test@example.com".to_string()),
            private_key: "not_valid_hex".to_string(),
            public_key: "key".to_string(),
            x25519_private_key: None,
            x25519_public_key: None,
        };

        let result = principal.get_private_key_bytes();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid private key hex"));
    }

    #[test]
    fn test_principal_get_private_key_bytes_wrong_length() {
        let principal = PrincipalConfig {
            id: "p1".to_string(),
            name: "test".to_string(),
            user_id: Some("user-123".to_string()),
            email: Some("test@example.com".to_string()),
            private_key: "aabbccdd".to_string(), // Only 4 bytes
            public_key: "key".to_string(),
            x25519_private_key: None,
            x25519_public_key: None,
        };

        let result = principal.get_private_key_bytes();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("32 bytes"));
    }

    #[test]
    fn test_principal_get_public_key_bytes() {
        let public_key_hex = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
        let principal = PrincipalConfig {
            id: "p1".to_string(),
            name: "test".to_string(),
            user_id: Some("user-123".to_string()),
            email: Some("test@example.com".to_string()),
            private_key: public_key_hex.to_string(),
            public_key: public_key_hex.to_string(),
            x25519_private_key: None,
            x25519_public_key: None,
        };

        let bytes = principal.get_public_key_bytes().unwrap();
        assert_eq!(bytes.len(), 32);
        assert_eq!(bytes[0], 0xfe);
        assert_eq!(bytes[1], 0xdc);
    }

    #[test]
    fn test_principal_get_public_key_bytes_invalid() {
        let principal = PrincipalConfig {
            id: "p1".to_string(),
            name: "test".to_string(),
            user_id: Some("user-123".to_string()),
            email: Some("test@example.com".to_string()),
            private_key: "key".to_string(),
            public_key: "invalid_hex!".to_string(),
            x25519_private_key: None,
            x25519_public_key: None,
        };

        let result = principal.get_public_key_bytes();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid public key hex"));
    }

    #[test]
    fn test_principal_get_x25519_private_key_bytes() {
        let x25519_key_hex = "1111111111111111222222222222222233333333333333334444444444444444";
        let principal = PrincipalConfig {
            id: "p1".to_string(),
            name: "test".to_string(),
            user_id: Some("user-123".to_string()),
            email: Some("test@example.com".to_string()),
            private_key: "key".to_string(),
            public_key: "key".to_string(),
            x25519_private_key: Some(x25519_key_hex.to_string()),
            x25519_public_key: None,
        };

        let bytes = principal.get_x25519_private_key_bytes().unwrap().unwrap();
        assert_eq!(bytes.len(), 32);
        assert_eq!(bytes[0], 0x11);
    }

    #[test]
    fn test_principal_get_x25519_private_key_bytes_none() {
        let principal = PrincipalConfig {
            id: "p1".to_string(),
            name: "test".to_string(),
            user_id: Some("user-123".to_string()),
            email: Some("test@example.com".to_string()),
            private_key: "key".to_string(),
            public_key: "key".to_string(),
            x25519_private_key: None,
            x25519_public_key: None,
        };

        let result = principal.get_x25519_private_key_bytes().unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_principal_get_x25519_private_key_bytes_invalid() {
        let principal = PrincipalConfig {
            id: "p1".to_string(),
            name: "test".to_string(),
            user_id: Some("user-123".to_string()),
            email: Some("test@example.com".to_string()),
            private_key: "key".to_string(),
            public_key: "key".to_string(),
            x25519_private_key: Some("bad_hex".to_string()),
            x25519_public_key: None,
        };

        let result = principal.get_x25519_private_key_bytes();
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("Invalid x25519 private key hex"));
    }

    #[test]
    fn test_principal_get_x25519_public_key_bytes() {
        let x25519_key_hex = "5555555555555555666666666666666677777777777777778888888888888888";
        let principal = PrincipalConfig {
            id: "p1".to_string(),
            name: "test".to_string(),
            user_id: Some("user-123".to_string()),
            email: Some("test@example.com".to_string()),
            private_key: "key".to_string(),
            public_key: "key".to_string(),
            x25519_private_key: None,
            x25519_public_key: Some(x25519_key_hex.to_string()),
        };

        let bytes = principal.get_x25519_public_key_bytes().unwrap().unwrap();
        assert_eq!(bytes.len(), 32);
        assert_eq!(bytes[0], 0x55);
    }

    #[test]
    fn test_principal_get_x25519_public_key_bytes_none() {
        let principal = PrincipalConfig {
            id: "p1".to_string(),
            name: "test".to_string(),
            user_id: Some("user-123".to_string()),
            email: Some("test@example.com".to_string()),
            private_key: "key".to_string(),
            public_key: "key".to_string(),
            x25519_private_key: None,
            x25519_public_key: None,
        };

        let result = principal.get_x25519_public_key_bytes().unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_principal_get_x25519_public_key_bytes_wrong_length() {
        let principal = PrincipalConfig {
            id: "p1".to_string(),
            name: "test".to_string(),
            user_id: Some("user-123".to_string()),
            email: Some("test@example.com".to_string()),
            private_key: "key".to_string(),
            public_key: "key".to_string(),
            x25519_private_key: None,
            x25519_public_key: Some("aabb".to_string()), // Only 2 bytes
        };

        let result = principal.get_x25519_public_key_bytes();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("32 bytes"));
    }

    #[test]
    fn test_config_error_display() {
        let not_found = ConfigError::NotFound;
        assert!(not_found.to_string().contains("not found"));

        let no_principals = ConfigError::NoPrincipals;
        assert!(no_principals.to_string().contains("No principals"));

        let principal_not_found = ConfigError::PrincipalNotFound("my-device".to_string());
        assert!(principal_not_found.to_string().contains("my-device"));
        assert!(principal_not_found.to_string().contains("not found"));
    }

    #[test]
    fn test_cli_config_with_optional_fields_absent() {
        // Test deserialization with optional fields missing (service principal)
        let json = r#"{
            "principals": [{
                "id": "p1",
                "name": "service-principal",
                "private_key": "key1",
                "public_key": "pub1"
            }]
        }"#;

        let config: CliConfig = serde_json::from_str(json).unwrap();
        // Service principals don't have user_id/email
        assert!(config.principals[0].user_id.is_none());
        assert!(config.principals[0].email.is_none());
        assert!(config.current_principal.is_none());
        assert!(config.principals[0].x25519_private_key.is_none());
        assert!(config.principals[0].x25519_public_key.is_none());
    }

    #[test]
    fn test_cli_config_with_user_identity() {
        // Test deserialization with user identity fields (human principal)
        let json = r#"{
            "principals": [{
                "id": "p1",
                "name": "device1",
                "user_id": "user-123",
                "email": "test@example.com",
                "private_key": "key1",
                "public_key": "pub1"
            }]
        }"#;

        let config: CliConfig = serde_json::from_str(json).unwrap();
        assert_eq!(
            config.principals[0].user_id,
            Some("user-123".to_string())
        );
        assert_eq!(
            config.principals[0].email,
            Some("test@example.com".to_string())
        );
    }

    #[test]
    fn test_default_path_returns_path() {
        let path = CliConfig::default_path();
        assert!(path.ends_with("config.json"));
        assert!(path.to_string_lossy().contains(".zopp"));
    }
}
