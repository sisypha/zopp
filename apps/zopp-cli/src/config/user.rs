use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::keychain;

#[derive(Serialize, Deserialize, Debug)]
pub struct CliConfig {
    pub principals: Vec<PrincipalConfig>,
    #[serde(default)]
    pub current_principal: Option<String>, // Name of current principal
    #[serde(default)]
    pub use_file_storage: bool, // If true, store private keys in config file instead of keychain
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PrincipalConfig {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub user_id: Option<String>, // Only for human principals (CLI users)
    #[serde(default)]
    pub email: Option<String>, // Only for human principals (CLI users)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub private_key: Option<String>, // Ed25519 private key (hex-encoded) - only if use_file_storage
    pub public_key: String, // Ed25519 public key (hex-encoded)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub x25519_private_key: Option<String>, // X25519 private key (hex-encoded) - only if use_file_storage
    #[serde(default)]
    pub x25519_public_key: Option<String>, // X25519 public key (hex-encoded)
}

/// Principal secrets loaded from keychain or file.
/// These are automatically zeroized when dropped.
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct PrincipalSecrets {
    pub ed25519_private_key: String,
    pub x25519_private_key: Option<String>,
}

fn config_path() -> PathBuf {
    dirs::home_dir()
        .expect("Failed to get home directory")
        .join(".zopp")
        .join("config.json")
}

pub fn load_config() -> Result<CliConfig, Box<dyn std::error::Error>> {
    let path = config_path();
    let contents = std::fs::read_to_string(&path)
        .map_err(|_| "Config not found. Run 'zopp join' or 'zopp login' first.")?;
    Ok(serde_json::from_str(&contents)?)
}

pub fn save_config(config: &CliConfig) -> Result<(), Box<dyn std::error::Error>> {
    let path = config_path();
    std::fs::create_dir_all(path.parent().unwrap())?;
    std::fs::write(&path, serde_json::to_string_pretty(&config)?)?;
    Ok(())
}

pub fn get_current_principal(
    config: &CliConfig,
) -> Result<&PrincipalConfig, Box<dyn std::error::Error>> {
    let principal_name = config
        .current_principal
        .as_ref()
        .or_else(|| config.principals.first().map(|p| &p.name))
        .ok_or("No principals configured")?;

    config
        .principals
        .iter()
        .find(|p| &p.name == principal_name)
        .ok_or_else(|| format!("Principal '{}' not found", principal_name).into())
}

/// Load a principal's secrets from keychain or file.
pub fn load_principal_with_secrets(
    principal: &PrincipalConfig,
    use_file_storage: bool,
) -> Result<PrincipalSecrets, Box<dyn std::error::Error>> {
    if use_file_storage {
        // Load from config file (private_key should be Some)
        let ed25519_key = principal
            .private_key
            .clone()
            .ok_or("Private key not found in config. Principal may have been created with keychain storage.")?;
        Ok(PrincipalSecrets {
            ed25519_private_key: ed25519_key,
            x25519_private_key: principal.x25519_private_key.clone(),
        })
    } else {
        // Load from keychain
        let ed25519_key = keychain::get_ed25519_key(&principal.id)?;
        let x25519_key = keychain::get_x25519_key(&principal.id)?;
        Ok(PrincipalSecrets {
            ed25519_private_key: (*ed25519_key).clone(),
            x25519_private_key: x25519_key.map(|k| (*k).clone()),
        })
    }
}

/// Store a principal's secrets in keychain or file.
/// If storing in keychain, the private keys in principal should be None.
/// If storing in file, the private keys should be set in principal before calling save_config.
pub fn store_principal_secrets(
    principal_id: &str,
    ed25519_private_key: &str,
    x25519_private_key: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    keychain::store_ed25519_key(principal_id, ed25519_private_key)?;
    if let Some(x25519_key) = x25519_private_key {
        keychain::store_x25519_key(principal_id, x25519_key)?;
    }
    Ok(())
}

/// Delete a principal's secrets from keychain.
pub fn delete_principal_secrets(principal_id: &str) -> Result<(), Box<dyn std::error::Error>> {
    keychain::delete_principal_keys(principal_id)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_principal(id: &str, name: &str) -> PrincipalConfig {
        PrincipalConfig {
            id: id.to_string(),
            name: name.to_string(),
            user_id: Some("user-123".to_string()),
            email: Some("test@example.com".to_string()),
            private_key: Some("a".repeat(64)), // 32 bytes hex
            public_key: "b".repeat(64),
            x25519_private_key: None,
            x25519_public_key: None,
        }
    }

    fn make_config(principals: Vec<PrincipalConfig>, current: Option<String>) -> CliConfig {
        CliConfig {
            principals,
            current_principal: current,
            use_file_storage: false,
        }
    }

    #[test]
    fn test_get_current_principal_explicit() {
        let config = make_config(
            vec![
                make_principal("p1", "device1"),
                make_principal("p2", "device2"),
            ],
            Some("device2".to_string()),
        );

        let result = get_current_principal(&config);
        assert!(result.is_ok());
        let principal = result.unwrap();
        assert_eq!(principal.name, "device2");
        assert_eq!(principal.id, "p2");
    }

    #[test]
    fn test_get_current_principal_fallback_to_first() {
        let config = make_config(
            vec![
                make_principal("p1", "device1"),
                make_principal("p2", "device2"),
            ],
            None, // No current principal set
        );

        let result = get_current_principal(&config);
        assert!(result.is_ok());
        let principal = result.unwrap();
        assert_eq!(principal.name, "device1");
        assert_eq!(principal.id, "p1");
    }

    #[test]
    fn test_get_current_principal_no_principals() {
        let config = make_config(vec![], None);

        let result = get_current_principal(&config);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("No principals"));
    }

    #[test]
    fn test_get_current_principal_not_found() {
        let config = make_config(
            vec![make_principal("p1", "device1")],
            Some("nonexistent".to_string()),
        );

        let result = get_current_principal(&config);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not found"));
    }

    #[test]
    fn test_cli_config_serialization_roundtrip() {
        let config = make_config(
            vec![
                make_principal("p1", "laptop"),
                make_principal("p2", "phone"),
            ],
            Some("laptop".to_string()),
        );

        let json = serde_json::to_string(&config).unwrap();
        let parsed: CliConfig = serde_json::from_str(&json).unwrap();

        assert_eq!(config.principals.len(), parsed.principals.len());
        assert_eq!(config.current_principal, parsed.current_principal);
        // user_id and email are now per-principal
        assert_eq!(config.principals[0].user_id, parsed.principals[0].user_id);
        assert_eq!(config.principals[0].email, parsed.principals[0].email);
    }

    #[test]
    fn test_cli_config_deserialization_missing_optional() {
        // Test that optional fields default correctly when missing (service principal)
        let json = r#"{
            "principals": [{
                "id": "p1",
                "name": "service-principal",
                "private_key": "abcd",
                "public_key": "efgh"
            }]
        }"#;

        let config: CliConfig = serde_json::from_str(json).unwrap();
        assert!(config.current_principal.is_none());
        // Service principals don't have user_id/email
        assert!(config.principals[0].user_id.is_none());
        assert!(config.principals[0].email.is_none());
        assert!(config.principals[0].x25519_private_key.is_none());
        assert!(config.principals[0].x25519_public_key.is_none());
    }

    #[test]
    fn test_cli_config_deserialization_with_user_identity() {
        // Test that user identity fields are parsed correctly (human principal)
        let json = r#"{
            "principals": [{
                "id": "p1",
                "name": "device1",
                "user_id": "user-123",
                "email": "test@example.com",
                "private_key": "abcd",
                "public_key": "efgh"
            }]
        }"#;

        let config: CliConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.principals[0].user_id, Some("user-123".to_string()));
        assert_eq!(
            config.principals[0].email,
            Some("test@example.com".to_string())
        );
    }

    #[test]
    fn test_principal_config_clone() {
        let principal = make_principal("p1", "device1");
        let cloned = principal.clone();

        assert_eq!(principal.id, cloned.id);
        assert_eq!(principal.name, cloned.name);
    }

    #[test]
    fn test_principal_config_with_x25519_keys() {
        let principal = PrincipalConfig {
            id: "p1".to_string(),
            name: "device1".to_string(),
            user_id: Some("user-123".to_string()),
            email: Some("test@example.com".to_string()),
            private_key: Some("a".repeat(64)),
            public_key: "b".repeat(64),
            x25519_private_key: Some("c".repeat(64)),
            x25519_public_key: Some("d".repeat(64)),
        };

        assert!(principal.x25519_private_key.is_some());
        assert!(principal.x25519_public_key.is_some());
        assert_eq!(principal.x25519_private_key.as_ref().unwrap().len(), 64);
    }

    #[test]
    fn test_load_principal_with_secrets_from_file() {
        let principal = make_principal("p1", "device1");
        let secrets = load_principal_with_secrets(&principal, true).unwrap();
        assert_eq!(secrets.ed25519_private_key, "a".repeat(64));
        assert!(secrets.x25519_private_key.is_none());
    }

    #[test]
    fn test_load_principal_with_secrets_missing_key() {
        let principal = PrincipalConfig {
            id: "p1".to_string(),
            name: "device1".to_string(),
            user_id: None,
            email: None,
            private_key: None, // No private key in file
            public_key: "b".repeat(64),
            x25519_private_key: None,
            x25519_public_key: None,
        };
        // Should fail when use_file_storage=true but no key in file
        let result = load_principal_with_secrets(&principal, true);
        assert!(result.is_err());
    }
}
