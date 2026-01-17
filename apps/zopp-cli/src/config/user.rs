use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Serialize, Deserialize, Debug)]
pub struct CliConfig {
    pub principals: Vec<PrincipalConfig>,
    #[serde(default)]
    pub current_principal: Option<String>, // Name of current principal
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PrincipalConfig {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub user_id: Option<String>, // Only for human principals (CLI users)
    #[serde(default)]
    pub email: Option<String>, // Only for human principals (CLI users)
    pub private_key: String, // Ed25519 private key (hex-encoded)
    pub public_key: String,  // Ed25519 public key (hex-encoded)
    #[serde(default)]
    pub x25519_private_key: Option<String>, // X25519 private key (hex-encoded)
    #[serde(default)]
    pub x25519_public_key: Option<String>, // X25519 public key (hex-encoded)
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

#[cfg(test)]
mod tests {
    use super::*;

    fn make_principal(id: &str, name: &str) -> PrincipalConfig {
        PrincipalConfig {
            id: id.to_string(),
            name: name.to_string(),
            user_id: Some("user-123".to_string()),
            email: Some("test@example.com".to_string()),
            private_key: "a".repeat(64), // 32 bytes hex
            public_key: "b".repeat(64),
            x25519_private_key: None,
            x25519_public_key: None,
        }
    }

    fn make_config(principals: Vec<PrincipalConfig>, current: Option<String>) -> CliConfig {
        CliConfig {
            principals,
            current_principal: current,
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
            private_key: "a".repeat(64),
            public_key: "b".repeat(64),
            x25519_private_key: Some("c".repeat(64)),
            x25519_public_key: Some("d".repeat(64)),
        };

        assert!(principal.x25519_private_key.is_some());
        assert!(principal.x25519_public_key.is_some());
        assert_eq!(principal.x25519_private_key.as_ref().unwrap().len(), 64);
    }
}
