use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Serialize, Deserialize, Debug)]
pub struct CliConfig {
    pub user_id: String,
    pub email: String,
    pub principals: Vec<PrincipalConfig>,
    #[serde(default)]
    pub current_principal: Option<String>, // Name of current principal
}

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

    fn make_test_config() -> CliConfig {
        CliConfig {
            user_id: "user-123".to_string(),
            email: "test@example.com".to_string(),
            principals: vec![
                PrincipalConfig {
                    id: "p1".to_string(),
                    name: "device1".to_string(),
                    private_key: "abc123".to_string(),
                    public_key: "def456".to_string(),
                    x25519_private_key: Some("x1".to_string()),
                    x25519_public_key: Some("x2".to_string()),
                },
                PrincipalConfig {
                    id: "p2".to_string(),
                    name: "device2".to_string(),
                    private_key: "ghi789".to_string(),
                    public_key: "jkl012".to_string(),
                    x25519_private_key: None,
                    x25519_public_key: None,
                },
            ],
            current_principal: Some("device2".to_string()),
        }
    }

    #[test]
    fn test_cli_config_serialization_roundtrip() {
        let config = make_test_config();
        let json = serde_json::to_string(&config).unwrap();
        let parsed: CliConfig = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.user_id, config.user_id);
        assert_eq!(parsed.email, config.email);
        assert_eq!(parsed.principals.len(), 2);
        assert_eq!(parsed.current_principal, Some("device2".to_string()));
    }

    #[test]
    fn test_get_current_principal_explicit() {
        let config = make_test_config();
        let principal = get_current_principal(&config).unwrap();
        assert_eq!(principal.name, "device2");
        assert_eq!(principal.id, "p2");
    }

    #[test]
    fn test_get_current_principal_fallback_to_first() {
        let mut config = make_test_config();
        config.current_principal = None;

        let principal = get_current_principal(&config).unwrap();
        assert_eq!(principal.name, "device1");
    }

    #[test]
    fn test_get_current_principal_no_principals() {
        let config = CliConfig {
            user_id: "user".to_string(),
            email: "test@test.com".to_string(),
            principals: vec![],
            current_principal: None,
        };

        let result = get_current_principal(&config);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("No principals configured"));
    }

    #[test]
    fn test_get_current_principal_not_found() {
        let mut config = make_test_config();
        config.current_principal = Some("nonexistent".to_string());

        let result = get_current_principal(&config);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not found"));
    }

    #[test]
    fn test_save_and_load_config() {
        let temp_dir = std::env::temp_dir();
        let config_dir = temp_dir.join(".zopp-test");
        let config_path = config_dir.join("config.json");

        // Create test config
        let config = make_test_config();

        // Save manually (since save_config uses fixed path)
        std::fs::create_dir_all(&config_dir).unwrap();
        std::fs::write(&config_path, serde_json::to_string_pretty(&config).unwrap()).unwrap();

        // Load and verify
        let contents = std::fs::read_to_string(&config_path).unwrap();
        let loaded: CliConfig = serde_json::from_str(&contents).unwrap();

        assert_eq!(loaded.user_id, "user-123");
        assert_eq!(loaded.principals.len(), 2);

        // Cleanup
        std::fs::remove_dir_all(&config_dir).ok();
    }

    #[test]
    fn test_principal_config_optional_x25519_keys() {
        let json = r#"{
            "id": "p1",
            "name": "test",
            "private_key": "abc",
            "public_key": "def"
        }"#;

        let principal: PrincipalConfig = serde_json::from_str(json).unwrap();
        assert_eq!(principal.x25519_private_key, None);
        assert_eq!(principal.x25519_public_key, None);
    }

    #[test]
    fn test_cli_config_default_current_principal() {
        let json = r#"{
            "user_id": "user-1",
            "email": "test@test.com",
            "principals": []
        }"#;

        let config: CliConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.current_principal, None);
    }
}
