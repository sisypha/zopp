use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct ProjectConfig {
    #[serde(default)]
    pub defaults: ProjectDefaults,
}

#[derive(Debug, Deserialize, Default)]
pub struct ProjectDefaults {
    pub workspace: Option<String>,
    pub project: Option<String>,
    pub environment: Option<String>,
}

pub fn find_project_config() -> Option<ProjectConfig> {
    let mut current_dir = std::env::current_dir().ok()?;

    loop {
        // Try toml, yaml, then json
        let candidates = [
            ("zopp.toml", "toml"),
            ("zopp.yaml", "yaml"),
            ("zopp.yml", "yaml"),
            ("zopp.json", "json"),
        ];

        for (filename, format) in candidates {
            let config_path = current_dir.join(filename);
            if let Ok(content) = std::fs::read_to_string(&config_path) {
                let config_result: Result<ProjectConfig, Box<dyn std::error::Error>> = match format
                {
                    "toml" => toml::from_str::<ProjectConfig>(&content).map_err(|e| e.into()),
                    "yaml" => serde_yaml::from_str::<ProjectConfig>(&content).map_err(|e| e.into()),
                    "json" => serde_json::from_str::<ProjectConfig>(&content).map_err(|e| e.into()),
                    _ => continue,
                };
                if let Ok(config) = config_result {
                    return Some(config);
                }
            }
        }

        // Move up to parent directory
        if !current_dir.pop() {
            break;
        }
    }

    None
}

pub fn resolve_workspace(
    workspace_arg: Option<&String>,
) -> Result<String, Box<dyn std::error::Error>> {
    let config = find_project_config();
    workspace_arg
        .cloned()
        .or_else(|| config.as_ref().and_then(|c| c.defaults.workspace.clone()))
        .ok_or("workspace not specified (use -w flag or set in zopp.toml)".into())
}

pub fn resolve_workspace_project(
    workspace_arg: Option<&String>,
    project_arg: Option<&String>,
) -> Result<(String, String), Box<dyn std::error::Error>> {
    let config = find_project_config();

    let workspace = workspace_arg
        .cloned()
        .or_else(|| config.as_ref().and_then(|c| c.defaults.workspace.clone()))
        .ok_or("workspace not specified (use -w flag or set in zopp.toml)")?;

    let project = project_arg
        .cloned()
        .or_else(|| config.as_ref().and_then(|c| c.defaults.project.clone()))
        .ok_or("project not specified (use -p flag or set in zopp.toml)")?;

    Ok((workspace, project))
}

pub fn resolve_context(
    workspace_arg: Option<&String>,
    project_arg: Option<&String>,
    environment_arg: Option<&String>,
) -> Result<(String, String, String), Box<dyn std::error::Error>> {
    let config = find_project_config();

    let workspace = workspace_arg
        .cloned()
        .or_else(|| config.as_ref().and_then(|c| c.defaults.workspace.clone()))
        .ok_or("workspace not specified (use -w flag or set in zopp.toml)")?;

    let project = project_arg
        .cloned()
        .or_else(|| config.as_ref().and_then(|c| c.defaults.project.clone()))
        .ok_or("project not specified (use -p flag or set in zopp.toml)")?;

    let environment = environment_arg
        .cloned()
        .or_else(|| config.as_ref().and_then(|c| c.defaults.environment.clone()))
        .ok_or("environment not specified (use -e flag or set in zopp.toml)")?;

    Ok((workspace, project, environment))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_project_config_deserialization_toml() {
        let toml_content = r#"
        [defaults]
        workspace = "my-workspace"
        project = "my-project"
        environment = "production"
        "#;

        let config: ProjectConfig = toml::from_str(toml_content).unwrap();
        assert_eq!(config.defaults.workspace, Some("my-workspace".to_string()));
        assert_eq!(config.defaults.project, Some("my-project".to_string()));
        assert_eq!(config.defaults.environment, Some("production".to_string()));
    }

    #[test]
    fn test_project_config_deserialization_yaml() {
        let yaml_content = r#"
        defaults:
          workspace: my-workspace
          project: my-project
          environment: staging
        "#;

        let config: ProjectConfig = serde_yaml::from_str(yaml_content).unwrap();
        assert_eq!(config.defaults.workspace, Some("my-workspace".to_string()));
        assert_eq!(config.defaults.project, Some("my-project".to_string()));
        assert_eq!(config.defaults.environment, Some("staging".to_string()));
    }

    #[test]
    fn test_project_config_deserialization_json() {
        let json_content = r#"{
            "defaults": {
                "workspace": "json-workspace",
                "project": "json-project",
                "environment": "dev"
            }
        }"#;

        let config: ProjectConfig = serde_json::from_str(json_content).unwrap();
        assert_eq!(config.defaults.workspace, Some("json-workspace".to_string()));
        assert_eq!(config.defaults.project, Some("json-project".to_string()));
        assert_eq!(config.defaults.environment, Some("dev".to_string()));
    }

    #[test]
    fn test_project_config_partial_defaults() {
        let toml_content = r#"
        [defaults]
        workspace = "only-workspace"
        "#;

        let config: ProjectConfig = toml::from_str(toml_content).unwrap();
        assert_eq!(config.defaults.workspace, Some("only-workspace".to_string()));
        assert!(config.defaults.project.is_none());
        assert!(config.defaults.environment.is_none());
    }

    #[test]
    fn test_project_config_empty_defaults() {
        let toml_content = r#"
        [defaults]
        "#;

        let config: ProjectConfig = toml::from_str(toml_content).unwrap();
        assert!(config.defaults.workspace.is_none());
        assert!(config.defaults.project.is_none());
        assert!(config.defaults.environment.is_none());
    }

    #[test]
    fn test_project_defaults_is_default() {
        let defaults = ProjectDefaults::default();
        assert!(defaults.workspace.is_none());
        assert!(defaults.project.is_none());
        assert!(defaults.environment.is_none());
    }

    #[test]
    fn test_project_config_no_defaults_section() {
        // Empty config should work since defaults is optional
        let toml_content = "";
        let config: ProjectConfig = toml::from_str(toml_content).unwrap();
        assert!(config.defaults.workspace.is_none());
    }

    #[test]
    fn test_project_config_debug() {
        let config = ProjectConfig {
            defaults: ProjectDefaults {
                workspace: Some("ws".to_string()),
                project: Some("proj".to_string()),
                environment: Some("env".to_string()),
            },
        };
        let debug_str = format!("{:?}", config);
        assert!(debug_str.contains("ws"));
        assert!(debug_str.contains("proj"));
        assert!(debug_str.contains("env"));
    }
}
