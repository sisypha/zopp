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
