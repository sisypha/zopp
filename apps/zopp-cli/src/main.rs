use chrono::Utc;
use clap::{Parser, Subcommand};
use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tonic::metadata::MetadataValue;
use tonic::transport::Channel;

use zopp_proto::zopp_service_client::ZoppServiceClient;
use zopp_proto::{
    CreateWorkspaceRequest, Empty, JoinRequest, RegisterRequest, RenamePrincipalRequest,
};

// ────────────────────────────────────── CLI Types ──────────────────────────────────────

#[derive(Parser)]
#[command(name = "zopp")]
#[command(about = "Zopp secrets management CLI")]
struct Cli {
    /// Server address
    #[arg(long, env = "ZOPP_SERVER", default_value = "http://0.0.0.0:50051")]
    server: String,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Join using an invite token (first-time setup)
    Join {
        /// Invite token
        token: String,

        /// Your email
        email: String,

        /// Principal name (optional, defaults to hostname)
        #[arg(long)]
        principal: Option<String>,
    },
    /// Workspace commands
    Workspace {
        #[command(subcommand)]
        workspace_cmd: WorkspaceCommand,
    },
    /// Principal commands (manage devices/credentials)
    Principal {
        #[command(subcommand)]
        principal_cmd: PrincipalCommand,
    },
    /// Project commands
    Project {
        #[command(subcommand)]
        project_cmd: ProjectCommand,
    },
    /// Environment commands
    Environment {
        #[command(subcommand)]
        environment_cmd: EnvironmentCommand,
    },
}

#[derive(Subcommand)]
enum WorkspaceCommand {
    /// List workspaces
    List,
    /// Create a new workspace
    Create {
        /// Workspace name
        name: String,
    },
}

#[derive(Subcommand)]
enum PrincipalCommand {
    /// List all principals
    List,
    /// Show current principal
    Current,
    /// Create a new principal (register new device)
    Create {
        /// Principal name
        name: String,
    },
    /// Switch to a different principal (set as default)
    Use {
        /// Principal name
        name: String,
    },
    /// Rename a principal
    Rename {
        /// Current name
        name: String,
        /// New name
        new_name: String,
    },
    /// Delete a principal
    Delete {
        /// Principal name
        name: String,
    },
}

#[derive(Subcommand)]
enum ProjectCommand {
    /// List projects in a workspace
    List {
        /// Workspace ID
        workspace_id: String,
    },
    /// Create a new project
    Create {
        /// Workspace ID
        workspace_id: String,
        /// Project name
        name: String,
    },
    /// Get project details
    Get {
        /// Project ID
        project_id: String,
    },
    /// Delete a project
    Delete {
        /// Project ID
        project_id: String,
    },
}

#[derive(Subcommand)]
enum EnvironmentCommand {
    /// List environments in a project
    List {
        /// Project ID
        project_id: String,
    },
    /// Create a new environment
    Create {
        /// Project ID
        project_id: String,
        /// Environment name
        name: String,
        /// Wrapped DEK (hex-encoded)
        #[arg(long)]
        dek_wrapped: String,
        /// DEK nonce (hex-encoded, 24 bytes)
        #[arg(long)]
        dek_nonce: String,
    },
    /// Get environment details
    Get {
        /// Environment ID
        environment_id: String,
    },
    /// Delete an environment
    Delete {
        /// Environment ID
        environment_id: String,
    },
}

// ────────────────────────────────────── Config ──────────────────────────────────────

#[derive(Serialize, Deserialize, Debug)]
struct CliConfig {
    user_id: String,
    email: String,
    principals: Vec<PrincipalConfig>,
    #[serde(default)]
    current_principal: Option<String>, // Name of current principal
}

#[derive(Serialize, Deserialize, Debug)]
struct PrincipalConfig {
    id: String,
    name: String,
    private_key: String, // hex-encoded
    public_key: String,  // hex-encoded
}

fn config_path() -> PathBuf {
    dirs::home_dir()
        .expect("Failed to get home directory")
        .join(".zopp")
        .join("config.json")
}

fn load_config() -> Result<CliConfig, Box<dyn std::error::Error>> {
    let path = config_path();
    let contents = std::fs::read_to_string(&path)
        .map_err(|_| "Config not found. Run 'zopp join' or 'zopp login' first.")?;
    Ok(serde_json::from_str(&contents)?)
}

fn save_config(config: &CliConfig) -> Result<(), Box<dyn std::error::Error>> {
    let path = config_path();
    std::fs::create_dir_all(path.parent().unwrap())?;
    std::fs::write(&path, serde_json::to_string_pretty(&config)?)?;
    Ok(())
}

fn get_current_principal(
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

// ────────────────────────────────────── gRPC Helpers ──────────────────────────────────────

async fn connect(server: &str) -> Result<ZoppServiceClient<Channel>, Box<dyn std::error::Error>> {
    let client = ZoppServiceClient::connect(server.to_string()).await?;
    Ok(client)
}

fn sign_request(private_key_hex: &str) -> Result<(i64, Vec<u8>), Box<dyn std::error::Error>> {
    let timestamp = Utc::now().timestamp();
    let private_key_bytes = hex::decode(private_key_hex)?;
    let signing_key = SigningKey::from_bytes(
        private_key_bytes
            .as_slice()
            .try_into()
            .map_err(|_| "Invalid private key length")?,
    );
    let signature = signing_key.sign(&timestamp.to_le_bytes());
    Ok((timestamp, signature.to_bytes().to_vec()))
}

// ────────────────────────────────────── Commands ──────────────────────────────────────

async fn cmd_join(
    server: &str,
    token: &str,
    email: &str,
    principal_name: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Use provided principal name or default to hostname
    let principal_name = match principal_name {
        Some(name) => name.to_string(),
        None => hostname::get()?.to_string_lossy().to_string(),
    };
    // Generate new keypair
    let signing_key = SigningKey::generate(&mut rand_core::OsRng);
    let verifying_key = signing_key.verifying_key();
    let public_key = verifying_key.to_bytes().to_vec();

    let mut client = connect(server).await?;

    let response = client
        .join(JoinRequest {
            invite_token: token.to_string(),
            email: email.to_string(),
            principal_name: principal_name.clone(),
            public_key,
        })
        .await?
        .into_inner();

    println!("✓ Joined successfully!\n");
    println!("User ID:      {}", response.user_id);
    println!("Principal ID: {}", response.principal_id);
    println!("Principal:    {}", principal_name);
    println!("\nWorkspaces:");
    for ws in &response.workspaces {
        println!("  - {} ({})", ws.name, ws.id);
    }

    // Save config
    let config = CliConfig {
        user_id: response.user_id,
        email: email.to_string(),
        principals: vec![PrincipalConfig {
            id: response.principal_id,
            name: principal_name.clone(),
            private_key: hex::encode(signing_key.to_bytes()),
            public_key: hex::encode(verifying_key.to_bytes()),
        }],
        current_principal: Some(principal_name),
    };
    save_config(&config)?;

    println!("\nConfig saved to: {}", config_path().display());

    Ok(())
}

async fn cmd_workspace_list(server: &str) -> Result<(), Box<dyn std::error::Error>> {
    let config = load_config()?;
    let principal = get_current_principal(&config)?;

    let (timestamp, signature) = sign_request(&principal.private_key)?;

    let mut client = connect(server).await?;

    let mut request = tonic::Request::new(Empty {});
    request
        .metadata_mut()
        .insert("principal-id", MetadataValue::try_from(&principal.id)?);
    request
        .metadata_mut()
        .insert("timestamp", MetadataValue::try_from(timestamp.to_string())?);
    request.metadata_mut().insert(
        "signature",
        MetadataValue::try_from(hex::encode(&signature))?,
    );

    let response = client.list_workspaces(request).await?.into_inner();

    if response.workspaces.is_empty() {
        println!("No workspaces found.");
    } else {
        println!("Workspaces:\n");
        for ws in response.workspaces {
            println!("  {} ({})", ws.name, ws.id);
        }
    }

    Ok(())
}

async fn cmd_workspace_create(server: &str, name: &str) -> Result<(), Box<dyn std::error::Error>> {
    let config = load_config()?;
    let principal = get_current_principal(&config)?;

    let (timestamp, signature) = sign_request(&principal.private_key)?;

    let mut client = connect(server).await?;

    let mut request = tonic::Request::new(CreateWorkspaceRequest {
        name: name.to_string(),
    });
    request
        .metadata_mut()
        .insert("principal-id", MetadataValue::try_from(&principal.id)?);
    request
        .metadata_mut()
        .insert("timestamp", MetadataValue::try_from(timestamp.to_string())?);
    request.metadata_mut().insert(
        "signature",
        MetadataValue::try_from(hex::encode(&signature))?,
    );

    let response = client.create_workspace(request).await?.into_inner();

    println!("✓ Workspace created!\n");
    println!("Name: {}", response.name);
    println!("ID:   {}", response.id);

    Ok(())
}

// ────────────────────────────────────── Principal Commands ──────────────────────────────────────

async fn cmd_principal_list() -> Result<(), Box<dyn std::error::Error>> {
    let config = load_config()?;
    let current = config
        .current_principal
        .as_deref()
        .or_else(|| config.principals.first().map(|p| p.name.as_str()));

    println!("Principals:");
    for principal in &config.principals {
        let marker = if Some(principal.name.as_str()) == current {
            " *"
        } else {
            "  "
        };
        println!("{} {}", marker, principal.name);
    }
    Ok(())
}

async fn cmd_principal_current() -> Result<(), Box<dyn std::error::Error>> {
    let config = load_config()?;
    let principal = get_current_principal(&config)?;
    println!("{}", principal.name);
    Ok(())
}

async fn cmd_principal_create(server: &str, name: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut config = load_config()?;

    if config.principals.iter().any(|p| p.name == name) {
        return Err(format!("Principal '{}' already exists", name).into());
    }

    let signing_key = SigningKey::generate(&mut rand_core::OsRng);
    let verifying_key = signing_key.verifying_key();
    let public_key = verifying_key.to_bytes().to_vec();

    let mut client = connect(server).await?;
    let principal = get_current_principal(&config)?;
    let (timestamp, signature) = sign_request(&principal.private_key)?;

    let mut request = tonic::Request::new(RegisterRequest {
        email: config.email.clone(),
        principal_name: name.to_string(),
        public_key,
    });
    request
        .metadata_mut()
        .insert("principal-id", MetadataValue::try_from(&principal.id)?);
    request
        .metadata_mut()
        .insert("timestamp", MetadataValue::try_from(timestamp.to_string())?);
    request.metadata_mut().insert(
        "signature",
        MetadataValue::try_from(hex::encode(&signature))?,
    );

    let response = client.register(request).await?.into_inner();

    config.principals.push(PrincipalConfig {
        id: response.principal_id,
        name: name.to_string(),
        private_key: hex::encode(signing_key.to_bytes()),
        public_key: hex::encode(verifying_key.to_bytes()),
    });
    save_config(&config)?;

    println!("✓ Principal '{}' created", name);
    Ok(())
}

async fn cmd_principal_use(name: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut config = load_config()?;

    if !config.principals.iter().any(|p| p.name == name) {
        return Err(format!("Principal '{}' not found", name).into());
    }

    config.current_principal = Some(name.to_string());
    save_config(&config)?;

    println!("✓ Switched to principal '{}'", name);
    Ok(())
}

async fn cmd_principal_rename(
    server: &str,
    name: &str,
    new_name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut config = load_config()?;

    if !config.principals.iter().any(|p| p.name == name) {
        return Err(format!("Principal '{}' not found", name).into());
    }

    if config.principals.iter().any(|p| p.name == new_name) {
        return Err(format!("Principal '{}' already exists", new_name).into());
    }

    let principal = config.principals.iter().find(|p| p.name == name).unwrap();

    let principal_id = principal.id.clone();
    let (timestamp, signature) = sign_request(&principal.private_key)?;

    let mut client = connect(server).await?;
    let mut request = tonic::Request::new(RenamePrincipalRequest {
        principal_id: principal_id.clone(),
        new_name: new_name.to_string(),
    });
    request
        .metadata_mut()
        .insert("principal-id", MetadataValue::try_from(&principal_id)?);
    request
        .metadata_mut()
        .insert("timestamp", MetadataValue::try_from(timestamp.to_string())?);
    request.metadata_mut().insert(
        "signature",
        MetadataValue::try_from(hex::encode(&signature))?,
    );

    client.rename_principal(request).await?;

    let principal = config
        .principals
        .iter_mut()
        .find(|p| p.name == name)
        .unwrap();
    principal.name = new_name.to_string();

    if config.current_principal.as_deref() == Some(name) {
        config.current_principal = Some(new_name.to_string());
    }
    save_config(&config)?;

    println!("✓ Principal renamed from '{}' to '{}'", name, new_name);
    Ok(())
}

async fn cmd_principal_delete(name: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut config = load_config()?;

    if config.principals.len() == 1 {
        return Err("Cannot delete the only principal".into());
    }

    let idx = config
        .principals
        .iter()
        .position(|p| p.name == name)
        .ok_or_else(|| format!("Principal '{}' not found", name))?;

    config.principals.remove(idx);

    if config.current_principal.as_deref() == Some(name) {
        config.current_principal = config.principals.first().map(|p| p.name.clone());
    }

    save_config(&config)?;

    println!("✓ Principal '{}' deleted", name);
    if let Some(current) = &config.current_principal {
        println!("Switched to principal '{}'", current);
    }
    Ok(())
}

// ────────────────────────────────────── Project Commands ──────────────────────────────────────

async fn cmd_project_list(
    server: &str,
    workspace_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = load_config()?;
    let principal = get_current_principal(&config)?;

    let mut client = ZoppServiceClient::connect(server.to_string()).await?;

    let (timestamp, signature) = sign_request(&principal.private_key)?;

    let mut request = tonic::Request::new(zopp_proto::ListProjectsRequest {
        workspace_id: workspace_id.to_string(),
    });
    request
        .metadata_mut()
        .insert("principal-id", MetadataValue::try_from(&principal.id)?);
    request
        .metadata_mut()
        .insert("timestamp", MetadataValue::try_from(timestamp.to_string())?);
    request.metadata_mut().insert(
        "signature",
        MetadataValue::try_from(hex::encode(&signature))?,
    );

    let response = client.list_projects(request).await?.into_inner();

    if response.projects.is_empty() {
        println!("No projects found");
    } else {
        println!("Projects:");
        for project in response.projects {
            println!(
                "  {} - {} (ID: {})",
                project.name, project.workspace_id, project.id
            );
        }
    }

    Ok(())
}

async fn cmd_project_create(
    server: &str,
    workspace_id: &str,
    name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = load_config()?;
    let principal = get_current_principal(&config)?;

    let mut client = ZoppServiceClient::connect(server.to_string()).await?;

    let (timestamp, signature) = sign_request(&principal.private_key)?;

    let mut request = tonic::Request::new(zopp_proto::CreateProjectRequest {
        workspace_id: workspace_id.to_string(),
        name: name.to_string(),
    });
    request
        .metadata_mut()
        .insert("principal-id", MetadataValue::try_from(&principal.id)?);
    request
        .metadata_mut()
        .insert("timestamp", MetadataValue::try_from(timestamp.to_string())?);
    request.metadata_mut().insert(
        "signature",
        MetadataValue::try_from(hex::encode(&signature))?,
    );

    let response = client.create_project(request).await?.into_inner();

    println!(
        "✓ Project '{}' created (ID: {})",
        response.name, response.id
    );

    Ok(())
}

async fn cmd_project_get(server: &str, project_id: &str) -> Result<(), Box<dyn std::error::Error>> {
    let config = load_config()?;
    let principal = get_current_principal(&config)?;

    let mut client = ZoppServiceClient::connect(server.to_string()).await?;

    let (timestamp, signature) = sign_request(&principal.private_key)?;

    let mut request = tonic::Request::new(zopp_proto::GetProjectRequest {
        project_id: project_id.to_string(),
    });
    request
        .metadata_mut()
        .insert("principal-id", MetadataValue::try_from(&principal.id)?);
    request
        .metadata_mut()
        .insert("timestamp", MetadataValue::try_from(timestamp.to_string())?);
    request.metadata_mut().insert(
        "signature",
        MetadataValue::try_from(hex::encode(&signature))?,
    );

    let response = client.get_project(request).await?.into_inner();

    println!("Project: {}", response.name);
    println!("  ID: {}", response.id);
    println!("  Workspace ID: {}", response.workspace_id);
    println!(
        "  Created: {}",
        chrono::DateTime::from_timestamp(response.created_at, 0)
            .map(|dt| dt.to_rfc3339())
            .unwrap_or_else(|| "Unknown".to_string())
    );
    println!(
        "  Updated: {}",
        chrono::DateTime::from_timestamp(response.updated_at, 0)
            .map(|dt| dt.to_rfc3339())
            .unwrap_or_else(|| "Unknown".to_string())
    );

    Ok(())
}

async fn cmd_project_delete(
    server: &str,
    project_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = load_config()?;
    let principal = get_current_principal(&config)?;

    let mut client = ZoppServiceClient::connect(server.to_string()).await?;

    let (timestamp, signature) = sign_request(&principal.private_key)?;

    let mut request = tonic::Request::new(zopp_proto::DeleteProjectRequest {
        project_id: project_id.to_string(),
    });
    request
        .metadata_mut()
        .insert("principal-id", MetadataValue::try_from(&principal.id)?);
    request
        .metadata_mut()
        .insert("timestamp", MetadataValue::try_from(timestamp.to_string())?);
    request.metadata_mut().insert(
        "signature",
        MetadataValue::try_from(hex::encode(&signature))?,
    );

    client.delete_project(request).await?;

    println!("✓ Project '{}' deleted", project_id);

    Ok(())
}

async fn cmd_environment_list(
    server: &str,
    project_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = load_config()?;
    let principal = get_current_principal(&config)?;

    let mut client = ZoppServiceClient::connect(server.to_string()).await?;

    let (timestamp, signature) = sign_request(&principal.private_key)?;

    let mut request = tonic::Request::new(zopp_proto::ListEnvironmentsRequest {
        project_id: project_id.to_string(),
    });
    request
        .metadata_mut()
        .insert("principal-id", MetadataValue::try_from(&principal.id)?);
    request
        .metadata_mut()
        .insert("timestamp", MetadataValue::try_from(timestamp.to_string())?);
    request.metadata_mut().insert(
        "signature",
        MetadataValue::try_from(hex::encode(&signature))?,
    );

    let response = client.list_environments(request).await?.into_inner();

    if response.environments.is_empty() {
        println!("No environments found");
    } else {
        println!("Environments:");
        for env in response.environments {
            println!(
                "  {} (ID: {}, Project: {})",
                env.name, env.id, env.project_id
            );
        }
    }

    Ok(())
}

async fn cmd_environment_create(
    server: &str,
    project_id: &str,
    name: &str,
    dek_wrapped_hex: &str,
    dek_nonce_hex: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = load_config()?;
    let principal = get_current_principal(&config)?;

    // Decode hex strings to bytes
    let dek_wrapped =
        hex::decode(dek_wrapped_hex).map_err(|e| format!("Invalid dek_wrapped hex: {}", e))?;
    let dek_nonce =
        hex::decode(dek_nonce_hex).map_err(|e| format!("Invalid dek_nonce hex: {}", e))?;

    if dek_nonce.len() != 24 {
        return Err(format!(
            "dek_nonce must be exactly 24 bytes, got {}",
            dek_nonce.len()
        )
        .into());
    }

    let mut client = ZoppServiceClient::connect(server.to_string()).await?;

    let (timestamp, signature) = sign_request(&principal.private_key)?;

    let mut request = tonic::Request::new(zopp_proto::CreateEnvironmentRequest {
        project_id: project_id.to_string(),
        name: name.to_string(),
        dek_wrapped,
        dek_nonce,
    });
    request
        .metadata_mut()
        .insert("principal-id", MetadataValue::try_from(&principal.id)?);
    request
        .metadata_mut()
        .insert("timestamp", MetadataValue::try_from(timestamp.to_string())?);
    request.metadata_mut().insert(
        "signature",
        MetadataValue::try_from(hex::encode(&signature))?,
    );

    let response = client.create_environment(request).await?.into_inner();

    println!(
        "✓ Environment '{}' created (ID: {})",
        response.name, response.id
    );

    Ok(())
}

async fn cmd_environment_get(
    server: &str,
    environment_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = load_config()?;
    let principal = get_current_principal(&config)?;

    let mut client = ZoppServiceClient::connect(server.to_string()).await?;

    let (timestamp, signature) = sign_request(&principal.private_key)?;

    let mut request = tonic::Request::new(zopp_proto::GetEnvironmentRequest {
        environment_id: environment_id.to_string(),
    });
    request
        .metadata_mut()
        .insert("principal-id", MetadataValue::try_from(&principal.id)?);
    request
        .metadata_mut()
        .insert("timestamp", MetadataValue::try_from(timestamp.to_string())?);
    request.metadata_mut().insert(
        "signature",
        MetadataValue::try_from(hex::encode(&signature))?,
    );

    let response = client.get_environment(request).await?.into_inner();

    println!("Environment: {}", response.name);
    println!("  ID: {}", response.id);
    println!("  Project ID: {}", response.project_id);
    println!("  DEK Wrapped: {}", hex::encode(&response.dek_wrapped));
    println!("  DEK Nonce: {}", hex::encode(&response.dek_nonce));
    println!(
        "  Created: {}",
        chrono::DateTime::from_timestamp(response.created_at, 0)
            .map(|dt| dt.to_rfc3339())
            .unwrap_or_else(|| "Unknown".to_string())
    );
    println!(
        "  Updated: {}",
        chrono::DateTime::from_timestamp(response.updated_at, 0)
            .map(|dt| dt.to_rfc3339())
            .unwrap_or_else(|| "Unknown".to_string())
    );

    Ok(())
}

async fn cmd_environment_delete(
    server: &str,
    environment_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = load_config()?;
    let principal = get_current_principal(&config)?;

    let mut client = ZoppServiceClient::connect(server.to_string()).await?;

    let (timestamp, signature) = sign_request(&principal.private_key)?;

    let mut request = tonic::Request::new(zopp_proto::DeleteEnvironmentRequest {
        environment_id: environment_id.to_string(),
    });
    request
        .metadata_mut()
        .insert("principal-id", MetadataValue::try_from(&principal.id)?);
    request
        .metadata_mut()
        .insert("timestamp", MetadataValue::try_from(timestamp.to_string())?);
    request.metadata_mut().insert(
        "signature",
        MetadataValue::try_from(hex::encode(&signature))?,
    );

    client.delete_environment(request).await?;

    println!("✓ Environment '{}' deleted", environment_id);

    Ok(())
}

// ────────────────────────────────────── Main ──────────────────────────────────────

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Command::Join {
            token,
            email,
            principal,
        } => {
            cmd_join(&cli.server, &token, &email, principal.as_deref()).await?;
        }
        Command::Workspace { workspace_cmd } => match workspace_cmd {
            WorkspaceCommand::List => {
                cmd_workspace_list(&cli.server).await?;
            }
            WorkspaceCommand::Create { name } => {
                cmd_workspace_create(&cli.server, &name).await?;
            }
        },
        Command::Principal { principal_cmd } => match principal_cmd {
            PrincipalCommand::List => {
                cmd_principal_list().await?;
            }
            PrincipalCommand::Current => {
                cmd_principal_current().await?;
            }
            PrincipalCommand::Create { name } => {
                cmd_principal_create(&cli.server, &name).await?;
            }
            PrincipalCommand::Use { name } => {
                cmd_principal_use(&name).await?;
            }
            PrincipalCommand::Rename { name, new_name } => {
                cmd_principal_rename(&cli.server, &name, &new_name).await?;
            }
            PrincipalCommand::Delete { name } => {
                cmd_principal_delete(&name).await?;
            }
        },
        Command::Project { project_cmd } => match project_cmd {
            ProjectCommand::List { workspace_id } => {
                cmd_project_list(&cli.server, &workspace_id).await?;
            }
            ProjectCommand::Create { workspace_id, name } => {
                cmd_project_create(&cli.server, &workspace_id, &name).await?;
            }
            ProjectCommand::Get { project_id } => {
                cmd_project_get(&cli.server, &project_id).await?;
            }
            ProjectCommand::Delete { project_id } => {
                cmd_project_delete(&cli.server, &project_id).await?;
            }
        },
        Command::Environment { environment_cmd } => match environment_cmd {
            EnvironmentCommand::List { project_id } => {
                cmd_environment_list(&cli.server, &project_id).await?;
            }
            EnvironmentCommand::Create {
                project_id,
                name,
                dek_wrapped,
                dek_nonce,
            } => {
                cmd_environment_create(&cli.server, &project_id, &name, &dek_wrapped, &dek_nonce)
                    .await?;
            }
            EnvironmentCommand::Get { environment_id } => {
                cmd_environment_get(&cli.server, &environment_id).await?;
            }
            EnvironmentCommand::Delete { environment_id } => {
                cmd_environment_delete(&cli.server, &environment_id).await?;
            }
        },
    }

    Ok(())
}
