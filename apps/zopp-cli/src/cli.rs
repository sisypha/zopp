use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "zopp")]
#[command(about = "Zopp secrets management CLI")]
pub struct Cli {
    /// Server address
    #[arg(long, env = "ZOPP_SERVER", default_value = "http://0.0.0.0:50051")]
    pub server: String,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
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
    /// Secret commands
    Secret {
        #[command(subcommand)]
        secret_cmd: SecretCommand,
    },
    /// Invite commands
    Invite {
        #[command(subcommand)]
        invite_cmd: InviteCommand,
    },
    /// Sync secrets to external systems
    Sync {
        #[command(subcommand)]
        sync_cmd: SyncCommand,
    },
    /// Show diff between zopp and external systems
    Diff {
        #[command(subcommand)]
        diff_cmd: DiffCommand,
    },
    /// Run a command with secrets injected as environment variables
    Run {
        /// Workspace name (defaults from zopp.toml)
        #[arg(long, short = 'w')]
        workspace: Option<String>,
        /// Project name (defaults from zopp.toml)
        #[arg(long, short = 'p')]
        project: Option<String>,
        /// Environment name (defaults from zopp.toml)
        #[arg(long, short = 'e')]
        environment: Option<String>,
        /// Command and arguments to run
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },
}

#[derive(Subcommand)]
pub enum WorkspaceCommand {
    /// List workspaces
    List,
    /// Create a new workspace
    Create {
        /// Workspace name
        name: String,
    },
}

#[derive(Subcommand)]
pub enum PrincipalCommand {
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
pub enum ProjectCommand {
    /// List projects in a workspace
    List {
        /// Workspace name
        #[arg(long, short = 'w')]
        workspace: String,
    },
    /// Create a new project
    Create {
        /// Project name
        name: String,
        /// Workspace name
        #[arg(long, short = 'w')]
        workspace: String,
    },
    /// Get project details
    Get {
        /// Project name
        name: String,
        /// Workspace name
        #[arg(long, short = 'w')]
        workspace: String,
    },
    /// Delete a project
    Delete {
        /// Project name
        name: String,
        /// Workspace name
        #[arg(long, short = 'w')]
        workspace: String,
    },
}

#[derive(Subcommand)]
pub enum EnvironmentCommand {
    /// List environments in a project
    List {
        /// Workspace name
        #[arg(long, short = 'w')]
        workspace: Option<String>,
        /// Project name
        #[arg(long, short = 'p')]
        project: Option<String>,
    },
    /// Create a new environment
    Create {
        /// Environment name
        name: String,
        /// Workspace name
        #[arg(long, short = 'w')]
        workspace: Option<String>,
        /// Project name
        #[arg(long, short = 'p')]
        project: Option<String>,
    },
    /// Get environment details
    Get {
        /// Environment name
        name: String,
        /// Workspace name
        #[arg(long, short = 'w')]
        workspace: Option<String>,
        /// Project name
        #[arg(long, short = 'p')]
        project: Option<String>,
    },
    /// Delete an environment
    Delete {
        /// Environment name
        name: String,
        /// Workspace name
        #[arg(long, short = 'w')]
        workspace: Option<String>,
        /// Project name
        #[arg(long, short = 'p')]
        project: Option<String>,
    },
}

#[derive(Subcommand)]
pub enum SecretCommand {
    /// Set (upsert) a secret
    Set {
        /// Workspace name (defaults from zopp.toml)
        #[arg(long, short = 'w')]
        workspace: Option<String>,
        /// Project name (defaults from zopp.toml)
        #[arg(long, short = 'p')]
        project: Option<String>,
        /// Environment name (defaults from zopp.toml)
        #[arg(long, short = 'e')]
        environment: Option<String>,
        /// Secret key
        key: String,
        /// Secret value (plaintext - will be encrypted automatically)
        value: String,
    },
    /// Get a secret
    Get {
        /// Workspace name (defaults from zopp.toml)
        #[arg(long, short = 'w')]
        workspace: Option<String>,
        /// Project name (defaults from zopp.toml)
        #[arg(long, short = 'p')]
        project: Option<String>,
        /// Environment name (defaults from zopp.toml)
        #[arg(long, short = 'e')]
        environment: Option<String>,
        /// Secret key
        key: String,
    },
    /// List all secrets in an environment
    List {
        /// Workspace name (defaults from zopp.toml)
        #[arg(long, short = 'w')]
        workspace: Option<String>,
        /// Project name (defaults from zopp.toml)
        #[arg(long, short = 'p')]
        project: Option<String>,
        /// Environment name (defaults from zopp.toml)
        #[arg(long, short = 'e')]
        environment: Option<String>,
    },
    /// Delete a secret
    Delete {
        /// Workspace name (defaults from zopp.toml)
        #[arg(long, short = 'w')]
        workspace: Option<String>,
        /// Project name (defaults from zopp.toml)
        #[arg(long, short = 'p')]
        project: Option<String>,
        /// Environment name (defaults from zopp.toml)
        #[arg(long, short = 'e')]
        environment: Option<String>,
        /// Secret key
        key: String,
    },
    /// Export secrets to .env file
    Export {
        /// Workspace name (defaults from zopp.toml)
        #[arg(long, short = 'w')]
        workspace: Option<String>,
        /// Project name (defaults from zopp.toml)
        #[arg(long, short = 'p')]
        project: Option<String>,
        /// Environment name (defaults from zopp.toml)
        #[arg(long, short = 'e')]
        environment: Option<String>,
        /// Output file (defaults to stdout)
        #[arg(long, short = 'o')]
        output: Option<String>,
    },
    /// Import secrets from .env file
    Import {
        /// Workspace name (defaults from zopp.toml)
        #[arg(long, short = 'w')]
        workspace: Option<String>,
        /// Project name (defaults from zopp.toml)
        #[arg(long, short = 'p')]
        project: Option<String>,
        /// Environment name (defaults from zopp.toml)
        #[arg(long, short = 'e')]
        environment: Option<String>,
        /// Input file (defaults to stdin)
        #[arg(long, short = 'i')]
        input: Option<String>,
    },
}

#[derive(Subcommand)]
pub enum InviteCommand {
    /// Create a workspace invite
    Create {
        /// Workspace name
        #[arg(long, short = 'w')]
        workspace: Option<String>,
        /// Hours until invite expires (default: 168 = 7 days)
        #[arg(long, default_value = "168")]
        expires_hours: i64,
        /// Output only the invite code (for scripts)
        #[arg(long)]
        plain: bool,
    },
    /// List workspace invites
    List,
    /// Revoke an invite
    Revoke {
        /// Invite code (e.g. inv_abc123...)
        invite_code: String,
    },
}

#[derive(Subcommand)]
pub enum SyncCommand {
    /// Sync secrets to Kubernetes
    K8s {
        /// Kubernetes namespace
        #[arg(long)]
        namespace: String,

        /// Kubernetes Secret name to create/update
        #[arg(long)]
        secret: String,

        /// Workspace name (defaults from zopp.toml)
        #[arg(long, short = 'w')]
        workspace: Option<String>,

        /// Project name (defaults from zopp.toml)
        #[arg(long, short = 'p')]
        project: Option<String>,

        /// Environment name (defaults from zopp.toml)
        #[arg(long, short = 'e')]
        environment: Option<String>,

        /// Path to kubeconfig file (default: ~/.kube/config)
        #[arg(long)]
        kubeconfig: Option<PathBuf>,

        /// Kubernetes context to use
        #[arg(long)]
        context: Option<String>,

        /// Force sync even if Secret exists and not managed by zopp
        #[arg(long)]
        force: bool,

        /// Dry run - show what would be synced without applying
        #[arg(long)]
        dry_run: bool,
    },
}

#[derive(Subcommand)]
pub enum DiffCommand {
    /// Show diff between zopp and Kubernetes Secret
    K8s {
        /// Kubernetes namespace
        #[arg(long)]
        namespace: String,

        /// Kubernetes Secret name
        #[arg(long)]
        secret: String,

        /// Workspace name (defaults from zopp.toml)
        #[arg(long, short = 'w')]
        workspace: Option<String>,

        /// Project name (defaults from zopp.toml)
        #[arg(long, short = 'p')]
        project: Option<String>,

        /// Environment name (defaults from zopp.toml)
        #[arg(long, short = 'e')]
        environment: Option<String>,

        /// Path to kubeconfig file (default: ~/.kube/config)
        #[arg(long)]
        kubeconfig: Option<PathBuf>,

        /// Kubernetes context to use
        #[arg(long)]
        context: Option<String>,
    },
}
