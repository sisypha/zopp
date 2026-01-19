use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "zopp")]
#[command(about = "Zopp secrets management CLI")]
pub struct Cli {
    /// Server address
    #[arg(long, env = "ZOPP_SERVER", default_value = "http://127.0.0.1:50051")]
    pub server: String,

    /// Path to TLS CA certificate for server connection (optional, for self-signed certs)
    #[arg(long, env = "ZOPP_TLS_CA_CERT")]
    pub tls_ca_cert: Option<PathBuf>,

    /// Store credentials in config file instead of system keychain.
    /// Use this on systems without keychain support (e.g., headless servers, containers).
    #[arg(long, env = "ZOPP_USE_FILE_STORAGE")]
    pub use_file_storage: bool,

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
    /// Permission commands (RBAC)
    Permission {
        #[command(subcommand)]
        permission_cmd: PermissionCommand,
    },
    /// Group commands (user groups)
    Group {
        #[command(subcommand)]
        group_cmd: GroupCommand,
    },
    /// Audit log commands (admin only)
    Audit {
        #[command(subcommand)]
        audit_cmd: AuditCommand,
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
    /// Grant an existing service principal access to this workspace
    GrantPrincipalAccess {
        /// Workspace name
        #[arg(long, short = 'w')]
        workspace: String,
        /// Principal ID to grant access to
        #[arg(long, short = 'p')]
        principal: String,
    },
}

#[derive(Subcommand)]
pub enum PrincipalCommand {
    /// List all principals
    List,
    /// Show current principal
    Current,
    /// Create a new principal (register new device or service principal)
    Create {
        /// Principal name
        name: String,
        /// Create as service principal (no user association)
        #[arg(long)]
        service: bool,
        /// Workspace to add service principal to (required for --service)
        #[arg(long, short = 'w')]
        workspace: Option<String>,
        /// Export the principal immediately after creation (for easy setup on this device)
        #[arg(long)]
        export: bool,
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
    /// List service principals in a workspace
    ServiceList {
        /// Workspace name
        #[arg(long, short = 'w')]
        workspace: String,
    },
    /// Remove a principal from a workspace (revokes all permissions too)
    WorkspaceRemove {
        /// Workspace name
        #[arg(long, short = 'w')]
        workspace: String,
        /// Principal ID (UUID)
        #[arg(long)]
        principal: String,
    },
    /// Revoke all permissions for a principal in a workspace
    RevokeAll {
        /// Workspace name
        #[arg(long, short = 'w')]
        workspace: String,
        /// Principal ID (UUID)
        #[arg(long)]
        principal: String,
    },
    /// Export a principal to the server (generates passphrase for retrieval)
    Export {
        /// Principal name to export
        name: String,
        /// Expiration time in hours (default: 24)
        #[arg(long, default_value = "24")]
        expires_hours: u32,
    },
    /// Import a principal from the server using export code and passphrase
    Import {
        /// Export code from export (if not provided, will prompt)
        #[arg(long, short = 'c')]
        code: Option<String>,
        /// Passphrase from export (if not provided, will prompt).
        /// WARNING: Passing via CLI exposes the passphrase in shell history.
        /// Prefer interactive prompt or ZOPP_EXPORT_PASSPHRASE env var.
        #[arg(long, short = 'p', hide = true, env = "ZOPP_EXPORT_PASSPHRASE")]
        passphrase: Option<String>,
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
    /// Create a workspace invite (requires admin)
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

#[derive(Subcommand)]
pub enum PermissionCommand {
    /// Set workspace permission for a principal
    Set {
        /// Workspace name
        #[arg(long, short = 'w')]
        workspace: String,
        /// Principal ID (UUID)
        #[arg(long)]
        principal: String,
        /// Role: admin, write, or read
        #[arg(long)]
        role: String,
    },
    /// Get workspace permission for a principal
    Get {
        /// Workspace name
        #[arg(long, short = 'w')]
        workspace: String,
        /// Principal ID (UUID)
        #[arg(long)]
        principal: String,
    },
    /// List all permissions on a workspace
    List {
        /// Workspace name
        #[arg(long, short = 'w')]
        workspace: String,
    },
    /// Remove workspace permission for a principal
    Remove {
        /// Workspace name
        #[arg(long, short = 'w')]
        workspace: String,
        /// Principal ID (UUID)
        #[arg(long)]
        principal: String,
    },
    /// Set project permission for a principal
    ProjectSet {
        /// Workspace name
        #[arg(long, short = 'w')]
        workspace: String,
        /// Project name
        #[arg(long, short = 'p')]
        project: String,
        /// Principal ID (UUID)
        #[arg(long)]
        principal: String,
        /// Role: admin, write, or read
        #[arg(long)]
        role: String,
    },
    /// Get project permission for a principal
    ProjectGet {
        /// Workspace name
        #[arg(long, short = 'w')]
        workspace: String,
        /// Project name
        #[arg(long, short = 'p')]
        project: String,
        /// Principal ID (UUID)
        #[arg(long)]
        principal: String,
    },
    /// List all principal permissions on a project
    ProjectList {
        /// Workspace name
        #[arg(long, short = 'w')]
        workspace: String,
        /// Project name
        #[arg(long, short = 'p')]
        project: String,
    },
    /// Remove project permission for a principal
    ProjectRemove {
        /// Workspace name
        #[arg(long, short = 'w')]
        workspace: String,
        /// Project name
        #[arg(long, short = 'p')]
        project: String,
        /// Principal ID (UUID)
        #[arg(long)]
        principal: String,
    },
    /// Set environment permission for a principal
    EnvSet {
        /// Workspace name
        #[arg(long, short = 'w')]
        workspace: String,
        /// Project name
        #[arg(long, short = 'p')]
        project: String,
        /// Environment name
        #[arg(long, short = 'e')]
        environment: String,
        /// Principal ID (UUID)
        #[arg(long)]
        principal: String,
        /// Role: admin, write, or read
        #[arg(long)]
        role: String,
    },
    /// Get environment permission for a principal
    EnvGet {
        /// Workspace name
        #[arg(long, short = 'w')]
        workspace: String,
        /// Project name
        #[arg(long, short = 'p')]
        project: String,
        /// Environment name
        #[arg(long, short = 'e')]
        environment: String,
        /// Principal ID (UUID)
        #[arg(long)]
        principal: String,
    },
    /// List all principal permissions on an environment
    EnvList {
        /// Workspace name
        #[arg(long, short = 'w')]
        workspace: String,
        /// Project name
        #[arg(long, short = 'p')]
        project: String,
        /// Environment name
        #[arg(long, short = 'e')]
        environment: String,
    },
    /// Remove environment permission for a principal
    EnvRemove {
        /// Workspace name
        #[arg(long, short = 'w')]
        workspace: String,
        /// Project name
        #[arg(long, short = 'p')]
        project: String,
        /// Environment name
        #[arg(long, short = 'e')]
        environment: String,
        /// Principal ID (UUID)
        #[arg(long)]
        principal: String,
    },
    /// Set workspace permission for a user (by email)
    UserSet {
        /// Workspace name
        #[arg(long, short = 'w')]
        workspace: String,
        /// User email
        #[arg(long)]
        email: String,
        /// Role: admin, write, or read
        #[arg(long)]
        role: String,
    },
    /// Get workspace permission for a user (by email)
    UserGet {
        /// Workspace name
        #[arg(long, short = 'w')]
        workspace: String,
        /// User email
        #[arg(long)]
        email: String,
    },
    /// List all user permissions on a workspace
    UserList {
        /// Workspace name
        #[arg(long, short = 'w')]
        workspace: String,
    },
    /// Remove workspace permission for a user (by email)
    UserRemove {
        /// Workspace name
        #[arg(long, short = 'w')]
        workspace: String,
        /// User email
        #[arg(long)]
        email: String,
    },
    /// Set project permission for a user (by email)
    UserProjectSet {
        /// Workspace name
        #[arg(long, short = 'w')]
        workspace: String,
        /// Project name
        #[arg(long, short = 'p')]
        project: String,
        /// User email
        #[arg(long)]
        email: String,
        /// Role: admin, write, or read
        #[arg(long)]
        role: String,
    },
    /// Remove project permission for a user (by email)
    UserProjectRemove {
        /// Workspace name
        #[arg(long, short = 'w')]
        workspace: String,
        /// Project name
        #[arg(long, short = 'p')]
        project: String,
        /// User email
        #[arg(long)]
        email: String,
    },
    /// Get project permission for a user (by email)
    UserProjectGet {
        /// Workspace name
        #[arg(long, short = 'w')]
        workspace: String,
        /// Project name
        #[arg(long, short = 'p')]
        project: String,
        /// User email
        #[arg(long)]
        email: String,
    },
    /// Set environment permission for a user (by email)
    UserEnvSet {
        /// Workspace name
        #[arg(long, short = 'w')]
        workspace: String,
        /// Project name
        #[arg(long, short = 'p')]
        project: String,
        /// Environment name
        #[arg(long, short = 'e')]
        environment: String,
        /// User email
        #[arg(long)]
        email: String,
        /// Role: admin, write, or read
        #[arg(long)]
        role: String,
    },
    /// Remove environment permission for a user (by email)
    UserEnvRemove {
        /// Workspace name
        #[arg(long, short = 'w')]
        workspace: String,
        /// Project name
        #[arg(long, short = 'p')]
        project: String,
        /// Environment name
        #[arg(long, short = 'e')]
        environment: String,
        /// User email
        #[arg(long)]
        email: String,
    },
    /// Get environment permission for a user (by email)
    UserEnvGet {
        /// Workspace name
        #[arg(long, short = 'w')]
        workspace: String,
        /// Project name
        #[arg(long, short = 'p')]
        project: String,
        /// Environment name
        #[arg(long, short = 'e')]
        environment: String,
        /// User email
        #[arg(long)]
        email: String,
    },
    /// List all user permissions on a project
    UserProjectList {
        /// Workspace name
        #[arg(long, short = 'w')]
        workspace: String,
        /// Project name
        #[arg(long, short = 'p')]
        project: String,
    },
    /// List all user permissions on an environment
    UserEnvList {
        /// Workspace name
        #[arg(long, short = 'w')]
        workspace: String,
        /// Project name
        #[arg(long, short = 'p')]
        project: String,
        /// Environment name
        #[arg(long, short = 'e')]
        environment: String,
    },
    /// Show effective permissions for a principal (aggregated view)
    Effective {
        /// Workspace name
        #[arg(long, short = 'w')]
        workspace: String,
        /// Principal ID (UUID)
        #[arg(long)]
        principal: String,
    },
}

#[derive(Subcommand)]
pub enum GroupCommand {
    /// Create a new group
    Create {
        /// Workspace name
        #[arg(long, short = 'w')]
        workspace: Option<String>,
        /// Group name
        name: String,
        /// Group description
        #[arg(long, short = 'd')]
        description: Option<String>,
    },
    /// List groups in a workspace
    List {
        /// Workspace name
        #[arg(long, short = 'w')]
        workspace: Option<String>,
    },
    /// Delete a group
    Delete {
        /// Workspace name
        #[arg(long, short = 'w')]
        workspace: Option<String>,
        /// Group name
        name: String,
    },
    /// Update a group (rename or change description)
    Update {
        /// Workspace name
        #[arg(long, short = 'w')]
        workspace: Option<String>,
        /// Current group name
        name: String,
        /// New group name
        #[arg(long)]
        new_name: Option<String>,
        /// New description
        #[arg(long, short = 'd')]
        description: Option<String>,
    },
    /// Add a user to a group
    AddMember {
        /// Workspace name
        #[arg(long, short = 'w')]
        workspace: Option<String>,
        /// Group name
        #[arg(long, short = 'g')]
        group: String,
        /// User email
        email: String,
    },
    /// Remove a user from a group
    RemoveMember {
        /// Workspace name
        #[arg(long, short = 'w')]
        workspace: Option<String>,
        /// Group name
        #[arg(long, short = 'g')]
        group: String,
        /// User email
        email: String,
    },
    /// List members of a group
    ListMembers {
        /// Workspace name
        #[arg(long, short = 'w')]
        workspace: Option<String>,
        /// Group name
        #[arg(long, short = 'g')]
        group: String,
    },
    /// Set workspace permission for a group
    SetPermission {
        /// Workspace name
        #[arg(long, short = 'w')]
        workspace: Option<String>,
        /// Group name
        #[arg(long, short = 'g')]
        group: String,
        /// Role: admin, write, or read
        #[arg(long)]
        role: String,
    },
    /// Remove workspace permission for a group
    RemovePermission {
        /// Workspace name
        #[arg(long, short = 'w')]
        workspace: Option<String>,
        /// Group name
        #[arg(long, short = 'g')]
        group: String,
    },
    /// Get workspace permission for a group
    GetPermission {
        /// Workspace name
        #[arg(long, short = 'w')]
        workspace: Option<String>,
        /// Group name
        #[arg(long, short = 'g')]
        group: String,
    },
    /// List all group permissions on a workspace
    ListPermissions {
        /// Workspace name
        #[arg(long, short = 'w')]
        workspace: Option<String>,
    },
    /// Set project permission for a group
    SetProjectPermission {
        /// Workspace name
        #[arg(long, short = 'w')]
        workspace: Option<String>,
        /// Project name
        #[arg(long, short = 'p')]
        project: String,
        /// Group name
        #[arg(long, short = 'g')]
        group: String,
        /// Role: admin, write, or read
        #[arg(long)]
        role: String,
    },
    /// Remove project permission for a group
    RemoveProjectPermission {
        /// Workspace name
        #[arg(long, short = 'w')]
        workspace: Option<String>,
        /// Project name
        #[arg(long, short = 'p')]
        project: String,
        /// Group name
        #[arg(long, short = 'g')]
        group: String,
    },
    /// Get project permission for a group
    GetProjectPermission {
        /// Workspace name
        #[arg(long, short = 'w')]
        workspace: Option<String>,
        /// Project name
        #[arg(long, short = 'p')]
        project: String,
        /// Group name
        #[arg(long, short = 'g')]
        group: String,
    },
    /// List all group permissions on a project
    ListProjectPermissions {
        /// Workspace name
        #[arg(long, short = 'w')]
        workspace: Option<String>,
        /// Project name
        #[arg(long, short = 'p')]
        project: String,
    },
    /// Set environment permission for a group
    SetEnvPermission {
        /// Workspace name
        #[arg(long, short = 'w')]
        workspace: Option<String>,
        /// Project name
        #[arg(long, short = 'p')]
        project: String,
        /// Environment name
        #[arg(long, short = 'e')]
        environment: String,
        /// Group name
        #[arg(long, short = 'g')]
        group: String,
        /// Role: admin, write, or read
        #[arg(long)]
        role: String,
    },
    /// Remove environment permission for a group
    RemoveEnvPermission {
        /// Workspace name
        #[arg(long, short = 'w')]
        workspace: Option<String>,
        /// Project name
        #[arg(long, short = 'p')]
        project: String,
        /// Environment name
        #[arg(long, short = 'e')]
        environment: String,
        /// Group name
        #[arg(long, short = 'g')]
        group: String,
    },
    /// Get environment permission for a group
    GetEnvPermission {
        /// Workspace name
        #[arg(long, short = 'w')]
        workspace: Option<String>,
        /// Project name
        #[arg(long, short = 'p')]
        project: String,
        /// Environment name
        #[arg(long, short = 'e')]
        environment: String,
        /// Group name
        #[arg(long, short = 'g')]
        group: String,
    },
    /// List all group permissions on an environment
    ListEnvPermissions {
        /// Workspace name
        #[arg(long, short = 'w')]
        workspace: Option<String>,
        /// Project name
        #[arg(long, short = 'p')]
        project: String,
        /// Environment name
        #[arg(long, short = 'e')]
        environment: String,
    },
}

#[derive(Subcommand)]
pub enum AuditCommand {
    /// List audit log entries in a workspace
    List {
        /// Workspace name
        #[arg(long, short = 'w')]
        workspace: String,
        /// Filter by action type
        #[arg(long)]
        action: Option<String>,
        /// Filter by result
        #[arg(long)]
        result: Option<String>,
        /// Maximum entries to return
        #[arg(long, default_value = "50")]
        limit: u32,
    },
    /// Get a specific audit log entry
    Get {
        /// Workspace name
        #[arg(long, short = 'w')]
        workspace: String,
        /// Audit entry ID
        id: String,
    },
    /// Count audit log entries in a workspace
    Count {
        /// Workspace name
        #[arg(long, short = 'w')]
        workspace: String,
        /// Filter by action type
        #[arg(long)]
        action: Option<String>,
        /// Filter by result
        #[arg(long)]
        result: Option<String>,
    },
}
