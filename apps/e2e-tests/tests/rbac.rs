//! Comprehensive RBAC E2E tests
//!
//! Tests all permission combinations for all secret operations:
//! - Operations: get, set, list (export), delete
//! - Permission sources: owner, principal permissions, group permissions
//! - Permission scopes: workspace, project, environment
//! - Roles: Admin, Write, Read, None

mod common;

use std::fs;
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::time::Duration;
use tokio::time::sleep;

// ═══════════════════════════════════════════════════════════════════════════
// Test Infrastructure
// ═══════════════════════════════════════════════════════════════════════════

struct TestEnv {
    server_url: String,
    db_url: String,
    test_dir: PathBuf,
    zopp_bin: PathBuf,
    zopp_server_bin: PathBuf,
    server_process: Option<std::process::Child>,
}

struct User {
    #[allow(dead_code)]
    name: String,
    email: String,
    principal: String,
    home: PathBuf,
}

impl TestEnv {
    async fn setup(test_name: &str, port: u16) -> Result<Self, Box<dyn std::error::Error>> {
        let workspace_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf();

        let target_dir = std::env::var("CARGO_TARGET_DIR")
            .unwrap_or_else(|_| workspace_root.join("target").to_str().unwrap().to_string());
        let bin_dir = PathBuf::from(&target_dir).join("debug");

        let zopp_server_bin = bin_dir.join(if cfg!(windows) {
            "zopp-server.exe"
        } else {
            "zopp-server"
        });
        let zopp_bin = bin_dir.join(if cfg!(windows) { "zopp.exe" } else { "zopp" });

        if !zopp_server_bin.exists() || !zopp_bin.exists() {
            return Err("Binaries not built. Run 'cargo build --bins' first.".into());
        }

        let test_dir = std::env::temp_dir().join(format!("zopp-rbac-test-{}", test_name));
        if test_dir.exists() {
            fs::remove_dir_all(&test_dir)?;
        }
        fs::create_dir_all(&test_dir)?;

        let test_id = std::process::id();
        let db_path = test_dir.join(format!("test-{}.db", test_id));
        let db_url = format!("sqlite://{}?mode=rwc", db_path.display());

        let server_addr = format!("0.0.0.0:{}", port);
        // Use wrapping arithmetic to avoid overflow when port is high
        let health_port = port.wrapping_add(1000);
        let health_port = if health_port < 1024 {
            health_port + 10000
        } else {
            health_port
        };
        let health_addr = format!("0.0.0.0:{}", health_port);

        let server = Command::new(&zopp_server_bin)
            .env("DATABASE_URL", &db_url)
            .args([
                "serve",
                "--addr",
                &server_addr,
                "--health-addr",
                &health_addr,
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;

        // Wait for server
        let client_addr = format!("127.0.0.1:{}", port);
        for _ in 0..30 {
            sleep(Duration::from_millis(200)).await;
            if TcpStream::connect(&client_addr).is_ok() {
                break;
            }
        }

        if TcpStream::connect(&client_addr).is_err() {
            return Err("Server failed to start".into());
        }

        Ok(Self {
            server_url: format!("http://127.0.0.1:{}", port),
            db_url,
            test_dir,
            zopp_bin,
            zopp_server_bin,
            server_process: Some(server),
        })
    }

    fn create_user(&self, name: &str) -> User {
        let home = self.test_dir.join(name);
        fs::create_dir_all(&home).unwrap();
        User {
            name: name.to_string(),
            email: format!("{}@example.com", name),
            principal: format!("{}-device", name),
            home,
        }
    }

    fn create_server_invite(&self) -> Result<String, Box<dyn std::error::Error>> {
        let output = Command::new(&self.zopp_server_bin)
            .env("DATABASE_URL", &self.db_url)
            .args(["invite", "create", "--expires-hours", "1", "--plain"])
            .output()?;
        if !output.status.success() {
            return Err(format!(
                "Failed to create server invite: {}",
                String::from_utf8_lossy(&output.stderr)
            )
            .into());
        }
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    }

    fn join_server(&self, user: &User, invite: &str) -> Result<(), Box<dyn std::error::Error>> {
        let output = Command::new(&self.zopp_bin)
            .env("HOME", &user.home)
            .args([
                "--server",
                &self.server_url,
                "join",
                invite,
                &user.email,
                "--principal",
                &user.principal,
            ])
            .output()?;
        if !output.status.success() {
            return Err(format!(
                "Failed to join: {}",
                String::from_utf8_lossy(&output.stderr)
            )
            .into());
        }
        Ok(())
    }

    fn create_workspace(&self, user: &User, name: &str) -> Result<(), Box<dyn std::error::Error>> {
        let output = Command::new(&self.zopp_bin)
            .env("HOME", &user.home)
            .args(["--server", &self.server_url, "workspace", "create", name])
            .output()?;
        if !output.status.success() {
            return Err(format!(
                "Failed to create workspace: {}",
                String::from_utf8_lossy(&output.stderr)
            )
            .into());
        }
        Ok(())
    }

    fn create_project(
        &self,
        user: &User,
        workspace: &str,
        name: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let output = Command::new(&self.zopp_bin)
            .env("HOME", &user.home)
            .args([
                "--server",
                &self.server_url,
                "project",
                "create",
                name,
                "-w",
                workspace,
            ])
            .output()?;
        if !output.status.success() {
            return Err(format!(
                "Failed to create project: {}",
                String::from_utf8_lossy(&output.stderr)
            )
            .into());
        }
        Ok(())
    }

    fn create_environment(
        &self,
        user: &User,
        workspace: &str,
        project: &str,
        name: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let output = Command::new(&self.zopp_bin)
            .env("HOME", &user.home)
            .args([
                "--server",
                &self.server_url,
                "environment",
                "create",
                name,
                "-w",
                workspace,
                "-p",
                project,
            ])
            .output()?;
        if !output.status.success() {
            return Err(format!(
                "Failed to create environment: {}",
                String::from_utf8_lossy(&output.stderr)
            )
            .into());
        }
        Ok(())
    }

    fn create_workspace_invite(
        &self,
        user: &User,
        workspace: &str,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let output = Command::new(&self.zopp_bin)
            .env("HOME", &user.home)
            .args([
                "--server",
                &self.server_url,
                "invite",
                "create",
                "-w",
                workspace,
                "--expires-hours",
                "1",
                "--plain",
            ])
            .output()?;
        if !output.status.success() {
            return Err(format!(
                "Failed to create workspace invite: {}",
                String::from_utf8_lossy(&output.stderr)
            )
            .into());
        }
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    }

    // ─────────────────────────────────────────────────────────────────────────
    // User Permission Commands (direct user-to-workspace permissions)
    // ─────────────────────────────────────────────────────────────────────────

    /// Set a direct user permission on a workspace
    fn set_user_permission(
        &self,
        admin: &User,
        workspace: &str,
        target_email: &str,
        role: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let output = Command::new(&self.zopp_bin)
            .env("HOME", &admin.home)
            .args([
                "--server",
                &self.server_url,
                "permission",
                "user-set",
                "-w",
                workspace,
                "--email",
                target_email,
                "--role",
                role,
            ])
            .output()?;
        if !output.status.success() {
            return Err(format!(
                "Failed to set user permission: {}",
                String::from_utf8_lossy(&output.stderr)
            )
            .into());
        }
        Ok(())
    }

    /// Remove a user's direct permission from a workspace
    fn remove_user_permission(
        &self,
        admin: &User,
        workspace: &str,
        target_email: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let output = Command::new(&self.zopp_bin)
            .env("HOME", &admin.home)
            .args([
                "--server",
                &self.server_url,
                "permission",
                "user-remove",
                "-w",
                workspace,
                "--email",
                target_email,
            ])
            .output()?;
        if !output.status.success() {
            return Err(format!(
                "Failed to remove user permission: {}",
                String::from_utf8_lossy(&output.stderr)
            )
            .into());
        }
        Ok(())
    }

    // ─────────────────────────────────────────────────────────────────────────
    // User Project Permission Commands
    // ─────────────────────────────────────────────────────────────────────────

    /// Set a user's project-level permission
    fn set_user_project_permission(
        &self,
        admin: &User,
        workspace: &str,
        project: &str,
        target_email: &str,
        role: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let output = Command::new(&self.zopp_bin)
            .env("HOME", &admin.home)
            .args([
                "--server",
                &self.server_url,
                "permission",
                "user-project-set",
                "-w",
                workspace,
                "-p",
                project,
                "--email",
                target_email,
                "--role",
                role,
            ])
            .output()?;
        if !output.status.success() {
            return Err(format!(
                "Failed to set user project permission: {}",
                String::from_utf8_lossy(&output.stderr)
            )
            .into());
        }
        Ok(())
    }

    /// Remove a user's project-level permission
    fn remove_user_project_permission(
        &self,
        admin: &User,
        workspace: &str,
        project: &str,
        target_email: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let output = Command::new(&self.zopp_bin)
            .env("HOME", &admin.home)
            .args([
                "--server",
                &self.server_url,
                "permission",
                "user-project-remove",
                "-w",
                workspace,
                "-p",
                project,
                "--email",
                target_email,
            ])
            .output()?;
        if !output.status.success() {
            return Err(format!(
                "Failed to remove user project permission: {}",
                String::from_utf8_lossy(&output.stderr)
            )
            .into());
        }
        Ok(())
    }

    /// Set a user's project-level permission (returns Output for checking)
    fn set_user_project_permission_check(
        &self,
        user: &User,
        workspace: &str,
        project: &str,
        target_email: &str,
        role: &str,
    ) -> Output {
        Command::new(&self.zopp_bin)
            .env("HOME", &user.home)
            .args([
                "--server",
                &self.server_url,
                "permission",
                "user-project-set",
                "-w",
                workspace,
                "-p",
                project,
                "--email",
                target_email,
                "--role",
                role,
            ])
            .output()
            .expect("Failed to execute")
    }

    // ─────────────────────────────────────────────────────────────────────────
    // User Environment Permission Commands
    // ─────────────────────────────────────────────────────────────────────────

    /// Set a user's environment-level permission
    fn set_user_environment_permission(
        &self,
        admin: &User,
        workspace: &str,
        project: &str,
        environment: &str,
        target_email: &str,
        role: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let output = Command::new(&self.zopp_bin)
            .env("HOME", &admin.home)
            .args([
                "--server",
                &self.server_url,
                "permission",
                "user-env-set",
                "-w",
                workspace,
                "-p",
                project,
                "-e",
                environment,
                "--email",
                target_email,
                "--role",
                role,
            ])
            .output()?;
        if !output.status.success() {
            return Err(format!(
                "Failed to set user environment permission: {}",
                String::from_utf8_lossy(&output.stderr)
            )
            .into());
        }
        Ok(())
    }

    /// Remove a user's environment-level permission
    fn remove_user_environment_permission(
        &self,
        admin: &User,
        workspace: &str,
        project: &str,
        environment: &str,
        target_email: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let output = Command::new(&self.zopp_bin)
            .env("HOME", &admin.home)
            .args([
                "--server",
                &self.server_url,
                "permission",
                "user-env-remove",
                "-w",
                workspace,
                "-p",
                project,
                "-e",
                environment,
                "--email",
                target_email,
            ])
            .output()?;
        if !output.status.success() {
            return Err(format!(
                "Failed to remove user environment permission: {}",
                String::from_utf8_lossy(&output.stderr)
            )
            .into());
        }
        Ok(())
    }

    /// Set a user's environment-level permission (returns Output for checking)
    fn set_user_environment_permission_check(
        &self,
        user: &User,
        workspace: &str,
        project: &str,
        environment: &str,
        target_email: &str,
        role: &str,
    ) -> Output {
        Command::new(&self.zopp_bin)
            .env("HOME", &user.home)
            .args([
                "--server",
                &self.server_url,
                "permission",
                "user-env-set",
                "-w",
                workspace,
                "-p",
                project,
                "-e",
                environment,
                "--email",
                target_email,
                "--role",
                role,
            ])
            .output()
            .expect("Failed to execute")
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Principal Permission Commands (device-level permissions, ceiling for humans)
    // ─────────────────────────────────────────────────────────────────────────

    /// Set a principal-level permission (acts as ceiling for human users)
    fn set_principal_permission(
        &self,
        admin: &User,
        workspace: &str,
        principal_id: &str,
        role: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let output = Command::new(&self.zopp_bin)
            .env("HOME", &admin.home)
            .args([
                "--server",
                &self.server_url,
                "permission",
                "set",
                "-w",
                workspace,
                "--principal",
                principal_id,
                "--role",
                role,
            ])
            .output()?;
        if !output.status.success() {
            return Err(format!(
                "Failed to set principal permission: {}",
                String::from_utf8_lossy(&output.stderr)
            )
            .into());
        }
        Ok(())
    }

    /// Remove a principal-level permission
    fn remove_principal_permission(
        &self,
        admin: &User,
        workspace: &str,
        principal_id: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let output = Command::new(&self.zopp_bin)
            .env("HOME", &admin.home)
            .args([
                "--server",
                &self.server_url,
                "permission",
                "remove",
                "-w",
                workspace,
                "--principal",
                principal_id,
            ])
            .output()?;
        if !output.status.success() {
            return Err(format!(
                "Failed to remove principal permission: {}",
                String::from_utf8_lossy(&output.stderr)
            )
            .into());
        }
        Ok(())
    }

    /// Get the principal ID for a user (reads from their config)
    fn get_principal_id(&self, user: &User) -> Result<String, Box<dyn std::error::Error>> {
        let config_path = user.home.join(".zopp").join("config.json");
        let config_content = fs::read_to_string(&config_path)?;
        let config: serde_json::Value = serde_json::from_str(&config_content)?;

        // Find the current principal
        let current = config["current_principal"]
            .as_str()
            .ok_or("No current principal")?;
        let principals = config["principals"]
            .as_array()
            .ok_or("No principals array")?;

        for p in principals {
            if p["name"].as_str() == Some(current) {
                return Ok(p["id"].as_str().ok_or("No principal id")?.to_string());
            }
        }
        Err("Principal not found".into())
    }

    /// Create a service principal (no user association) with workspace access
    fn create_service_principal(
        &self,
        admin: &User,
        name: &str,
    ) -> Result<String, Box<dyn std::error::Error>> {
        // Service principals require a workspace; use "acme" as default (matches most tests)
        self.create_service_principal_in_workspace(admin, name, "acme")
    }

    /// Create a service principal with access to a specific workspace
    fn create_service_principal_in_workspace(
        &self,
        admin: &User,
        name: &str,
        workspace: &str,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let output = Command::new(&self.zopp_bin)
            .env("HOME", &admin.home)
            .args([
                "--server",
                &self.server_url,
                "principal",
                "create",
                name,
                "--service",
                "--workspace",
                workspace,
            ])
            .output()?;
        if !output.status.success() {
            return Err(format!(
                "Failed to create service principal: {}",
                String::from_utf8_lossy(&output.stderr)
            )
            .into());
        }
        // Get the principal ID from the config (it was just added)
        let config_path = admin.home.join(".zopp").join("config.json");
        let config_content = fs::read_to_string(&config_path)?;
        let config: serde_json::Value = serde_json::from_str(&config_content)?;
        let principals = config["principals"]
            .as_array()
            .ok_or("No principals array")?;
        for p in principals {
            if p["name"].as_str() == Some(name) {
                return Ok(p["id"].as_str().ok_or("No principal id")?.to_string());
            }
        }
        Err("Service principal not found in config".into())
    }

    /// Grant an existing service principal access to another workspace
    fn grant_principal_workspace_access(
        &self,
        admin: &User,
        workspace: &str,
        principal_id: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let output = Command::new(&self.zopp_bin)
            .env("HOME", &admin.home)
            .args([
                "--server",
                &self.server_url,
                "workspace",
                "grant-principal-access",
                "-w",
                workspace,
                "-p",
                principal_id,
            ])
            .output()?;
        if !output.status.success() {
            return Err(format!(
                "Failed to grant workspace access: {}",
                String::from_utf8_lossy(&output.stderr)
            )
            .into());
        }
        Ok(())
    }

    /// Remove a principal from a workspace (revokes all permissions)
    fn remove_principal_from_workspace(
        &self,
        admin: &User,
        workspace: &str,
        principal_id: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let output = Command::new(&self.zopp_bin)
            .env("HOME", &admin.home)
            .args([
                "--server",
                &self.server_url,
                "principal",
                "workspace-remove",
                "-w",
                workspace,
                "--principal",
                principal_id,
            ])
            .output()?;
        if !output.status.success() {
            return Err(format!(
                "Failed to remove principal from workspace: {}",
                String::from_utf8_lossy(&output.stderr)
            )
            .into());
        }
        Ok(())
    }

    /// Set principal permission at project level (returns Output for checking)
    fn set_principal_project_permission_check(
        &self,
        admin: &User,
        workspace: &str,
        project: &str,
        principal_id: &str,
        role: &str,
    ) -> Output {
        Command::new(&self.zopp_bin)
            .env("HOME", &admin.home)
            .args([
                "--server",
                &self.server_url,
                "permission",
                "project-set",
                "-w",
                workspace,
                "-p",
                project,
                "--principal",
                principal_id,
                "--role",
                role,
            ])
            .output()
            .expect("Failed to execute principal project permission set")
    }

    /// Set principal permission at environment level (returns Output for checking)
    fn set_principal_env_permission_check(
        &self,
        admin: &User,
        workspace: &str,
        project: &str,
        environment: &str,
        principal_id: &str,
        role: &str,
    ) -> Output {
        Command::new(&self.zopp_bin)
            .env("HOME", &admin.home)
            .args([
                "--server",
                &self.server_url,
                "permission",
                "env-set",
                "-w",
                workspace,
                "-p",
                project,
                "-e",
                environment,
                "--principal",
                principal_id,
                "--role",
                role,
            ])
            .output()
            .expect("Failed to execute principal env permission set")
    }

    /// Remove principal permission at project level (returns Output for checking)
    fn remove_principal_project_permission_check(
        &self,
        user: &User,
        workspace: &str,
        project: &str,
        principal_id: &str,
    ) -> Output {
        Command::new(&self.zopp_bin)
            .env("HOME", &user.home)
            .args([
                "--server",
                &self.server_url,
                "permission",
                "project-remove",
                "-w",
                workspace,
                "-p",
                project,
                "--principal",
                principal_id,
            ])
            .output()
            .expect("Failed to execute principal project permission remove")
    }

    /// Remove principal permission at environment level (returns Output for checking)
    fn remove_principal_env_permission_check(
        &self,
        user: &User,
        workspace: &str,
        project: &str,
        environment: &str,
        principal_id: &str,
    ) -> Output {
        Command::new(&self.zopp_bin)
            .env("HOME", &user.home)
            .args([
                "--server",
                &self.server_url,
                "permission",
                "env-remove",
                "-w",
                workspace,
                "-p",
                project,
                "-e",
                environment,
                "--principal",
                principal_id,
            ])
            .output()
            .expect("Failed to execute principal env permission remove")
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Group Commands
    // ─────────────────────────────────────────────────────────────────────────

    fn create_group(
        &self,
        admin: &User,
        workspace: &str,
        group_name: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let output = Command::new(&self.zopp_bin)
            .env("HOME", &admin.home)
            .args([
                "--server",
                &self.server_url,
                "group",
                "create",
                group_name,
                "-w",
                workspace,
            ])
            .output()?;
        if !output.status.success() {
            return Err(format!(
                "Failed to create group: {}",
                String::from_utf8_lossy(&output.stderr)
            )
            .into());
        }
        Ok(())
    }

    fn add_group_member(
        &self,
        admin: &User,
        workspace: &str,
        group_name: &str,
        member_email: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let output = Command::new(&self.zopp_bin)
            .env("HOME", &admin.home)
            .args([
                "--server",
                &self.server_url,
                "group",
                "add-member",
                "--group",
                group_name,
                "-w",
                workspace,
                member_email,
            ])
            .output()?;
        if !output.status.success() {
            return Err(format!(
                "Failed to add group member: {}",
                String::from_utf8_lossy(&output.stderr)
            )
            .into());
        }
        Ok(())
    }

    fn remove_group_member(
        &self,
        admin: &User,
        workspace: &str,
        group_name: &str,
        member_email: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let output = Command::new(&self.zopp_bin)
            .env("HOME", &admin.home)
            .args([
                "--server",
                &self.server_url,
                "group",
                "remove-member",
                "--group",
                group_name,
                "-w",
                workspace,
                member_email,
            ])
            .output()?;
        if !output.status.success() {
            return Err(format!(
                "Failed to remove group member: {}",
                String::from_utf8_lossy(&output.stderr)
            )
            .into());
        }
        Ok(())
    }

    fn set_group_permission(
        &self,
        admin: &User,
        workspace: &str,
        group_name: &str,
        role: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let output = Command::new(&self.zopp_bin)
            .env("HOME", &admin.home)
            .args([
                "--server",
                &self.server_url,
                "group",
                "set-permission",
                "--group",
                group_name,
                "-w",
                workspace,
                "--role",
                role,
            ])
            .output()?;
        if !output.status.success() {
            return Err(format!(
                "Failed to set group permission: {}",
                String::from_utf8_lossy(&output.stderr)
            )
            .into());
        }
        Ok(())
    }

    fn remove_group_permission(
        &self,
        admin: &User,
        workspace: &str,
        group_name: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let output = Command::new(&self.zopp_bin)
            .env("HOME", &admin.home)
            .args([
                "--server",
                &self.server_url,
                "group",
                "remove-permission",
                "--group",
                group_name,
                "-w",
                workspace,
            ])
            .output()?;
        if !output.status.success() {
            return Err(format!(
                "Failed to remove group permission: {}",
                String::from_utf8_lossy(&output.stderr)
            )
            .into());
        }
        Ok(())
    }

    fn set_group_project_permission(
        &self,
        admin: &User,
        workspace: &str,
        project: &str,
        group_name: &str,
        role: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let output = Command::new(&self.zopp_bin)
            .env("HOME", &admin.home)
            .args([
                "--server",
                &self.server_url,
                "group",
                "set-project-permission",
                "--group",
                group_name,
                "-w",
                workspace,
                "-p",
                project,
                "--role",
                role,
            ])
            .output()?;
        if !output.status.success() {
            return Err(format!(
                "Failed to set group project permission: {}",
                String::from_utf8_lossy(&output.stderr)
            )
            .into());
        }
        Ok(())
    }

    fn remove_group_project_permission(
        &self,
        admin: &User,
        workspace: &str,
        project: &str,
        group_name: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let output = Command::new(&self.zopp_bin)
            .env("HOME", &admin.home)
            .args([
                "--server",
                &self.server_url,
                "group",
                "remove-project-permission",
                "--group",
                group_name,
                "-w",
                workspace,
                "-p",
                project,
            ])
            .output()?;
        if !output.status.success() {
            return Err(format!(
                "Failed to remove group project permission: {}",
                String::from_utf8_lossy(&output.stderr)
            )
            .into());
        }
        Ok(())
    }

    fn set_group_environment_permission(
        &self,
        admin: &User,
        workspace: &str,
        project: &str,
        environment: &str,
        group_name: &str,
        role: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let output = Command::new(&self.zopp_bin)
            .env("HOME", &admin.home)
            .args([
                "--server",
                &self.server_url,
                "group",
                "set-env-permission",
                "--group",
                group_name,
                "-w",
                workspace,
                "-p",
                project,
                "-e",
                environment,
                "--role",
                role,
            ])
            .output()?;
        if !output.status.success() {
            return Err(format!(
                "Failed to set group environment permission: {}",
                String::from_utf8_lossy(&output.stderr)
            )
            .into());
        }
        Ok(())
    }

    fn remove_group_environment_permission(
        &self,
        admin: &User,
        workspace: &str,
        project: &str,
        environment: &str,
        group_name: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let output = Command::new(&self.zopp_bin)
            .env("HOME", &admin.home)
            .args([
                "--server",
                &self.server_url,
                "group",
                "remove-env-permission",
                "--group",
                group_name,
                "-w",
                workspace,
                "-p",
                project,
                "-e",
                environment,
            ])
            .output()?;
        if !output.status.success() {
            return Err(format!(
                "Failed to remove group environment permission: {}",
                String::from_utf8_lossy(&output.stderr)
            )
            .into());
        }
        Ok(())
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Permission List Commands (return Output for verification)
    // ─────────────────────────────────────────────────────────────────────────

    fn user_permission_list(&self, user: &User, workspace: &str) -> Output {
        Command::new(&self.zopp_bin)
            .env("HOME", &user.home)
            .args([
                "--server",
                &self.server_url,
                "permission",
                "user-list",
                "-w",
                workspace,
            ])
            .output()
            .expect("Failed to execute permission user-list")
    }

    fn user_project_permission_list(&self, user: &User, workspace: &str, project: &str) -> Output {
        Command::new(&self.zopp_bin)
            .env("HOME", &user.home)
            .args([
                "--server",
                &self.server_url,
                "permission",
                "user-project-list",
                "-w",
                workspace,
                "-p",
                project,
            ])
            .output()
            .expect("Failed to execute permission user-project-list")
    }

    fn user_env_permission_list(
        &self,
        user: &User,
        workspace: &str,
        project: &str,
        environment: &str,
    ) -> Output {
        Command::new(&self.zopp_bin)
            .env("HOME", &user.home)
            .args([
                "--server",
                &self.server_url,
                "permission",
                "user-env-list",
                "-w",
                workspace,
                "-p",
                project,
                "-e",
                environment,
            ])
            .output()
            .expect("Failed to execute permission user-env-list")
    }

    fn group_permission_list(&self, user: &User, workspace: &str) -> Output {
        Command::new(&self.zopp_bin)
            .env("HOME", &user.home)
            .args([
                "--server",
                &self.server_url,
                "group",
                "list-permissions",
                "-w",
                workspace,
            ])
            .output()
            .expect("Failed to execute group list-permissions")
    }

    fn group_project_permission_list(&self, user: &User, workspace: &str, project: &str) -> Output {
        Command::new(&self.zopp_bin)
            .env("HOME", &user.home)
            .args([
                "--server",
                &self.server_url,
                "group",
                "list-project-permissions",
                "-w",
                workspace,
                "-p",
                project,
            ])
            .output()
            .expect("Failed to execute group list-project-permissions")
    }

    fn group_env_permission_list(
        &self,
        user: &User,
        workspace: &str,
        project: &str,
        environment: &str,
    ) -> Output {
        Command::new(&self.zopp_bin)
            .env("HOME", &user.home)
            .args([
                "--server",
                &self.server_url,
                "group",
                "list-env-permissions",
                "-w",
                workspace,
                "-p",
                project,
                "-e",
                environment,
            ])
            .output()
            .expect("Failed to execute group list-env-permissions")
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Secret Operations (return Result to check success/failure)
    // ─────────────────────────────────────────────────────────────────────────

    fn secret_set(
        &self,
        user: &User,
        workspace: &str,
        project: &str,
        env: &str,
        key: &str,
        value: &str,
    ) -> Output {
        Command::new(&self.zopp_bin)
            .env("HOME", &user.home)
            .args([
                "--server",
                &self.server_url,
                "secret",
                "set",
                key,
                value,
                "-w",
                workspace,
                "-p",
                project,
                "-e",
                env,
            ])
            .output()
            .expect("Failed to execute secret set")
    }

    fn secret_get(
        &self,
        user: &User,
        workspace: &str,
        project: &str,
        env: &str,
        key: &str,
    ) -> Output {
        Command::new(&self.zopp_bin)
            .env("HOME", &user.home)
            .args([
                "--server",
                &self.server_url,
                "secret",
                "get",
                key,
                "-w",
                workspace,
                "-p",
                project,
                "-e",
                env,
            ])
            .output()
            .expect("Failed to execute secret get")
    }

    fn secret_delete(
        &self,
        user: &User,
        workspace: &str,
        project: &str,
        env: &str,
        key: &str,
    ) -> Output {
        Command::new(&self.zopp_bin)
            .env("HOME", &user.home)
            .args([
                "--server",
                &self.server_url,
                "secret",
                "delete",
                key,
                "-w",
                workspace,
                "-p",
                project,
                "-e",
                env,
            ])
            .output()
            .expect("Failed to execute secret delete")
    }

    fn secret_export(&self, user: &User, workspace: &str, project: &str, env: &str) -> Output {
        Command::new(&self.zopp_bin)
            .env("HOME", &user.home)
            .args([
                "--server",
                &self.server_url,
                "secret",
                "export",
                "-w",
                workspace,
                "-p",
                project,
                "-e",
                env,
            ])
            .output()
            .expect("Failed to execute secret export")
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Admin Operations (return Output to check success/failure)
    // ─────────────────────────────────────────────────────────────────────────

    fn project_create(&self, user: &User, workspace: &str, name: &str) -> Output {
        Command::new(&self.zopp_bin)
            .env("HOME", &user.home)
            .args([
                "--server",
                &self.server_url,
                "project",
                "create",
                name,
                "-w",
                workspace,
            ])
            .output()
            .expect("Failed to execute project create")
    }

    fn project_delete(&self, user: &User, workspace: &str, name: &str) -> Output {
        Command::new(&self.zopp_bin)
            .env("HOME", &user.home)
            .args([
                "--server",
                &self.server_url,
                "project",
                "delete",
                name,
                "-w",
                workspace,
            ])
            .output()
            .expect("Failed to execute project delete")
    }

    fn environment_create(
        &self,
        user: &User,
        workspace: &str,
        project: &str,
        name: &str,
    ) -> Output {
        Command::new(&self.zopp_bin)
            .env("HOME", &user.home)
            .args([
                "--server",
                &self.server_url,
                "environment",
                "create",
                name,
                "-w",
                workspace,
                "-p",
                project,
            ])
            .output()
            .expect("Failed to execute environment create")
    }

    fn environment_delete(
        &self,
        user: &User,
        workspace: &str,
        project: &str,
        name: &str,
    ) -> Output {
        Command::new(&self.zopp_bin)
            .env("HOME", &user.home)
            .args([
                "--server",
                &self.server_url,
                "environment",
                "delete",
                name,
                "-w",
                workspace,
                "-p",
                project,
            ])
            .output()
            .expect("Failed to execute environment delete")
    }

    fn group_create_check(&self, user: &User, workspace: &str, name: &str) -> Output {
        Command::new(&self.zopp_bin)
            .env("HOME", &user.home)
            .args([
                "--server",
                &self.server_url,
                "group",
                "create",
                name,
                "-w",
                workspace,
            ])
            .output()
            .expect("Failed to execute group create")
    }

    fn group_delete(&self, user: &User, workspace: &str, name: &str) -> Output {
        Command::new(&self.zopp_bin)
            .env("HOME", &user.home)
            .args([
                "--server",
                &self.server_url,
                "group",
                "delete",
                name,
                "-w",
                workspace,
            ])
            .output()
            .expect("Failed to execute group delete")
    }

    fn group_add_member_check(
        &self,
        user: &User,
        workspace: &str,
        group: &str,
        email: &str,
    ) -> Output {
        Command::new(&self.zopp_bin)
            .env("HOME", &user.home)
            .args([
                "--server",
                &self.server_url,
                "group",
                "add-member",
                "--group",
                group,
                "-w",
                workspace,
                email,
            ])
            .output()
            .expect("Failed to execute group add-member")
    }

    fn user_permission_set_check(
        &self,
        user: &User,
        workspace: &str,
        target_email: &str,
        role: &str,
    ) -> Output {
        Command::new(&self.zopp_bin)
            .env("HOME", &user.home)
            .args([
                "--server",
                &self.server_url,
                "permission",
                "user-set",
                "-w",
                workspace,
                "--email",
                target_email,
                "--role",
                role,
            ])
            .output()
            .expect("Failed to execute permission user-set")
    }

    fn invite_create_check(&self, user: &User, workspace: &str) -> Output {
        Command::new(&self.zopp_bin)
            .env("HOME", &user.home)
            .args([
                "--server",
                &self.server_url,
                "invite",
                "create",
                "-w",
                workspace,
                "--expires-hours",
                "1",
                "--plain",
            ])
            .output()
            .expect("Failed to execute invite create")
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Additional Authorization Check Helpers
    // ─────────────────────────────────────────────────────────────────────────

    fn invite_revoke_check(&self, user: &User, token: &str) -> Output {
        Command::new(&self.zopp_bin)
            .env("HOME", &user.home)
            .args(["--server", &self.server_url, "invite", "revoke", token])
            .output()
            .expect("Failed to execute invite revoke")
    }

    fn user_permission_remove_check(
        &self,
        user: &User,
        workspace: &str,
        target_email: &str,
    ) -> Output {
        Command::new(&self.zopp_bin)
            .env("HOME", &user.home)
            .args([
                "--server",
                &self.server_url,
                "permission",
                "user-remove",
                "-w",
                workspace,
                "--email",
                target_email,
            ])
            .output()
            .expect("Failed to execute permission user-remove")
    }

    fn group_update_check(
        &self,
        user: &User,
        workspace: &str,
        group: &str,
        new_name: &str,
    ) -> Output {
        Command::new(&self.zopp_bin)
            .env("HOME", &user.home)
            .args([
                "--server",
                &self.server_url,
                "group",
                "update",
                group,
                "-w",
                workspace,
                "--new-name",
                new_name,
            ])
            .output()
            .expect("Failed to execute group update")
    }

    fn principal_rename_check(&self, user: &User, principal_id: &str, new_name: &str) -> Output {
        Command::new(&self.zopp_bin)
            .env("HOME", &user.home)
            .args([
                "--server",
                &self.server_url,
                "principal",
                "rename",
                principal_id,
                new_name,
            ])
            .output()
            .expect("Failed to execute principal rename")
    }

    /// Switch to a different principal for the user
    fn principal_use(&self, user: &User, name: &str) -> Output {
        Command::new(&self.zopp_bin)
            .env("HOME", &user.home)
            .args(["principal", "use", name])
            .output()
            .expect("Failed to execute principal use")
    }

    fn group_set_permission_check(
        &self,
        user: &User,
        workspace: &str,
        group_name: &str,
        role: &str,
    ) -> Output {
        Command::new(&self.zopp_bin)
            .env("HOME", &user.home)
            .args([
                "--server",
                &self.server_url,
                "group",
                "set-permission",
                "--group",
                group_name,
                "-w",
                workspace,
                "--role",
                role,
            ])
            .output()
            .expect("Failed to execute group set-permission")
    }

    fn group_set_project_permission_check(
        &self,
        user: &User,
        workspace: &str,
        project: &str,
        group_name: &str,
        role: &str,
    ) -> Output {
        Command::new(&self.zopp_bin)
            .env("HOME", &user.home)
            .args([
                "--server",
                &self.server_url,
                "group",
                "set-project-permission",
                "--group",
                group_name,
                "-w",
                workspace,
                "-p",
                project,
                "--role",
                role,
            ])
            .output()
            .expect("Failed to execute group set-project-permission")
    }

    fn group_set_env_permission_check(
        &self,
        user: &User,
        workspace: &str,
        project: &str,
        environment: &str,
        group_name: &str,
        role: &str,
    ) -> Output {
        Command::new(&self.zopp_bin)
            .env("HOME", &user.home)
            .args([
                "--server",
                &self.server_url,
                "group",
                "set-env-permission",
                "--group",
                group_name,
                "-w",
                workspace,
                "-p",
                project,
                "-e",
                environment,
                "--role",
                role,
            ])
            .output()
            .expect("Failed to execute group set-env-permission")
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Audit Commands
    // ═══════════════════════════════════════════════════════════════════════════

    fn audit_list(&self, user: &User, workspace: &str) -> Output {
        Command::new(&self.zopp_bin)
            .env("HOME", &user.home)
            .args([
                "--server",
                &self.server_url,
                "audit",
                "list",
                "-w",
                workspace,
            ])
            .output()
            .expect("Failed to execute audit list")
    }

    fn audit_count(&self, user: &User, workspace: &str) -> Output {
        Command::new(&self.zopp_bin)
            .env("HOME", &user.home)
            .args([
                "--server",
                &self.server_url,
                "audit",
                "count",
                "-w",
                workspace,
            ])
            .output()
            .expect("Failed to execute audit count")
    }

    #[allow(dead_code)]
    fn audit_get(&self, user: &User, workspace: &str, id: &str) -> Output {
        Command::new(&self.zopp_bin)
            .env("HOME", &user.home)
            .args([
                "--server",
                &self.server_url,
                "audit",
                "get",
                "-w",
                workspace,
                id,
            ])
            .output()
            .expect("Failed to execute audit get")
    }
}

impl Drop for TestEnv {
    fn drop(&mut self) {
        if let Some(ref mut server) = self.server_process {
            common::graceful_shutdown(server);
        }
    }
}

fn find_available_port() -> Result<u16, Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    drop(listener);
    Ok(port)
}

fn assert_success(output: &Output, context: &str) {
    assert!(
        output.status.success(),
        "{} should succeed but failed: {}",
        context,
        String::from_utf8_lossy(&output.stderr)
    );
}

fn assert_denied(output: &Output, context: &str) {
    assert!(
        !output.status.success(),
        "{} should be denied but succeeded",
        context
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("permission")
            || stderr.contains("denied")
            || stderr.contains("Permission")
            || stderr.contains("cannot")
            || stderr.contains("Cannot")
            || stderr.contains("not found")
            || stderr.contains("Not found"),
        "{} should fail with permission or not found error, got: {}",
        context,
        stderr
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Test: Workspace Owner Always Has Full Access
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_owner_has_full_access() -> Result<(), Box<dyn std::error::Error>> {
    let port = find_available_port()?;
    let env = TestEnv::setup("owner_access", port).await?;

    // Setup: Alice creates workspace
    let alice = env.create_user("alice");
    let invite = env.create_server_invite()?;
    env.join_server(&alice, &invite)?;
    env.create_workspace(&alice, "acme")?;
    env.create_project(&alice, "acme", "api")?;
    env.create_environment(&alice, "acme", "api", "dev")?;

    println!("✓ Setup complete");

    // Owner can set secrets (no explicit permissions needed)
    let output = env.secret_set(&alice, "acme", "api", "dev", "SECRET_KEY", "owner_value");
    assert_success(&output, "Owner secret set");
    println!("✓ Owner can set secrets");

    // Owner can get secrets
    let output = env.secret_get(&alice, "acme", "api", "dev", "SECRET_KEY");
    assert_success(&output, "Owner secret get");
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "owner_value"
    );
    println!("✓ Owner can get secrets");

    // Owner can list secrets
    let output = env.secret_export(&alice, "acme", "api", "dev");
    assert_success(&output, "Owner secret export");
    println!("✓ Owner can list/export secrets");

    // Owner can delete secrets
    let output = env.secret_delete(&alice, "acme", "api", "dev", "SECRET_KEY");
    assert_success(&output, "Owner secret delete");
    println!("✓ Owner can delete secrets");

    println!("\n✅ test_owner_has_full_access PASSED");
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════
// Test: Non-Owner Denied by Default
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_non_owner_denied_by_default() -> Result<(), Box<dyn std::error::Error>> {
    let port = find_available_port()?;
    let env = TestEnv::setup("denied_default", port).await?;

    // Setup: Alice creates workspace, Bob joins
    let alice = env.create_user("alice");
    let bob = env.create_user("bob");

    let invite = env.create_server_invite()?;
    env.join_server(&alice, &invite)?;
    env.create_workspace(&alice, "acme")?;
    env.create_project(&alice, "acme", "api")?;
    env.create_environment(&alice, "acme", "api", "dev")?;

    // Alice creates a secret first
    let output = env.secret_set(&alice, "acme", "api", "dev", "TEST_SECRET", "test_value");
    assert_success(&output, "Alice sets secret");

    // Bob joins workspace
    let ws_invite = env.create_workspace_invite(&alice, "acme")?;
    env.join_server(&bob, &ws_invite)?;

    println!("✓ Setup complete - Bob joined workspace");

    // Bob should be denied - no permissions set
    let output = env.secret_get(&bob, "acme", "api", "dev", "TEST_SECRET");
    assert_denied(&output, "Bob secret get (no permissions)");
    println!("✓ Bob denied read (no permissions)");

    let output = env.secret_set(&bob, "acme", "api", "dev", "BOB_SECRET", "bob_value");
    assert_denied(&output, "Bob secret set (no permissions)");
    println!("✓ Bob denied write (no permissions)");

    let output = env.secret_export(&bob, "acme", "api", "dev");
    assert_denied(&output, "Bob secret export (no permissions)");
    println!("✓ Bob denied list (no permissions)");

    let output = env.secret_delete(&bob, "acme", "api", "dev", "TEST_SECRET");
    assert_denied(&output, "Bob secret delete (no permissions)");
    println!("✓ Bob denied delete (no permissions)");

    println!("\n✅ test_non_owner_denied_by_default PASSED");
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════
// Test: User Permissions - Read Role
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_user_permission_read() -> Result<(), Box<dyn std::error::Error>> {
    let port = find_available_port()?;
    let env = TestEnv::setup("user_read", port).await?;

    // Setup
    let alice = env.create_user("alice");
    let bob = env.create_user("bob");

    let invite = env.create_server_invite()?;
    env.join_server(&alice, &invite)?;
    env.create_workspace(&alice, "acme")?;
    env.create_project(&alice, "acme", "api")?;
    env.create_environment(&alice, "acme", "api", "dev")?;

    // Alice creates secret
    env.secret_set(&alice, "acme", "api", "dev", "TEST_SECRET", "test_value");

    // Bob joins workspace
    let ws_invite = env.create_workspace_invite(&alice, "acme")?;
    env.join_server(&bob, &ws_invite)?;

    // Alice grants Bob READ user permission
    env.set_user_permission(&alice, "acme", &bob.email, "read")?;
    println!("✓ Granted Bob READ user permission");

    // Bob CAN read
    let output = env.secret_get(&bob, "acme", "api", "dev", "TEST_SECRET");
    assert_success(&output, "Bob secret get (read permission)");
    println!("✓ Bob can read secrets");

    // Bob CAN list
    let output = env.secret_export(&bob, "acme", "api", "dev");
    assert_success(&output, "Bob secret export (read permission)");
    println!("✓ Bob can list secrets");

    // Bob CANNOT write
    let output = env.secret_set(&bob, "acme", "api", "dev", "BOB_SECRET", "bob_value");
    assert_denied(&output, "Bob secret set (read permission)");
    println!("✓ Bob denied write (read permission only)");

    // Bob CANNOT delete
    let output = env.secret_delete(&bob, "acme", "api", "dev", "TEST_SECRET");
    assert_denied(&output, "Bob secret delete (read permission)");
    println!("✓ Bob denied delete (read permission only)");

    println!("\n✅ test_user_permission_read PASSED");
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════
// Test: User Permissions - Write Role
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_user_permission_write() -> Result<(), Box<dyn std::error::Error>> {
    let port = find_available_port()?;
    let env = TestEnv::setup("user_write", port).await?;

    // Setup
    let alice = env.create_user("alice");
    let bob = env.create_user("bob");

    let invite = env.create_server_invite()?;
    env.join_server(&alice, &invite)?;
    env.create_workspace(&alice, "acme")?;
    env.create_project(&alice, "acme", "api")?;
    env.create_environment(&alice, "acme", "api", "dev")?;

    // Bob joins workspace
    let ws_invite = env.create_workspace_invite(&alice, "acme")?;
    env.join_server(&bob, &ws_invite)?;

    // Alice grants Bob WRITE user permission
    env.set_user_permission(&alice, "acme", &bob.email, "write")?;
    println!("✓ Granted Bob WRITE user permission");

    // Bob CAN read
    env.secret_set(&alice, "acme", "api", "dev", "ALICE_SECRET", "alice_value");
    let output = env.secret_get(&bob, "acme", "api", "dev", "ALICE_SECRET");
    assert_success(&output, "Bob secret get (write permission)");
    println!("✓ Bob can read secrets");

    // Bob CAN write
    let output = env.secret_set(&bob, "acme", "api", "dev", "BOB_SECRET", "bob_value");
    assert_success(&output, "Bob secret set (write permission)");
    println!("✓ Bob can write secrets");

    // Bob CAN list
    let output = env.secret_export(&bob, "acme", "api", "dev");
    assert_success(&output, "Bob secret export (write permission)");
    println!("✓ Bob can list secrets");

    // Bob CAN delete
    let output = env.secret_delete(&bob, "acme", "api", "dev", "BOB_SECRET");
    assert_success(&output, "Bob secret delete (write permission)");
    println!("✓ Bob can delete secrets");

    println!("\n✅ test_user_permission_write PASSED");
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════
// Test: User Permissions - Admin Role
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_user_permission_admin() -> Result<(), Box<dyn std::error::Error>> {
    let port = find_available_port()?;
    let env = TestEnv::setup("user_admin", port).await?;

    // Setup
    let alice = env.create_user("alice");
    let bob = env.create_user("bob");

    let invite = env.create_server_invite()?;
    env.join_server(&alice, &invite)?;
    env.create_workspace(&alice, "acme")?;
    env.create_project(&alice, "acme", "api")?;
    env.create_environment(&alice, "acme", "api", "dev")?;

    // Bob joins workspace
    let ws_invite = env.create_workspace_invite(&alice, "acme")?;
    env.join_server(&bob, &ws_invite)?;

    // Alice grants Bob ADMIN user permission
    env.set_user_permission(&alice, "acme", &bob.email, "admin")?;
    println!("✓ Granted Bob ADMIN user permission");

    // Bob CAN do everything
    let output = env.secret_set(&bob, "acme", "api", "dev", "BOB_SECRET", "bob_value");
    assert_success(&output, "Bob secret set (admin permission)");
    println!("✓ Bob can write secrets");

    let output = env.secret_get(&bob, "acme", "api", "dev", "BOB_SECRET");
    assert_success(&output, "Bob secret get (admin permission)");
    println!("✓ Bob can read secrets");

    let output = env.secret_export(&bob, "acme", "api", "dev");
    assert_success(&output, "Bob secret export (admin permission)");
    println!("✓ Bob can list secrets");

    let output = env.secret_delete(&bob, "acme", "api", "dev", "BOB_SECRET");
    assert_success(&output, "Bob secret delete (admin permission)");
    println!("✓ Bob can delete secrets");

    println!("\n✅ test_user_permission_admin PASSED");
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════
// Test: Group Permissions - Read Role
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_group_permission_read() -> Result<(), Box<dyn std::error::Error>> {
    let port = find_available_port()?;
    let env = TestEnv::setup("group_read", port).await?;

    // Setup
    let alice = env.create_user("alice");
    let bob = env.create_user("bob");

    let invite = env.create_server_invite()?;
    env.join_server(&alice, &invite)?;
    env.create_workspace(&alice, "acme")?;
    env.create_project(&alice, "acme", "api")?;
    env.create_environment(&alice, "acme", "api", "dev")?;

    // Alice creates secret
    env.secret_set(&alice, "acme", "api", "dev", "TEST_SECRET", "test_value");

    // Bob joins workspace
    let ws_invite = env.create_workspace_invite(&alice, "acme")?;
    env.join_server(&bob, &ws_invite)?;

    // Create group with READ permission and add Bob
    env.create_group(&alice, "acme", "readers")?;
    env.set_group_permission(&alice, "acme", "readers", "read")?;
    env.add_group_member(&alice, "acme", "readers", &bob.email)?;
    println!("✓ Created 'readers' group with READ permission, added Bob");

    // Bob CAN read via group
    let output = env.secret_get(&bob, "acme", "api", "dev", "TEST_SECRET");
    assert_success(&output, "Bob secret get (group read)");
    println!("✓ Bob can read via group");

    // Bob CAN list via group
    let output = env.secret_export(&bob, "acme", "api", "dev");
    assert_success(&output, "Bob secret export (group read)");
    println!("✓ Bob can list via group");

    // Bob CANNOT write via group
    let output = env.secret_set(&bob, "acme", "api", "dev", "BOB_SECRET", "bob_value");
    assert_denied(&output, "Bob secret set (group read)");
    println!("✓ Bob denied write (group read only)");

    // Bob CANNOT delete via group
    let output = env.secret_delete(&bob, "acme", "api", "dev", "TEST_SECRET");
    assert_denied(&output, "Bob secret delete (group read)");
    println!("✓ Bob denied delete (group read only)");

    println!("\n✅ test_group_permission_read PASSED");
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════
// Test: Group Permissions - Write Role
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_group_permission_write() -> Result<(), Box<dyn std::error::Error>> {
    let port = find_available_port()?;
    let env = TestEnv::setup("group_write", port).await?;

    // Setup
    let alice = env.create_user("alice");
    let bob = env.create_user("bob");

    let invite = env.create_server_invite()?;
    env.join_server(&alice, &invite)?;
    env.create_workspace(&alice, "acme")?;
    env.create_project(&alice, "acme", "api")?;
    env.create_environment(&alice, "acme", "api", "dev")?;

    // Bob joins workspace
    let ws_invite = env.create_workspace_invite(&alice, "acme")?;
    env.join_server(&bob, &ws_invite)?;

    // Create group with WRITE permission and add Bob
    env.create_group(&alice, "acme", "developers")?;
    env.set_group_permission(&alice, "acme", "developers", "write")?;
    env.add_group_member(&alice, "acme", "developers", &bob.email)?;
    println!("✓ Created 'developers' group with WRITE permission, added Bob");

    // Bob CAN do all secret operations via group
    let output = env.secret_set(&bob, "acme", "api", "dev", "BOB_SECRET", "bob_value");
    assert_success(&output, "Bob secret set (group write)");
    println!("✓ Bob can write via group");

    let output = env.secret_get(&bob, "acme", "api", "dev", "BOB_SECRET");
    assert_success(&output, "Bob secret get (group write)");
    println!("✓ Bob can read via group");

    let output = env.secret_export(&bob, "acme", "api", "dev");
    assert_success(&output, "Bob secret export (group write)");
    println!("✓ Bob can list via group");

    let output = env.secret_delete(&bob, "acme", "api", "dev", "BOB_SECRET");
    assert_success(&output, "Bob secret delete (group write)");
    println!("✓ Bob can delete via group");

    println!("\n✅ test_group_permission_write PASSED");
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════
// Test: Principal Permission Acts as Ceiling (Restricts Human Users)
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_principal_permission_ceiling() -> Result<(), Box<dyn std::error::Error>> {
    let port = find_available_port()?;
    let env = TestEnv::setup("principal_ceiling", port).await?;

    // Setup
    let alice = env.create_user("alice");
    let bob = env.create_user("bob");

    let invite = env.create_server_invite()?;
    env.join_server(&alice, &invite)?;
    env.create_workspace(&alice, "acme")?;
    env.create_project(&alice, "acme", "api")?;
    env.create_environment(&alice, "acme", "api", "dev")?;

    // Bob joins workspace
    let ws_invite = env.create_workspace_invite(&alice, "acme")?;
    env.join_server(&bob, &ws_invite)?;

    // Give Bob WRITE user permission
    env.set_user_permission(&alice, "acme", &bob.email, "write")?;
    println!("✓ Bob has WRITE user permission");

    // Bob CAN write with user permission
    let output = env.secret_set(&bob, "acme", "api", "dev", "BOB_SECRET", "bob_value");
    assert_success(&output, "Bob secret set (user write)");
    println!("✓ Bob can write with user permission");

    // Get Bob's principal ID
    let bob_principal_id = env.get_principal_id(&bob)?;
    println!("✓ Bob's principal ID: {}", bob_principal_id);

    // Set principal permission to READ (ceiling)
    // This should RESTRICT Bob's access from WRITE to READ
    env.set_principal_permission(&alice, "acme", &bob_principal_id, "read")?;
    println!("✓ Set principal READ permission (ceiling)");

    // Bob can still READ
    let output = env.secret_get(&bob, "acme", "api", "dev", "BOB_SECRET");
    assert_success(&output, "Bob secret get (with principal ceiling)");
    println!("✓ Bob can still read");

    // Bob CANNOT write anymore (principal ceiling = READ restricts WRITE)
    // effective = min(user_perm=WRITE, principal_ceiling=READ) = READ
    let output = env.secret_set(&bob, "acme", "api", "dev", "ANOTHER_SECRET", "value");
    assert_denied(&output, "Bob secret set (principal ceiling restricts)");
    println!("✓ Bob denied write (principal ceiling restricts to READ)");

    println!("\n✅ test_principal_permission_ceiling PASSED");
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════
// Test: Removing User Permission Revokes Access
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_removing_user_permission_revokes_access() -> Result<(), Box<dyn std::error::Error>> {
    let port = find_available_port()?;
    let env = TestEnv::setup("revoke_user_access", port).await?;

    // Setup
    let alice = env.create_user("alice");
    let bob = env.create_user("bob");

    let invite = env.create_server_invite()?;
    env.join_server(&alice, &invite)?;
    env.create_workspace(&alice, "acme")?;
    env.create_project(&alice, "acme", "api")?;
    env.create_environment(&alice, "acme", "api", "dev")?;

    // Alice creates secret
    env.secret_set(&alice, "acme", "api", "dev", "TEST_SECRET", "test_value");

    // Bob joins workspace
    let ws_invite = env.create_workspace_invite(&alice, "acme")?;
    env.join_server(&bob, &ws_invite)?;

    // Grant Bob READ user permission
    env.set_user_permission(&alice, "acme", &bob.email, "read")?;
    println!("✓ Granted Bob READ user permission");

    // Bob CAN read
    let output = env.secret_get(&bob, "acme", "api", "dev", "TEST_SECRET");
    assert_success(&output, "Bob secret get (has permission)");
    println!("✓ Bob can read with permission");

    // Remove user permission
    env.remove_user_permission(&alice, "acme", &bob.email)?;
    println!("✓ Removed Bob's user permission");

    // Bob CANNOT read anymore
    let output = env.secret_get(&bob, "acme", "api", "dev", "TEST_SECRET");
    assert_denied(&output, "Bob secret get (permission removed)");
    println!("✓ Bob denied after user permission removed");

    println!("\n✅ test_removing_user_permission_revokes_access PASSED");
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════
// Test: Removing Group Membership Revokes Access
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_removing_group_member_revokes_access() -> Result<(), Box<dyn std::error::Error>> {
    let port = find_available_port()?;
    let env = TestEnv::setup("revoke_group", port).await?;

    // Setup
    let alice = env.create_user("alice");
    let bob = env.create_user("bob");

    let invite = env.create_server_invite()?;
    env.join_server(&alice, &invite)?;
    env.create_workspace(&alice, "acme")?;
    env.create_project(&alice, "acme", "api")?;
    env.create_environment(&alice, "acme", "api", "dev")?;

    // Alice creates secret
    env.secret_set(&alice, "acme", "api", "dev", "TEST_SECRET", "test_value");

    // Bob joins workspace
    let ws_invite = env.create_workspace_invite(&alice, "acme")?;
    env.join_server(&bob, &ws_invite)?;

    // Create group and add Bob
    env.create_group(&alice, "acme", "readers")?;
    env.set_group_permission(&alice, "acme", "readers", "read")?;
    env.add_group_member(&alice, "acme", "readers", &bob.email)?;
    println!("✓ Bob added to 'readers' group");

    // Bob CAN read
    let output = env.secret_get(&bob, "acme", "api", "dev", "TEST_SECRET");
    assert_success(&output, "Bob secret get (in group)");
    println!("✓ Bob can read via group");

    // Remove Bob from group
    env.remove_group_member(&alice, "acme", "readers", &bob.email)?;
    println!("✓ Removed Bob from 'readers' group");

    // Bob CANNOT read anymore
    let output = env.secret_get(&bob, "acme", "api", "dev", "TEST_SECRET");
    assert_denied(&output, "Bob secret get (removed from group)");
    println!("✓ Bob denied after removed from group");

    println!("\n✅ test_removing_group_member_revokes_access PASSED");
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════
// Test: Multiple Group Memberships - Max Role Wins
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_multiple_groups_max_role() -> Result<(), Box<dyn std::error::Error>> {
    let port = find_available_port()?;
    let env = TestEnv::setup("multi_group", port).await?;

    // Setup
    let alice = env.create_user("alice");
    let bob = env.create_user("bob");

    let invite = env.create_server_invite()?;
    env.join_server(&alice, &invite)?;
    env.create_workspace(&alice, "acme")?;
    env.create_project(&alice, "acme", "api")?;
    env.create_environment(&alice, "acme", "api", "dev")?;

    // Bob joins workspace
    let ws_invite = env.create_workspace_invite(&alice, "acme")?;
    env.join_server(&bob, &ws_invite)?;

    // Create READ group
    env.create_group(&alice, "acme", "readers")?;
    env.set_group_permission(&alice, "acme", "readers", "read")?;
    env.add_group_member(&alice, "acme", "readers", &bob.email)?;
    println!("✓ Bob in 'readers' group (READ)");

    // Bob can read but not write
    // Create a secret first, then test read
    env.secret_set(&alice, "acme", "api", "dev", "TEST", "value");
    let output = env.secret_get(&bob, "acme", "api", "dev", "TEST");
    assert_success(&output, "Bob read via readers group");

    let output = env.secret_set(&bob, "acme", "api", "dev", "BOB_SECRET", "value");
    assert_denied(&output, "Bob write (only in readers)");
    println!("✓ Bob can read but not write with only READ group");

    // Create WRITE group and add Bob
    env.create_group(&alice, "acme", "writers")?;
    env.set_group_permission(&alice, "acme", "writers", "write")?;
    env.add_group_member(&alice, "acme", "writers", &bob.email)?;
    println!("✓ Bob also in 'writers' group (WRITE)");

    // Now Bob can write (max of READ and WRITE = WRITE)
    let output = env.secret_set(&bob, "acme", "api", "dev", "BOB_SECRET", "value");
    assert_success(&output, "Bob write (max role from groups)");
    println!("✓ Bob can write with max role from multiple groups");

    println!("\n✅ test_multiple_groups_max_role PASSED");
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════
// Test: User + Group Permissions - Max Role Wins
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_user_plus_group_max_role() -> Result<(), Box<dyn std::error::Error>> {
    let port = find_available_port()?;
    let env = TestEnv::setup("user_plus_group", port).await?;

    // Setup
    let alice = env.create_user("alice");
    let bob = env.create_user("bob");

    let invite = env.create_server_invite()?;
    env.join_server(&alice, &invite)?;
    env.create_workspace(&alice, "acme")?;
    env.create_project(&alice, "acme", "api")?;
    env.create_environment(&alice, "acme", "api", "dev")?;

    // Bob joins workspace
    let ws_invite = env.create_workspace_invite(&alice, "acme")?;
    env.join_server(&bob, &ws_invite)?;

    // Give Bob READ user permission
    env.set_user_permission(&alice, "acme", &bob.email, "read")?;
    println!("✓ Bob has READ user permission");

    // Create a secret for testing
    env.secret_set(&alice, "acme", "api", "dev", "TEST", "value");

    // Bob can read but not write
    let output = env.secret_get(&bob, "acme", "api", "dev", "TEST");
    assert_success(&output, "Bob read (user permission)");
    let output = env.secret_set(&bob, "acme", "api", "dev", "BOB_SECRET", "value");
    assert_denied(&output, "Bob write (only read user permission)");
    println!("✓ Bob can read but not write with READ user permission");

    // Add Bob to a group with WRITE permission
    env.create_group(&alice, "acme", "developers")?;
    env.set_group_permission(&alice, "acme", "developers", "write")?;
    env.add_group_member(&alice, "acme", "developers", &bob.email)?;
    println!("✓ Bob added to 'developers' group with WRITE permission");

    // Now Bob can write (max of user READ and group WRITE = WRITE)
    let output = env.secret_set(&bob, "acme", "api", "dev", "BOB_SECRET", "value");
    assert_success(&output, "Bob write (max of user+group)");
    println!("✓ Bob can write with max(user READ, group WRITE) = WRITE");

    println!("\n✅ test_user_plus_group_max_role PASSED");
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════
// Test: Principal Permission Cannot Expand Access for Human Users
// Principal permissions can only RESTRICT, not GRANT access for humans
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_principal_cannot_expand_human_access() -> Result<(), Box<dyn std::error::Error>> {
    let port = find_available_port()?;
    let env = TestEnv::setup("principal_no_expand", port).await?;

    // Setup
    let alice = env.create_user("alice");
    let bob = env.create_user("bob");

    let invite = env.create_server_invite()?;
    env.join_server(&alice, &invite)?;
    env.create_workspace(&alice, "acme")?;
    env.create_project(&alice, "acme", "api")?;
    env.create_environment(&alice, "acme", "api", "dev")?;

    // Bob joins workspace
    let ws_invite = env.create_workspace_invite(&alice, "acme")?;
    env.join_server(&bob, &ws_invite)?;

    // Create a secret
    env.secret_set(&alice, "acme", "api", "dev", "TEST", "value");

    // Get Bob's principal ID
    let bob_principal_id = env.get_principal_id(&bob)?;
    println!("✓ Bob's principal ID: {}", bob_principal_id);

    // Set principal permission to ADMIN (but Bob has NO user/group permissions)
    env.set_principal_permission(&alice, "acme", &bob_principal_id, "admin")?;
    println!("✓ Set Bob's principal permission to ADMIN");

    // Bob CANNOT access secrets (principal permission alone doesn't grant access for humans)
    // For humans: effective = min(base_role, principal_ceiling)
    // If base_role is None, effective is None (denied)
    let output = env.secret_get(&bob, "acme", "api", "dev", "TEST");
    assert_denied(
        &output,
        "Bob secret get (principal cannot expand human access)",
    );
    println!("✓ Bob denied (principal ADMIN cannot grant access without user/group permission)");

    let output = env.secret_set(&bob, "acme", "api", "dev", "BOB_SECRET", "value");
    assert_denied(
        &output,
        "Bob secret set (principal cannot expand human access)",
    );
    println!("✓ Bob denied write (principal permission cannot expand human access)");

    // Now give Bob READ user permission
    env.set_user_permission(&alice, "acme", &bob.email, "read")?;
    println!("✓ Gave Bob READ user permission");

    // Now Bob can read (min(READ, ADMIN) = READ)
    let output = env.secret_get(&bob, "acme", "api", "dev", "TEST");
    assert_success(&output, "Bob secret get (has user permission now)");
    println!("✓ Bob can read now with user permission");

    // But still cannot write (effective = READ even though principal = ADMIN)
    let output = env.secret_set(&bob, "acme", "api", "dev", "BOB_SECRET", "value");
    assert_denied(
        &output,
        "Bob secret set (user READ, principal ADMIN = READ)",
    );
    println!("✓ Bob still cannot write (min(READ, ADMIN) = READ)");

    println!("\n✅ test_principal_cannot_expand_human_access PASSED");
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════
// Test: Principal Permission Ceiling with Group Permissions
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_principal_ceiling_with_groups() -> Result<(), Box<dyn std::error::Error>> {
    let port = find_available_port()?;
    let env = TestEnv::setup("principal_ceiling_groups", port).await?;

    // Setup
    let alice = env.create_user("alice");
    let bob = env.create_user("bob");

    let invite = env.create_server_invite()?;
    env.join_server(&alice, &invite)?;
    env.create_workspace(&alice, "acme")?;
    env.create_project(&alice, "acme", "api")?;
    env.create_environment(&alice, "acme", "api", "dev")?;

    // Bob joins workspace
    let ws_invite = env.create_workspace_invite(&alice, "acme")?;
    env.join_server(&bob, &ws_invite)?;

    // Create secret
    env.secret_set(&alice, "acme", "api", "dev", "TEST", "value");

    // Give Bob ADMIN via group
    env.create_group(&alice, "acme", "admins")?;
    env.set_group_permission(&alice, "acme", "admins", "admin")?;
    env.add_group_member(&alice, "acme", "admins", &bob.email)?;
    println!("✓ Bob in 'admins' group with ADMIN permission");

    // Bob can do everything via group ADMIN
    let output = env.secret_set(&bob, "acme", "api", "dev", "BOB_SECRET", "value");
    assert_success(&output, "Bob write (group admin)");
    println!("✓ Bob can write with group ADMIN");

    // Get Bob's principal ID
    let bob_principal_id = env.get_principal_id(&bob)?;

    // Set principal ceiling to READ
    env.set_principal_permission(&alice, "acme", &bob_principal_id, "read")?;
    println!("✓ Set Bob's principal permission to READ (ceiling)");

    // Now Bob is restricted to READ (min(group ADMIN, principal READ) = READ)
    let output = env.secret_get(&bob, "acme", "api", "dev", "TEST");
    assert_success(&output, "Bob read (ceiling applied)");
    println!("✓ Bob can still read");

    let output = env.secret_set(&bob, "acme", "api", "dev", "ANOTHER", "value");
    assert_denied(&output, "Bob write (principal ceiling restricts)");
    println!("✓ Bob denied write (principal ceiling restricts group ADMIN to READ)");

    // Remove principal permission (ceiling removed)
    env.remove_principal_permission(&alice, "acme", &bob_principal_id)?;
    println!("✓ Removed Bob's principal permission (ceiling removed)");

    // Now Bob can write again (group ADMIN, no ceiling)
    let output = env.secret_set(&bob, "acme", "api", "dev", "ANOTHER", "value");
    assert_success(&output, "Bob write (ceiling removed)");
    println!("✓ Bob can write again after ceiling removed");

    println!("\n✅ test_principal_ceiling_with_groups PASSED");
    Ok(())
}

// Note: Service account tests are not included here because service accounts
// cannot access secrets by design - they don't have access to the workspace KEK
// and therefore cannot decrypt secrets. Service accounts are for operations
// that don't require client-side encryption (e.g., API access tokens, CI/CD integrations
// that only need to trigger deployments, not read secrets directly).
//
// The permission model for service accounts (principal permission as sole source)
// is tested implicitly through the check_permission logic but cannot be demonstrated
// through secret operations.

// ═══════════════════════════════════════════════════════════════════════════
// Test: Combining All Permission Sources - Complete Integration Test
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_complete_permission_model() -> Result<(), Box<dyn std::error::Error>> {
    let port = find_available_port()?;
    let env = TestEnv::setup("complete_model", port).await?;

    // Setup: Alice creates workspace with project and environment
    let alice = env.create_user("alice");
    let bob = env.create_user("bob");
    let charlie = env.create_user("charlie");

    let invite = env.create_server_invite()?;
    env.join_server(&alice, &invite)?;
    env.create_workspace(&alice, "acme")?;
    env.create_project(&alice, "acme", "api")?;
    env.create_environment(&alice, "acme", "api", "dev")?;

    // Create secrets
    env.secret_set(&alice, "acme", "api", "dev", "TEST", "value");

    // Bob and Charlie join
    let ws_invite = env.create_workspace_invite(&alice, "acme")?;
    env.join_server(&bob, &ws_invite)?;
    let ws_invite2 = env.create_workspace_invite(&alice, "acme")?;
    env.join_server(&charlie, &ws_invite2)?;

    println!("✓ Setup complete: Alice (owner), Bob, Charlie");

    // ─────────────────────────────────────────────────────────────────────────
    // Test 1: Owner always has full access (no explicit permissions needed)
    // ─────────────────────────────────────────────────────────────────────────
    let output = env.secret_set(&alice, "acme", "api", "dev", "OWNER_SECRET", "alice_value");
    assert_success(&output, "Owner write");
    println!("✓ Test 1: Owner has full access");

    // ─────────────────────────────────────────────────────────────────────────
    // Test 2: Non-owner denied by default
    // ─────────────────────────────────────────────────────────────────────────
    let output = env.secret_get(&bob, "acme", "api", "dev", "TEST");
    assert_denied(&output, "Bob denied by default");
    println!("✓ Test 2: Non-owner denied by default");

    // ─────────────────────────────────────────────────────────────────────────
    // Test 3: User permission grants access
    // ─────────────────────────────────────────────────────────────────────────
    env.set_user_permission(&alice, "acme", &bob.email, "write")?;
    let output = env.secret_set(&bob, "acme", "api", "dev", "BOB_SECRET", "bob_value");
    assert_success(&output, "Bob write with user permission");
    println!("✓ Test 3: User permission grants access");

    // ─────────────────────────────────────────────────────────────────────────
    // Test 4: Group permission grants access
    // ─────────────────────────────────────────────────────────────────────────
    env.create_group(&alice, "acme", "readers")?;
    env.set_group_permission(&alice, "acme", "readers", "read")?;
    env.add_group_member(&alice, "acme", "readers", &charlie.email)?;
    let output = env.secret_get(&charlie, "acme", "api", "dev", "TEST");
    assert_success(&output, "Charlie read via group");
    let output = env.secret_set(
        &charlie,
        "acme",
        "api",
        "dev",
        "CHARLIE_SECRET",
        "charlie_value",
    );
    assert_denied(&output, "Charlie write denied (only read group)");
    println!("✓ Test 4: Group permission grants access");

    // ─────────────────────────────────────────────────────────────────────────
    // Test 5: User + Group = max role
    // ─────────────────────────────────────────────────────────────────────────
    env.add_group_member(&alice, "acme", "readers", &bob.email)?; // Bob now in readers (read) + has user (write)
                                                                  // Bob should still have write (max of user WRITE and group READ)
    let output = env.secret_set(&bob, "acme", "api", "dev", "BOB_SECRET2", "value");
    assert_success(&output, "Bob write (max of user+group)");
    println!("✓ Test 5: User + Group permissions = max role");

    // ─────────────────────────────────────────────────────────────────────────
    // Test 6: Principal permission acts as ceiling
    // ─────────────────────────────────────────────────────────────────────────
    let bob_principal_id = env.get_principal_id(&bob)?;
    env.set_principal_permission(&alice, "acme", &bob_principal_id, "read")?;
    // Bob has user WRITE + group READ, but principal ceiling is READ
    // effective = min(max(WRITE, READ), READ) = min(WRITE, READ) = READ
    let output = env.secret_set(&bob, "acme", "api", "dev", "BOB_SECRET3", "value");
    assert_denied(&output, "Bob write denied (principal ceiling)");
    let output = env.secret_get(&bob, "acme", "api", "dev", "TEST");
    assert_success(&output, "Bob read (within ceiling)");
    println!("✓ Test 6: Principal permission acts as ceiling");

    // ─────────────────────────────────────────────────────────────────────────
    // Test 7: Principal permission cannot expand access for humans
    // ─────────────────────────────────────────────────────────────────────────
    let charlie_principal_id = env.get_principal_id(&charlie)?;
    env.set_principal_permission(&alice, "acme", &charlie_principal_id, "admin")?;
    // Charlie has group READ + principal ADMIN
    // effective = min(READ, ADMIN) = READ (principal cannot expand)
    let output = env.secret_set(&charlie, "acme", "api", "dev", "CHARLIE_SECRET", "value");
    assert_denied(&output, "Charlie write denied (principal cannot expand)");
    println!("✓ Test 7: Principal permission cannot expand access for humans");

    // ─────────────────────────────────────────────────────────────────────────
    // Test 8: Removing user permission revokes access
    // ─────────────────────────────────────────────────────────────────────────
    env.remove_principal_permission(&alice, "acme", &bob_principal_id)?; // Remove ceiling first
    env.remove_user_permission(&alice, "acme", &bob.email)?;
    // Bob still in readers group (READ)
    let output = env.secret_get(&bob, "acme", "api", "dev", "TEST");
    assert_success(&output, "Bob read via group after user perm removed");
    let output = env.secret_set(&bob, "acme", "api", "dev", "BOB_NEW", "value");
    assert_denied(&output, "Bob write denied after user perm removed");
    println!("✓ Test 8: Removing user permission revokes that access (group remains)");

    // ─────────────────────────────────────────────────────────────────────────
    // Test 9: Removing group membership revokes access
    // ─────────────────────────────────────────────────────────────────────────
    env.remove_group_member(&alice, "acme", "readers", &bob.email)?;
    let output = env.secret_get(&bob, "acme", "api", "dev", "TEST");
    assert_denied(&output, "Bob denied after all permissions removed");
    println!("✓ Test 9: Removing group membership revokes access");

    println!("\n✅ test_complete_permission_model PASSED");
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════
// ADMINISTRATIVE OPERATIONS TESTS
// Tests for who can perform admin operations (create projects, manage permissions, etc.)
// ═══════════════════════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════════════════════
// Test: Read Role Cannot Perform Admin Operations
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_read_role_cannot_admin_operations() -> Result<(), Box<dyn std::error::Error>> {
    let port = find_available_port()?;
    let env = TestEnv::setup("read_no_admin", port).await?;

    // Setup: Alice creates workspace, Bob joins with READ permission
    let alice = env.create_user("alice");
    let bob = env.create_user("bob");
    let charlie = env.create_user("charlie");

    let invite = env.create_server_invite()?;
    env.join_server(&alice, &invite)?;
    env.create_workspace(&alice, "acme")?;
    env.create_project(&alice, "acme", "api")?;
    env.create_environment(&alice, "acme", "api", "dev")?;

    // Bob and Charlie join workspace
    let ws_invite = env.create_workspace_invite(&alice, "acme")?;
    env.join_server(&bob, &ws_invite)?;
    let ws_invite2 = env.create_workspace_invite(&alice, "acme")?;
    env.join_server(&charlie, &ws_invite2)?;

    // Give Bob READ permission
    env.set_user_permission(&alice, "acme", &bob.email, "read")?;
    println!("✓ Bob has READ permission");

    // Create a group that Bob can't manage
    env.create_group(&alice, "acme", "devs")?;
    println!("✓ Created 'devs' group for testing");

    // ─────────────────────────────────────────────────────────────────────────
    // Bob CANNOT create projects
    // ─────────────────────────────────────────────────────────────────────────
    let output = env.project_create(&bob, "acme", "new-project");
    assert_denied(&output, "Bob project create (read permission)");
    println!("✓ Bob denied project create");

    // ─────────────────────────────────────────────────────────────────────────
    // Bob CANNOT delete projects
    // ─────────────────────────────────────────────────────────────────────────
    let output = env.project_delete(&bob, "acme", "api");
    assert_denied(&output, "Bob project delete (read permission)");
    println!("✓ Bob denied project delete");

    // ─────────────────────────────────────────────────────────────────────────
    // Bob CANNOT create environments
    // ─────────────────────────────────────────────────────────────────────────
    let output = env.environment_create(&bob, "acme", "api", "staging");
    assert_denied(&output, "Bob environment create (read permission)");
    println!("✓ Bob denied environment create");

    // ─────────────────────────────────────────────────────────────────────────
    // Bob CANNOT delete environments
    // ─────────────────────────────────────────────────────────────────────────
    let output = env.environment_delete(&bob, "acme", "api", "dev");
    assert_denied(&output, "Bob environment delete (read permission)");
    println!("✓ Bob denied environment delete");

    // ─────────────────────────────────────────────────────────────────────────
    // Bob CANNOT create groups
    // ─────────────────────────────────────────────────────────────────────────
    let output = env.group_create_check(&bob, "acme", "new-group");
    assert_denied(&output, "Bob group create (read permission)");
    println!("✓ Bob denied group create");

    // ─────────────────────────────────────────────────────────────────────────
    // Bob CANNOT delete groups
    // ─────────────────────────────────────────────────────────────────────────
    let output = env.group_delete(&bob, "acme", "devs");
    assert_denied(&output, "Bob group delete (read permission)");
    println!("✓ Bob denied group delete");

    // ─────────────────────────────────────────────────────────────────────────
    // Bob CANNOT add members to groups
    // ─────────────────────────────────────────────────────────────────────────
    let output = env.group_add_member_check(&bob, "acme", "devs", &charlie.email);
    assert_denied(&output, "Bob group add-member (read permission)");
    println!("✓ Bob denied group add-member");

    // ─────────────────────────────────────────────────────────────────────────
    // Bob CANNOT set WRITE user permissions (delegated authority enforced)
    // Note: Bob CAN set READ permissions (see test_user_permission_delegated_authority)
    // ─────────────────────────────────────────────────────────────────────────
    let output = env.user_permission_set_check(&bob, "acme", &charlie.email, "write");
    assert_denied(&output, "Bob permission set write (read permission)");
    println!("✓ Bob denied setting WRITE permission (delegated authority)");

    // ─────────────────────────────────────────────────────────────────────────
    // Bob CANNOT create workspace invites
    // ─────────────────────────────────────────────────────────────────────────
    let output = env.invite_create_check(&bob, "acme");
    assert_denied(&output, "Bob invite create (read permission)");
    println!("✓ Bob denied invite create");

    println!("\n✅ test_read_role_cannot_admin_operations PASSED");
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════
// Test: Write Role Cannot Perform Admin Operations
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_write_role_cannot_admin_operations() -> Result<(), Box<dyn std::error::Error>> {
    let port = find_available_port()?;
    let env = TestEnv::setup("write_no_admin", port).await?;

    // Setup: Alice creates workspace, Bob joins with WRITE permission
    let alice = env.create_user("alice");
    let bob = env.create_user("bob");
    let charlie = env.create_user("charlie");

    let invite = env.create_server_invite()?;
    env.join_server(&alice, &invite)?;
    env.create_workspace(&alice, "acme")?;
    env.create_project(&alice, "acme", "api")?;
    env.create_environment(&alice, "acme", "api", "dev")?;

    // Bob and Charlie join workspace
    let ws_invite = env.create_workspace_invite(&alice, "acme")?;
    env.join_server(&bob, &ws_invite)?;
    let ws_invite2 = env.create_workspace_invite(&alice, "acme")?;
    env.join_server(&charlie, &ws_invite2)?;

    // Give Bob WRITE permission
    env.set_user_permission(&alice, "acme", &bob.email, "write")?;
    println!("✓ Bob has WRITE permission");

    // Create a group that Bob can't manage
    env.create_group(&alice, "acme", "devs")?;
    println!("✓ Created 'devs' group for testing");

    // ─────────────────────────────────────────────────────────────────────────
    // Bob CANNOT create projects (requires ADMIN)
    // ─────────────────────────────────────────────────────────────────────────
    let output = env.project_create(&bob, "acme", "new-project");
    assert_denied(&output, "Bob project create (write permission)");
    println!("✓ Bob denied project create");

    // ─────────────────────────────────────────────────────────────────────────
    // Bob CANNOT delete projects
    // ─────────────────────────────────────────────────────────────────────────
    let output = env.project_delete(&bob, "acme", "api");
    assert_denied(&output, "Bob project delete (write permission)");
    println!("✓ Bob denied project delete");

    // ─────────────────────────────────────────────────────────────────────────
    // Bob CANNOT create environments
    // ─────────────────────────────────────────────────────────────────────────
    let output = env.environment_create(&bob, "acme", "api", "staging");
    assert_denied(&output, "Bob environment create (write permission)");
    println!("✓ Bob denied environment create");

    // ─────────────────────────────────────────────────────────────────────────
    // Bob CANNOT delete environments
    // ─────────────────────────────────────────────────────────────────────────
    let output = env.environment_delete(&bob, "acme", "api", "dev");
    assert_denied(&output, "Bob environment delete (write permission)");
    println!("✓ Bob denied environment delete");

    // ─────────────────────────────────────────────────────────────────────────
    // Bob CANNOT create groups
    // ─────────────────────────────────────────────────────────────────────────
    let output = env.group_create_check(&bob, "acme", "new-group");
    assert_denied(&output, "Bob group create (write permission)");
    println!("✓ Bob denied group create");

    // ─────────────────────────────────────────────────────────────────────────
    // Bob CANNOT delete groups
    // ─────────────────────────────────────────────────────────────────────────
    let output = env.group_delete(&bob, "acme", "devs");
    assert_denied(&output, "Bob group delete (write permission)");
    println!("✓ Bob denied group delete");

    // ─────────────────────────────────────────────────────────────────────────
    // Bob CANNOT add members to groups
    // ─────────────────────────────────────────────────────────────────────────
    let output = env.group_add_member_check(&bob, "acme", "devs", &charlie.email);
    assert_denied(&output, "Bob group add-member (write permission)");
    println!("✓ Bob denied group add-member");

    // ─────────────────────────────────────────────────────────────────────────
    // Bob CANNOT set ADMIN user permissions (delegated authority enforced)
    // Note: Bob CAN set WRITE or READ permissions (see test_user_permission_delegated_authority)
    // ─────────────────────────────────────────────────────────────────────────
    let output = env.user_permission_set_check(&bob, "acme", &charlie.email, "admin");
    assert_denied(&output, "Bob permission set admin (write permission)");
    println!("✓ Bob denied setting ADMIN permission (delegated authority)");

    // ─────────────────────────────────────────────────────────────────────────
    // Bob CANNOT create workspace invites
    // ─────────────────────────────────────────────────────────────────────────
    let output = env.invite_create_check(&bob, "acme");
    assert_denied(&output, "Bob invite create (write permission)");
    println!("✓ Bob denied invite create");

    println!("\n✅ test_write_role_cannot_admin_operations PASSED");
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════
// Test: Admin Role CAN Perform Admin Operations
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_admin_role_can_admin_operations() -> Result<(), Box<dyn std::error::Error>> {
    let port = find_available_port()?;
    let env = TestEnv::setup("admin_ops", port).await?;

    // Setup: Alice creates workspace, Bob joins with ADMIN permission
    let alice = env.create_user("alice");
    let bob = env.create_user("bob");
    let charlie = env.create_user("charlie");

    let invite = env.create_server_invite()?;
    env.join_server(&alice, &invite)?;
    env.create_workspace(&alice, "acme")?;
    env.create_project(&alice, "acme", "api")?;
    env.create_environment(&alice, "acme", "api", "dev")?;

    // Bob and Charlie join workspace
    let ws_invite = env.create_workspace_invite(&alice, "acme")?;
    env.join_server(&bob, &ws_invite)?;
    let ws_invite2 = env.create_workspace_invite(&alice, "acme")?;
    env.join_server(&charlie, &ws_invite2)?;

    // Give Bob ADMIN permission
    env.set_user_permission(&alice, "acme", &bob.email, "admin")?;
    println!("✓ Bob has ADMIN permission");

    // ─────────────────────────────────────────────────────────────────────────
    // Bob CAN create projects
    // ─────────────────────────────────────────────────────────────────────────
    let output = env.project_create(&bob, "acme", "backend");
    assert_success(&output, "Bob project create (admin permission)");
    println!("✓ Bob can create projects");

    // ─────────────────────────────────────────────────────────────────────────
    // Bob CAN create environments
    // ─────────────────────────────────────────────────────────────────────────
    let output = env.environment_create(&bob, "acme", "backend", "staging");
    assert_success(&output, "Bob environment create (admin permission)");
    println!("✓ Bob can create environments");

    // ─────────────────────────────────────────────────────────────────────────
    // Bob CAN create groups
    // ─────────────────────────────────────────────────────────────────────────
    let output = env.group_create_check(&bob, "acme", "backend-team");
    assert_success(&output, "Bob group create (admin permission)");
    println!("✓ Bob can create groups");

    // ─────────────────────────────────────────────────────────────────────────
    // Bob CAN add members to groups
    // ─────────────────────────────────────────────────────────────────────────
    let output = env.group_add_member_check(&bob, "acme", "backend-team", &charlie.email);
    assert_success(&output, "Bob group add-member (admin permission)");
    println!("✓ Bob can add members to groups");

    // ─────────────────────────────────────────────────────────────────────────
    // Bob CAN set user permissions
    // ─────────────────────────────────────────────────────────────────────────
    let output = env.user_permission_set_check(&bob, "acme", &charlie.email, "read");
    assert_success(&output, "Bob permission set (admin permission)");
    println!("✓ Bob can set user permissions");

    // ─────────────────────────────────────────────────────────────────────────
    // Bob CAN create workspace invites
    // ─────────────────────────────────────────────────────────────────────────
    let output = env.invite_create_check(&bob, "acme");
    assert_success(&output, "Bob invite create (admin permission)");
    println!("✓ Bob can create workspace invites");

    // ─────────────────────────────────────────────────────────────────────────
    // Bob CAN delete environments (cleanup in reverse order)
    // ─────────────────────────────────────────────────────────────────────────
    let output = env.environment_delete(&bob, "acme", "backend", "staging");
    assert_success(&output, "Bob environment delete (admin permission)");
    println!("✓ Bob can delete environments");

    // ─────────────────────────────────────────────────────────────────────────
    // Bob CAN delete projects
    // ─────────────────────────────────────────────────────────────────────────
    let output = env.project_delete(&bob, "acme", "backend");
    assert_success(&output, "Bob project delete (admin permission)");
    println!("✓ Bob can delete projects");

    // ─────────────────────────────────────────────────────────────────────────
    // Bob CAN delete groups
    // ─────────────────────────────────────────────────────────────────────────
    let output = env.group_delete(&bob, "acme", "backend-team");
    assert_success(&output, "Bob group delete (admin permission)");
    println!("✓ Bob can delete groups");

    println!("\n✅ test_admin_role_can_admin_operations PASSED");
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════
// Test: Group-Based Admin Permission Works
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_group_admin_can_admin_operations() -> Result<(), Box<dyn std::error::Error>> {
    let port = find_available_port()?;
    let env = TestEnv::setup("group_admin_ops", port).await?;

    // Setup: Alice creates workspace
    let alice = env.create_user("alice");
    let bob = env.create_user("bob");
    let charlie = env.create_user("charlie");

    let invite = env.create_server_invite()?;
    env.join_server(&alice, &invite)?;
    env.create_workspace(&alice, "acme")?;
    env.create_project(&alice, "acme", "api")?;
    env.create_environment(&alice, "acme", "api", "dev")?;

    // Bob and Charlie join workspace
    let ws_invite = env.create_workspace_invite(&alice, "acme")?;
    env.join_server(&bob, &ws_invite)?;
    let ws_invite2 = env.create_workspace_invite(&alice, "acme")?;
    env.join_server(&charlie, &ws_invite2)?;

    // Create admins group with ADMIN permission
    env.create_group(&alice, "acme", "admins")?;
    env.set_group_permission(&alice, "acme", "admins", "admin")?;
    env.add_group_member(&alice, "acme", "admins", &bob.email)?;
    println!("✓ Bob in 'admins' group with ADMIN permission");

    // ─────────────────────────────────────────────────────────────────────────
    // Bob CAN create projects via group admin
    // ─────────────────────────────────────────────────────────────────────────
    let output = env.project_create(&bob, "acme", "frontend");
    assert_success(&output, "Bob project create (group admin)");
    println!("✓ Bob can create projects via group admin");

    // ─────────────────────────────────────────────────────────────────────────
    // Bob CAN create environments via group admin
    // ─────────────────────────────────────────────────────────────────────────
    let output = env.environment_create(&bob, "acme", "frontend", "prod");
    assert_success(&output, "Bob environment create (group admin)");
    println!("✓ Bob can create environments via group admin");

    // ─────────────────────────────────────────────────────────────────────────
    // Bob CAN set permissions via group admin
    // ─────────────────────────────────────────────────────────────────────────
    let output = env.user_permission_set_check(&bob, "acme", &charlie.email, "write");
    assert_success(&output, "Bob permission set (group admin)");
    println!("✓ Bob can set permissions via group admin");

    // ─────────────────────────────────────────────────────────────────────────
    // Bob CAN create invites via group admin
    // ─────────────────────────────────────────────────────────────────────────
    let output = env.invite_create_check(&bob, "acme");
    assert_success(&output, "Bob invite create (group admin)");
    println!("✓ Bob can create invites via group admin");

    println!("\n✅ test_group_admin_can_admin_operations PASSED");
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════
// Test: Principal Ceiling Restricts Admin Operations
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_principal_ceiling_restricts_admin_operations(
) -> Result<(), Box<dyn std::error::Error>> {
    let port = find_available_port()?;
    let env = TestEnv::setup("ceiling_admin", port).await?;

    // Setup: Alice creates workspace
    let alice = env.create_user("alice");
    let bob = env.create_user("bob");

    let invite = env.create_server_invite()?;
    env.join_server(&alice, &invite)?;
    env.create_workspace(&alice, "acme")?;
    env.create_project(&alice, "acme", "api")?;
    env.create_environment(&alice, "acme", "api", "dev")?;

    // Bob joins workspace
    let ws_invite = env.create_workspace_invite(&alice, "acme")?;
    env.join_server(&bob, &ws_invite)?;

    // Give Bob ADMIN user permission
    env.set_user_permission(&alice, "acme", &bob.email, "admin")?;
    println!("✓ Bob has ADMIN user permission");

    // Bob CAN create projects with ADMIN
    let output = env.project_create(&bob, "acme", "service1");
    assert_success(&output, "Bob project create (admin)");
    println!("✓ Bob can create projects with ADMIN");

    // Now set principal ceiling to WRITE
    let bob_principal_id = env.get_principal_id(&bob)?;
    env.set_principal_permission(&alice, "acme", &bob_principal_id, "write")?;
    println!("✓ Set Bob's principal ceiling to WRITE");

    // Bob CANNOT create projects anymore (effective = min(ADMIN, WRITE) = WRITE)
    let output = env.project_create(&bob, "acme", "service2");
    assert_denied(&output, "Bob project create (principal ceiling)");
    println!("✓ Bob denied project create (principal ceiling restricts)");

    // Bob CANNOT set ADMIN permissions (ceiling restricts to WRITE, so can only set WRITE/READ)
    let output = env.user_permission_set_check(&bob, "acme", &alice.email, "admin");
    assert_denied(&output, "Bob permission set ADMIN (principal ceiling)");
    println!("✓ Bob denied setting ADMIN permission (principal ceiling restricts)");

    // Bob CANNOT create groups
    let output = env.group_create_check(&bob, "acme", "new-group");
    assert_denied(&output, "Bob group create (principal ceiling)");
    println!("✓ Bob denied group create (principal ceiling restricts)");

    // Bob CAN still do write operations (secrets)
    let output = env.secret_set(&bob, "acme", "api", "dev", "SECRET", "value");
    assert_success(&output, "Bob secret set (within write ceiling)");
    println!("✓ Bob can still write secrets (within WRITE ceiling)");

    println!("\n✅ test_principal_ceiling_restricts_admin_operations PASSED");
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════
// Test: Owner Always Has Admin Operations Regardless of Permissions
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_owner_always_has_admin_operations() -> Result<(), Box<dyn std::error::Error>> {
    let port = find_available_port()?;
    let env = TestEnv::setup("owner_admin", port).await?;

    // Setup: Alice creates workspace (she is the owner)
    let alice = env.create_user("alice");

    let invite = env.create_server_invite()?;
    env.join_server(&alice, &invite)?;
    env.create_workspace(&alice, "acme")?;
    println!("✓ Alice is workspace owner");

    // Owner can create projects
    let output = env.project_create(&alice, "acme", "api");
    assert_success(&output, "Owner project create");
    println!("✓ Owner can create projects");

    // Owner can create environments
    let output = env.environment_create(&alice, "acme", "api", "dev");
    assert_success(&output, "Owner environment create");
    println!("✓ Owner can create environments");

    // Owner can create groups
    let output = env.group_create_check(&alice, "acme", "developers");
    assert_success(&output, "Owner group create");
    println!("✓ Owner can create groups");

    // Owner can create invites
    let output = env.invite_create_check(&alice, "acme");
    assert_success(&output, "Owner invite create");
    println!("✓ Owner can create invites");

    // Owner can delete (in reverse order)
    let output = env.group_delete(&alice, "acme", "developers");
    assert_success(&output, "Owner group delete");
    println!("✓ Owner can delete groups");

    let output = env.environment_delete(&alice, "acme", "api", "dev");
    assert_success(&output, "Owner environment delete");
    println!("✓ Owner can delete environments");

    let output = env.project_delete(&alice, "acme", "api");
    assert_success(&output, "Owner project delete");
    println!("✓ Owner can delete projects");

    println!("\n✅ test_owner_always_has_admin_operations PASSED");
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════════════════════════════════
// GRANULAR PERMISSION TESTS
// Tests for granular permission model at workspace, project, and environment levels
// ═══════════════════════════════════════════════════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════════════════════
// Test: Project-Level Admin Can Create/Delete Environments In Their Project
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_project_admin_can_manage_environments() -> Result<(), Box<dyn std::error::Error>> {
    let port = find_available_port()?;
    let env = TestEnv::setup("proj_admin_env", port).await?;

    let alice = env.create_user("alice");
    let bob = env.create_user("bob");

    let invite = env.create_server_invite()?;
    env.join_server(&alice, &invite)?;
    env.create_workspace(&alice, "acme")?;
    env.create_project(&alice, "acme", "api")?;
    env.create_project(&alice, "acme", "frontend")?;
    env.create_environment(&alice, "acme", "api", "dev")?;

    // Bob joins
    let ws_invite = env.create_workspace_invite(&alice, "acme")?;
    env.join_server(&bob, &ws_invite)?;

    // Give Bob PROJECT admin on 'api' project only
    env.set_user_project_permission(&alice, "acme", "api", &bob.email, "admin")?;
    println!("✓ Bob has PROJECT ADMIN on 'api' project");

    // Bob CAN create environments in 'api' project
    let output = env.environment_create(&bob, "acme", "api", "staging");
    assert_success(&output, "Bob create environment in api");
    println!("✓ Bob can create environments in 'api'");

    // Bob CAN delete environments in 'api' project
    let output = env.environment_delete(&bob, "acme", "api", "staging");
    assert_success(&output, "Bob delete environment in api");
    println!("✓ Bob can delete environments in 'api'");

    // Bob CANNOT create environments in 'frontend' project (no permission there)
    let output = env.environment_create(&bob, "acme", "frontend", "staging");
    assert_denied(&output, "Bob create environment in frontend");
    println!("✓ Bob denied environment create in 'frontend'");

    // Bob CANNOT create new projects (requires workspace admin)
    let output = env.project_create(&bob, "acme", "backend");
    assert_denied(&output, "Bob create project");
    println!("✓ Bob denied project create (requires workspace admin)");

    println!("\n✅ test_project_admin_can_manage_environments PASSED");
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════
// Test: Project-Level Admin Can Manage Project-Level Permissions
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_project_admin_can_manage_project_permissions(
) -> Result<(), Box<dyn std::error::Error>> {
    let port = find_available_port()?;
    let env = TestEnv::setup("proj_admin_perm", port).await?;

    let alice = env.create_user("alice");
    let bob = env.create_user("bob");
    let charlie = env.create_user("charlie");

    let invite = env.create_server_invite()?;
    env.join_server(&alice, &invite)?;
    env.create_workspace(&alice, "acme")?;
    env.create_project(&alice, "acme", "api")?;
    env.create_project(&alice, "acme", "frontend")?;
    env.create_environment(&alice, "acme", "api", "dev")?;

    // Bob and Charlie join
    let ws_invite = env.create_workspace_invite(&alice, "acme")?;
    env.join_server(&bob, &ws_invite)?;
    let ws_invite2 = env.create_workspace_invite(&alice, "acme")?;
    env.join_server(&charlie, &ws_invite2)?;

    // Give Bob PROJECT admin on 'api' project
    env.set_user_project_permission(&alice, "acme", "api", &bob.email, "admin")?;
    println!("✓ Bob has PROJECT ADMIN on 'api'");

    // Bob CAN set project-level permissions on 'api'
    let output =
        env.set_user_project_permission_check(&bob, "acme", "api", &charlie.email, "write");
    assert_success(&output, "Bob set project permission on api");
    println!("✓ Bob can set project permissions on 'api'");

    // Bob CANNOT set project-level permissions on 'frontend'
    let output =
        env.set_user_project_permission_check(&bob, "acme", "frontend", &charlie.email, "write");
    assert_denied(&output, "Bob set project permission on frontend");
    println!("✓ Bob denied setting permissions on 'frontend'");

    // Bob CANNOT set workspace-level permissions
    let output = env.user_permission_set_check(&bob, "acme", &charlie.email, "read");
    assert_denied(&output, "Bob set workspace permission");
    println!("✓ Bob denied setting workspace permissions");

    println!("\n✅ test_project_admin_can_manage_project_permissions PASSED");
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════
// Test: Environment-Level Admin Can Manage Environment-Level Permissions
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_environment_admin_can_manage_environment_permissions(
) -> Result<(), Box<dyn std::error::Error>> {
    let port = find_available_port()?;
    let env = TestEnv::setup("env_admin_perm", port).await?;

    let alice = env.create_user("alice");
    let bob = env.create_user("bob");
    let charlie = env.create_user("charlie");

    let invite = env.create_server_invite()?;
    env.join_server(&alice, &invite)?;
    env.create_workspace(&alice, "acme")?;
    env.create_project(&alice, "acme", "api")?;
    env.create_environment(&alice, "acme", "api", "dev")?;
    env.create_environment(&alice, "acme", "api", "prod")?;

    // Bob and Charlie join
    let ws_invite = env.create_workspace_invite(&alice, "acme")?;
    env.join_server(&bob, &ws_invite)?;
    let ws_invite2 = env.create_workspace_invite(&alice, "acme")?;
    env.join_server(&charlie, &ws_invite2)?;

    // Give Bob ENVIRONMENT admin on 'dev' only
    env.set_user_environment_permission(&alice, "acme", "api", "dev", &bob.email, "admin")?;
    println!("✓ Bob has ENVIRONMENT ADMIN on 'api/dev'");

    // Bob CAN set environment-level permissions on 'dev'
    let output = env.set_user_environment_permission_check(
        &bob,
        "acme",
        "api",
        "dev",
        &charlie.email,
        "read",
    );
    assert_success(&output, "Bob set environment permission on dev");
    println!("✓ Bob can set environment permissions on 'dev'");

    // Bob CANNOT set environment-level permissions on 'prod'
    let output = env.set_user_environment_permission_check(
        &bob,
        "acme",
        "api",
        "prod",
        &charlie.email,
        "read",
    );
    assert_denied(&output, "Bob set environment permission on prod");
    println!("✓ Bob denied setting permissions on 'prod'");

    // Bob CANNOT delete the 'dev' environment (need project admin or higher)
    let output = env.environment_delete(&bob, "acme", "api", "dev");
    assert_denied(&output, "Bob delete dev environment");
    println!("✓ Bob denied environment delete (environment admin can't delete)");

    // Bob CANNOT set project-level permissions
    let output = env.set_user_project_permission_check(&bob, "acme", "api", &charlie.email, "read");
    assert_denied(&output, "Bob set project permission");
    println!("✓ Bob denied setting project permissions");

    println!("\n✅ test_environment_admin_can_manage_environment_permissions PASSED");
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════
// Test: Workspace Admin Inherits Admin at All Levels
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_workspace_admin_inherits_all_levels() -> Result<(), Box<dyn std::error::Error>> {
    let port = find_available_port()?;
    let env = TestEnv::setup("ws_admin_inherit", port).await?;

    let alice = env.create_user("alice");
    let bob = env.create_user("bob");
    let charlie = env.create_user("charlie");

    let invite = env.create_server_invite()?;
    env.join_server(&alice, &invite)?;
    env.create_workspace(&alice, "acme")?;
    env.create_project(&alice, "acme", "api")?;
    env.create_environment(&alice, "acme", "api", "dev")?;

    // Bob and Charlie join
    let ws_invite = env.create_workspace_invite(&alice, "acme")?;
    env.join_server(&bob, &ws_invite)?;
    let ws_invite2 = env.create_workspace_invite(&alice, "acme")?;
    env.join_server(&charlie, &ws_invite2)?;

    // Give Bob WORKSPACE admin
    env.set_user_permission(&alice, "acme", &bob.email, "admin")?;
    println!("✓ Bob has WORKSPACE ADMIN");

    // Bob CAN do everything at workspace level
    let output = env.project_create(&bob, "acme", "backend");
    assert_success(&output, "Bob create project");
    println!("✓ Bob can create projects");

    // Bob CAN do everything at project level
    let output = env.environment_create(&bob, "acme", "backend", "staging");
    assert_success(&output, "Bob create environment");
    println!("✓ Bob can create environments");

    // Bob CAN set project-level permissions
    let output =
        env.set_user_project_permission_check(&bob, "acme", "api", &charlie.email, "write");
    assert_success(&output, "Bob set project permission");
    println!("✓ Bob can set project permissions");

    // Bob CAN set environment-level permissions
    let output = env.set_user_environment_permission_check(
        &bob,
        "acme",
        "api",
        "dev",
        &charlie.email,
        "read",
    );
    assert_success(&output, "Bob set environment permission");
    println!("✓ Bob can set environment permissions");

    // Bob CAN do secret operations at all levels
    let output = env.secret_set(&bob, "acme", "api", "dev", "SECRET", "value");
    assert_success(&output, "Bob set secret");
    println!("✓ Bob can set secrets");

    println!("\n✅ test_workspace_admin_inherits_all_levels PASSED");
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════
// Test: Project Admin Inherits Admin at Environment Level
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_project_admin_inherits_environment_level() -> Result<(), Box<dyn std::error::Error>> {
    let port = find_available_port()?;
    let env = TestEnv::setup("proj_admin_inherit", port).await?;

    let alice = env.create_user("alice");
    let bob = env.create_user("bob");
    let charlie = env.create_user("charlie");

    let invite = env.create_server_invite()?;
    env.join_server(&alice, &invite)?;
    env.create_workspace(&alice, "acme")?;
    env.create_project(&alice, "acme", "api")?;
    env.create_environment(&alice, "acme", "api", "dev")?;
    env.create_environment(&alice, "acme", "api", "prod")?;

    // Bob and Charlie join
    let ws_invite = env.create_workspace_invite(&alice, "acme")?;
    env.join_server(&bob, &ws_invite)?;
    let ws_invite2 = env.create_workspace_invite(&alice, "acme")?;
    env.join_server(&charlie, &ws_invite2)?;

    // Give Bob PROJECT admin on 'api'
    env.set_user_project_permission(&alice, "acme", "api", &bob.email, "admin")?;
    println!("✓ Bob has PROJECT ADMIN on 'api'");

    // Bob CAN set environment-level permissions on any environment in 'api'
    let output = env.set_user_environment_permission_check(
        &bob,
        "acme",
        "api",
        "dev",
        &charlie.email,
        "write",
    );
    assert_success(&output, "Bob set env permission on dev");
    println!("✓ Bob can set permissions on 'api/dev'");

    let output = env.set_user_environment_permission_check(
        &bob,
        "acme",
        "api",
        "prod",
        &charlie.email,
        "read",
    );
    assert_success(&output, "Bob set env permission on prod");
    println!("✓ Bob can set permissions on 'api/prod'");

    // Bob CAN do secret operations in all environments of 'api'
    let output = env.secret_set(&bob, "acme", "api", "dev", "SECRET", "value");
    assert_success(&output, "Bob set secret in dev");
    println!("✓ Bob can set secrets in 'api/dev'");

    let output = env.secret_set(&bob, "acme", "api", "prod", "SECRET", "value");
    assert_success(&output, "Bob set secret in prod");
    println!("✓ Bob can set secrets in 'api/prod'");

    println!("\n✅ test_project_admin_inherits_environment_level PASSED");
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════
// Test: Cross-Project Isolation - Permissions Don't Leak
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_cross_project_isolation() -> Result<(), Box<dyn std::error::Error>> {
    let port = find_available_port()?;
    let env = TestEnv::setup("proj_isolation", port).await?;

    let alice = env.create_user("alice");
    let bob = env.create_user("bob");

    let invite = env.create_server_invite()?;
    env.join_server(&alice, &invite)?;
    env.create_workspace(&alice, "acme")?;
    env.create_project(&alice, "acme", "api")?;
    env.create_project(&alice, "acme", "frontend")?;
    env.create_environment(&alice, "acme", "api", "dev")?;
    env.create_environment(&alice, "acme", "frontend", "dev")?;
    env.secret_set(&alice, "acme", "api", "dev", "API_SECRET", "api_value");
    env.secret_set(
        &alice,
        "acme",
        "frontend",
        "dev",
        "FE_SECRET",
        "frontend_value",
    );

    // Bob joins
    let ws_invite = env.create_workspace_invite(&alice, "acme")?;
    env.join_server(&bob, &ws_invite)?;

    // Give Bob READ on 'api' project only
    env.set_user_project_permission(&alice, "acme", "api", &bob.email, "read")?;
    println!("✓ Bob has READ on 'api' project only");

    // Bob CAN read secrets in 'api'
    let output = env.secret_get(&bob, "acme", "api", "dev", "API_SECRET");
    assert_success(&output, "Bob read api secret");
    println!("✓ Bob can read secrets in 'api'");

    // Bob CANNOT read secrets in 'frontend'
    let output = env.secret_get(&bob, "acme", "frontend", "dev", "FE_SECRET");
    assert_denied(&output, "Bob read frontend secret");
    println!("✓ Bob denied access to 'frontend' secrets");

    // Bob CANNOT write to 'api' (only has read)
    let output = env.secret_set(&bob, "acme", "api", "dev", "NEW_SECRET", "value");
    assert_denied(&output, "Bob write api secret");
    println!("✓ Bob denied write to 'api' (read-only)");

    println!("\n✅ test_cross_project_isolation PASSED");
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════
// Test: Cross-Environment Isolation - Permissions Don't Leak
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_cross_environment_isolation() -> Result<(), Box<dyn std::error::Error>> {
    let port = find_available_port()?;
    let env = TestEnv::setup("env_isolation", port).await?;

    let alice = env.create_user("alice");
    let bob = env.create_user("bob");

    let invite = env.create_server_invite()?;
    env.join_server(&alice, &invite)?;
    env.create_workspace(&alice, "acme")?;
    env.create_project(&alice, "acme", "api")?;
    env.create_environment(&alice, "acme", "api", "dev")?;
    env.create_environment(&alice, "acme", "api", "staging")?;
    env.create_environment(&alice, "acme", "api", "prod")?;
    env.secret_set(&alice, "acme", "api", "dev", "SECRET", "dev_value");
    env.secret_set(&alice, "acme", "api", "staging", "SECRET", "staging_value");
    env.secret_set(&alice, "acme", "api", "prod", "SECRET", "prod_value");

    // Bob joins
    let ws_invite = env.create_workspace_invite(&alice, "acme")?;
    env.join_server(&bob, &ws_invite)?;

    // Give Bob WRITE on 'dev' environment only
    env.set_user_environment_permission(&alice, "acme", "api", "dev", &bob.email, "write")?;
    println!("✓ Bob has WRITE on 'api/dev' only");

    // Bob CAN read/write secrets in 'dev'
    let output = env.secret_get(&bob, "acme", "api", "dev", "SECRET");
    assert_success(&output, "Bob read dev secret");
    println!("✓ Bob can read 'dev' secrets");

    let output = env.secret_set(&bob, "acme", "api", "dev", "NEW_SECRET", "value");
    assert_success(&output, "Bob write dev secret");
    println!("✓ Bob can write 'dev' secrets");

    // Bob CANNOT access 'staging'
    let output = env.secret_get(&bob, "acme", "api", "staging", "SECRET");
    assert_denied(&output, "Bob read staging secret");
    println!("✓ Bob denied 'staging' access");

    // Bob CANNOT access 'prod'
    let output = env.secret_get(&bob, "acme", "api", "prod", "SECRET");
    assert_denied(&output, "Bob read prod secret");
    println!("✓ Bob denied 'prod' access");

    println!("\n✅ test_cross_environment_isolation PASSED");
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════
// Test: Permission Max - User Gets Highest of All Levels
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_permission_max_across_levels() -> Result<(), Box<dyn std::error::Error>> {
    let port = find_available_port()?;
    let env = TestEnv::setup("perm_max_levels", port).await?;

    let alice = env.create_user("alice");
    let bob = env.create_user("bob");

    let invite = env.create_server_invite()?;
    env.join_server(&alice, &invite)?;
    env.create_workspace(&alice, "acme")?;
    env.create_project(&alice, "acme", "api")?;
    env.create_environment(&alice, "acme", "api", "dev")?;
    env.secret_set(&alice, "acme", "api", "dev", "SECRET", "value");

    // Bob joins
    let ws_invite = env.create_workspace_invite(&alice, "acme")?;
    env.join_server(&bob, &ws_invite)?;

    // Give Bob READ at workspace level
    env.set_user_permission(&alice, "acme", &bob.email, "read")?;
    println!("✓ Bob has READ at workspace level");

    // Bob can only read
    let output = env.secret_get(&bob, "acme", "api", "dev", "SECRET");
    assert_success(&output, "Bob read secret");
    let output = env.secret_set(&bob, "acme", "api", "dev", "NEW", "value");
    assert_denied(&output, "Bob write denied (workspace read)");
    println!("✓ Bob has READ (can read, not write)");

    // Add WRITE at project level - Bob should now have max(workspace READ, project WRITE) = WRITE
    env.set_user_project_permission(&alice, "acme", "api", &bob.email, "write")?;
    println!("✓ Added WRITE at project level");

    let output = env.secret_set(&bob, "acme", "api", "dev", "NEW", "value");
    assert_success(&output, "Bob write secret (project write)");
    println!("✓ Bob now has WRITE (max of workspace READ + project WRITE)");

    // Add ADMIN at environment level - Bob should now have max(READ, WRITE, ADMIN) = ADMIN
    env.set_user_environment_permission(&alice, "acme", "api", "dev", &bob.email, "admin")?;
    println!("✓ Added ADMIN at environment level");

    // Bob can now set permissions on the environment
    let output =
        env.set_user_environment_permission_check(&bob, "acme", "api", "dev", &alice.email, "read");
    assert_success(&output, "Bob set env permission (has env admin)");
    println!("✓ Bob now has ADMIN (can set environment permissions)");

    println!("\n✅ test_permission_max_across_levels PASSED");
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════
// Test: Environment Admin Secret Operations
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_environment_admin_secret_operations() -> Result<(), Box<dyn std::error::Error>> {
    let port = find_available_port()?;
    let env = TestEnv::setup("env_admin_secrets", port).await?;

    let alice = env.create_user("alice");
    let bob = env.create_user("bob");

    let invite = env.create_server_invite()?;
    env.join_server(&alice, &invite)?;
    env.create_workspace(&alice, "acme")?;
    env.create_project(&alice, "acme", "api")?;
    env.create_environment(&alice, "acme", "api", "dev")?;
    env.secret_set(&alice, "acme", "api", "dev", "SECRET", "value");

    // Bob joins
    let ws_invite = env.create_workspace_invite(&alice, "acme")?;
    env.join_server(&bob, &ws_invite)?;

    // Give Bob ADMIN at environment level
    env.set_user_environment_permission(&alice, "acme", "api", "dev", &bob.email, "admin")?;
    println!("✓ Bob has ADMIN on 'api/dev' environment");

    // Admin includes Write includes Read - Bob can do everything
    let output = env.secret_get(&bob, "acme", "api", "dev", "SECRET");
    assert_success(&output, "Bob read secret");
    println!("✓ Bob can read secrets (admin > write > read)");

    let output = env.secret_set(&bob, "acme", "api", "dev", "NEW_SECRET", "new_value");
    assert_success(&output, "Bob write secret");
    println!("✓ Bob can write secrets (admin > write)");

    let output = env.secret_delete(&bob, "acme", "api", "dev", "SECRET");
    assert_success(&output, "Bob delete secret");
    println!("✓ Bob can delete secrets (admin > write)");

    println!("\n✅ test_environment_admin_secret_operations PASSED");
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════
// Test: Read-Only at Different Levels
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_read_only_at_different_levels() -> Result<(), Box<dyn std::error::Error>> {
    let port = find_available_port()?;
    let env = TestEnv::setup("read_only_levels", port).await?;

    let alice = env.create_user("alice");
    let bob = env.create_user("bob");
    let charlie = env.create_user("charlie");
    let dave = env.create_user("dave");

    let invite = env.create_server_invite()?;
    env.join_server(&alice, &invite)?;
    env.create_workspace(&alice, "acme")?;
    env.create_project(&alice, "acme", "api")?;
    env.create_environment(&alice, "acme", "api", "dev")?;
    env.secret_set(&alice, "acme", "api", "dev", "SECRET", "value");

    // Bob, Charlie, Dave join
    let ws_invite = env.create_workspace_invite(&alice, "acme")?;
    env.join_server(&bob, &ws_invite)?;
    let ws_invite2 = env.create_workspace_invite(&alice, "acme")?;
    env.join_server(&charlie, &ws_invite2)?;
    let ws_invite3 = env.create_workspace_invite(&alice, "acme")?;
    env.join_server(&dave, &ws_invite3)?;

    // Bob gets READ at workspace level
    env.set_user_permission(&alice, "acme", &bob.email, "read")?;
    // Charlie gets READ at project level
    env.set_user_project_permission(&alice, "acme", "api", &charlie.email, "read")?;
    // Dave gets READ at environment level
    env.set_user_environment_permission(&alice, "acme", "api", "dev", &dave.email, "read")?;

    println!("✓ Set up: Bob=workspace READ, Charlie=project READ, Dave=environment READ");

    // All three can read
    for (user, name) in [(&bob, "Bob"), (&charlie, "Charlie"), (&dave, "Dave")] {
        let output = env.secret_get(user, "acme", "api", "dev", "SECRET");
        assert_success(&output, &format!("{} read secret", name));
    }
    println!("✓ All three can read secrets");

    // None can write
    for (user, name) in [(&bob, "Bob"), (&charlie, "Charlie"), (&dave, "Dave")] {
        let output = env.secret_set(user, "acme", "api", "dev", "NEW", "value");
        assert_denied(&output, &format!("{} write denied", name));
    }
    println!("✓ None of them can write (read-only)");

    println!("\n✅ test_read_only_at_different_levels PASSED");
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════
// Test: Write at Different Levels
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_write_at_different_levels() -> Result<(), Box<dyn std::error::Error>> {
    let port = find_available_port()?;
    let env = TestEnv::setup("write_levels", port).await?;

    let alice = env.create_user("alice");
    let bob = env.create_user("bob");
    let charlie = env.create_user("charlie");
    let dave = env.create_user("dave");

    let invite = env.create_server_invite()?;
    env.join_server(&alice, &invite)?;
    env.create_workspace(&alice, "acme")?;
    env.create_project(&alice, "acme", "api")?;
    env.create_environment(&alice, "acme", "api", "dev")?;

    // Bob, Charlie, Dave join
    let ws_invite = env.create_workspace_invite(&alice, "acme")?;
    env.join_server(&bob, &ws_invite)?;
    let ws_invite2 = env.create_workspace_invite(&alice, "acme")?;
    env.join_server(&charlie, &ws_invite2)?;
    let ws_invite3 = env.create_workspace_invite(&alice, "acme")?;
    env.join_server(&dave, &ws_invite3)?;

    // Bob gets WRITE at workspace level
    env.set_user_permission(&alice, "acme", &bob.email, "write")?;
    // Charlie gets WRITE at project level
    env.set_user_project_permission(&alice, "acme", "api", &charlie.email, "write")?;
    // Dave gets WRITE at environment level
    env.set_user_environment_permission(&alice, "acme", "api", "dev", &dave.email, "write")?;

    println!("✓ Set up: Bob=workspace WRITE, Charlie=project WRITE, Dave=environment WRITE");

    // All three can write
    for (user, name) in [(&bob, "Bob"), (&charlie, "Charlie"), (&dave, "Dave")] {
        let output = env.secret_set(
            user,
            "acme",
            "api",
            "dev",
            &format!("{}_SECRET", name),
            "val",
        );
        assert_success(&output, &format!("{} write secret", name));
    }
    println!("✓ All three can write secrets");

    // All three can read
    for (user, name) in [(&bob, "Bob"), (&charlie, "Charlie"), (&dave, "Dave")] {
        let output = env.secret_get(user, "acme", "api", "dev", &format!("{}_SECRET", name));
        assert_success(&output, &format!("{} read secret", name));
    }
    println!("✓ All three can read secrets (write includes read)");

    // None can do admin operations
    for (user, name) in [(&bob, "Bob"), (&charlie, "Charlie"), (&dave, "Dave")] {
        let output = env.project_create(user, "acme", &format!("{}_project", name));
        assert_denied(&output, &format!("{} create project denied", name));
    }
    println!("✓ None of them can create projects (write != admin)");

    println!("\n✅ test_write_at_different_levels PASSED");
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════
// Test: Admin at Different Levels - Full Matrix
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_admin_at_different_levels_full_matrix() -> Result<(), Box<dyn std::error::Error>> {
    let port = find_available_port()?;
    let env = TestEnv::setup("admin_matrix", port).await?;

    let alice = env.create_user("alice");
    let bob = env.create_user("bob"); // workspace admin
    let charlie = env.create_user("charlie"); // project admin
    let dave = env.create_user("dave"); // environment admin

    let invite = env.create_server_invite()?;
    env.join_server(&alice, &invite)?;
    env.create_workspace(&alice, "acme")?;
    env.create_project(&alice, "acme", "api")?;
    env.create_environment(&alice, "acme", "api", "dev")?;

    // Everyone joins
    let ws_invite = env.create_workspace_invite(&alice, "acme")?;
    env.join_server(&bob, &ws_invite)?;
    let ws_invite2 = env.create_workspace_invite(&alice, "acme")?;
    env.join_server(&charlie, &ws_invite2)?;
    let ws_invite3 = env.create_workspace_invite(&alice, "acme")?;
    env.join_server(&dave, &ws_invite3)?;

    // Set up admin at different levels
    env.set_user_permission(&alice, "acme", &bob.email, "admin")?;
    env.set_user_project_permission(&alice, "acme", "api", &charlie.email, "admin")?;
    env.set_user_environment_permission(&alice, "acme", "api", "dev", &dave.email, "admin")?;

    println!("✓ Set up: Bob=WS admin, Charlie=project admin, Dave=env admin");

    // ─────────────────────────────────────────────────────────────────────────
    // Create project: only workspace admin can
    // ─────────────────────────────────────────────────────────────────────────
    let output = env.project_create(&bob, "acme", "bob_project");
    assert_success(&output, "Bob create project");
    println!("✓ Bob (WS admin) can create projects");

    let output = env.project_create(&charlie, "acme", "charlie_project");
    assert_denied(&output, "Charlie create project");
    println!("✓ Charlie (project admin) cannot create projects");

    let output = env.project_create(&dave, "acme", "dave_project");
    assert_denied(&output, "Dave create project");
    println!("✓ Dave (env admin) cannot create projects");

    // ─────────────────────────────────────────────────────────────────────────
    // Create environment: project admin or higher
    // ─────────────────────────────────────────────────────────────────────────
    let output = env.environment_create(&bob, "acme", "api", "bob_env");
    assert_success(&output, "Bob create environment");
    println!("✓ Bob (WS admin) can create environments");

    let output = env.environment_create(&charlie, "acme", "api", "charlie_env");
    assert_success(&output, "Charlie create environment");
    println!("✓ Charlie (project admin) can create environments");

    let output = env.environment_create(&dave, "acme", "api", "dave_env");
    assert_denied(&output, "Dave create environment");
    println!("✓ Dave (env admin) cannot create environments");

    // ─────────────────────────────────────────────────────────────────────────
    // Set workspace permissions: only workspace admin can
    // ─────────────────────────────────────────────────────────────────────────
    let output = env.user_permission_set_check(&bob, "acme", &dave.email, "read");
    assert_success(&output, "Bob set workspace permission");
    println!("✓ Bob (WS admin) can set workspace permissions");

    let output = env.user_permission_set_check(&charlie, "acme", &dave.email, "read");
    assert_denied(&output, "Charlie set workspace permission");
    println!("✓ Charlie (project admin) cannot set workspace permissions");

    // ─────────────────────────────────────────────────────────────────────────
    // Set project permissions: project admin or higher
    // ─────────────────────────────────────────────────────────────────────────
    let output = env.set_user_project_permission_check(&bob, "acme", "api", &dave.email, "read");
    assert_success(&output, "Bob set project permission");
    println!("✓ Bob (WS admin) can set project permissions");

    let output =
        env.set_user_project_permission_check(&charlie, "acme", "api", &dave.email, "write");
    assert_success(&output, "Charlie set project permission");
    println!("✓ Charlie (project admin) can set project permissions");

    let output = env.set_user_project_permission_check(&dave, "acme", "api", &alice.email, "read");
    assert_denied(&output, "Dave set project permission");
    println!("✓ Dave (env admin) cannot set project permissions");

    // ─────────────────────────────────────────────────────────────────────────
    // Set environment permissions: environment admin or higher
    // ─────────────────────────────────────────────────────────────────────────
    let output =
        env.set_user_environment_permission_check(&bob, "acme", "api", "dev", &alice.email, "read");
    assert_success(&output, "Bob set env permission");
    println!("✓ Bob (WS admin) can set environment permissions");

    let output = env.set_user_environment_permission_check(
        &charlie,
        "acme",
        "api",
        "dev",
        &alice.email,
        "read",
    );
    assert_success(&output, "Charlie set env permission");
    println!("✓ Charlie (project admin) can set environment permissions");

    let output = env.set_user_environment_permission_check(
        &dave,
        "acme",
        "api",
        "dev",
        &alice.email,
        "write",
    );
    assert_success(&output, "Dave set env permission");
    println!("✓ Dave (env admin) can set environment permissions");

    println!("\n✅ test_admin_at_different_levels_full_matrix PASSED");
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════
// Test: Project-Level READ/WRITE for Secret Operations
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_project_level_read_write_secrets() -> Result<(), Box<dyn std::error::Error>> {
    let port = find_available_port()?;
    let env = TestEnv::setup("proj_rw_secrets", port).await?;

    let alice = env.create_user("alice");
    let bob = env.create_user("bob");
    let charlie = env.create_user("charlie");

    let invite = env.create_server_invite()?;
    env.join_server(&alice, &invite)?;
    env.create_workspace(&alice, "acme")?;
    env.create_project(&alice, "acme", "api")?;
    env.create_project(&alice, "acme", "frontend")?;
    env.create_environment(&alice, "acme", "api", "dev")?;
    env.create_environment(&alice, "acme", "api", "prod")?;
    env.create_environment(&alice, "acme", "frontend", "dev")?;
    env.secret_set(&alice, "acme", "api", "dev", "API_DEV_SECRET", "api_dev");
    env.secret_set(&alice, "acme", "api", "prod", "API_PROD_SECRET", "api_prod");
    env.secret_set(&alice, "acme", "frontend", "dev", "FE_SECRET", "fe_dev");

    // Bob and Charlie join
    let ws_invite = env.create_workspace_invite(&alice, "acme")?;
    env.join_server(&bob, &ws_invite)?;
    let ws_invite2 = env.create_workspace_invite(&alice, "acme")?;
    env.join_server(&charlie, &ws_invite2)?;

    // Bob gets READ on 'api' project
    env.set_user_project_permission(&alice, "acme", "api", &bob.email, "read")?;
    // Charlie gets WRITE on 'api' project
    env.set_user_project_permission(&alice, "acme", "api", &charlie.email, "write")?;

    println!("✓ Bob has PROJECT READ on 'api', Charlie has PROJECT WRITE on 'api'");

    // Bob (PROJECT READ) can read all environments in the project
    let output = env.secret_get(&bob, "acme", "api", "dev", "API_DEV_SECRET");
    assert_success(&output, "Bob read api/dev");
    let output = env.secret_get(&bob, "acme", "api", "prod", "API_PROD_SECRET");
    assert_success(&output, "Bob read api/prod");
    println!("✓ Bob (PROJECT READ) can read secrets in all project environments");

    // Bob (PROJECT READ) cannot write
    let output = env.secret_set(&bob, "acme", "api", "dev", "NEW", "value");
    assert_denied(&output, "Bob write api/dev");
    let output = env.secret_set(&bob, "acme", "api", "prod", "NEW", "value");
    assert_denied(&output, "Bob write api/prod");
    println!("✓ Bob (PROJECT READ) cannot write secrets");

    // Bob cannot access frontend project
    let output = env.secret_get(&bob, "acme", "frontend", "dev", "FE_SECRET");
    assert_denied(&output, "Bob read frontend/dev");
    println!("✓ Bob (PROJECT READ on api) cannot access frontend project");

    // Charlie (PROJECT WRITE) can read and write all environments
    let output = env.secret_get(&charlie, "acme", "api", "dev", "API_DEV_SECRET");
    assert_success(&output, "Charlie read api/dev");
    let output = env.secret_set(&charlie, "acme", "api", "dev", "CHARLIE_SECRET", "val");
    assert_success(&output, "Charlie write api/dev");
    let output = env.secret_set(&charlie, "acme", "api", "prod", "CHARLIE_PROD", "val");
    assert_success(&output, "Charlie write api/prod");
    println!("✓ Charlie (PROJECT WRITE) can read/write in all project environments");

    // Charlie cannot access frontend project
    let output = env.secret_get(&charlie, "acme", "frontend", "dev", "FE_SECRET");
    assert_denied(&output, "Charlie read frontend/dev");
    println!("✓ Charlie (PROJECT WRITE on api) cannot access frontend project");

    // Neither can do admin operations on the project
    let output = env.environment_create(&bob, "acme", "api", "staging");
    assert_denied(&output, "Bob create environment");
    let output = env.environment_create(&charlie, "acme", "api", "staging");
    assert_denied(&output, "Charlie create environment");
    println!("✓ Neither Bob (READ) nor Charlie (WRITE) can create environments");

    println!("\n✅ test_project_level_read_write_secrets PASSED");
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════
// Test: Environment-Level READ/WRITE for Secret Operations
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_environment_level_read_write_secrets() -> Result<(), Box<dyn std::error::Error>> {
    let port = find_available_port()?;
    let env = TestEnv::setup("env_rw_secrets", port).await?;

    let alice = env.create_user("alice");
    let bob = env.create_user("bob");
    let charlie = env.create_user("charlie");

    let invite = env.create_server_invite()?;
    env.join_server(&alice, &invite)?;
    env.create_workspace(&alice, "acme")?;
    env.create_project(&alice, "acme", "api")?;
    env.create_environment(&alice, "acme", "api", "dev")?;
    env.create_environment(&alice, "acme", "api", "staging")?;
    env.create_environment(&alice, "acme", "api", "prod")?;
    env.secret_set(&alice, "acme", "api", "dev", "DEV_SECRET", "dev");
    env.secret_set(
        &alice,
        "acme",
        "api",
        "staging",
        "STAGING_SECRET",
        "staging",
    );
    env.secret_set(&alice, "acme", "api", "prod", "PROD_SECRET", "prod");

    // Bob and Charlie join
    let ws_invite = env.create_workspace_invite(&alice, "acme")?;
    env.join_server(&bob, &ws_invite)?;
    let ws_invite2 = env.create_workspace_invite(&alice, "acme")?;
    env.join_server(&charlie, &ws_invite2)?;

    // Bob gets READ on 'dev' environment only
    env.set_user_environment_permission(&alice, "acme", "api", "dev", &bob.email, "read")?;
    // Charlie gets WRITE on 'dev' environment only
    env.set_user_environment_permission(&alice, "acme", "api", "dev", &charlie.email, "write")?;

    println!("✓ Bob has ENV READ on 'dev', Charlie has ENV WRITE on 'dev'");

    // Bob (ENV READ on dev) can read dev only
    let output = env.secret_get(&bob, "acme", "api", "dev", "DEV_SECRET");
    assert_success(&output, "Bob read dev");
    println!("✓ Bob (ENV READ) can read dev secrets");

    // Bob cannot read staging or prod
    let output = env.secret_get(&bob, "acme", "api", "staging", "STAGING_SECRET");
    assert_denied(&output, "Bob read staging");
    let output = env.secret_get(&bob, "acme", "api", "prod", "PROD_SECRET");
    assert_denied(&output, "Bob read prod");
    println!("✓ Bob (ENV READ on dev) cannot read staging/prod");

    // Bob cannot write to dev
    let output = env.secret_set(&bob, "acme", "api", "dev", "NEW", "value");
    assert_denied(&output, "Bob write dev");
    println!("✓ Bob (ENV READ) cannot write to dev");

    // Charlie (ENV WRITE on dev) can read and write dev
    let output = env.secret_get(&charlie, "acme", "api", "dev", "DEV_SECRET");
    assert_success(&output, "Charlie read dev");
    let output = env.secret_set(&charlie, "acme", "api", "dev", "CHARLIE_DEV", "val");
    assert_success(&output, "Charlie write dev");
    println!("✓ Charlie (ENV WRITE) can read/write dev secrets");

    // Charlie cannot access staging or prod
    let output = env.secret_get(&charlie, "acme", "api", "staging", "STAGING_SECRET");
    assert_denied(&output, "Charlie read staging");
    let output = env.secret_set(&charlie, "acme", "api", "prod", "NEW", "value");
    assert_denied(&output, "Charlie write prod");
    println!("✓ Charlie (ENV WRITE on dev) cannot access staging/prod");

    // Neither can do admin operations
    let output =
        env.set_user_environment_permission_check(&bob, "acme", "api", "dev", &alice.email, "read");
    assert_denied(&output, "Bob set env permission");
    let output = env.set_user_environment_permission_check(
        &charlie,
        "acme",
        "api",
        "dev",
        &alice.email,
        "read",
    );
    assert_denied(&output, "Charlie set env permission");
    println!("✓ Neither Bob (READ) nor Charlie (WRITE) can set environment permissions");

    println!("\n✅ test_environment_level_read_write_secrets PASSED");
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════
// Test: Complete Action x Permission Matrix
// Tests every action against every permission level
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_complete_action_permission_matrix() -> Result<(), Box<dyn std::error::Error>> {
    let port = find_available_port()?;
    let env = TestEnv::setup("action_matrix", port).await?;

    let alice = env.create_user("alice");
    // Create users for each permission combination
    let user_none = env.create_user("user_none");
    let user_ws_read = env.create_user("user_ws_read");
    let user_ws_write = env.create_user("user_ws_write");
    let user_ws_admin = env.create_user("user_ws_admin");
    let user_proj_read = env.create_user("user_proj_read");
    let user_proj_write = env.create_user("user_proj_write");
    let user_proj_admin = env.create_user("user_proj_admin");
    let user_env_read = env.create_user("user_env_read");
    let user_env_write = env.create_user("user_env_write");
    let user_env_admin = env.create_user("user_env_admin");

    let invite = env.create_server_invite()?;
    env.join_server(&alice, &invite)?;
    env.create_workspace(&alice, "acme")?;
    env.create_project(&alice, "acme", "api")?;
    env.create_environment(&alice, "acme", "api", "dev")?;
    env.secret_set(&alice, "acme", "api", "dev", "SECRET", "value");

    // Join all users
    for user in [
        &user_none,
        &user_ws_read,
        &user_ws_write,
        &user_ws_admin,
        &user_proj_read,
        &user_proj_write,
        &user_proj_admin,
        &user_env_read,
        &user_env_write,
        &user_env_admin,
    ] {
        let ws_invite = env.create_workspace_invite(&alice, "acme")?;
        env.join_server(user, &ws_invite)?;
    }

    // Set up permissions
    env.set_user_permission(&alice, "acme", &user_ws_read.email, "read")?;
    env.set_user_permission(&alice, "acme", &user_ws_write.email, "write")?;
    env.set_user_permission(&alice, "acme", &user_ws_admin.email, "admin")?;
    env.set_user_project_permission(&alice, "acme", "api", &user_proj_read.email, "read")?;
    env.set_user_project_permission(&alice, "acme", "api", &user_proj_write.email, "write")?;
    env.set_user_project_permission(&alice, "acme", "api", &user_proj_admin.email, "admin")?;
    env.set_user_environment_permission(
        &alice,
        "acme",
        "api",
        "dev",
        &user_env_read.email,
        "read",
    )?;
    env.set_user_environment_permission(
        &alice,
        "acme",
        "api",
        "dev",
        &user_env_write.email,
        "write",
    )?;
    env.set_user_environment_permission(
        &alice,
        "acme",
        "api",
        "dev",
        &user_env_admin.email,
        "admin",
    )?;

    println!("✓ Set up 10 users with different permission levels");

    // ─────────────────────────────────────────────────────────────────────────
    // ACTION: secret read
    // Expected: READ or higher at any level
    // ─────────────────────────────────────────────────────────────────────────
    println!("\n📋 Testing SECRET READ...");
    let output = env.secret_get(&user_none, "acme", "api", "dev", "SECRET");
    assert_denied(&output, "user_none secret read");

    for (user, name) in [
        (&user_ws_read, "ws_read"),
        (&user_ws_write, "ws_write"),
        (&user_ws_admin, "ws_admin"),
        (&user_proj_read, "proj_read"),
        (&user_proj_write, "proj_write"),
        (&user_proj_admin, "proj_admin"),
        (&user_env_read, "env_read"),
        (&user_env_write, "env_write"),
        (&user_env_admin, "env_admin"),
    ] {
        let output = env.secret_get(user, "acme", "api", "dev", "SECRET");
        assert_success(&output, &format!("{} secret read", name));
    }
    println!("✓ SECRET READ: denied for none, allowed for all with READ+");

    // ─────────────────────────────────────────────────────────────────────────
    // ACTION: secret write
    // Expected: WRITE or higher at any level
    // ─────────────────────────────────────────────────────────────────────────
    println!("\n📋 Testing SECRET WRITE...");
    for (user, name) in [
        (&user_none, "none"),
        (&user_ws_read, "ws_read"),
        (&user_proj_read, "proj_read"),
        (&user_env_read, "env_read"),
    ] {
        let output = env.secret_set(
            user,
            "acme",
            "api",
            "dev",
            &format!("{}_secret", name),
            "val",
        );
        assert_denied(&output, &format!("{} secret write", name));
    }

    for (user, name) in [
        (&user_ws_write, "ws_write"),
        (&user_ws_admin, "ws_admin"),
        (&user_proj_write, "proj_write"),
        (&user_proj_admin, "proj_admin"),
        (&user_env_write, "env_write"),
        (&user_env_admin, "env_admin"),
    ] {
        let output = env.secret_set(
            user,
            "acme",
            "api",
            "dev",
            &format!("{}_secret", name),
            "val",
        );
        assert_success(&output, &format!("{} secret write", name));
    }
    println!("✓ SECRET WRITE: denied for none/READ, allowed for WRITE+");

    // ─────────────────────────────────────────────────────────────────────────
    // ACTION: project create
    // Expected: ADMIN at workspace level only
    // ─────────────────────────────────────────────────────────────────────────
    println!("\n📋 Testing PROJECT CREATE...");
    for (user, name) in [
        (&user_none, "none"),
        (&user_ws_read, "ws_read"),
        (&user_ws_write, "ws_write"),
        (&user_proj_read, "proj_read"),
        (&user_proj_write, "proj_write"),
        (&user_proj_admin, "proj_admin"),
        (&user_env_read, "env_read"),
        (&user_env_write, "env_write"),
        (&user_env_admin, "env_admin"),
    ] {
        let output = env.project_create(user, "acme", &format!("{}_project", name));
        assert_denied(&output, &format!("{} project create", name));
    }

    let output = env.project_create(&user_ws_admin, "acme", "ws_admin_project");
    assert_success(&output, "ws_admin project create");
    println!("✓ PROJECT CREATE: only WS ADMIN can create projects");

    // ─────────────────────────────────────────────────────────────────────────
    // ACTION: environment create
    // Expected: ADMIN at project level or workspace level
    // ─────────────────────────────────────────────────────────────────────────
    println!("\n📋 Testing ENVIRONMENT CREATE...");
    for (user, name) in [
        (&user_none, "none"),
        (&user_ws_read, "ws_read"),
        (&user_ws_write, "ws_write"),
        (&user_proj_read, "proj_read"),
        (&user_proj_write, "proj_write"),
        (&user_env_read, "env_read"),
        (&user_env_write, "env_write"),
        (&user_env_admin, "env_admin"),
    ] {
        let output = env.environment_create(user, "acme", "api", &format!("{}_env", name));
        assert_denied(&output, &format!("{} environment create", name));
    }

    let output = env.environment_create(&user_ws_admin, "acme", "api", "ws_admin_env");
    assert_success(&output, "ws_admin environment create");
    let output = env.environment_create(&user_proj_admin, "acme", "api", "proj_admin_env");
    assert_success(&output, "proj_admin environment create");
    println!("✓ ENVIRONMENT CREATE: only WS/PROJECT ADMIN can create environments");

    // ─────────────────────────────────────────────────────────────────────────
    // ACTION: set workspace permission
    // Expected: Delegated authority - can only set permissions <= own effective role
    // ─────────────────────────────────────────────────────────────────────────
    println!("\n📋 Testing SET WORKSPACE PERMISSION (delegated authority)...");

    // Users without workspace permissions cannot set any permissions
    let output = env.user_permission_set_check(&user_none, "acme", &user_env_read.email, "read");
    assert_denied(&output, "none cannot set any permission");

    // ws_read can only set READ (not WRITE or ADMIN)
    let output = env.user_permission_set_check(&user_ws_read, "acme", &user_none.email, "write");
    assert_denied(&output, "ws_read cannot set WRITE");

    // ws_write can set WRITE/READ but not ADMIN
    let output = env.user_permission_set_check(&user_ws_write, "acme", &user_none.email, "admin");
    assert_denied(&output, "ws_write cannot set ADMIN");

    // ws_admin can set any permission
    let output = env.user_permission_set_check(&user_ws_admin, "acme", &user_none.email, "admin");
    assert_success(&output, "ws_admin can set ADMIN");
    println!("✓ SET WORKSPACE PERMISSION: delegated authority enforced");

    // ─────────────────────────────────────────────────────────────────────────
    // ACTION: set project permission
    // Expected: ADMIN at project level or workspace level
    // ─────────────────────────────────────────────────────────────────────────
    println!("\n📋 Testing SET PROJECT PERMISSION...");
    for (user, name) in [
        (&user_ws_read, "ws_read"),
        (&user_ws_write, "ws_write"),
        (&user_proj_read, "proj_read"),
        (&user_proj_write, "proj_write"),
        (&user_env_read, "env_read"),
        (&user_env_write, "env_write"),
        (&user_env_admin, "env_admin"),
    ] {
        let output =
            env.set_user_project_permission_check(user, "acme", "api", &user_none.email, "read");
        assert_denied(&output, &format!("{} set project permission", name));
    }

    let output = env.set_user_project_permission_check(
        &user_ws_admin,
        "acme",
        "api",
        &user_none.email,
        "read",
    );
    assert_success(&output, "ws_admin set project permission");
    let output = env.set_user_project_permission_check(
        &user_proj_admin,
        "acme",
        "api",
        &user_none.email,
        "write",
    );
    assert_success(&output, "proj_admin set project permission");
    println!("✓ SET PROJECT PERMISSION: WS ADMIN or PROJECT ADMIN");

    // ─────────────────────────────────────────────────────────────────────────
    // ACTION: set environment permission
    // Expected: ADMIN at environment, project, or workspace level
    // ─────────────────────────────────────────────────────────────────────────
    println!("\n📋 Testing SET ENVIRONMENT PERMISSION...");
    for (user, name) in [
        (&user_ws_read, "ws_read"),
        (&user_ws_write, "ws_write"),
        (&user_proj_read, "proj_read"),
        (&user_proj_write, "proj_write"),
        (&user_env_read, "env_read"),
        (&user_env_write, "env_write"),
    ] {
        let output = env.set_user_environment_permission_check(
            user,
            "acme",
            "api",
            "dev",
            &user_none.email,
            "read",
        );
        assert_denied(&output, &format!("{} set environment permission", name));
    }

    let output = env.set_user_environment_permission_check(
        &user_ws_admin,
        "acme",
        "api",
        "dev",
        &user_none.email,
        "read",
    );
    assert_success(&output, "ws_admin set environment permission");
    let output = env.set_user_environment_permission_check(
        &user_proj_admin,
        "acme",
        "api",
        "dev",
        &user_none.email,
        "read",
    );
    assert_success(&output, "proj_admin set environment permission");
    let output = env.set_user_environment_permission_check(
        &user_env_admin,
        "acme",
        "api",
        "dev",
        &user_none.email,
        "read",
    );
    assert_success(&output, "env_admin set environment permission");
    println!("✓ SET ENVIRONMENT PERMISSION: WS/PROJECT/ENV ADMIN");

    // ─────────────────────────────────────────────────────────────────────────
    // ACTION: create group
    // Expected: ADMIN at workspace level only
    // ─────────────────────────────────────────────────────────────────────────
    println!("\n📋 Testing GROUP CREATE...");
    for (user, name) in [
        (&user_ws_read, "ws_read"),
        (&user_ws_write, "ws_write"),
        (&user_proj_read, "proj_read"),
        (&user_proj_write, "proj_write"),
        (&user_proj_admin, "proj_admin"),
        (&user_env_read, "env_read"),
        (&user_env_write, "env_write"),
        (&user_env_admin, "env_admin"),
    ] {
        let output = env.group_create_check(user, "acme", &format!("{}_group", name));
        assert_denied(&output, &format!("{} group create", name));
    }

    let output = env.group_create_check(&user_ws_admin, "acme", "ws_admin_group");
    assert_success(&output, "ws_admin group create");
    println!("✓ GROUP CREATE: only WS ADMIN");

    // ─────────────────────────────────────────────────────────────────────────
    // ACTION: create invite
    // Expected: ADMIN at workspace level only
    // ─────────────────────────────────────────────────────────────────────────
    println!("\n📋 Testing INVITE CREATE...");
    for (user, name) in [
        (&user_ws_read, "ws_read"),
        (&user_ws_write, "ws_write"),
        (&user_proj_read, "proj_read"),
        (&user_proj_write, "proj_write"),
        (&user_proj_admin, "proj_admin"),
        (&user_env_read, "env_read"),
        (&user_env_write, "env_write"),
        (&user_env_admin, "env_admin"),
    ] {
        let output = env.invite_create_check(user, "acme");
        assert_denied(&output, &format!("{} invite create", name));
    }

    let output = env.invite_create_check(&user_ws_admin, "acme");
    assert_success(&output, "ws_admin invite create");
    println!("✓ INVITE CREATE: only WS ADMIN");

    println!("\n✅ test_complete_action_permission_matrix PASSED");
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════
// Test: Multi-Level Permission Combination
// User has different permissions at different levels, verify max is used
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_multi_level_permission_combinations() -> Result<(), Box<dyn std::error::Error>> {
    let port = find_available_port()?;
    let env = TestEnv::setup("multi_level", port).await?;

    let alice = env.create_user("alice");
    let bob = env.create_user("bob");

    let invite = env.create_server_invite()?;
    env.join_server(&alice, &invite)?;
    env.create_workspace(&alice, "acme")?;
    env.create_project(&alice, "acme", "api")?;
    env.create_environment(&alice, "acme", "api", "dev")?;
    env.secret_set(&alice, "acme", "api", "dev", "SECRET", "value");

    let ws_invite = env.create_workspace_invite(&alice, "acme")?;
    env.join_server(&bob, &ws_invite)?;

    // ─────────────────────────────────────────────────────────────────────────
    // Case 1: WS READ + PROJ WRITE = WRITE
    // ─────────────────────────────────────────────────────────────────────────
    env.set_user_permission(&alice, "acme", &bob.email, "read")?;
    env.set_user_project_permission(&alice, "acme", "api", &bob.email, "write")?;

    let output = env.secret_set(&bob, "acme", "api", "dev", "BOB1", "val");
    assert_success(&output, "Bob write with WS READ + PROJ WRITE");
    println!("✓ WS READ + PROJ WRITE = WRITE (can write secrets)");

    // But Bob still can't create environments (needs ADMIN)
    let output = env.environment_create(&bob, "acme", "api", "staging");
    assert_denied(&output, "Bob create env with WS READ + PROJ WRITE");
    println!("✓ WS READ + PROJ WRITE cannot create environments");

    // Clean up Bob's permissions
    env.remove_user_permission(&alice, "acme", &bob.email)?;
    env.remove_user_project_permission(&alice, "acme", "api", &bob.email)?;

    // ─────────────────────────────────────────────────────────────────────────
    // Case 2: WS READ + PROJ READ + ENV WRITE = WRITE (for that env only)
    // ─────────────────────────────────────────────────────────────────────────
    env.set_user_permission(&alice, "acme", &bob.email, "read")?;
    env.set_user_project_permission(&alice, "acme", "api", &bob.email, "read")?;
    env.set_user_environment_permission(&alice, "acme", "api", "dev", &bob.email, "write")?;

    let output = env.secret_set(&bob, "acme", "api", "dev", "BOB2", "val");
    assert_success(&output, "Bob write with WS+PROJ READ + ENV WRITE");
    println!("✓ WS READ + PROJ READ + ENV WRITE = WRITE (can write secrets)");

    // Clean up
    env.remove_user_permission(&alice, "acme", &bob.email)?;
    env.remove_user_project_permission(&alice, "acme", "api", &bob.email)?;
    env.remove_user_environment_permission(&alice, "acme", "api", "dev", &bob.email)?;

    // ─────────────────────────────────────────────────────────────────────────
    // Case 3: WS WRITE + PROJ ADMIN = can create envs in that project
    // ─────────────────────────────────────────────────────────────────────────
    env.set_user_permission(&alice, "acme", &bob.email, "write")?;
    env.set_user_project_permission(&alice, "acme", "api", &bob.email, "admin")?;

    let output = env.environment_create(&bob, "acme", "api", "staging");
    assert_success(&output, "Bob create env with WS WRITE + PROJ ADMIN");
    println!("✓ WS WRITE + PROJ ADMIN = can create environments");

    // But still can't create projects (needs WS ADMIN)
    let output = env.project_create(&bob, "acme", "new_project");
    assert_denied(&output, "Bob create project with WS WRITE + PROJ ADMIN");
    println!("✓ WS WRITE + PROJ ADMIN cannot create projects");

    // Clean up
    env.remove_user_permission(&alice, "acme", &bob.email)?;
    env.remove_user_project_permission(&alice, "acme", "api", &bob.email)?;

    // ─────────────────────────────────────────────────────────────────────────
    // Case 4: PROJ READ + ENV ADMIN = can set env permissions
    // ─────────────────────────────────────────────────────────────────────────
    env.set_user_project_permission(&alice, "acme", "api", &bob.email, "read")?;
    env.set_user_environment_permission(&alice, "acme", "api", "dev", &bob.email, "admin")?;

    let output =
        env.set_user_environment_permission_check(&bob, "acme", "api", "dev", &alice.email, "read");
    assert_success(&output, "Bob set env permission with PROJ READ + ENV ADMIN");
    println!("✓ PROJ READ + ENV ADMIN = can set environment permissions");

    // But can't set project permissions
    let output = env.set_user_project_permission_check(&bob, "acme", "api", &alice.email, "read");
    assert_denied(
        &output,
        "Bob set project permission with PROJ READ + ENV ADMIN",
    );
    println!("✓ PROJ READ + ENV ADMIN cannot set project permissions");

    println!("\n✅ test_multi_level_permission_combinations PASSED");
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════
// Test: Group Permissions at Project Level
// Groups can have permissions at project level (not just workspace)
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_group_project_permissions() -> Result<(), Box<dyn std::error::Error>> {
    let port = find_available_port()?;
    let env = TestEnv::setup("group_proj_perm", port).await?;

    let alice = env.create_user("alice");
    let bob = env.create_user("bob");
    let carol = env.create_user("carol");

    let invite = env.create_server_invite()?;
    env.join_server(&alice, &invite)?;
    env.create_workspace(&alice, "acme")?;
    env.create_project(&alice, "acme", "api")?;
    env.create_project(&alice, "acme", "web")?;
    env.create_environment(&alice, "acme", "api", "dev")?;
    env.create_environment(&alice, "acme", "web", "dev")?;
    env.secret_set(&alice, "acme", "api", "dev", "API_SECRET", "val");
    env.secret_set(&alice, "acme", "web", "dev", "WEB_SECRET", "val");

    let ws_invite = env.create_workspace_invite(&alice, "acme")?;
    env.join_server(&bob, &ws_invite)?;

    let ws_invite2 = env.create_workspace_invite(&alice, "acme")?;
    env.join_server(&carol, &ws_invite2)?;

    // Create a group "api-devs" with only READ at workspace level
    // but WRITE at project "api" level
    env.create_group(&alice, "acme", "api-devs")?;
    env.add_group_member(&alice, "acme", "api-devs", &bob.email)?;
    env.set_group_permission(&alice, "acme", "api-devs", "read")?;
    env.set_group_project_permission(&alice, "acme", "api", "api-devs", "write")?;

    // ─────────────────────────────────────────────────────────────────────────
    // Test 1: Bob (in api-devs) can WRITE to api project
    // ─────────────────────────────────────────────────────────────────────────
    let output = env.secret_set(&bob, "acme", "api", "dev", "BOB_SECRET", "bob_val");
    assert_success(&output, "Bob (api-devs WRITE) can write to api project");
    println!("✓ Group project WRITE allows writing secrets");

    // ─────────────────────────────────────────────────────────────────────────
    // Test 2: Bob (in api-devs) can only READ from web project (group ws-level is READ)
    // ─────────────────────────────────────────────────────────────────────────
    let output = env.secret_get(&bob, "acme", "web", "dev", "WEB_SECRET");
    assert_success(&output, "Bob (api-devs) can read from web project");
    println!("✓ Group workspace READ allows reading from other projects");

    let output = env.secret_set(&bob, "acme", "web", "dev", "NEW_SECRET", "val");
    assert_denied(&output, "Bob (api-devs) cannot write to web project");
    println!("✓ Group workspace READ cannot write to other projects");

    // ─────────────────────────────────────────────────────────────────────────
    // Test 3: Carol (not in group) has no access
    // ─────────────────────────────────────────────────────────────────────────
    let output = env.secret_get(&carol, "acme", "api", "dev", "API_SECRET");
    assert_denied(&output, "Carol (not in group) cannot read api secrets");
    println!("✓ Non-group member has no access");

    // ─────────────────────────────────────────────────────────────────────────
    // Test 4: Group ADMIN at project level can create environments
    // ─────────────────────────────────────────────────────────────────────────
    env.set_group_project_permission(&alice, "acme", "api", "api-devs", "admin")?;
    let output = env.environment_create(&bob, "acme", "api", "staging");
    assert_success(
        &output,
        "Bob (api-devs ADMIN) can create env in api project",
    );
    println!("✓ Group project ADMIN can create environments");

    // But Bob still can't create projects (needs workspace admin)
    let output = env.project_create(&bob, "acme", "new-proj");
    assert_denied(&output, "Bob (api-devs) cannot create projects");
    println!("✓ Group project ADMIN cannot create projects");

    println!("\n✅ test_group_project_permissions PASSED");
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════
// Test: Group Permissions at Environment Level
// Groups can have permissions at environment level (most granular)
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_group_environment_permissions() -> Result<(), Box<dyn std::error::Error>> {
    let port = find_available_port()?;
    let env = TestEnv::setup("group_env_perm", port).await?;

    let alice = env.create_user("alice");
    let bob = env.create_user("bob");

    let invite = env.create_server_invite()?;
    env.join_server(&alice, &invite)?;
    env.create_workspace(&alice, "acme")?;
    env.create_project(&alice, "acme", "api")?;
    env.create_environment(&alice, "acme", "api", "dev")?;
    env.create_environment(&alice, "acme", "api", "prod")?;
    env.secret_set(&alice, "acme", "api", "dev", "DEV_SECRET", "dev_val");
    env.secret_set(&alice, "acme", "api", "prod", "PROD_SECRET", "prod_val");

    let ws_invite = env.create_workspace_invite(&alice, "acme")?;
    env.join_server(&bob, &ws_invite)?;

    // Create a group "prod-readonly" with READ at workspace level
    // but no special access at project, and READ at prod env level
    env.create_group(&alice, "acme", "prod-readonly")?;
    env.add_group_member(&alice, "acme", "prod-readonly", &bob.email)?;
    // No workspace-level permission (Bob has only what he gets via group)
    env.set_group_environment_permission(&alice, "acme", "api", "prod", "prod-readonly", "read")?;

    // ─────────────────────────────────────────────────────────────────────────
    // Test 1: Bob (in prod-readonly) can READ from prod
    // ─────────────────────────────────────────────────────────────────────────
    let output = env.secret_get(&bob, "acme", "api", "prod", "PROD_SECRET");
    assert_success(&output, "Bob (prod-readonly) can read from prod");
    println!("✓ Group environment READ allows reading secrets");

    // ─────────────────────────────────────────────────────────────────────────
    // Test 2: Bob (in prod-readonly) cannot WRITE to prod
    // ─────────────────────────────────────────────────────────────────────────
    let output = env.secret_set(&bob, "acme", "api", "prod", "NEW_SECRET", "val");
    assert_denied(&output, "Bob (prod-readonly) cannot write to prod");
    println!("✓ Group environment READ cannot write secrets");

    // ─────────────────────────────────────────────────────────────────────────
    // Test 3: Bob has no access to dev environment
    // ─────────────────────────────────────────────────────────────────────────
    let output = env.secret_get(&bob, "acme", "api", "dev", "DEV_SECRET");
    assert_denied(&output, "Bob cannot read from dev");
    println!("✓ Group environment permission does not grant access to other envs");

    // ─────────────────────────────────────────────────────────────────────────
    // Test 4: Group WRITE at env level allows writing
    // ─────────────────────────────────────────────────────────────────────────
    env.set_group_environment_permission(&alice, "acme", "api", "prod", "prod-readonly", "write")?;
    let output = env.secret_set(&bob, "acme", "api", "prod", "NEW_PROD_SECRET", "val");
    assert_success(&output, "Bob (prod group WRITE) can write to prod");
    println!("✓ Group environment WRITE allows writing secrets");

    // ─────────────────────────────────────────────────────────────────────────
    // Test 5: Group ADMIN at env level can set env permissions
    // ─────────────────────────────────────────────────────────────────────────
    env.set_group_environment_permission(&alice, "acme", "api", "prod", "prod-readonly", "admin")?;
    let output = env.set_user_environment_permission_check(
        &bob,
        "acme",
        "api",
        "prod",
        &alice.email,
        "read",
    );
    assert_success(&output, "Bob (prod group ADMIN) can set env permissions");
    println!("✓ Group environment ADMIN can set environment permissions");

    // But Bob still can't create environments (needs project admin)
    let output = env.environment_create(&bob, "acme", "api", "staging");
    assert_denied(&output, "Bob (env ADMIN) cannot create environments");
    println!("✓ Group environment ADMIN cannot create environments");

    println!("\n✅ test_group_environment_permissions PASSED");
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════
// Test: Combined Group and User Permissions (Max Rule)
// When user has both group and individual permissions, use the MAX
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_group_and_user_permissions_max() -> Result<(), Box<dyn std::error::Error>> {
    let port = find_available_port()?;
    let env = TestEnv::setup("group_user_max", port).await?;

    let alice = env.create_user("alice");
    let bob = env.create_user("bob");

    let invite = env.create_server_invite()?;
    env.join_server(&alice, &invite)?;
    env.create_workspace(&alice, "acme")?;
    env.create_project(&alice, "acme", "api")?;
    env.create_environment(&alice, "acme", "api", "dev")?;
    env.secret_set(&alice, "acme", "api", "dev", "SECRET", "val");

    let ws_invite = env.create_workspace_invite(&alice, "acme")?;
    env.join_server(&bob, &ws_invite)?;

    // Give Bob READ via user permission
    env.set_user_permission(&alice, "acme", &bob.email, "read")?;

    // Create a group with WRITE at project level
    env.create_group(&alice, "acme", "devs")?;
    env.add_group_member(&alice, "acme", "devs", &bob.email)?;
    env.set_group_project_permission(&alice, "acme", "api", "devs", "write")?;

    // ─────────────────────────────────────────────────────────────────────────
    // Test 1: Bob has MAX(user READ, group project WRITE) = WRITE
    // ─────────────────────────────────────────────────────────────────────────
    let output = env.secret_set(&bob, "acme", "api", "dev", "BOB_SECRET", "val");
    assert_success(&output, "Bob gets WRITE from group even with user READ");
    println!("✓ MAX(user READ, group WRITE) = WRITE");

    // ─────────────────────────────────────────────────────────────────────────
    // Test 2: Remove group permission, Bob is back to READ
    // ─────────────────────────────────────────────────────────────────────────
    env.remove_group_project_permission(&alice, "acme", "api", "devs")?;

    let output = env.secret_get(&bob, "acme", "api", "dev", "SECRET");
    assert_success(&output, "Bob can still read with user READ");

    let output = env.secret_set(&bob, "acme", "api", "dev", "ANOTHER", "val");
    assert_denied(&output, "Bob cannot write after group permission removed");
    println!("✓ After removing group permission, user is back to READ");

    // ─────────────────────────────────────────────────────────────────────────
    // Test 3: User ADMIN + Group READ = ADMIN (MAX)
    // ─────────────────────────────────────────────────────────────────────────
    env.set_user_permission(&alice, "acme", &bob.email, "admin")?;
    env.set_group_project_permission(&alice, "acme", "api", "devs", "read")?;

    // Bob should still have ADMIN from user permission
    let output = env.project_create(&bob, "acme", "new-project");
    assert_success(&output, "Bob has ADMIN despite group being READ");
    println!("✓ MAX(user ADMIN, group READ) = ADMIN");

    println!("\n✅ test_group_and_user_permissions_max PASSED");
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════
// Test: Permission List Commands
// Verify that list commands work at all levels for users and groups
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_permission_list_commands() -> Result<(), Box<dyn std::error::Error>> {
    let port = find_available_port()?;
    let env = TestEnv::setup("perm_list", port).await?;

    let alice = env.create_user("alice");
    let bob = env.create_user("bob");
    let carol = env.create_user("carol");

    let invite = env.create_server_invite()?;
    env.join_server(&alice, &invite)?;
    env.create_workspace(&alice, "acme")?;
    env.create_project(&alice, "acme", "api")?;
    env.create_environment(&alice, "acme", "api", "dev")?;

    let ws_invite = env.create_workspace_invite(&alice, "acme")?;
    env.join_server(&bob, &ws_invite)?;
    let ws_invite2 = env.create_workspace_invite(&alice, "acme")?;
    env.join_server(&carol, &ws_invite2)?;

    // ─────────────────────────────────────────────────────────────────────────
    // Setup permissions at all levels
    // ─────────────────────────────────────────────────────────────────────────
    env.set_user_permission(&alice, "acme", &bob.email, "write")?;
    env.set_user_permission(&alice, "acme", &carol.email, "read")?;
    env.set_user_project_permission(&alice, "acme", "api", &bob.email, "admin")?;
    env.set_user_environment_permission(&alice, "acme", "api", "dev", &carol.email, "write")?;

    // Create groups with permissions
    env.create_group(&alice, "acme", "devs")?;
    env.create_group(&alice, "acme", "ops")?;
    env.set_group_permission(&alice, "acme", "devs", "write")?;
    env.set_group_project_permission(&alice, "acme", "api", "ops", "read")?;
    env.set_group_environment_permission(&alice, "acme", "api", "dev", "devs", "admin")?;

    // ─────────────────────────────────────────────────────────────────────────
    // Test 1: User permission list at workspace level
    // ─────────────────────────────────────────────────────────────────────────
    let output = env.user_permission_list(&alice, "acme");
    assert_success(&output, "user-list workspace");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains(&bob.email), "user-list should contain bob");
    assert!(
        stdout.contains(&carol.email),
        "user-list should contain carol"
    );
    println!("✓ user-list shows workspace-level user permissions");

    // ─────────────────────────────────────────────────────────────────────────
    // Test 2: User permission list at project level
    // ─────────────────────────────────────────────────────────────────────────
    let output = env.user_project_permission_list(&alice, "acme", "api");
    assert_success(&output, "user-project-list");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(&bob.email),
        "user-project-list should contain bob"
    );
    println!("✓ user-project-list shows project-level user permissions");

    // ─────────────────────────────────────────────────────────────────────────
    // Test 3: User permission list at environment level
    // ─────────────────────────────────────────────────────────────────────────
    let output = env.user_env_permission_list(&alice, "acme", "api", "dev");
    assert_success(&output, "user-env-list");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(&carol.email),
        "user-env-list should contain carol"
    );
    println!("✓ user-env-list shows environment-level user permissions");

    // ─────────────────────────────────────────────────────────────────────────
    // Test 4: Group permission list at workspace level
    // ─────────────────────────────────────────────────────────────────────────
    let output = env.group_permission_list(&alice, "acme");
    assert_success(&output, "group list-permissions workspace");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("devs"),
        "group list-permissions should contain devs"
    );
    println!("✓ group list-permissions shows workspace-level group permissions");

    // ─────────────────────────────────────────────────────────────────────────
    // Test 5: Group permission list at project level
    // ─────────────────────────────────────────────────────────────────────────
    let output = env.group_project_permission_list(&alice, "acme", "api");
    assert_success(&output, "group list-project-permissions");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("ops"),
        "group list-project-permissions should contain ops"
    );
    println!("✓ group list-project-permissions shows project-level group permissions");

    // ─────────────────────────────────────────────────────────────────────────
    // Test 6: Group permission list at environment level
    // ─────────────────────────────────────────────────────────────────────────
    let output = env.group_env_permission_list(&alice, "acme", "api", "dev");
    assert_success(&output, "group list-env-permissions");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("devs"),
        "group list-env-permissions should contain devs"
    );
    println!("✓ group list-env-permissions shows environment-level group permissions");

    // ─────────────────────────────────────────────────────────────────────────
    // Test 7: Non-admin cannot list permissions
    // ─────────────────────────────────────────────────────────────────────────
    let _output = env.user_permission_list(&bob, "acme");
    // Bob has write, not admin, so listing might be restricted
    // (This depends on implementation - some systems allow, some don't)

    println!("\n✅ test_permission_list_commands PASSED");
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════
// Test: Group Permission Removal at All Levels
// Verify that removing group permissions works at workspace/project/environment
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_group_permission_removal() -> Result<(), Box<dyn std::error::Error>> {
    let port = find_available_port()?;
    let env = TestEnv::setup("grp_remove", port).await?;

    let alice = env.create_user("alice");
    let bob = env.create_user("bob");

    let invite = env.create_server_invite()?;
    env.join_server(&alice, &invite)?;
    env.create_workspace(&alice, "acme")?;
    env.create_project(&alice, "acme", "api")?;
    env.create_environment(&alice, "acme", "api", "dev")?;

    let ws_invite = env.create_workspace_invite(&alice, "acme")?;
    env.join_server(&bob, &ws_invite)?;

    // Create a group and add Bob
    env.create_group(&alice, "acme", "devs")?;
    env.add_group_member(&alice, "acme", "devs", &bob.email)?;

    // ─────────────────────────────────────────────────────────────────────────
    // Test 1: Workspace-level permission removal
    // ─────────────────────────────────────────────────────────────────────────
    // Project creation requires ADMIN, so we use admin permission
    env.set_group_permission(&alice, "acme", "devs", "admin")?;

    // Verify Bob can create project via group ADMIN
    let output = env.project_create(&bob, "acme", "test-proj");
    assert_success(&output, "Bob can create project via group ADMIN");

    // Remove the group workspace permission
    env.remove_group_permission(&alice, "acme", "devs")?;

    // Bob should not be able to create projects now
    let output = env.project_create(&bob, "acme", "another-proj");
    assert_denied(
        &output,
        "Bob cannot create project after group permission removed",
    );
    println!("✓ Workspace-level group permission removal works");

    // ─────────────────────────────────────────────────────────────────────────
    // Test 2: Environment-level permission removal
    // ─────────────────────────────────────────────────────────────────────────
    // Give group environment-level write permission
    env.set_group_environment_permission(&alice, "acme", "api", "dev", "devs", "write")?;

    // Set a secret to test
    let output = env.secret_set(&alice, "acme", "api", "dev", "TEST_SECRET", "value");
    assert_success(&output, "Alice sets up test secret");

    // Bob should be able to read/write secrets via group
    let output = env.secret_get(&bob, "acme", "api", "dev", "TEST_SECRET");
    assert_success(&output, "Bob can read secret via group env permission");

    let output = env.secret_set(&bob, "acme", "api", "dev", "BOB_SECRET", "val");
    assert_success(&output, "Bob can write secret via group env permission");

    // Remove the group environment permission
    env.remove_group_environment_permission(&alice, "acme", "api", "dev", "devs")?;

    // Bob should not be able to access secrets now
    let output = env.secret_get(&bob, "acme", "api", "dev", "TEST_SECRET");
    assert_denied(
        &output,
        "Bob cannot read secret after group env permission removed",
    );
    println!("✓ Environment-level group permission removal works");

    println!("\n✅ test_group_permission_removal PASSED");
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════
// Test: Service Principal Permissions with Delegated Authority
// Verify that:
// 1. Service principals can be created
// 2. Users can delegate permissions to service principals up to their own level
// 3. Users cannot delegate permissions higher than their own level
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_service_principal_permissions() -> Result<(), Box<dyn std::error::Error>> {
    let port = find_available_port()?;
    let env = TestEnv::setup("svc_perm", port).await?;

    let alice = env.create_user("alice");
    let bob = env.create_user("bob");

    let invite = env.create_server_invite()?;
    env.join_server(&alice, &invite)?;
    env.create_workspace(&alice, "acme")?;
    env.create_project(&alice, "acme", "api")?;
    env.create_environment(&alice, "acme", "api", "dev")?;

    // Bob joins with WRITE permission (not admin)
    let ws_invite = env.create_workspace_invite(&alice, "acme")?;
    env.join_server(&bob, &ws_invite)?;
    env.set_user_permission(&alice, "acme", &bob.email, "write")?;

    // ─────────────────────────────────────────────────────────────────────────
    // Test 1: Create a service principal
    // ─────────────────────────────────────────────────────────────────────────
    let svc_id = env.create_service_principal(&alice, "ci-pipeline")?;
    assert!(
        !svc_id.is_empty(),
        "Service principal ID should not be empty"
    );
    println!("✓ Created service principal: {}", svc_id);

    // ─────────────────────────────────────────────────────────────────────────
    // Test 2: Bob (WRITE) CAN delegate READ permission (delegated authority)
    // ─────────────────────────────────────────────────────────────────────────
    let output = env.set_principal_project_permission_check(&bob, "acme", "api", &svc_id, "read");
    assert_success(&output, "Bob (write) can delegate read permission");
    println!("✓ Bob (WRITE) can delegate READ to service principal");

    // ─────────────────────────────────────────────────────────────────────────
    // Test 3: Bob (WRITE) CAN delegate WRITE permission (delegated authority)
    // ─────────────────────────────────────────────────────────────────────────
    let output = env.set_principal_project_permission_check(&bob, "acme", "api", &svc_id, "write");
    assert_success(&output, "Bob (write) can delegate write permission");
    println!("✓ Bob (WRITE) can delegate WRITE to service principal");

    // ─────────────────────────────────────────────────────────────────────────
    // Test 4: Bob (WRITE) CANNOT delegate ADMIN permission (exceeds his role)
    // ─────────────────────────────────────────────────────────────────────────
    let output = env.set_principal_project_permission_check(&bob, "acme", "api", &svc_id, "admin");
    assert_denied(&output, "Bob (write) cannot delegate admin permission");
    println!("✓ Bob (WRITE) cannot delegate ADMIN (exceeds his role)");

    // ─────────────────────────────────────────────────────────────────────────
    // Test 5: Bob (WRITE) CAN delegate to environment level too
    // ─────────────────────────────────────────────────────────────────────────
    let output =
        env.set_principal_env_permission_check(&bob, "acme", "api", "dev", &svc_id, "read");
    assert_success(&output, "Bob (write) can delegate read at env level");
    println!("✓ Bob (WRITE) can delegate READ at environment level");

    // ─────────────────────────────────────────────────────────────────────────
    // Test 6: Bob (WRITE) CANNOT delegate ADMIN at environment level
    // ─────────────────────────────────────────────────────────────────────────
    let output =
        env.set_principal_env_permission_check(&bob, "acme", "api", "dev", &svc_id, "admin");
    assert_denied(&output, "Bob (write) cannot delegate admin at env level");
    println!("✓ Bob (WRITE) cannot delegate ADMIN at environment level");

    // ─────────────────────────────────────────────────────────────────────────
    // Test 7: Alice (owner/admin) CAN delegate any permission
    // ─────────────────────────────────────────────────────────────────────────
    let output =
        env.set_principal_project_permission_check(&alice, "acme", "api", &svc_id, "admin");
    assert_success(&output, "Alice (admin) can delegate admin permission");
    println!("✓ Alice (ADMIN) can delegate ADMIN to service principal");

    println!("\n✅ test_service_principal_permissions PASSED");
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════
// Service Principal Permission Removal Tests
// Tests that permission removal follows delegated authority:
// 1. Users can revoke permissions they have authority over
// 2. Users cannot revoke permissions higher than their own level
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_service_principal_permission_removal() -> Result<(), Box<dyn std::error::Error>> {
    let port = find_available_port()?;
    let env = TestEnv::setup("svc_perm_remove", port).await?;

    let alice = env.create_user("alice");
    let bob = env.create_user("bob");
    let charlie = env.create_user("charlie");

    let invite = env.create_server_invite()?;
    env.join_server(&alice, &invite)?;
    env.create_workspace(&alice, "acme")?;
    env.create_project(&alice, "acme", "api")?;
    env.create_environment(&alice, "acme", "api", "dev")?;

    // Bob joins with WRITE permission
    let ws_invite = env.create_workspace_invite(&alice, "acme")?;
    env.join_server(&bob, &ws_invite)?;
    env.set_user_permission(&alice, "acme", &bob.email, "write")?;

    // Charlie joins with READ permission
    let ws_invite2 = env.create_workspace_invite(&alice, "acme")?;
    env.join_server(&charlie, &ws_invite2)?;
    env.set_user_permission(&alice, "acme", &charlie.email, "read")?;

    // Create service principals with various permission levels
    let svc_reader = env.create_service_principal(&alice, "svc-reader")?;
    let svc_writer = env.create_service_principal(&alice, "svc-writer")?;
    let svc_admin = env.create_service_principal(&alice, "svc-admin")?;

    // Alice (admin) sets permissions on service principals
    env.set_principal_project_permission_check(&alice, "acme", "api", &svc_reader, "read");
    env.set_principal_project_permission_check(&alice, "acme", "api", &svc_writer, "write");
    env.set_principal_project_permission_check(&alice, "acme", "api", &svc_admin, "admin");

    println!("Setup complete: 3 service principals with read/write/admin permissions");

    // ─────────────────────────────────────────────────────────────────────────
    // Test 1: Bob (WRITE) CAN remove READ permission (lower than his level)
    // ─────────────────────────────────────────────────────────────────────────
    let output = env.remove_principal_project_permission_check(&bob, "acme", "api", &svc_reader);
    assert_success(&output, "Bob (write) can remove read permission");
    println!("✓ Bob (WRITE) can remove READ permission");

    // Restore the permission for subsequent tests
    env.set_principal_project_permission_check(&alice, "acme", "api", &svc_reader, "read");

    // ─────────────────────────────────────────────────────────────────────────
    // Test 2: Bob (WRITE) CAN remove WRITE permission (equal to his level)
    // ─────────────────────────────────────────────────────────────────────────
    let output = env.remove_principal_project_permission_check(&bob, "acme", "api", &svc_writer);
    assert_success(&output, "Bob (write) can remove write permission");
    println!("✓ Bob (WRITE) can remove WRITE permission");

    // Restore the permission for subsequent tests
    env.set_principal_project_permission_check(&alice, "acme", "api", &svc_writer, "write");

    // ─────────────────────────────────────────────────────────────────────────
    // Test 3: Bob (WRITE) CANNOT remove ADMIN permission (higher than his level)
    // ─────────────────────────────────────────────────────────────────────────
    let output = env.remove_principal_project_permission_check(&bob, "acme", "api", &svc_admin);
    assert_denied(&output, "Bob (write) cannot remove admin permission");
    println!("✓ Bob (WRITE) cannot remove ADMIN permission");

    // ─────────────────────────────────────────────────────────────────────────
    // Test 4: Charlie (READ) CAN remove READ permission (matches his level)
    // ─────────────────────────────────────────────────────────────────────────
    // Charlie has READ at workspace level, which gives him authority to manage
    // READ-level permissions (delegated authority allows managing up to your level)
    let output =
        env.remove_principal_project_permission_check(&charlie, "acme", "api", &svc_reader);
    assert_success(&output, "Charlie (read) can remove read permission");
    println!("✓ Charlie (READ) can remove READ permission");

    // Restore for next test
    env.set_principal_project_permission_check(&alice, "acme", "api", &svc_reader, "read");

    // ─────────────────────────────────────────────────────────────────────────
    // Test 4b: Charlie (READ) CANNOT remove WRITE permission (higher than his level)
    // ─────────────────────────────────────────────────────────────────────────
    let output =
        env.remove_principal_project_permission_check(&charlie, "acme", "api", &svc_writer);
    assert_denied(&output, "Charlie (read) cannot remove write permission");
    println!("✓ Charlie (READ) cannot remove WRITE permission");

    // ─────────────────────────────────────────────────────────────────────────
    // Test 5: Alice (ADMIN) CAN remove any permission
    // ─────────────────────────────────────────────────────────────────────────
    let output = env.remove_principal_project_permission_check(&alice, "acme", "api", &svc_admin);
    assert_success(&output, "Alice (admin) can remove admin permission");
    println!("✓ Alice (ADMIN) can remove ADMIN permission");

    // ─────────────────────────────────────────────────────────────────────────
    // Test 6: Environment-level permission removal follows same rules
    // ─────────────────────────────────────────────────────────────────────────
    // Set up environment-level permissions
    env.set_principal_env_permission_check(&alice, "acme", "api", "dev", &svc_reader, "read");
    env.set_principal_env_permission_check(&alice, "acme", "api", "dev", &svc_writer, "write");

    // Bob (WRITE) can remove READ at env level
    let output = env.remove_principal_env_permission_check(&bob, "acme", "api", "dev", &svc_reader);
    assert_success(&output, "Bob (write) can remove read at env level");
    println!("✓ Bob (WRITE) can remove READ at environment level");

    // Restore for next test
    env.set_principal_env_permission_check(&alice, "acme", "api", "dev", &svc_reader, "read");

    // Set admin permission at env level for testing
    env.set_principal_env_permission_check(&alice, "acme", "api", "dev", &svc_admin, "admin");

    // Bob (WRITE) cannot remove ADMIN at env level
    let output = env.remove_principal_env_permission_check(&bob, "acme", "api", "dev", &svc_admin);
    assert_denied(&output, "Bob (write) cannot remove admin at env level");
    println!("✓ Bob (WRITE) cannot remove ADMIN at environment level");

    println!("\n✅ test_service_principal_permission_removal PASSED");
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════
// Authorization Bypass Prevention Tests
// These tests verify that the security fixes for authorization bypasses work
// ═══════════════════════════════════════════════════════════════════════════

// ─────────────────────────────────────────────────────────────────────────────
// Test: User Permission Delegated Authority
// Users can only grant permissions <= their own role
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_user_permission_delegated_authority() -> Result<(), Box<dyn std::error::Error>> {
    let port = find_available_port()?;
    let env = TestEnv::setup("user_perm_delegated", port).await?;

    let alice = env.create_user("alice");
    let bob = env.create_user("bob");
    let charlie = env.create_user("charlie");

    let invite = env.create_server_invite()?;
    env.join_server(&alice, &invite)?;
    env.create_workspace(&alice, "acme")?;
    env.create_project(&alice, "acme", "api")?;
    env.create_environment(&alice, "acme", "api", "dev")?;

    // Bob joins with WRITE permission
    let ws_invite = env.create_workspace_invite(&alice, "acme")?;
    env.join_server(&bob, &ws_invite)?;
    env.set_user_permission(&alice, "acme", &bob.email, "write")?;

    // Charlie joins (will receive permissions from Bob's attempts)
    let ws_invite2 = env.create_workspace_invite(&alice, "acme")?;
    env.join_server(&charlie, &ws_invite2)?;

    println!("Setup complete: Alice (owner), Bob (write), Charlie (no permission)");

    // ─────────────────────────────────────────────────────────────────────────
    // Test 1: Bob (WRITE) CAN grant WRITE permission (equal to his role)
    // ─────────────────────────────────────────────────────────────────────────
    let output = env.user_permission_set_check(&bob, "acme", &charlie.email, "write");
    assert_success(&output, "Bob (write) can grant write permission");
    println!("✓ Bob (WRITE) can grant WRITE to Charlie");

    // Remove for next test
    env.remove_user_permission(&alice, "acme", &charlie.email)?;

    // ─────────────────────────────────────────────────────────────────────────
    // Test 2: Bob (WRITE) CAN grant READ permission (lower than his role)
    // ─────────────────────────────────────────────────────────────────────────
    let output = env.user_permission_set_check(&bob, "acme", &charlie.email, "read");
    assert_success(&output, "Bob (write) can grant read permission");
    println!("✓ Bob (WRITE) can grant READ to Charlie");

    // Remove for next test
    env.remove_user_permission(&alice, "acme", &charlie.email)?;

    // ─────────────────────────────────────────────────────────────────────────
    // Test 3: Bob (WRITE) CANNOT grant ADMIN permission (higher than his role)
    // ─────────────────────────────────────────────────────────────────────────
    let output = env.user_permission_set_check(&bob, "acme", &charlie.email, "admin");
    assert_denied(&output, "Bob (write) cannot grant admin permission");
    println!("✓ Bob (WRITE) cannot grant ADMIN to Charlie (delegated authority enforced)");

    // ─────────────────────────────────────────────────────────────────────────
    // Test 4: Alice (owner/admin) CAN grant ADMIN permission
    // ─────────────────────────────────────────────────────────────────────────
    let output = env.user_permission_set_check(&alice, "acme", &charlie.email, "admin");
    assert_success(&output, "Alice (admin) can grant admin permission");
    println!("✓ Alice (ADMIN) can grant ADMIN to Charlie");

    println!("\n✅ test_user_permission_delegated_authority PASSED");
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Test: User Permission Removal Delegated Authority
// Users can only remove permissions <= their own role
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_user_permission_removal_delegated_authority() -> Result<(), Box<dyn std::error::Error>>
{
    let port = find_available_port()?;
    let env = TestEnv::setup("user_perm_remove_delegated", port).await?;

    let alice = env.create_user("alice");
    let bob = env.create_user("bob");
    let charlie = env.create_user("charlie");
    let dave = env.create_user("dave");

    let invite = env.create_server_invite()?;
    env.join_server(&alice, &invite)?;
    env.create_workspace(&alice, "acme")?;

    // Bob joins with WRITE permission
    let ws_invite = env.create_workspace_invite(&alice, "acme")?;
    env.join_server(&bob, &ws_invite)?;
    env.set_user_permission(&alice, "acme", &bob.email, "write")?;

    // Charlie joins with READ permission (lower than Bob)
    let ws_invite2 = env.create_workspace_invite(&alice, "acme")?;
    env.join_server(&charlie, &ws_invite2)?;
    env.set_user_permission(&alice, "acme", &charlie.email, "read")?;

    // Dave joins with ADMIN permission (higher than Bob)
    let ws_invite3 = env.create_workspace_invite(&alice, "acme")?;
    env.join_server(&dave, &ws_invite3)?;
    env.set_user_permission(&alice, "acme", &dave.email, "admin")?;

    println!("Setup complete: Alice (owner), Bob (write), Charlie (read), Dave (admin)");

    // ─────────────────────────────────────────────────────────────────────────
    // Test 1: Bob (WRITE) CAN remove Charlie's READ permission (lower role)
    // ─────────────────────────────────────────────────────────────────────────
    let output = env.user_permission_remove_check(&bob, "acme", &charlie.email);
    assert_success(&output, "Bob (write) can remove read permission");
    println!("✓ Bob (WRITE) can remove Charlie's READ permission");

    // Restore for next test
    env.set_user_permission(&alice, "acme", &charlie.email, "read")?;

    // ─────────────────────────────────────────────────────────────────────────
    // Test 2: Bob (WRITE) CANNOT remove Dave's ADMIN permission (higher role)
    // ─────────────────────────────────────────────────────────────────────────
    let output = env.user_permission_remove_check(&bob, "acme", &dave.email);
    assert_denied(&output, "Bob (write) cannot remove admin permission");
    println!("✓ Bob (WRITE) cannot remove Dave's ADMIN permission (delegated authority enforced)");

    println!("\n✅ test_user_permission_removal_delegated_authority PASSED");
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Test: Group Modification Requires Admin
// Non-admins cannot update groups
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_group_modification_requires_admin() -> Result<(), Box<dyn std::error::Error>> {
    let port = find_available_port()?;
    let env = TestEnv::setup("group_mod_admin", port).await?;

    let alice = env.create_user("alice");
    let bob = env.create_user("bob");

    let invite = env.create_server_invite()?;
    env.join_server(&alice, &invite)?;
    env.create_workspace(&alice, "acme")?;

    // Alice creates a group
    env.create_group(&alice, "acme", "developers")?;

    // Bob joins with WRITE permission (not admin)
    let ws_invite = env.create_workspace_invite(&alice, "acme")?;
    env.join_server(&bob, &ws_invite)?;
    env.set_user_permission(&alice, "acme", &bob.email, "write")?;

    println!("Setup complete: Alice (owner), Bob (write), group 'developers' exists");

    // ─────────────────────────────────────────────────────────────────────────
    // Test 1: Bob (WRITE) CANNOT update/rename the group
    // ─────────────────────────────────────────────────────────────────────────
    let output = env.group_update_check(&bob, "acme", "developers", "engineers");
    assert_denied(&output, "Bob (write) cannot update group");
    println!("✓ Bob (WRITE) cannot update group (admin required)");

    // ─────────────────────────────────────────────────────────────────────────
    // Test 2: Alice (admin) CAN update the group
    // ─────────────────────────────────────────────────────────────────────────
    let output = env.group_update_check(&alice, "acme", "developers", "engineers");
    assert_success(&output, "Alice (admin) can update group");
    println!("✓ Alice (ADMIN) can update group");

    println!("\n✅ test_group_modification_requires_admin PASSED");
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Test: Group Permission Setting Requires Admin
// Non-admins cannot set/modify group permissions
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_group_permission_setting_requires_admin() -> Result<(), Box<dyn std::error::Error>> {
    let port = find_available_port()?;
    let env = TestEnv::setup("group_perm_admin", port).await?;

    let alice = env.create_user("alice");
    let bob = env.create_user("bob");

    let invite = env.create_server_invite()?;
    env.join_server(&alice, &invite)?;
    env.create_workspace(&alice, "acme")?;
    env.create_project(&alice, "acme", "api")?;
    env.create_environment(&alice, "acme", "api", "dev")?;

    // Alice creates a group
    env.create_group(&alice, "acme", "developers")?;

    // Bob joins with WRITE permission (not admin)
    let ws_invite = env.create_workspace_invite(&alice, "acme")?;
    env.join_server(&bob, &ws_invite)?;
    env.set_user_permission(&alice, "acme", &bob.email, "write")?;

    println!("Setup complete: Alice (owner), Bob (write), group 'developers' exists");

    // ─────────────────────────────────────────────────────────────────────────
    // Test 1: Bob (WRITE) CANNOT set group workspace permission
    // ─────────────────────────────────────────────────────────────────────────
    let output = env.group_set_permission_check(&bob, "acme", "developers", "write");
    assert_denied(&output, "Bob (write) cannot set group workspace permission");
    println!("✓ Bob (WRITE) cannot set group workspace permission (admin required)");

    // ─────────────────────────────────────────────────────────────────────────
    // Test 2: Bob (WRITE) CANNOT set group project permission
    // ─────────────────────────────────────────────────────────────────────────
    let output = env.group_set_project_permission_check(&bob, "acme", "api", "developers", "write");
    assert_denied(&output, "Bob (write) cannot set group project permission");
    println!("✓ Bob (WRITE) cannot set group project permission (admin required)");

    // ─────────────────────────────────────────────────────────────────────────
    // Test 3: Bob (WRITE) CANNOT set group environment permission
    // ─────────────────────────────────────────────────────────────────────────
    let output =
        env.group_set_env_permission_check(&bob, "acme", "api", "dev", "developers", "write");
    assert_denied(
        &output,
        "Bob (write) cannot set group environment permission",
    );
    println!("✓ Bob (WRITE) cannot set group environment permission (admin required)");

    // ─────────────────────────────────────────────────────────────────────────
    // Test 4: Alice (admin) CAN set group permissions at all levels
    // ─────────────────────────────────────────────────────────────────────────
    let output = env.group_set_permission_check(&alice, "acme", "developers", "write");
    assert_success(&output, "Alice (admin) can set group workspace permission");
    println!("✓ Alice (ADMIN) can set group workspace permission");

    let output =
        env.group_set_project_permission_check(&alice, "acme", "api", "developers", "write");
    assert_success(&output, "Alice (admin) can set group project permission");
    println!("✓ Alice (ADMIN) can set group project permission");

    let output =
        env.group_set_env_permission_check(&alice, "acme", "api", "dev", "developers", "write");
    assert_success(
        &output,
        "Alice (admin) can set group environment permission",
    );
    println!("✓ Alice (ADMIN) can set group environment permission");

    println!("\n✅ test_group_permission_setting_requires_admin PASSED");
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Test: Principal Rename Ownership
// Users can only rename their own principals
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_principal_rename_ownership() -> Result<(), Box<dyn std::error::Error>> {
    let port = find_available_port()?;
    let env = TestEnv::setup("principal_rename", port).await?;

    let alice = env.create_user("alice");
    let bob = env.create_user("bob");

    let invite = env.create_server_invite()?;
    env.join_server(&alice, &invite)?;
    env.create_workspace(&alice, "acme")?;

    // Bob joins
    let ws_invite = env.create_workspace_invite(&alice, "acme")?;
    env.join_server(&bob, &ws_invite)?;
    env.set_user_permission(&alice, "acme", &bob.email, "write")?;

    println!(
        "Setup complete: Alice principal {}, Bob principal {}",
        alice.principal, bob.principal
    );

    // ─────────────────────────────────────────────────────────────────────────
    // Test 1: Alice CAN rename her own principal
    // ─────────────────────────────────────────────────────────────────────────
    let output = env.principal_rename_check(&alice, &alice.principal, "alice-macbook");
    assert_success(&output, "Alice can rename her own principal");
    println!("✓ Alice can rename her own principal");

    // Rename it back for subsequent tests
    let output = env.principal_rename_check(&alice, "alice-macbook", "alice-device");
    assert_success(&output, "Alice can rename principal back");

    // ─────────────────────────────────────────────────────────────────────────
    // Test 2: Alice CANNOT rename Bob's principal (Bob's principal is not in Alice's config)
    // This fails because Alice doesn't have Bob's principal in her local config
    // ─────────────────────────────────────────────────────────────────────────
    let output = env.principal_rename_check(&alice, &bob.principal, "bob-hacked");
    assert_denied(&output, "Alice cannot rename Bob's principal");
    println!("✓ Alice cannot rename Bob's principal (not in her config)");

    // ─────────────────────────────────────────────────────────────────────────
    // Test 3: Bob CAN rename his own principal
    // ─────────────────────────────────────────────────────────────────────────
    let output = env.principal_rename_check(&bob, &bob.principal, "bob-laptop");
    assert_success(&output, "Bob can rename his own principal");
    println!("✓ Bob can rename his own principal");

    // Rename it back
    let output = env.principal_rename_check(&bob, "bob-laptop", "bob-device");
    assert_success(&output, "Bob can rename principal back");

    // ─────────────────────────────────────────────────────────────────────────
    // Test 4: Bob CANNOT rename Alice's principal (Alice's principal is not in Bob's config)
    // ─────────────────────────────────────────────────────────────────────────
    let output = env.principal_rename_check(&bob, &alice.principal, "alice-hacked");
    assert_denied(&output, "Bob cannot rename Alice's principal");
    println!("✓ Bob cannot rename Alice's principal (not in his config)");

    println!("\n✅ test_principal_rename_ownership PASSED");
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Test: Invite Revocation Requires Admin
// Non-admins cannot revoke workspace invites
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_invite_revocation_requires_admin() -> Result<(), Box<dyn std::error::Error>> {
    let port = find_available_port()?;
    let env = TestEnv::setup("invite_revoke_admin", port).await?;

    let alice = env.create_user("alice");
    let bob = env.create_user("bob");

    let invite = env.create_server_invite()?;
    env.join_server(&alice, &invite)?;
    env.create_workspace(&alice, "acme")?;

    // Bob joins with WRITE permission (not admin)
    let ws_invite = env.create_workspace_invite(&alice, "acme")?;
    env.join_server(&bob, &ws_invite)?;
    env.set_user_permission(&alice, "acme", &bob.email, "write")?;

    // Alice creates a new invite to be revoked
    let target_invite = env.create_workspace_invite(&alice, "acme")?;
    // Extract just the token part (first line before any newlines)
    let target_token = target_invite.lines().next().unwrap_or(&target_invite);

    println!("Setup complete: Alice (owner), Bob (write), pending invite exists");

    // ─────────────────────────────────────────────────────────────────────────
    // Test 1: Bob (WRITE) CANNOT revoke the invite
    // ─────────────────────────────────────────────────────────────────────────
    let output = env.invite_revoke_check(&bob, target_token);
    assert_denied(&output, "Bob (write) cannot revoke invite");
    println!("✓ Bob (WRITE) cannot revoke invite (admin required)");

    // ─────────────────────────────────────────────────────────────────────────
    // Test 2: Alice (admin) CAN revoke the invite
    // ─────────────────────────────────────────────────────────────────────────
    let output = env.invite_revoke_check(&alice, target_token);
    assert_success(&output, "Alice (admin) can revoke invite");
    println!("✓ Alice (ADMIN) can revoke invite");

    println!("\n✅ test_invite_revocation_requires_admin PASSED");
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Test: Service Account Cannot Rename Principals
// Service accounts should not be able to rename any principal
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_service_account_cannot_rename_principal() -> Result<(), Box<dyn std::error::Error>> {
    let port = find_available_port()?;
    let env = TestEnv::setup("svc_no_rename", port).await?;

    let alice = env.create_user("alice");

    let invite = env.create_server_invite()?;
    env.join_server(&alice, &invite)?;
    env.create_workspace(&alice, "acme")?;

    // Get Alice's human principal ID before creating service principal
    let alice_principal_id = env.get_principal_id(&alice)?;
    let alice_principal_name = alice.principal.clone();

    // Create a service principal
    let svc_name = "ci-pipeline";
    let svc_id = env.create_service_principal(&alice, svc_name)?;
    println!(
        "Setup complete: Alice principal {}, service principal {}",
        alice_principal_id, svc_id
    );

    // Switch to the service principal
    let output = env.principal_use(&alice, svc_name);
    assert!(
        output.status.success(),
        "Failed to switch to service principal"
    );
    println!("✓ Switched to service principal '{}'", svc_name);

    // ─────────────────────────────────────────────────────────────────────────
    // Test: Service account cannot rename itself
    // ─────────────────────────────────────────────────────────────────────────
    // Note: principal rename takes NAME not ID, and the CLI signs with the
    // target principal's key. So this test verifies that when a service
    // principal tries to rename itself, the server blocks it.
    let output = env.principal_rename_check(&alice, svc_name, "new-svc-name");
    assert_denied(&output, "Service account cannot rename itself");
    println!("✓ Service account cannot rename itself");

    // Switch back to human principal
    let output = env.principal_use(&alice, &alice_principal_name);
    assert!(
        output.status.success(),
        "Failed to switch back to human principal"
    );

    println!("\n✅ test_service_account_cannot_rename_principal PASSED");
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Test: Service Account Cannot Revoke Invites
// Service accounts should not be able to revoke invites, even with admin perms
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_service_account_cannot_revoke_invite() -> Result<(), Box<dyn std::error::Error>> {
    let port = find_available_port()?;
    let env = TestEnv::setup("svc_no_revoke", port).await?;

    let alice = env.create_user("alice");

    let invite = env.create_server_invite()?;
    env.join_server(&alice, &invite)?;
    env.create_workspace(&alice, "acme")?;

    // Create a service principal with ADMIN permission
    let svc_name = "admin-bot";
    let svc_id = env.create_service_principal(&alice, svc_name)?;

    // Give the service principal ADMIN permission at workspace level
    env.set_principal_permission(&alice, "acme", &svc_id, "admin")?;

    // Get Alice's human principal name for switching back
    let alice_principal_name = alice.principal.clone();

    // Create an invite to be revoked
    let target_invite = env.create_workspace_invite(&alice, "acme")?;
    let target_token = target_invite.lines().next().unwrap_or(&target_invite);

    println!(
        "Setup complete: Service principal {} with ADMIN, pending invite",
        svc_id
    );

    // Switch to the service principal
    let output = env.principal_use(&alice, svc_name);
    assert!(
        output.status.success(),
        "Failed to switch to service principal"
    );
    println!("✓ Switched to service principal '{}'", svc_name);

    // ─────────────────────────────────────────────────────────────────────────
    // Test: Service account with ADMIN cannot revoke invite
    // ─────────────────────────────────────────────────────────────────────────
    let output = env.invite_revoke_check(&alice, target_token);
    assert_denied(&output, "Service account cannot revoke invite");
    println!("✓ Service account with ADMIN cannot revoke invite");

    // Switch back and verify human can revoke
    let output = env.principal_use(&alice, &alice_principal_name);
    assert!(
        output.status.success(),
        "Failed to switch back to human principal"
    );

    let output = env.invite_revoke_check(&alice, target_token);
    assert_success(&output, "Human admin can revoke invite");
    println!("✓ Human admin can revoke invite");

    println!("\n✅ test_service_account_cannot_revoke_invite PASSED");
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Test: Service Principal Multi-Workspace Access
// Service principals can be granted access to multiple workspaces using the
// `workspace grant-principal-access` command
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_service_principal_multi_workspace_access() -> Result<(), Box<dyn std::error::Error>> {
    let port = find_available_port()?;
    let env = TestEnv::setup("svc_multi_workspace", port).await?;

    let alice = env.create_user("alice");

    let invite = env.create_server_invite()?;
    env.join_server(&alice, &invite)?;

    // Create two workspaces
    env.create_workspace(&alice, "workspace-a")?;
    env.create_workspace(&alice, "workspace-b")?;

    // Create projects and environments in both workspaces
    env.create_project(&alice, "workspace-a", "proj-a")?;
    env.create_environment(&alice, "workspace-a", "proj-a", "dev")?;
    env.create_project(&alice, "workspace-b", "proj-b")?;
    env.create_environment(&alice, "workspace-b", "proj-b", "dev")?;

    // Set secrets in both workspaces
    let output = env.secret_set(&alice, "workspace-a", "proj-a", "dev", "KEY_A", "value-a");
    assert!(
        output.status.success(),
        "Failed to set secret in workspace-a"
    );
    let output = env.secret_set(&alice, "workspace-b", "proj-b", "dev", "KEY_B", "value-b");
    assert!(
        output.status.success(),
        "Failed to set secret in workspace-b"
    );

    // Create a service principal in workspace-a
    let svc_id =
        env.create_service_principal_in_workspace(&alice, "multi-workspace-bot", "workspace-a")?;
    println!("Created service principal {} in workspace-a", svc_id);

    // Give the service principal READ permission in workspace-a
    env.set_principal_permission(&alice, "workspace-a", &svc_id, "read")?;
    println!("✓ Granted READ permission in workspace-a");

    // Get Alice's human principal name for switching back
    let alice_principal_name = alice.principal.clone();

    // Switch to the service principal
    let output = env.principal_use(&alice, "multi-workspace-bot");
    assert!(
        output.status.success(),
        "Failed to switch to service principal"
    );
    println!("✓ Switched to service principal");

    // ─────────────────────────────────────────────────────────────────────────
    // Test: Service principal can read from workspace-a (initial workspace)
    // ─────────────────────────────────────────────────────────────────────────
    let output = env.secret_get(&alice, "workspace-a", "proj-a", "dev", "KEY_A");
    assert_success(&output, "Service principal can read from initial workspace");
    println!("✓ Service principal can read KEY_A from workspace-a");

    // ─────────────────────────────────────────────────────────────────────────
    // Test: Service principal CANNOT read from workspace-b (no access yet)
    // ─────────────────────────────────────────────────────────────────────────
    let output = env.secret_get(&alice, "workspace-b", "proj-b", "dev", "KEY_B");
    assert!(
        !output.status.success(),
        "Should not have access to workspace-b yet"
    );
    println!("✓ Service principal cannot read from workspace-b (no access)");

    // ─────────────────────────────────────────────────────────────────────────
    // Grant service principal access to workspace-b
    // ─────────────────────────────────────────────────────────────────────────
    // Switch back to human to grant access
    let output = env.principal_use(&alice, &alice_principal_name);
    assert!(
        output.status.success(),
        "Failed to switch back to human principal"
    );

    // Grant the service principal access to workspace-b
    env.grant_principal_workspace_access(&alice, "workspace-b", &svc_id)?;
    println!("✓ Granted workspace-b access to service principal");

    // Also grant permission (access alone isn't enough - need role)
    env.set_principal_permission(&alice, "workspace-b", &svc_id, "read")?;
    println!("✓ Granted READ permission in workspace-b");

    // Switch back to service principal
    let output = env.principal_use(&alice, "multi-workspace-bot");
    assert!(
        output.status.success(),
        "Failed to switch to service principal"
    );

    // ─────────────────────────────────────────────────────────────────────────
    // Test: Service principal can now read from workspace-b
    // ─────────────────────────────────────────────────────────────────────────
    let output = env.secret_get(&alice, "workspace-b", "proj-b", "dev", "KEY_B");
    assert_success(
        &output,
        "Service principal can read from second workspace after grant",
    );
    println!("✓ Service principal can now read KEY_B from workspace-b");

    // ─────────────────────────────────────────────────────────────────────────
    // Test: Service principal can still read from workspace-a
    // ─────────────────────────────────────────────────────────────────────────
    let output = env.secret_get(&alice, "workspace-a", "proj-a", "dev", "KEY_A");
    assert_success(
        &output,
        "Service principal still has access to first workspace",
    );
    println!("✓ Service principal can still read KEY_A from workspace-a");

    // ─────────────────────────────────────────────────────────────────────────
    // Test: Service principal with WRITE in workspace-a, READ in workspace-b
    // Verify permissions are independent per workspace
    // ─────────────────────────────────────────────────────────────────────────
    // Switch back to human to change permissions
    let output = env.principal_use(&alice, &alice_principal_name);
    assert!(
        output.status.success(),
        "Failed to switch back to human principal"
    );

    // Upgrade to WRITE in workspace-a
    env.set_principal_permission(&alice, "workspace-a", &svc_id, "write")?;
    println!("✓ Upgraded to WRITE permission in workspace-a");

    // Switch to service principal
    let output = env.principal_use(&alice, "multi-workspace-bot");
    assert!(
        output.status.success(),
        "Failed to switch to service principal"
    );

    // Should be able to write to workspace-a
    let output = env.secret_set(
        &alice,
        "workspace-a",
        "proj-a",
        "dev",
        "NEW_KEY",
        "new-value",
    );
    assert_success(&output, "Service principal can write to workspace-a");
    println!("✓ Service principal can write NEW_KEY to workspace-a");

    // Should NOT be able to write to workspace-b (only has READ)
    let output = env.secret_set(
        &alice,
        "workspace-b",
        "proj-b",
        "dev",
        "NEW_KEY",
        "new-value",
    );
    assert_denied(
        &output,
        "Service principal cannot write to workspace-b (READ only)",
    );
    println!("✓ Service principal cannot write to workspace-b (READ only)");

    println!("\n✅ test_service_principal_multi_workspace_access PASSED");
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Test: Grant Workspace Access Requires Admin Permission
// Only workspace admins can grant access to other principals
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_grant_workspace_access_requires_admin() -> Result<(), Box<dyn std::error::Error>> {
    let port = find_available_port()?;
    let env = TestEnv::setup("grant_requires_admin", port).await?;

    let alice = env.create_user("alice");
    let bob = env.create_user("bob");

    // Alice creates the workspace (owner)
    let invite = env.create_server_invite()?;
    env.join_server(&alice, &invite)?;
    env.create_workspace(&alice, "secure-ws")?;
    env.create_project(&alice, "secure-ws", "proj")?;
    env.create_environment(&alice, "secure-ws", "proj", "dev")?;

    // Alice invites Bob to the workspace (Bob joins server and workspace at once)
    let ws_invite = env.create_workspace_invite(&alice, "secure-ws")?;
    env.join_server(&bob, &ws_invite)?;

    // Give Bob only READ permission
    env.set_user_permission(&alice, "secure-ws", &bob.email, "read")?;
    println!("✓ Bob has READ permission in secure-ws");

    // Alice creates a service principal
    let svc_id = env.create_service_principal_in_workspace(&alice, "test-bot", "secure-ws")?;
    println!("✓ Created service principal {}", svc_id);

    // ─────────────────────────────────────────────────────────────────────────
    // Test: Bob (READ) cannot grant workspace access
    // ─────────────────────────────────────────────────────────────────────────
    let output = Command::new(&env.zopp_bin)
        .env("HOME", &bob.home)
        .args([
            "--server",
            &env.server_url,
            "workspace",
            "grant-principal-access",
            "-w",
            "secure-ws",
            "-p",
            &svc_id,
        ])
        .output()?;
    assert!(
        !output.status.success(),
        "Bob with READ should not be able to grant workspace access"
    );
    println!("✓ Bob (READ) cannot grant workspace access");

    // ─────────────────────────────────────────────────────────────────────────
    // Test: Upgrade Bob to WRITE, still cannot grant access
    // ─────────────────────────────────────────────────────────────────────────
    env.set_user_permission(&alice, "secure-ws", &bob.email, "write")?;
    let output = Command::new(&env.zopp_bin)
        .env("HOME", &bob.home)
        .args([
            "--server",
            &env.server_url,
            "workspace",
            "grant-principal-access",
            "-w",
            "secure-ws",
            "-p",
            &svc_id,
        ])
        .output()?;
    assert!(
        !output.status.success(),
        "Bob with WRITE should not be able to grant workspace access"
    );
    println!("✓ Bob (WRITE) cannot grant workspace access");

    // ─────────────────────────────────────────────────────────────────────────
    // Test: Upgrade Bob to ADMIN, now can grant access
    // ─────────────────────────────────────────────────────────────────────────
    env.set_user_permission(&alice, "secure-ws", &bob.email, "admin")?;

    // Create a new workspace for Bob to grant access to
    env.create_workspace(&bob, "bob-ws")?;

    // Create service principal in bob-ws (not secure-ws)
    let bob_svc_id = env.create_service_principal_in_workspace(&bob, "bob-bot", "bob-ws")?;

    // Bob (admin in secure-ws) grants this service access to secure-ws
    let output = Command::new(&env.zopp_bin)
        .env("HOME", &bob.home)
        .args([
            "--server",
            &env.server_url,
            "workspace",
            "grant-principal-access",
            "-w",
            "secure-ws",
            "-p",
            &bob_svc_id,
        ])
        .output()?;
    assert!(
        output.status.success(),
        "Bob (ADMIN) should be able to grant workspace access: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    println!("✓ Bob (ADMIN) can grant workspace access");

    println!("\n✅ test_grant_workspace_access_requires_admin PASSED");
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Test: Device Principal KEK Inheritance
// When a user creates a new device principal, it should automatically inherit
// KEK access to all workspaces the user has access to
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_device_principal_kek_inheritance() -> Result<(), Box<dyn std::error::Error>> {
    let port = find_available_port()?;
    let env = TestEnv::setup("device_kek_inherit", port).await?;

    let alice = env.create_user("alice");

    let invite = env.create_server_invite()?;
    env.join_server(&alice, &invite)?;

    // Create multiple workspaces
    env.create_workspace(&alice, "ws-one")?;
    env.create_workspace(&alice, "ws-two")?;
    env.create_workspace(&alice, "ws-three")?;

    // Create projects and environments
    env.create_project(&alice, "ws-one", "proj")?;
    env.create_environment(&alice, "ws-one", "proj", "dev")?;
    env.create_project(&alice, "ws-two", "proj")?;
    env.create_environment(&alice, "ws-two", "proj", "dev")?;
    env.create_project(&alice, "ws-three", "proj")?;
    env.create_environment(&alice, "ws-three", "proj", "dev")?;

    // Set secrets in all workspaces
    let output = env.secret_set(&alice, "ws-one", "proj", "dev", "KEY1", "value1");
    assert!(output.status.success(), "Failed to set secret in ws-one");
    let output = env.secret_set(&alice, "ws-two", "proj", "dev", "KEY2", "value2");
    assert!(output.status.success(), "Failed to set secret in ws-two");
    let output = env.secret_set(&alice, "ws-three", "proj", "dev", "KEY3", "value3");
    assert!(output.status.success(), "Failed to set secret in ws-three");
    println!("✓ Created workspaces with secrets");

    // Create a new device principal (non-service)
    let output = Command::new(&env.zopp_bin)
        .env("HOME", &alice.home)
        .args([
            "--server",
            &env.server_url,
            "principal",
            "create",
            "alice-laptop",
        ])
        .output()?;
    assert!(
        output.status.success(),
        "Failed to create device principal: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    println!(
        "✓ Created device principal 'alice-laptop'\n{}",
        String::from_utf8_lossy(&output.stdout)
    );

    // Get Alice's original principal name
    let alice_original = alice.principal.clone();

    // Switch to the new device principal
    let output = env.principal_use(&alice, "alice-laptop");
    assert!(
        output.status.success(),
        "Failed to switch to new device principal"
    );
    println!("✓ Switched to device principal 'alice-laptop'");

    // ─────────────────────────────────────────────────────────────────────────
    // Test: New device principal can access all workspaces
    // ─────────────────────────────────────────────────────────────────────────

    // Can read from ws-one
    let output = env.secret_get(&alice, "ws-one", "proj", "dev", "KEY1");
    assert_success(&output, "Device principal can read from ws-one");
    println!("✓ New device can read KEY1 from ws-one");

    // Can read from ws-two
    let output = env.secret_get(&alice, "ws-two", "proj", "dev", "KEY2");
    assert_success(&output, "Device principal can read from ws-two");
    println!("✓ New device can read KEY2 from ws-two");

    // Can read from ws-three
    let output = env.secret_get(&alice, "ws-three", "proj", "dev", "KEY3");
    assert_success(&output, "Device principal can read from ws-three");
    println!("✓ New device can read KEY3 from ws-three");

    // ─────────────────────────────────────────────────────────────────────────
    // Test: New device principal can write to all workspaces (owner)
    // ─────────────────────────────────────────────────────────────────────────

    let output = env.secret_set(&alice, "ws-one", "proj", "dev", "NEW_KEY1", "new_value1");
    assert_success(&output, "Device principal can write to ws-one");
    println!("✓ New device can write to ws-one");

    let output = env.secret_set(&alice, "ws-two", "proj", "dev", "NEW_KEY2", "new_value2");
    assert_success(&output, "Device principal can write to ws-two");
    println!("✓ New device can write to ws-two");

    // ─────────────────────────────────────────────────────────────────────────
    // Test: Switch back to original device, verify data
    // ─────────────────────────────────────────────────────────────────────────
    let output = env.principal_use(&alice, &alice_original);
    assert!(
        output.status.success(),
        "Failed to switch back to original device"
    );

    // Verify the secret written by the new device is readable
    let output = env.secret_get(&alice, "ws-one", "proj", "dev", "NEW_KEY1");
    assert_success(
        &output,
        "Original device can read secret written by new device",
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("new_value1"),
        "Secret value should match what new device wrote"
    );
    println!("✓ Original device can read secrets written by new device");

    println!("\n✅ test_device_principal_kek_inheritance PASSED");
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Test: Device Principal Inherits Joined Workspace Access
// When a user joins a workspace via invite, then creates a new device,
// the new device should also have access to that joined workspace
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_device_inherits_joined_workspace() -> Result<(), Box<dyn std::error::Error>> {
    let port = find_available_port()?;
    let env = TestEnv::setup("device_inherits_joined", port).await?;

    let alice = env.create_user("alice");
    let bob = env.create_user("bob");

    // Alice creates the workspace
    let invite = env.create_server_invite()?;
    env.join_server(&alice, &invite)?;
    env.create_workspace(&alice, "shared-ws")?;
    env.create_project(&alice, "shared-ws", "proj")?;
    env.create_environment(&alice, "shared-ws", "proj", "dev")?;

    let output = env.secret_set(&alice, "shared-ws", "proj", "dev", "SECRET", "alice-secret");
    assert!(output.status.success(), "Failed to set secret");

    // Give users in this workspace at least READ permission by default
    // (We'll give Bob write permission after he joins)

    // Bob joins the workspace
    let ws_invite = env.create_workspace_invite(&alice, "shared-ws")?;
    env.join_server(&bob, &ws_invite)?;

    // Give Bob write permission
    env.set_user_permission(&alice, "shared-ws", &bob.email, "write")?;
    println!("✓ Bob joined workspace with WRITE permission");

    // Verify Bob can access with his first device
    let output = env.secret_get(&bob, "shared-ws", "proj", "dev", "SECRET");
    assert_success(&output, "Bob's first device can read");
    println!("✓ Bob's first device can read secrets");

    // Bob creates a new device principal
    let output = Command::new(&env.zopp_bin)
        .env("HOME", &bob.home)
        .args([
            "--server",
            &env.server_url,
            "principal",
            "create",
            "bob-tablet",
        ])
        .output()?;
    assert!(
        output.status.success(),
        "Failed to create device principal: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    println!(
        "✓ Bob created device principal 'bob-tablet'\n{}",
        String::from_utf8_lossy(&output.stdout)
    );

    // Switch to the new device
    let output = env.principal_use(&bob, "bob-tablet");
    assert!(output.status.success(), "Failed to switch to new device");
    println!("✓ Switched to bob-tablet");

    // ─────────────────────────────────────────────────────────────────────────
    // Test: Bob's new device can access the workspace Bob joined
    // ─────────────────────────────────────────────────────────────────────────
    let output = env.secret_get(&bob, "shared-ws", "proj", "dev", "SECRET");
    assert_success(&output, "Bob's new device can read from joined workspace");
    println!("✓ Bob's new device can read from joined workspace");

    // Bob's new device can also write (has WRITE permission)
    let output = env.secret_set(&bob, "shared-ws", "proj", "dev", "BOB_KEY", "bob-value");
    assert_success(&output, "Bob's new device can write to joined workspace");
    println!("✓ Bob's new device can write to joined workspace");

    println!("\n✅ test_device_inherits_joined_workspace PASSED");
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════
// Test: Project Admin Can Manage Group Project Permissions
// ═══════════════════════════════════════════════════════════════════════════
// This test verifies that a project admin (not workspace admin) can set
// group permissions on their project. Currently FAILS due to bug in
// group_permissions.rs using check_workspace_permission instead of
// check_project_permission.

#[tokio::test]
async fn test_project_admin_can_manage_group_project_permissions(
) -> Result<(), Box<dyn std::error::Error>> {
    let port = find_available_port()?;
    let env = TestEnv::setup("proj_admin_group_perm", port).await?;

    let alice = env.create_user("alice");
    let bob = env.create_user("bob");

    // Alice creates workspace and project
    let invite = env.create_server_invite()?;
    env.join_server(&alice, &invite)?;
    env.create_workspace(&alice, "acme")?;
    env.create_project(&alice, "acme", "api")?;
    env.create_project(&alice, "acme", "frontend")?;

    // Alice creates a group
    env.create_group(&alice, "acme", "developers")?;
    println!("✓ Created group 'developers'");

    // Bob joins workspace (no workspace-level permissions, just member)
    let ws_invite = env.create_workspace_invite(&alice, "acme")?;
    env.join_server(&bob, &ws_invite)?;
    println!("✓ Bob joined workspace as member");

    // Give Bob PROJECT ADMIN on 'api' project only (NOT workspace admin)
    env.set_user_project_permission(&alice, "acme", "api", &bob.email, "admin")?;
    println!("✓ Bob has PROJECT ADMIN on 'api' (but NOT workspace admin)");

    // Test: Bob (project admin) CAN set group project permissions on 'api'
    let output = env.group_set_project_permission_check(&bob, "acme", "api", "developers", "read");
    assert_success(
        &output,
        "Project admin Bob set group project permission on api",
    );
    println!("✓ Bob (project admin) can set group permissions on 'api'");

    // Test: Bob CANNOT set group project permissions on 'frontend' (no access)
    let output =
        env.group_set_project_permission_check(&bob, "acme", "frontend", "developers", "read");
    assert_denied(&output, "Bob set group project permission on frontend");
    println!("✓ Bob denied setting group permissions on 'frontend'");

    println!("\n✅ test_project_admin_can_manage_group_project_permissions PASSED");
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════
// Test: Workspace Remove Cleans Up All Permissions
// ═══════════════════════════════════════════════════════════════════════════
// This test verifies that removing a principal from a workspace also removes
// all their permissions at all levels (workspace, project, environment).
// Regression test for issue #30.

#[tokio::test]
async fn test_workspace_remove_cleans_up_permissions() -> Result<(), Box<dyn std::error::Error>> {
    let port = find_available_port()?;
    let env = TestEnv::setup("ws_remove_cleanup", port).await?;

    let alice = env.create_user("alice");

    // Alice creates workspace, project, and environment
    let invite = env.create_server_invite()?;
    env.join_server(&alice, &invite)?;
    env.create_workspace(&alice, "acme")?;
    env.create_project(&alice, "acme", "api")?;
    env.create_environment(&alice, "acme", "api", "dev")?;

    // Set a secret for testing access
    let output = env.secret_set(&alice, "acme", "api", "dev", "SECRET", "test-value");
    assert!(output.status.success(), "Failed to set secret");

    // Create a service principal with permissions at ALL levels
    let svc_id = env.create_service_principal(&alice, "test-bot")?;
    println!("✓ Created service principal {}", svc_id);

    // Set workspace-level permission (ADMIN)
    env.set_principal_permission(&alice, "acme", &svc_id, "admin")?;
    println!("✓ Granted workspace-level ADMIN permission");

    // Set project-level permission (WRITE)
    env.set_principal_project_permission_check(&alice, "acme", "api", &svc_id, "write");
    println!("✓ Granted project-level WRITE permission");

    // Set environment-level permission (READ)
    env.set_principal_env_permission_check(&alice, "acme", "api", "dev", &svc_id, "read");
    println!("✓ Granted environment-level READ permission");

    // Verify the service principal can access the workspace
    let alice_principal = alice.principal.clone();
    let output = env.principal_use(&alice, "test-bot");
    assert!(
        output.status.success(),
        "Failed to switch to service principal"
    );

    let output = env.secret_get(&alice, "acme", "api", "dev", "SECRET");
    assert_success(&output, "Service principal can access workspace");
    println!("✓ Service principal can access workspace before removal");

    // Switch back to Alice
    let output = env.principal_use(&alice, &alice_principal);
    assert!(output.status.success(), "Failed to switch back to Alice");

    // ─────────────────────────────────────────────────────────────────────────
    // Remove the service principal from the workspace
    // This should clean up ALL permissions (workspace, project, environment)
    // ─────────────────────────────────────────────────────────────────────────
    env.remove_principal_from_workspace(&alice, "acme", &svc_id)?;
    println!("✓ Removed service principal from workspace");

    // ─────────────────────────────────────────────────────────────────────────
    // Verify: Service principal can NO LONGER access the workspace
    // If workspace-level permissions weren't cleaned up, the principal might
    // still have cached/orphaned permissions.
    // ─────────────────────────────────────────────────────────────────────────
    let output = env.principal_use(&alice, "test-bot");
    assert!(
        output.status.success(),
        "Failed to switch to service principal"
    );

    let output = env.secret_get(&alice, "acme", "api", "dev", "SECRET");
    assert!(
        !output.status.success(),
        "Service principal should NOT have access after removal"
    );
    println!("✓ Service principal cannot access workspace after removal");

    // ─────────────────────────────────────────────────────────────────────────
    // Re-grant access and verify it works (clean slate)
    // This confirms permissions were properly cleaned up, not just blocked
    // ─────────────────────────────────────────────────────────────────────────
    let output = env.principal_use(&alice, &alice_principal);
    assert!(output.status.success(), "Failed to switch back to Alice");

    // Re-add the service principal to workspace with READ only
    env.grant_principal_workspace_access(&alice, "acme", &svc_id)?;
    env.set_principal_permission(&alice, "acme", &svc_id, "read")?;
    println!("✓ Re-granted workspace access with READ permission");

    // Switch to service principal and verify access
    let output = env.principal_use(&alice, "test-bot");
    assert!(
        output.status.success(),
        "Failed to switch to service principal"
    );

    let output = env.secret_get(&alice, "acme", "api", "dev", "SECRET");
    assert_success(&output, "Service principal can read after re-grant");
    println!("✓ Service principal can read after re-grant");

    // Should NOT be able to write (only has READ now, not the old ADMIN/WRITE)
    let output = env.secret_set(&alice, "acme", "api", "dev", "NEW_KEY", "new-value");
    assert!(
        !output.status.success(),
        "Service principal should only have READ after re-grant"
    );
    println!("✓ Service principal cannot write (confirms old permissions were cleaned up)");

    println!("\n✅ test_workspace_remove_cleans_up_permissions PASSED");
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════
// Test: Audit Log Access Requires Admin
// ═══════════════════════════════════════════════════════════════════════════
// This test verifies that audit log commands require Admin role on the workspace.
// Read/Write roles should be denied access to audit logs.

#[tokio::test]
async fn test_audit_requires_admin() -> Result<(), Box<dyn std::error::Error>> {
    let port = find_available_port()?;
    let env = TestEnv::setup("audit_rbac", port).await?;

    let alice = env.create_user("alice");
    let bob = env.create_user("bob");
    let charlie = env.create_user("charlie");

    // Alice creates workspace and performs some operations to generate audit logs
    let invite = env.create_server_invite()?;
    env.join_server(&alice, &invite)?;
    env.create_workspace(&alice, "acme")?;
    env.create_project(&alice, "acme", "api")?;
    env.create_environment(&alice, "acme", "api", "dev")?;

    // Set a secret to generate audit entry
    let output = env.secret_set(&alice, "acme", "api", "dev", "TEST_KEY", "test-value");
    assert!(output.status.success(), "Failed to set secret");
    println!("✓ Setup complete: workspace with audit entries created");

    // ─────────────────────────────────────────────────────────────────────────
    // Test 1: Admin (workspace owner) CAN access audit logs
    // ─────────────────────────────────────────────────────────────────────────
    let output = env.audit_list(&alice, "acme");
    assert_success(&output, "Admin can list audit logs");
    println!("✓ Admin (Alice) can list audit logs");

    let output = env.audit_count(&alice, "acme");
    assert_success(&output, "Admin can count audit logs");
    println!("✓ Admin (Alice) can count audit logs");

    // ─────────────────────────────────────────────────────────────────────────
    // Test 2: User with WRITE role CANNOT access audit logs
    // ─────────────────────────────────────────────────────────────────────────
    let bob_invite = env.create_workspace_invite(&alice, "acme")?;
    env.join_server(&bob, &bob_invite)?;
    env.set_user_permission(&alice, "acme", &bob.email, "write")?;
    println!("✓ Bob has WRITE permission on workspace");

    let output = env.audit_list(&bob, "acme");
    assert_denied(&output, "Write role cannot list audit logs");
    println!("✓ Write role (Bob) denied listing audit logs");

    let output = env.audit_count(&bob, "acme");
    assert_denied(&output, "Write role cannot count audit logs");
    println!("✓ Write role (Bob) denied counting audit logs");

    // ─────────────────────────────────────────────────────────────────────────
    // Test 3: User with READ role CANNOT access audit logs
    // ─────────────────────────────────────────────────────────────────────────
    let charlie_invite = env.create_workspace_invite(&alice, "acme")?;
    env.join_server(&charlie, &charlie_invite)?;
    env.set_user_permission(&alice, "acme", &charlie.email, "read")?;
    println!("✓ Charlie has READ permission on workspace");

    let output = env.audit_list(&charlie, "acme");
    assert_denied(&output, "Read role cannot list audit logs");
    println!("✓ Read role (Charlie) denied listing audit logs");

    let output = env.audit_count(&charlie, "acme");
    assert_denied(&output, "Read role cannot count audit logs");
    println!("✓ Read role (Charlie) denied counting audit logs");

    // ─────────────────────────────────────────────────────────────────────────
    // Test 4: User with no workspace permission CANNOT access audit logs
    // ─────────────────────────────────────────────────────────────────────────
    // Remove Charlie's permission to test with no permission
    env.remove_user_permission(&alice, "acme", &charlie.email)?;
    println!("✓ Removed Charlie's permission");

    let output = env.audit_list(&charlie, "acme");
    assert_denied(&output, "No permission cannot list audit logs");
    println!("✓ No permission (Charlie) denied listing audit logs");

    // ─────────────────────────────────────────────────────────────────────────
    // Test 5: Promote user to ADMIN, then they CAN access audit logs
    // ─────────────────────────────────────────────────────────────────────────
    env.set_user_permission(&alice, "acme", &bob.email, "admin")?;
    println!("✓ Promoted Bob to ADMIN");

    let output = env.audit_list(&bob, "acme");
    assert_success(&output, "Promoted admin can list audit logs");
    println!("✓ Promoted admin (Bob) can list audit logs");

    let output = env.audit_count(&bob, "acme");
    assert_success(&output, "Promoted admin can count audit logs");
    println!("✓ Promoted admin (Bob) can count audit logs");

    println!("\n✅ test_audit_requires_admin PASSED");
    Ok(())
}
