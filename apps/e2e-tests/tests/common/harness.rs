//! Test harness for e2e tests with backend matrix support.
//!
//! This module provides shared test utilities. Not all methods are used by all tests,
//! so we allow dead_code to prevent warnings when compiling individual test files.

#![allow(dead_code)]

use std::fs::{self, File};
use std::io::Read as _;
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Output, Stdio};
use std::time::Duration;
use tokio::time::sleep;

use super::graceful_shutdown;

// ═══════════════════════════════════════════════════════════════════════════
// Backend Configuration
// ═══════════════════════════════════════════════════════════════════════════

/// Storage backend configuration
#[derive(Debug, Clone)]
pub enum StorageBackend {
    /// SQLite storage (path will be auto-generated)
    Sqlite,
    /// PostgreSQL storage (requires DATABASE_URL or running postgres on 5433)
    Postgres,
}

/// Event bus backend configuration
#[derive(Debug, Clone)]
pub enum EventsBackend {
    /// In-memory event bus (single replica only)
    Memory,
    /// PostgreSQL LISTEN/NOTIFY event bus (requires postgres)
    Postgres,
}

/// Full backend configuration for a test
#[derive(Debug, Clone)]
pub struct BackendConfig {
    pub storage: StorageBackend,
    pub events: EventsBackend,
}

impl BackendConfig {
    /// SQLite storage + Memory events (default, no external deps)
    pub fn sqlite_memory() -> Self {
        Self {
            storage: StorageBackend::Sqlite,
            events: EventsBackend::Memory,
        }
    }

    /// SQLite storage + PostgreSQL events
    pub fn sqlite_pg_events() -> Self {
        Self {
            storage: StorageBackend::Sqlite,
            events: EventsBackend::Postgres,
        }
    }

    /// PostgreSQL storage + Memory events
    pub fn postgres_memory() -> Self {
        Self {
            storage: StorageBackend::Postgres,
            events: EventsBackend::Memory,
        }
    }

    /// PostgreSQL storage + PostgreSQL events (full postgres)
    pub fn postgres_postgres() -> Self {
        Self {
            storage: StorageBackend::Postgres,
            events: EventsBackend::Postgres,
        }
    }

    /// Check if this config requires PostgreSQL
    pub fn requires_postgres(&self) -> bool {
        matches!(self.storage, StorageBackend::Postgres)
            || matches!(self.events, EventsBackend::Postgres)
    }

    /// Human-readable name for test output
    pub fn name(&self) -> &'static str {
        match (&self.storage, &self.events) {
            (StorageBackend::Sqlite, EventsBackend::Memory) => "sqlite+memory",
            (StorageBackend::Sqlite, EventsBackend::Postgres) => "sqlite+pg_events",
            (StorageBackend::Postgres, EventsBackend::Memory) => "postgres+memory",
            (StorageBackend::Postgres, EventsBackend::Postgres) => "postgres+postgres",
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Test Harness
// ═══════════════════════════════════════════════════════════════════════════

/// Test harness that manages server lifecycle and provides test utilities
pub struct TestHarness {
    /// Server URL for CLI connections
    pub server_url: String,
    /// Backend configuration
    pub config: BackendConfig,
    /// Test directory (temp)
    pub test_dir: PathBuf,
    /// Path to zopp CLI binary
    pub zopp_bin: PathBuf,
    /// Path to zopp-server binary
    pub zopp_server_bin: PathBuf,
    /// Server process
    server_process: Option<Child>,
    /// Server port
    port: u16,
    /// Health port
    health_port: u16,
    /// Database URL for server
    database_url: String,
    /// Events database URL (if different from storage)
    events_database_url: Option<String>,
    /// PostgreSQL database name (for cleanup)
    pg_db_name: Option<String>,
    /// PostgreSQL events database name (for cleanup)
    pg_events_db_name: Option<String>,
    /// Server stdout log file path (for diagnostics on failure)
    server_stdout_path: PathBuf,
    /// Server stderr log file path (for diagnostics on failure)
    server_stderr_path: PathBuf,
}

impl TestHarness {
    /// Create a new test harness with the specified backend configuration
    pub async fn new(
        test_name: &str,
        config: BackendConfig,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        // Check postgres availability if required
        if config.requires_postgres() {
            check_postgres_available()?;
        }

        // Get binary paths from shared function
        let (zopp_server_bin, zopp_bin, _) = super::get_binary_paths()?;

        // Create test directory
        let test_id = std::process::id();
        let config_name = config.name();
        let test_dir = std::env::temp_dir().join(format!(
            "zopp-e2e-{}-{}-{}",
            test_name, config_name, test_id
        ));
        if test_dir.exists() {
            fs::remove_dir_all(&test_dir)?;
        }
        fs::create_dir_all(&test_dir)?;

        // Find available ports
        let port = find_available_port()?;
        let health_port = find_available_port()?;

        // Setup database (include config name to avoid collisions when tests run in parallel)
        let full_test_name = format!("{}_{}", test_name, config.name());
        let (database_url, pg_db_name) =
            setup_database(&config.storage, &full_test_name, test_id).await?;

        // Setup events database if needed (separate from storage)
        let (events_database_url, pg_events_db_name) = match &config.events {
            EventsBackend::Memory => (None, None),
            EventsBackend::Postgres => {
                // If storage is also postgres, reuse the same database
                // Otherwise create a separate events database
                match &config.storage {
                    StorageBackend::Postgres => (None, None), // Reuse storage DB
                    StorageBackend::Sqlite => {
                        let events_db_name = format!(
                            "zopp_events_{}_{}_{}",
                            full_test_name.replace(['-', '+'], "_"),
                            test_id,
                            std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap()
                                .as_millis()
                                % 10000
                        );
                        let events_url = create_postgres_db(&events_db_name).await?;
                        (Some(events_url), Some(events_db_name))
                    }
                }
            }
        };

        // Create log file paths for server output (for diagnostics on failure)
        let server_stdout_path = test_dir.join("server_stdout.log");
        let server_stderr_path = test_dir.join("server_stderr.log");

        let mut harness = Self {
            server_url: format!("http://127.0.0.1:{}", port),
            config,
            test_dir,
            zopp_bin,
            zopp_server_bin,
            server_process: None,
            port,
            health_port,
            database_url,
            events_database_url,
            pg_db_name,
            pg_events_db_name,
            server_stdout_path,
            server_stderr_path,
        };

        // Start the server
        harness.start_server().await?;

        Ok(harness)
    }

    /// Start the server process with retry on port conflicts
    async fn start_server(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        const MAX_PORT_RETRIES: u32 = 5;

        for attempt in 0..MAX_PORT_RETRIES {
            match self.try_start_server().await {
                Ok(()) => return Ok(()),
                Err(e) => {
                    let err_str = e.to_string();
                    let is_port_conflict =
                        err_str.contains("Address already in use") || err_str.contains("AddrInUse");

                    // Only retry on port conflicts and if we have retries left
                    if is_port_conflict && attempt + 1 < MAX_PORT_RETRIES {
                        // Pick new ports and retry
                        self.port = find_available_port()?;
                        self.health_port = find_available_port()?;
                        self.server_url = format!("http://127.0.0.1:{}", self.port);
                        continue;
                    }

                    // Not a port conflict or max retries exceeded - propagate error
                    return Err(e);
                }
            }
        }

        Err("Failed to start server after max retries".into())
    }

    /// Attempt to start the server once
    async fn try_start_server(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let server_addr = format!("0.0.0.0:{}", self.port);
        let health_addr = format!("0.0.0.0:{}", self.health_port);

        // Create files to capture server output for diagnostics
        let stdout_file = File::create(&self.server_stdout_path)?;
        let stderr_file = File::create(&self.server_stderr_path)?;

        let mut cmd = Command::new(&self.zopp_server_bin);
        cmd.env("DATABASE_URL", &self.database_url).args([
            "serve",
            "--addr",
            &server_addr,
            "--health-addr",
            &health_addr,
        ]);

        // Configure events backend
        match &self.config.events {
            EventsBackend::Memory => {
                cmd.args(["--events-backend", "memory"]);
            }
            EventsBackend::Postgres => {
                cmd.args(["--events-backend", "postgres"]);
                // Use separate events DB URL if we have one, otherwise server will use DATABASE_URL
                if let Some(ref events_url) = self.events_database_url {
                    cmd.args(["--events-database-url", events_url]);
                }
            }
        }

        cmd.stdout(Stdio::from(stdout_file))
            .stderr(Stdio::from(stderr_file));

        let server = cmd.spawn()?;
        self.server_process = Some(server);

        // Wait for server to be ready using the /readyz endpoint
        // Timeout is configurable via ZOPP_E2E_SERVER_TIMEOUT_SECS (default: 30s for CI reliability)
        let timeout_secs: u64 = std::env::var("ZOPP_E2E_SERVER_TIMEOUT_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(30);

        let readiness_url = format!("http://127.0.0.1:{}/readyz", self.health_port);
        let client = reqwest::Client::new();

        // Use exponential backoff: start at 100ms, double each time, cap at 2s
        let mut delay_ms: u64 = 100;
        let max_delay_ms: u64 = 2000;
        let start = std::time::Instant::now();

        loop {
            sleep(Duration::from_millis(delay_ms)).await;

            // Check if server process exited early (e.g., port conflict)
            if let Some(ref mut server) = self.server_process {
                if let Ok(Some(_status)) = server.try_wait() {
                    // Server exited - read stderr to determine cause
                    let stderr = self.read_server_log(&self.server_stderr_path.clone());
                    let stdout = self.read_server_log(&self.server_stdout_path.clone());

                    return Err(format!(
                        "Server exited unexpectedly\n\
                         Server stdout:\n{}\n\
                         Server stderr:\n{}",
                        stdout.unwrap_or_else(|e| format!("<failed to read: {}>", e)),
                        stderr.unwrap_or_else(|e| format!("<failed to read: {}>", e))
                    )
                    .into());
                }
            }

            if let Ok(resp) = client.get(&readiness_url).send().await {
                if resp.status().is_success() {
                    return Ok(());
                }
            }

            let elapsed = start.elapsed();
            if elapsed.as_secs() >= timeout_secs {
                // Shutdown server and collect diagnostics
                if let Some(ref mut server) = self.server_process {
                    graceful_shutdown(server);
                }

                // Read server output for diagnostics
                let stdout = self.read_server_log(&self.server_stdout_path.clone());
                let stderr = self.read_server_log(&self.server_stderr_path.clone());

                return Err(format!(
                    "Server failed to become ready within {} seconds\n\
                     Server stdout:\n{}\n\
                     Server stderr:\n{}",
                    timeout_secs,
                    stdout.unwrap_or_else(|e| format!("<failed to read: {}>", e)),
                    stderr.unwrap_or_else(|e| format!("<failed to read: {}>", e))
                )
                .into());
            }

            // Exponential backoff with cap
            delay_ms = (delay_ms * 2).min(max_delay_ms);
        }
    }

    /// Read server log file contents (last 100 lines max)
    fn read_server_log(&self, path: &PathBuf) -> Result<String, std::io::Error> {
        let mut file = File::open(path)?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;

        // Return last 100 lines to avoid overwhelming output
        let lines: Vec<&str> = contents.lines().collect();
        if lines.len() > 100 {
            Ok(format!(
                "... ({} lines truncated) ...\n{}",
                lines.len() - 100,
                lines[lines.len() - 100..].join("\n")
            ))
        } else {
            Ok(contents)
        }
    }

    /// Create a server invite token
    pub fn create_server_invite(&self) -> Result<String, Box<dyn std::error::Error>> {
        let output = Command::new(&self.zopp_server_bin)
            .env("DATABASE_URL", &self.database_url)
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

    /// Create a test user with isolated HOME directory
    pub fn create_user(&self, name: &str) -> TestUser {
        let home_dir = self.test_dir.join(name);
        fs::create_dir_all(&home_dir).expect("Failed to create user home dir");

        TestUser {
            name: name.to_string(),
            home_dir,
            zopp_bin: self.zopp_bin.clone(),
            server_url: self.server_url.clone(),
        }
    }

    /// Create a zopp.toml file in the test directory
    pub fn create_zopp_toml(
        &self,
        workspace: &str,
        project: &str,
        environment: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let content = format!(
            "[defaults]\nworkspace = \"{}\"\nproject = \"{}\"\nenvironment = \"{}\"\n",
            workspace, project, environment
        );
        fs::write(self.test_dir.join("zopp.toml"), content)?;
        Ok(())
    }

    /// Get the test directory path
    pub fn test_dir(&self) -> &PathBuf {
        &self.test_dir
    }
}

impl Drop for TestHarness {
    fn drop(&mut self) {
        // Stop the server
        if let Some(ref mut server) = self.server_process {
            graceful_shutdown(server);
        }

        // Cleanup PostgreSQL databases if created
        if let Some(ref db_name) = self.pg_db_name {
            cleanup_postgres_db(db_name);
        }
        if let Some(ref db_name) = self.pg_events_db_name {
            cleanup_postgres_db(db_name);
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Test User
// ═══════════════════════════════════════════════════════════════════════════

/// Represents a test user with isolated configuration
pub struct TestUser {
    name: String,
    pub home_dir: PathBuf,
    pub zopp_bin: PathBuf,
    pub server_url: String,
}

impl TestUser {
    /// Get the user's email (derived from name)
    pub fn email(&self) -> String {
        format!("{}@example.com", self.name)
    }

    /// Get the user's principal name (derived from name)
    pub fn principal(&self) -> String {
        format!("{}-device", self.name)
    }

    /// Execute a zopp CLI command and return raw Output
    pub fn raw_exec(&self, args: &[&str]) -> Output {
        Command::new(&self.zopp_bin)
            .env("HOME", &self.home_dir)
            .args(["--server", &self.server_url, "--use-file-storage"])
            .args(args)
            .output()
            .expect("Failed to execute command")
    }

    /// Execute a zopp CLI command as this user
    pub fn exec(&self, args: &[&str]) -> CommandResult {
        let output = Command::new(&self.zopp_bin)
            .env("HOME", &self.home_dir)
            .args(["--server", &self.server_url, "--use-file-storage"])
            .args(args)
            .output()
            .expect("Failed to execute command");

        CommandResult { output }
    }

    /// Execute a zopp CLI command in a specific directory
    pub fn exec_in(&self, dir: &PathBuf, args: &[&str]) -> CommandResult {
        let output = Command::new(&self.zopp_bin)
            .env("HOME", &self.home_dir)
            .current_dir(dir)
            .args(["--server", &self.server_url, "--use-file-storage"])
            .args(args)
            .output()
            .expect("Failed to execute command");

        CommandResult { output }
    }

    /// Execute a zopp CLI command with additional environment variables
    pub fn exec_with_env(&self, args: &[&str], env_vars: &[(&str, &str)]) -> CommandResult {
        let mut cmd = Command::new(&self.zopp_bin);
        cmd.env("HOME", &self.home_dir)
            .args(["--server", &self.server_url, "--use-file-storage"])
            .args(args);
        for (key, value) in env_vars {
            cmd.env(key, value);
        }
        let output = cmd.output().expect("Failed to execute command");
        CommandResult { output }
    }

    /// Join the server with an invite
    pub fn join(
        &self,
        invite: &str,
        email: &str,
        principal: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let result = self.exec(&["join", invite, email, "--principal", principal]);
        result.success_or_err("join")
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Command Result
// ═══════════════════════════════════════════════════════════════════════════

/// Result of a CLI command execution
pub struct CommandResult {
    output: Output,
}

impl CommandResult {
    /// Check if command succeeded and return stdout
    pub fn success(self) -> Result<String, Box<dyn std::error::Error>> {
        if !self.output.status.success() {
            return Err(format!(
                "Command failed:\nstdout: {}\nstderr: {}",
                String::from_utf8_lossy(&self.output.stdout),
                String::from_utf8_lossy(&self.output.stderr)
            )
            .into());
        }
        Ok(String::from_utf8_lossy(&self.output.stdout)
            .trim()
            .to_string())
    }

    /// Check if command succeeded, return error with context
    pub fn success_or_err(self, context: &str) -> Result<(), Box<dyn std::error::Error>> {
        if !self.output.status.success() {
            return Err(format!(
                "{} failed:\nstdout: {}\nstderr: {}",
                context,
                String::from_utf8_lossy(&self.output.stdout),
                String::from_utf8_lossy(&self.output.stderr)
            )
            .into());
        }
        Ok(())
    }

    /// Get stdout as string
    pub fn stdout(&self) -> String {
        String::from_utf8_lossy(&self.output.stdout)
            .trim()
            .to_string()
    }

    /// Get stderr as string
    pub fn stderr(&self) -> String {
        String::from_utf8_lossy(&self.output.stderr)
            .trim()
            .to_string()
    }

    /// Check if the command failed (for negative tests)
    pub fn failed(&self) -> bool {
        !self.output.status.success()
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Helper Functions
// ═══════════════════════════════════════════════════════════════════════════

fn find_available_port() -> Result<u16, Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    drop(listener);
    Ok(port)
}

/// Get postgres connection URL
fn postgres_url(db_name: &str) -> String {
    std::env::var("TEST_POSTGRES_URL")
        .unwrap_or_else(|_| format!("postgres://postgres:postgres@localhost:5433/{}", db_name))
}

/// Get postgres admin URL (connects to 'postgres' database)
fn postgres_admin_url() -> String {
    std::env::var("TEST_POSTGRES_ADMIN_URL")
        .unwrap_or_else(|_| "postgres://postgres:postgres@localhost:5433/postgres".to_string())
}

/// Check if PostgreSQL is available
fn check_postgres_available() -> Result<(), Box<dyn std::error::Error>> {
    // Check if SKIP_POSTGRES_TESTS is set
    if std::env::var("SKIP_POSTGRES_TESTS").is_ok() {
        return Err("PostgreSQL tests skipped (SKIP_POSTGRES_TESTS=1)".into());
    }

    // Try to connect to postgres
    let admin_url = postgres_admin_url();

    // Use a simple TCP check first
    let host_port = admin_url
        .strip_prefix("postgres://")
        .and_then(|s| s.split('/').next())
        .and_then(|s| s.split('@').next_back())
        .expect("Failed to parse host:port from TEST_POSTGRES_ADMIN_URL - expected postgres://user:pass@host:port/db format");

    if TcpStream::connect(host_port).is_err() {
        return Err(format!(
            "PostgreSQL not available at {}. Either:\n\
             1. Start PostgreSQL: docker run --name zopp-test-pg -e POSTGRES_PASSWORD=postgres -p 5433:5432 -d postgres:16\n\
             2. Set SKIP_POSTGRES_TESTS=1 to skip PostgreSQL tests",
            host_port
        ).into());
    }

    Ok(())
}

/// Setup database based on storage backend
async fn setup_database(
    storage: &StorageBackend,
    test_name: &str,
    test_id: u32,
) -> Result<(String, Option<String>), Box<dyn std::error::Error>> {
    match storage {
        StorageBackend::Sqlite => {
            let db_path =
                std::env::temp_dir().join(format!("zopp-test-{}-{}.db", test_name, test_id));
            let db_url = format!("sqlite://{}?mode=rwc", db_path.display());
            Ok((db_url, None))
        }
        StorageBackend::Postgres => {
            let db_name = format!(
                "zopp_test_{}_{}",
                test_name.replace(['-', '+'], "_"),
                test_id
            );
            let db_url = create_postgres_db(&db_name).await?;
            Ok((db_url, Some(db_name)))
        }
    }
}

/// Create a PostgreSQL database and return its URL
async fn create_postgres_db(db_name: &str) -> Result<String, Box<dyn std::error::Error>> {
    use sqlx::postgres::PgConnection;
    use sqlx::{Connection, Executor};

    let admin_url = postgres_admin_url();
    let mut conn = PgConnection::connect(&admin_url).await?;

    // Drop if exists (cleanup from previous failed runs)
    let _ = conn
        .execute(format!("DROP DATABASE IF EXISTS {}", db_name).as_str())
        .await;

    // Create database
    conn.execute(format!("CREATE DATABASE {}", db_name).as_str())
        .await?;
    drop(conn);

    Ok(postgres_url(db_name))
}

/// Cleanup PostgreSQL database
fn cleanup_postgres_db(db_name: &str) {
    // Run cleanup synchronously in drop
    let admin_url = postgres_admin_url();
    let _ = std::process::Command::new("psql")
        .args([
            &admin_url,
            "-c",
            &format!("DROP DATABASE IF EXISTS {}", db_name),
        ])
        .output();
}

// ═══════════════════════════════════════════════════════════════════════════
// Test Generation Macro
// ═══════════════════════════════════════════════════════════════════════════

/// Generate tests for all backend combinations
///
/// Usage:
/// ```ignore
/// backend_test!(my_test, run_my_test);
///
/// async fn run_my_test(config: BackendConfig) -> Result<(), Box<dyn std::error::Error>> {
///     let harness = TestHarness::new("my_test", config).await?;
///     // ... test code
///     Ok(())
/// }
/// ```
#[macro_export]
macro_rules! backend_test {
    ($test_name:ident, $test_fn:ident) => {
        paste::paste! {
            #[tokio::test]
            async fn [<$test_name _sqlite_memory>]() -> Result<(), Box<dyn std::error::Error>> {
                $test_fn($crate::common::harness::BackendConfig::sqlite_memory()).await
            }

            #[tokio::test]
            async fn [<$test_name _sqlite_pg_events>]() -> Result<(), Box<dyn std::error::Error>> {
                let config = $crate::common::harness::BackendConfig::sqlite_pg_events();
                if config.requires_postgres() && std::env::var("SKIP_POSTGRES_TESTS").is_ok() {
                    eprintln!("Skipping {} (SKIP_POSTGRES_TESTS=1)", stringify!([<$test_name _sqlite_pg_events>]));
                    return Ok(());
                }
                $test_fn(config).await
            }

            #[tokio::test]
            async fn [<$test_name _postgres_memory>]() -> Result<(), Box<dyn std::error::Error>> {
                let config = $crate::common::harness::BackendConfig::postgres_memory();
                if config.requires_postgres() && std::env::var("SKIP_POSTGRES_TESTS").is_ok() {
                    eprintln!("Skipping {} (SKIP_POSTGRES_TESTS=1)", stringify!([<$test_name _postgres_memory>]));
                    return Ok(());
                }
                $test_fn(config).await
            }

            #[tokio::test]
            async fn [<$test_name _postgres_postgres>]() -> Result<(), Box<dyn std::error::Error>> {
                let config = $crate::common::harness::BackendConfig::postgres_postgres();
                if config.requires_postgres() && std::env::var("SKIP_POSTGRES_TESTS").is_ok() {
                    eprintln!("Skipping {} (SKIP_POSTGRES_TESTS=1)", stringify!([<$test_name _postgres_postgres>]));
                    return Ok(());
                }
                $test_fn(config).await
            }
        }
    };
}
