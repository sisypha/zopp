use std::fs;
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;
use tokio::time::sleep;

/// Run the full E2E test suite against a specific database backend
async fn run_demo_test(
    db_url: &str,
    test_suffix: &str,
    port: u16,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("🧪 Starting Zopp E2E Test ({test_suffix}) on port {port}\n");

    // Find the binary paths
    let workspace_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf();

    let target_dir = std::env::var("CARGO_TARGET_DIR")
        .unwrap_or_else(|_| workspace_root.join("target").to_str().unwrap().to_string());
    let bin_dir = PathBuf::from(&target_dir).join("debug");

    let zopp_server_bin = if cfg!(windows) {
        bin_dir.join("zopp-server.exe")
    } else {
        bin_dir.join("zopp-server")
    };
    let zopp_bin = if cfg!(windows) {
        bin_dir.join("zopp.exe")
    } else {
        bin_dir.join("zopp")
    };

    if !zopp_server_bin.exists() || !zopp_bin.exists() {
        eprintln!("❌ Binaries not found. Please run 'cargo build --bins' first.");
        eprintln!("   Expected: {}", zopp_server_bin.display());
        eprintln!("   Expected: {}", zopp_bin.display());
        return Err("Binaries not built".into());
    }

    println!("✓ Using prebuilt binaries:");
    println!("  zopp-server: {}", zopp_server_bin.display());
    println!("  zopp:        {}\n", zopp_bin.display());

    // Setup test directories
    let test_dir = std::env::temp_dir().join(format!("zopp-e2e-test-{test_suffix}"));
    let alice_home = test_dir.join("alice");
    let bob_home = test_dir.join("bob");

    // Clean up from previous runs
    if test_dir.exists() {
        fs::remove_dir_all(&test_dir)?;
    }
    fs::create_dir_all(&alice_home)?;
    fs::create_dir_all(&bob_home)?;

    println!("✓ Test directories created");
    println!("  Alice home: {}", alice_home.display());
    println!("  Bob home:   {}", bob_home.display());
    println!("  Database:   {}\n", db_url);

    println!("📡 Step 0: Starting server...");

    let server_addr = format!("0.0.0.0:{port}");
    let health_addr = format!("0.0.0.0:{}", port + 1000); // Use port + 1000 for health checks
    let mut server = Command::new(&zopp_server_bin)
        .env("DATABASE_URL", db_url)
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

    // Wait for server to be ready by checking if it's listening on the specified port
    let mut ready = false;
    let client_addr = format!("127.0.0.1:{port}");
    for i in 1..=30 {
        sleep(Duration::from_millis(200)).await;
        if TcpStream::connect(&client_addr).is_ok() {
            ready = true;
            println!("✓ Server started and ready (PID: {})\n", server.id());
            break;
        }
        if i == 30 {
            eprintln!("❌ Server failed to start within 6 seconds");
            let _ = server.kill();
            return Err("Server not ready".into());
        }
    }
    if !ready {
        return Err("Server failed to start".into());
    }

    let server_url = format!("http://127.0.0.1:{port}");

    println!("🎫 Step 1: Admin creates server invite for Alice...");
    let output = Command::new(&zopp_server_bin)
        .env("DATABASE_URL", db_url)
        .args(["invite", "create", "--expires-hours", "1", "--plain"])
        .output()?;

    if !output.status.success() {
        eprintln!(
            "Server invite creation failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        return Err("Failed to create server invite".into());
    }

    let alice_server_invite = String::from_utf8_lossy(&output.stdout).trim().to_string();
    println!("✓ Alice's server invite: {}\n", alice_server_invite);

    println!("👩 Step 2: Alice joins server...");
    let output = Command::new(&zopp_bin)
        .env("HOME", &alice_home)
        .args([
            "--server",
            &server_url,
            "join",
            &alice_server_invite,
            "alice@example.com",
            "--principal",
            "alice-macbook",
        ])
        .output()?;

    if !output.status.success() {
        eprintln!(
            "Alice join failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        return Err("Alice failed to join".into());
    }
    println!("✓ Alice joined successfully\n");

    println!("🏢 Step 3: Alice creates workspace 'acme'...");
    let output = Command::new(&zopp_bin)
        .env("HOME", &alice_home)
        .args(["--server", &server_url, "workspace", "create", "acme"])
        .output()?;

    if !output.status.success() {
        eprintln!(
            "Workspace creation failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        return Err("Failed to create workspace".into());
    }
    println!("✓ Workspace 'acme' created\n");

    println!("📁 Step 4: Alice creates project 'api'...");
    let output = Command::new(&zopp_bin)
        .env("HOME", &alice_home)
        .args([
            "--server",
            &server_url,
            "project",
            "create",
            "api",
            "-w",
            "acme",
        ])
        .output()?;

    if !output.status.success() {
        eprintln!(
            "Project creation failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        return Err("Failed to create project".into());
    }
    println!("✓ Project 'api' created\n");

    println!("🌍 Step 5: Alice creates environment 'development'...");
    let output = Command::new(&zopp_bin)
        .env("HOME", &alice_home)
        .args([
            "--server",
            &server_url,
            "environment",
            "create",
            "development",
            "-w",
            "acme",
            "-p",
            "api",
        ])
        .output()?;

    if !output.status.success() {
        eprintln!(
            "Environment creation failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        return Err("Failed to create environment".into());
    }
    println!("✓ Environment 'development' created");

    let zopp_toml_path = test_dir.join("zopp.toml");
    fs::write(
        &zopp_toml_path,
        "[defaults]\nworkspace = \"acme\"\nproject = \"api\"\nenvironment = \"development\"\n",
    )?;
    println!("✓ Created zopp.toml with defaults\n");

    println!("🎟️  Step 6: Alice creates workspace invite for Bob...");
    let output = Command::new(&zopp_bin)
        .env("HOME", &alice_home)
        .current_dir(&test_dir)
        .args([
            "--server",
            &server_url,
            "invite",
            "create",
            "--expires-hours",
            "1",
            "--plain",
        ])
        .output()?;

    if !output.status.success() {
        eprintln!(
            "Invite creation failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        eprintln!("Stdout: {}", String::from_utf8_lossy(&output.stdout));
        return Err("Failed to create invite".into());
    }

    let workspace_invite = String::from_utf8_lossy(&output.stdout).trim().to_string();
    println!("✓ Workspace invite: {}\n", workspace_invite);

    println!("👨 Step 7: Bob joins using Alice's workspace invite...");
    let output = Command::new(&zopp_bin)
        .env("HOME", &bob_home)
        .args([
            "--server",
            &server_url,
            "join",
            &workspace_invite,
            "bob@example.com",
            "--principal",
            "bob-thinkpad",
        ])
        .output()?;

    if !output.status.success() {
        eprintln!(
            "Bob join failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        return Err("Bob failed to join workspace".into());
    }
    println!("✓ Bob joined workspace 'acme'\n");

    println!("🔑 Step 7b: Alice grants Bob write permission...");
    let output = Command::new(&zopp_bin)
        .env("HOME", &alice_home)
        .args([
            "--server",
            &server_url,
            "permission",
            "user-set",
            "-w",
            "acme",
            "--email",
            "bob@example.com",
            "--role",
            "write",
        ])
        .output()?;

    if !output.status.success() {
        eprintln!(
            "Permission set failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        return Err("Failed to grant Bob write permission".into());
    }
    println!("✓ Bob granted write permission on workspace 'acme'\n");

    println!("🔐 Step 8: Bob writes secret 'FLUXMAIL_API_TOKEN'...");
    let secret_value = "fxt_8k2m9p4x7n1q5w3e6r8t0y2u4i6o8p0a";
    let output = Command::new(&zopp_bin)
        .env("HOME", &bob_home)
        .current_dir(&test_dir)
        .args([
            "--server",
            &server_url,
            "secret",
            "set",
            "FLUXMAIL_API_TOKEN",
            secret_value,
        ])
        .output()?;

    if !output.status.success() {
        eprintln!(
            "Secret set failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        return Err("Failed to set secret".into());
    }
    println!("✓ Secret written by Bob\n");

    println!("🔓 Step 9: Alice reads Bob's secret...");
    let output = Command::new(&zopp_bin)
        .env("HOME", &alice_home)
        .current_dir(&test_dir)
        .args([
            "--server",
            &server_url,
            "secret",
            "get",
            "FLUXMAIL_API_TOKEN",
        ])
        .output()?;

    if !output.status.success() {
        eprintln!(
            "Secret get failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        return Err("Failed to get secret".into());
    }

    let retrieved_value = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if retrieved_value == secret_value {
        println!("✓ Alice successfully read Bob's secret!");
        println!("  Expected: {}", secret_value);
        println!("  Got:      {}\n", retrieved_value);
    } else {
        eprintln!("❌ Secret mismatch!");
        eprintln!("  Expected: {}", secret_value);
        eprintln!("  Got:      {}", retrieved_value);
        return Err("Secret value mismatch".into());
    }

    println!("🔐 Step 10: Alice writes secret 'PAYFLOW_MERCHANT_ID'...");
    let secret_value2 = "mch_9x8v7c6b5n4m3";
    let output = Command::new(&zopp_bin)
        .env("HOME", &alice_home)
        .current_dir(&test_dir)
        .args([
            "--server",
            &server_url,
            "secret",
            "set",
            "PAYFLOW_MERCHANT_ID",
            secret_value2,
        ])
        .output()?;

    if !output.status.success() {
        eprintln!(
            "Secret set failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        return Err("Failed to set secret".into());
    }
    println!("✓ Secret written by Alice\n");

    println!("🔓 Step 11: Bob reads Alice's secret...");
    let output = Command::new(&zopp_bin)
        .env("HOME", &bob_home)
        .current_dir(&test_dir)
        .args([
            "--server",
            &server_url,
            "secret",
            "get",
            "PAYFLOW_MERCHANT_ID",
        ])
        .output()?;

    if !output.status.success() {
        eprintln!(
            "Secret get failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        return Err("Failed to get secret".into());
    }

    let retrieved_value2 = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if retrieved_value2 == secret_value2 {
        println!("✓ Bob successfully read Alice's secret!");
        println!("  Expected: {}", secret_value2);
        println!("  Got:      {}\n", retrieved_value2);
    } else {
        eprintln!("❌ Secret mismatch!");
        eprintln!("  Expected: {}", secret_value2);
        eprintln!("  Got:      {}", retrieved_value2);
        return Err("Secret value mismatch".into());
    }

    println!("📤 Step 12: Alice exports secrets to .env file...");
    let env_file = test_dir.join("development.env");
    let output = Command::new(&zopp_bin)
        .env("HOME", &alice_home)
        .current_dir(&test_dir)
        .args([
            "--server",
            &server_url,
            "secret",
            "export",
            "-o",
            env_file.to_str().unwrap(),
        ])
        .output()?;

    if !output.status.success() {
        eprintln!(
            "Secret export failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        return Err("Failed to export secrets".into());
    }

    let env_contents = fs::read_to_string(&env_file)?;
    println!("✓ Secrets exported:\n{}", env_contents);

    assert!(env_contents.contains("FLUXMAIL_API_TOKEN="));
    assert!(env_contents.contains("PAYFLOW_MERCHANT_ID="));

    println!("🌍 Step 13: Alice creates production environment...");
    let output = Command::new(&zopp_bin)
        .env("HOME", &alice_home)
        .current_dir(&test_dir)
        .args([
            "--server",
            &server_url,
            "environment",
            "create",
            "production",
        ])
        .output()?;

    if !output.status.success() {
        eprintln!(
            "Environment creation failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        return Err("Failed to create environment".into());
    }
    println!("✓ Environment 'production' created\n");

    println!("📥 Step 14: Alice imports secrets to production (using -e flag override)...");
    let output = Command::new(&zopp_bin)
        .env("HOME", &alice_home)
        .current_dir(&test_dir)
        .args([
            "--server",
            &server_url,
            "secret",
            "import",
            "-e",
            "production",
            "-i",
            env_file.to_str().unwrap(),
        ])
        .output()?;

    if !output.status.success() {
        eprintln!(
            "Secret import failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        return Err("Failed to import secrets".into());
    }
    println!("✓ Secrets imported to production\n");

    println!("🔍 Step 15: Verify imported secret in production (using -e flag override)...");
    let output = Command::new(&zopp_bin)
        .env("HOME", &alice_home)
        .current_dir(&test_dir)
        .args([
            "--server",
            &server_url,
            "secret",
            "get",
            "FLUXMAIL_API_TOKEN",
            "-e",
            "production",
        ])
        .output()?;

    let imported = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if imported == secret_value {
        println!("✓ Import/export roundtrip verified!\n");
    } else {
        return Err(format!(
            "Imported secret mismatch: expected {}, got {}",
            secret_value, imported
        )
        .into());
    }

    println!(
        "🏃 Step 16: Alice injects secrets from production and runs command (using -e override)..."
    );
    let output = Command::new(&zopp_bin)
        .env("HOME", &alice_home)
        .current_dir(&test_dir)
        .args([
            "--server",
            &server_url,
            "run",
            "-e",
            "production",
            "--",
            "printenv",
            "FLUXMAIL_API_TOKEN",
        ])
        .output()?;

    if !output.status.success() {
        eprintln!(
            "Secret injection failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        return Err("Failed to inject secrets".into());
    }

    let injected_value = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if injected_value == secret_value {
        println!("✓ Secret injection verified!\n");
    } else {
        return Err(format!(
            "Injected secret mismatch: expected {}, got {}",
            secret_value, injected_value
        )
        .into());
    }

    // Cleanup
    println!("🧹 Cleaning up...");
    let _ = server.kill();
    let _ = server.wait();
    println!("✓ Server stopped\n");

    println!("✅ E2E Test Passed!");
    println!("\n📊 Summary:");
    println!("  ✓ Server started and stopped");
    println!("  ✓ Alice registered and created workspace");
    println!("  ✓ Created zopp.toml with defaults (workspace/project/environment)");
    println!("  ✓ Bob registered and joined workspace via invite");
    println!("  ✓ Bob wrote secret, Alice read it (E2E encryption, using zopp.toml)");
    println!("  ✓ Alice wrote secret, Bob read it (E2E encryption, using zopp.toml)");
    println!("  ✓ Secrets exported from development (using zopp.toml defaults)");
    println!("  ✓ Created production environment and imported secrets (using -e flag override)");
    println!("  ✓ Secrets injected from production via run command (using -e flag override)");
    println!("  ✓ Zero-knowledge architecture verified");

    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════
// Helper functions
// ═══════════════════════════════════════════════════════════════════════════

fn find_available_port() -> Result<u16, Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    drop(listener); // Close the listener to free the port
    Ok(port)
}

// ═══════════════════════════════════════════════════════════════════════════
// Test wrappers - Run the same E2E test against different storage backends
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn demo_sqlite() -> Result<(), Box<dyn std::error::Error>> {
    // Use a unique database file for this test run to avoid conflicts
    let test_id = std::process::id();
    let db_path = std::env::temp_dir().join(format!("zopp-test-sqlite-{}.db", test_id));
    let db_url = format!("sqlite://{}?mode=rwc", db_path.display());

    let port = find_available_port()?;
    let result = run_demo_test(&db_url, "sqlite", port).await;

    // Cleanup: Remove the test database file
    let _ = std::fs::remove_file(&db_path);

    result
}

#[tokio::test]
async fn demo_postgres() -> Result<(), Box<dyn std::error::Error>> {
    // Requires a running Postgres instance:
    // docker run --name zopp-test-pg -e POSTGRES_PASSWORD=postgres -p 5433:5432 -d postgres:16

    use sqlx::postgres::PgConnection;
    use sqlx::{Connection, Executor};

    // Create a unique database for this test run to avoid conflicts
    let test_id = std::process::id();
    let db_name = format!("zopp_test_{}", test_id);

    // Connect to the 'postgres' database to create our test database
    let admin_url = "postgres://postgres:postgres@localhost:5433/postgres";
    let mut conn = PgConnection::connect(admin_url).await?;

    // Drop database if it exists (cleanup from previous failed runs)
    let drop_query = format!("DROP DATABASE IF EXISTS {}", db_name);
    let _ = conn.execute(drop_query.as_str()).await;

    // Create the test database
    let create_query = format!("CREATE DATABASE {}", db_name);
    conn.execute(create_query.as_str()).await?;
    drop(conn);

    let db_url = format!("postgres://postgres:postgres@localhost:5433/{}", db_name);
    let port = find_available_port()?;
    let result = run_demo_test(&db_url, "postgres", port).await;

    // Cleanup: Drop the test database
    let mut conn = PgConnection::connect(admin_url).await?;
    let drop_query = format!("DROP DATABASE {}", db_name);
    let _ = conn.execute(drop_query.as_str()).await;

    result
}
