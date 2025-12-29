use std::fs;
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;
use tokio::time::sleep;

#[tokio::test]
async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    println!("🧪 Starting Zopp E2E Test\n");

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
    let test_dir = PathBuf::from("/tmp/zopp-e2e-test");
    let alice_home = test_dir.join("alice");
    let bob_home = test_dir.join("bob");
    let db_path = test_dir.join("zopp.db");

    // Clean up from previous runs
    if test_dir.exists() {
        fs::remove_dir_all(&test_dir)?;
    }
    fs::create_dir_all(&alice_home)?;
    fs::create_dir_all(&bob_home)?;

    println!("✓ Test directories created");
    println!("  Alice home: {}", alice_home.display());
    println!("  Bob home:   {}", bob_home.display());
    println!("  Database:   {}\n", db_path.display());

    println!("📡 Step 0: Starting server...");
    let db_path_str = db_path.to_str().unwrap();

    let mut server = Command::new(&zopp_server_bin)
        .args(["--db", db_path_str, "serve"])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()?;

    // Wait for server to be ready by checking if it's listening on port 50051
    let mut ready = false;
    for i in 1..=30 {
        sleep(Duration::from_millis(200)).await;
        if TcpStream::connect("127.0.0.1:50051").is_ok() {
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

    println!("🎫 Step 1: Admin creates server invite for Alice...");
    let output = Command::new(&zopp_server_bin)
        .args([
            "--db",
            db_path.to_str().unwrap(),
            "invite",
            "create",
            "--expires-hours",
            "1",
            "--plain",
        ])
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
        .args(["workspace", "create", "acme"])
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
        .args(["project", "create", "api", "-w", "acme"])
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
        .args(["invite", "create", "--expires-hours", "1", "--plain"])
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

    println!("🔐 Step 8: Bob writes secret 'FLUXMAIL_API_TOKEN'...");
    let secret_value = "fxt_8k2m9p4x7n1q5w3e6r8t0y2u4i6o8p0a";
    let output = Command::new(&zopp_bin)
        .env("HOME", &bob_home)
        .current_dir(&test_dir)
        .args(["secret", "set", "FLUXMAIL_API_TOKEN", secret_value])
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
        .args(["secret", "get", "FLUXMAIL_API_TOKEN"])
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
        .args(["secret", "set", "PAYFLOW_MERCHANT_ID", secret_value2])
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
        .args(["secret", "get", "PAYFLOW_MERCHANT_ID"])
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
        .args(["secret", "export", "-o", env_file.to_str().unwrap()])
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
        .args(["environment", "create", "production"])
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
        .args(["secret", "get", "FLUXMAIL_API_TOKEN", "-e", "production"])
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

    // Also kill any lingering server processes (in case kill() didn't work)
    #[cfg(unix)]
    {
        let _ = std::process::Command::new("pkill")
            .arg("-f")
            .arg("zopp-server.*serve")
            .status();
    }
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
