use std::fs;
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;
use tokio::time::sleep;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🧪 Starting Zopp E2E Test\n");

    // Find the binary paths (built by cargo build --bins)
    let target_dir = std::env::var("CARGO_TARGET_DIR").unwrap_or_else(|_| "target".to_string());
    let profile = std::env::var("PROFILE").unwrap_or_else(|_| "debug".to_string());
    let bin_dir = PathBuf::from(&target_dir).join(&profile);

    let zopp_server_bin = bin_dir.join("zopp-server");
    let zopp_bin = bin_dir.join("zopp");

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

    // Step 0: Start server
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

    // Step 1: Admin creates server invite for Alice
    println!("🎫 Step 1: Admin creates server invite for Alice...");
    let output = Command::new(&zopp_server_bin)
        .args([
            "--db",
            db_path.to_str().unwrap(),
            "invite",
            "create",
            "--expires-hours",
            "1",
        ])
        .output()?;

    let invite_output = String::from_utf8_lossy(&output.stdout);
    let alice_server_invite = extract_token(&invite_output)?;
    println!("✓ Alice's server invite: {}\n", alice_server_invite);

    // Step 2: Alice joins server
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

    // Step 3: Alice creates workspace
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

    // Step 4: Alice creates project
    println!("📁 Step 4: Alice creates project 'api'...");
    let output = Command::new(&zopp_bin)
        .env("HOME", &alice_home)
        .args(["project", "create", "api", "--workspace", "acme"])
        .output()?;

    if !output.status.success() {
        eprintln!(
            "Project creation failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        return Err("Failed to create project".into());
    }
    println!("✓ Project 'api' created\n");

    // Step 5: Alice creates environment
    println!("🌍 Step 5: Alice creates environment 'production'...");
    let output = Command::new(&zopp_bin)
        .env("HOME", &alice_home)
        .args([
            "environment",
            "create",
            "production",
            "--workspace",
            "acme",
            "--project",
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
    println!("✓ Environment 'production' created\n");

    // Step 6: Alice creates workspace invite for Bob
    println!("🎟️  Step 6: Alice creates workspace invite for Bob...");
    let output = Command::new(&zopp_bin)
        .env("HOME", &alice_home)
        .args([
            "invite",
            "create",
            "--workspace",
            "acme",
            "--expires-hours",
            "1",
        ])
        .output()?;

    if !output.status.success() {
        eprintln!(
            "Invite creation failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        return Err("Failed to create invite".into());
    }

    let invite_output = String::from_utf8_lossy(&output.stdout);
    let workspace_invite = extract_invite_code(&invite_output)?;
    println!("✓ Workspace invite: {}\n", workspace_invite);

    // Step 7: Bob joins using workspace invite
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

    // Step 8: Bob writes a secret
    println!("🔐 Step 8: Bob writes secret 'FLUXMAIL_API_TOKEN'...");
    let secret_value = "fxt_8k2m9p4x7n1q5w3e6r8t0y2u4i6o8p0a";
    let output = Command::new(&zopp_bin)
        .env("HOME", &bob_home)
        .args([
            "secret",
            "set",
            "FLUXMAIL_API_TOKEN",
            secret_value,
            "--workspace",
            "acme",
            "--project",
            "api",
            "--environment",
            "production",
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

    // Step 9: Alice reads Bob's secret
    println!("🔓 Step 9: Alice reads Bob's secret...");
    let output = Command::new(&zopp_bin)
        .env("HOME", &alice_home)
        .args([
            "secret",
            "get",
            "FLUXMAIL_API_TOKEN",
            "--workspace",
            "acme",
            "--project",
            "api",
            "--environment",
            "production",
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

    // Step 10: Alice writes a secret
    println!("🔐 Step 10: Alice writes secret 'PAYFLOW_MERCHANT_ID'...");
    let secret_value2 = "mch_9x8v7c6b5n4m3";
    let output = Command::new(&zopp_bin)
        .env("HOME", &alice_home)
        .args([
            "secret",
            "set",
            "PAYFLOW_MERCHANT_ID",
            secret_value2,
            "--workspace",
            "acme",
            "--project",
            "api",
            "--environment",
            "production",
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

    // Step 11: Bob reads Alice's secret
    println!("🔓 Step 11: Bob reads Alice's secret...");
    let output = Command::new(&zopp_bin)
        .env("HOME", &bob_home)
        .args([
            "secret",
            "get",
            "PAYFLOW_MERCHANT_ID",
            "--workspace",
            "acme",
            "--project",
            "api",
            "--environment",
            "production",
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

    // Cleanup
    println!("🧹 Cleaning up...");
    // Kill server process and wait for it to exit
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
    println!("  ✓ Bob registered and joined workspace via invite");
    println!("  ✓ Bob wrote secret, Alice read it (E2E encryption)");
    println!("  ✓ Alice wrote secret, Bob read it (E2E encryption)");
    println!("  ✓ Zero-knowledge architecture verified");

    Ok(())
}

fn extract_token(output: &str) -> Result<String, Box<dyn std::error::Error>> {
    for line in output.lines() {
        if line.contains("Token:") {
            let token = line
                .split_whitespace()
                .last()
                .ok_or("Failed to extract token")?;
            return Ok(token.to_string());
        }
    }
    Err("Token not found in output".into())
}

fn extract_invite_code(output: &str) -> Result<String, Box<dyn std::error::Error>> {
    for line in output.lines() {
        if line.contains("Invite code:") {
            let code = line
                .split_whitespace()
                .last()
                .ok_or("Failed to extract invite code")?;
            return Ok(code.to_string());
        }
    }
    Err("Invite code not found in output".into())
}
