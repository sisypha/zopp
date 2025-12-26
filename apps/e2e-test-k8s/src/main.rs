use std::fs;
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;
use tokio::time::sleep;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🧪 Starting Zopp K8s Sync E2E Test\n");

    // Check prerequisites
    check_prerequisites()?;

    // Find the binary paths (built by cargo build --bins)
    let target_dir = std::env::var("CARGO_TARGET_DIR").unwrap_or_else(|_| "target".to_string());
    let profile = std::env::var("PROFILE").unwrap_or_else(|_| "debug".to_string());
    let bin_dir = PathBuf::from(&target_dir).join(&profile);

    // Convert to absolute paths so they work when we change current_dir
    let zopp_server_bin = std::fs::canonicalize(bin_dir.join("zopp-server"))?;
    let zopp_bin = std::fs::canonicalize(bin_dir.join("zopp"))?;

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
    let test_dir = PathBuf::from("/tmp/zopp-e2e-test-k8s");
    let alice_home = test_dir.join("alice");
    let db_path = test_dir.join("zopp.db");

    // Clean up from previous runs
    if test_dir.exists() {
        fs::remove_dir_all(&test_dir)?;
    }
    fs::create_dir_all(&alice_home)?;

    println!("✓ Test directories created");
    println!("  Alice home: {}", alice_home.display());
    println!("  Database:   {}\n", db_path.display());

    // Step 0: Create kind cluster
    println!("☸️  Step 0: Creating kind cluster...");
    let cluster_name = "zopp-test";

    // Delete cluster if it exists
    println!("  Deleting existing cluster if present...");
    let status = Command::new("kind")
        .args(["delete", "cluster", "--name", cluster_name])
        .status();

    if status.is_ok() && status.unwrap().success() {
        println!("  ✓ Deleted existing cluster");
    }

    println!("  Creating cluster (this may take 30-60s)...");
    let status = Command::new("kind")
        .args(["create", "cluster", "--name", cluster_name, "--wait", "60s"])
        .status()?;

    if !status.success() {
        eprintln!("❌ kind cluster creation failed");
        return Err("Failed to create kind cluster".into());
    }
    println!("✓ kind cluster '{}' created\n", cluster_name);

    // Step 1: Start zopp server
    println!("📡 Step 1: Starting zopp server...");
    let db_path_str = db_path.to_str().unwrap();

    let mut server = Command::new(&zopp_server_bin)
        .args(["--db", db_path_str, "serve"])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()?;

    // Wait for server to be ready
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
            cleanup_kind(cluster_name)?;
            return Err("Server not ready".into());
        }
    }
    if !ready {
        cleanup_kind(cluster_name)?;
        return Err("Server failed to start".into());
    }

    // Step 2: Setup Alice with workspace/project/environment
    println!("🎫 Step 2: Admin creates server invite for Alice...");
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
        cleanup(&mut server, cluster_name)?;
        return Err("Failed to create server invite".into());
    }

    let alice_server_invite = String::from_utf8_lossy(&output.stdout).trim().to_string();
    println!("✓ Alice's server invite: {}\n", alice_server_invite);

    println!("👩 Step 3: Alice joins server...");
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
        cleanup(&mut server, cluster_name)?;
        return Err("Alice failed to join".into());
    }
    println!("✓ Alice joined successfully\n");

    println!("🏢 Step 4: Alice creates workspace 'acme'...");
    let output = Command::new(&zopp_bin)
        .env("HOME", &alice_home)
        .args(["workspace", "create", "acme"])
        .output()?;

    if !output.status.success() {
        eprintln!(
            "Workspace creation failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        cleanup(&mut server, cluster_name)?;
        return Err("Failed to create workspace".into());
    }
    println!("✓ Workspace 'acme' created\n");

    println!("📁 Step 5: Alice creates project 'api'...");
    let output = Command::new(&zopp_bin)
        .env("HOME", &alice_home)
        .args(["project", "create", "api", "-w", "acme"])
        .output()?;

    if !output.status.success() {
        eprintln!(
            "Project creation failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        cleanup(&mut server, cluster_name)?;
        return Err("Failed to create project".into());
    }
    println!("✓ Project 'api' created\n");

    println!("🌍 Step 6: Alice creates environment 'development'...");
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
        cleanup(&mut server, cluster_name)?;
        return Err("Failed to create environment".into());
    }
    println!("✓ Environment 'development' created\n");

    // Create zopp.toml
    let zopp_toml_path = test_dir.join("zopp.toml");
    fs::write(
        &zopp_toml_path,
        "[defaults]\nworkspace = \"acme\"\nproject = \"api\"\nenvironment = \"development\"\n",
    )?;
    println!("✓ Created zopp.toml with defaults\n");

    // Step 7: Alice writes some secrets
    println!("🔐 Step 7: Alice writes secrets...");
    let secrets = vec![
        ("DATABASE_URL", "postgresql://localhost/mydb"),
        ("API_KEY", "sk-test-1234567890"),
        ("REDIS_URL", "redis://localhost:6379"),
    ];

    for (key, value) in &secrets {
        let output = Command::new(&zopp_bin)
            .env("HOME", &alice_home)
            .current_dir(&test_dir)
            .args(["secret", "set", key, value])
            .output()?;

        if !output.status.success() {
            eprintln!(
                "Secret set failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            cleanup(&mut server, cluster_name)?;
            return Err("Failed to set secret".into());
        }
    }
    println!("✓ Wrote {} secrets\n", secrets.len());

    // Step 8: Sync to k8s
    println!("☸️  Step 8: Syncing secrets to Kubernetes...");

    // Get real HOME for kubeconfig access (kind writes to ~/.kube/config)
    let real_home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    let kubeconfig = PathBuf::from(&real_home).join(".kube/config");

    let output = Command::new(&zopp_bin)
        .env("HOME", &alice_home) // For zopp config
        .env("KUBECONFIG", &kubeconfig) // For k8s config
        .current_dir(&test_dir)
        .args([
            "sync",
            "k8s",
            "--namespace",
            "default",
            "--secret",
            "zopp-test-secrets",
        ])
        .output()?;

    if !output.status.success() {
        eprintln!(
            "K8s sync failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        eprintln!("Stdout: {}", String::from_utf8_lossy(&output.stdout));
        cleanup(&mut server, cluster_name)?;
        return Err("Failed to sync to k8s".into());
    }
    println!("{}", String::from_utf8_lossy(&output.stdout));

    // Step 9: Verify k8s Secret exists and has correct data
    println!("🔍 Step 9: Verifying k8s Secret...");
    verify_k8s_secret("zopp-test-secrets", &secrets).await?;

    // Step 10: Update a secret and re-sync
    println!("🔄 Step 10: Updating secret and re-syncing...");
    let output = Command::new(&zopp_bin)
        .env("HOME", &alice_home)
        .current_dir(&test_dir)
        .args([
            "secret",
            "set",
            "DATABASE_URL",
            "postgresql://newhost/newdb",
        ])
        .output()?;

    if !output.status.success() {
        eprintln!(
            "Secret update failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        cleanup(&mut server, cluster_name)?;
        return Err("Failed to update secret".into());
    }

    let output = Command::new(&zopp_bin)
        .env("HOME", &alice_home)
        .env("KUBECONFIG", &kubeconfig)
        .current_dir(&test_dir)
        .args([
            "sync",
            "k8s",
            "--namespace",
            "default",
            "--secret",
            "zopp-test-secrets",
        ])
        .output()?;

    if !output.status.success() {
        eprintln!(
            "K8s re-sync failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        cleanup(&mut server, cluster_name)?;
        return Err("Failed to re-sync to k8s".into());
    }
    println!("✓ Re-synced after update\n");

    let updated_secrets = vec![
        ("DATABASE_URL", "postgresql://newhost/newdb"),
        ("API_KEY", "sk-test-1234567890"),
        ("REDIS_URL", "redis://localhost:6379"),
    ];
    verify_k8s_secret("zopp-test-secrets", &updated_secrets).await?;

    // Step 11: Test --force flag
    println!("⚠️  Step 11: Testing --force flag...");

    // Create a non-zopp Secret
    let output = Command::new("kubectl")
        .args([
            "create",
            "secret",
            "generic",
            "manual-secret",
            "--from-literal=foo=bar",
        ])
        .output()?;

    if !output.status.success() {
        eprintln!(
            "Manual secret creation failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        cleanup(&mut server, cluster_name)?;
        return Err("Failed to create manual secret".into());
    }
    println!("✓ Created non-zopp Secret\n");

    // Try to sync without --force (should fail)
    println!("  Testing sync without --force (should fail)...");
    let output = Command::new(&zopp_bin)
        .env("HOME", &alice_home)
        .env("KUBECONFIG", &kubeconfig)
        .current_dir(&test_dir)
        .args([
            "sync",
            "k8s",
            "--namespace",
            "default",
            "--secret",
            "manual-secret",
        ])
        .output()?;

    if output.status.success() {
        eprintln!("❌ Sync should have failed without --force!");
        cleanup(&mut server, cluster_name)?;
        return Err("Sync succeeded when it should have failed".into());
    }
    println!("  ✓ Sync correctly failed without --force\n");

    // Try with --force (should succeed)
    println!("  Testing sync with --force (should succeed)...");
    let output = Command::new(&zopp_bin)
        .env("HOME", &alice_home)
        .env("KUBECONFIG", &kubeconfig)
        .current_dir(&test_dir)
        .args([
            "sync",
            "k8s",
            "--namespace",
            "default",
            "--secret",
            "manual-secret",
            "--force",
        ])
        .output()?;

    if !output.status.success() {
        eprintln!(
            "K8s sync with --force failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        cleanup(&mut server, cluster_name)?;
        return Err("Failed to sync with --force".into());
    }
    println!("  ✓ Sync with --force succeeded\n");

    // Cleanup
    println!("🧹 Cleaning up...");
    cleanup(&mut server, cluster_name)?;

    println!("✅ K8s Sync E2E Test Passed!\n");
    println!("📊 Summary:");
    println!("  ✓ kind cluster created and cleaned up");
    println!("  ✓ Secrets synced to Kubernetes");
    println!("  ✓ Secret updates propagated correctly");
    println!("  ✓ Ownership validation works (--force flag)");
    println!("  ✓ Metadata labels and annotations verified");

    Ok(())
}

fn check_prerequisites() -> Result<(), Box<dyn std::error::Error>> {
    // Check if kind is installed
    let output = Command::new("kind").arg("version").output();
    if output.is_err() || !output.as_ref().unwrap().status.success() {
        return Err("kind is not installed. Install with: brew install kind (or see https://kind.sigs.k8s.io/docs/user/quick-start/)".into());
    }

    // Check if kubectl is installed
    let output = Command::new("kubectl").arg("version").arg("--client").output();
    if output.is_err() || !output.as_ref().unwrap().status.success() {
        return Err("kubectl is not installed. Install with: brew install kubectl".into());
    }

    // Check if Docker is running
    let output = Command::new("docker").arg("ps").output();
    if output.is_err() || !output.as_ref().unwrap().status.success() {
        return Err("Docker is not running. Please start Docker Desktop.".into());
    }

    println!("✓ Prerequisites checked (kind, kubectl, docker)\n");
    Ok(())
}

async fn verify_k8s_secret(
    secret_name: &str,
    expected_secrets: &[(&str, &str)],
) -> Result<(), Box<dyn std::error::Error>> {
    use k8s_openapi::api::core::v1::Secret;
    use kube::{Api, Client, Config};

    let config = Config::from_kubeconfig(&kube::config::KubeConfigOptions::default()).await?;
    let client = Client::try_from(config)?;
    let secrets_api: Api<Secret> = Api::namespaced(client, "default");

    let secret = secrets_api.get(secret_name).await?;

    // Verify metadata
    let labels = secret.metadata.labels.as_ref().ok_or("No labels found")?;
    if labels.get("app.kubernetes.io/managed-by") != Some(&"zopp".to_string()) {
        return Err("Missing or incorrect managed-by label".into());
    }
    println!("  ✓ Metadata labels verified");

    let annotations = secret
        .metadata
        .annotations
        .as_ref()
        .ok_or("No annotations found")?;
    if !annotations.contains_key("zopp.io/workspace")
        || !annotations.contains_key("zopp.io/project")
        || !annotations.contains_key("zopp.io/environment")
    {
        return Err("Missing zopp annotations".into());
    }
    println!("  ✓ Metadata annotations verified");

    // Verify secret data
    let data = secret.data.as_ref().ok_or("No data found in Secret")?;

    for (key, expected_value) in expected_secrets {
        let actual_value = data.get(*key).ok_or_else(|| format!("Key {} not found", key))?;
        let decoded = String::from_utf8(actual_value.0.clone())?;

        if decoded != *expected_value {
            return Err(format!(
                "Secret value mismatch for {}: expected '{}', got '{}'",
                key, expected_value, decoded
            )
            .into());
        }
    }
    println!("  ✓ Secret data verified ({} keys)\n", expected_secrets.len());

    Ok(())
}

fn cleanup(
    server: &mut std::process::Child,
    cluster_name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let _ = server.kill();
    let _ = server.wait();

    #[cfg(unix)]
    {
        let _ = std::process::Command::new("pkill")
            .arg("-f")
            .arg("zopp-server.*serve")
            .status();
    }
    println!("✓ Server stopped");

    cleanup_kind(cluster_name)?;

    Ok(())
}

fn cleanup_kind(cluster_name: &str) -> Result<(), Box<dyn std::error::Error>> {
    println!("  Deleting kind cluster...");
    let status = Command::new("kind")
        .args(["delete", "cluster", "--name", cluster_name])
        .status()?;

    if !status.success() {
        eprintln!("  Warning: kind cleanup failed");
    } else {
        println!("✓ kind cluster deleted");
    }

    Ok(())
}
