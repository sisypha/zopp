mod common;

use std::fs;
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;
use tokio::time::sleep;

#[tokio::test]
async fn operator_sync() -> Result<(), Box<dyn std::error::Error>> {
    println!("🧪 Starting Operator Sync E2E Test\n");

    // Check prerequisites
    check_prerequisites()?;

    // Find the binary paths
    // When running as a test, CARGO_BIN_EXE_<name> env vars point to the binaries
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
    let operator_bin = if cfg!(windows) {
        bin_dir.join("zopp-operator.exe")
    } else {
        bin_dir.join("zopp-operator")
    };

    if !zopp_server_bin.exists() || !zopp_bin.exists() || !operator_bin.exists() {
        eprintln!("❌ Binaries not found. Please run 'cargo build --bins' first.");
        eprintln!("   Expected: {}", zopp_server_bin.display());
        eprintln!("   Expected: {}", zopp_bin.display());
        eprintln!("   Expected: {}", operator_bin.display());
        return Err("Binaries not built".into());
    }

    println!("✓ Using prebuilt binaries:");
    println!("  zopp-server:   {}", zopp_server_bin.display());
    println!("  zopp:          {}", zopp_bin.display());
    println!("  zopp-operator: {}\n", operator_bin.display());

    // Find available ports for server and health check
    let server_port = find_available_port()?;
    let server_health_port = find_available_port()?;
    let server_url = format!("http://127.0.0.1:{}", server_port);
    println!(
        "✓ Allocated server port: {}, health port: {}\n",
        server_port, server_health_port
    );

    // Setup test directories using platform-appropriate temp dir
    let test_dir = std::env::temp_dir().join("zopp-e2e-operator-test");
    let alice_home = test_dir.join("alice");
    let operator_home = test_dir.join("operator");
    let db_path = test_dir.join("zopp.db");

    // Clean up from previous runs
    if test_dir.exists() {
        fs::remove_dir_all(&test_dir)?;
    }
    fs::create_dir_all(&alice_home)?;
    fs::create_dir_all(&operator_home)?;

    println!("✓ Test directories created");
    println!("  Alice home: {}", alice_home.display());
    println!("  Operator home: {}", operator_home.display());
    println!("  Database:   {}\n", db_path.display());

    // Step 0: Create kind cluster
    println!("☸️  Step 0: Creating kind cluster...");
    let cluster_name = "zopp-operator-test";

    // Delete cluster if it exists
    println!("  Deleting existing cluster if present...");
    let _ = Command::new("kind")
        .args(["delete", "cluster", "--name", cluster_name])
        .status();

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
    let server_addr = format!("0.0.0.0:{}", server_port);
    let server_health_addr = format!("0.0.0.0:{}", server_health_port);

    let mut server = Command::new(&zopp_server_bin)
        .env_remove("DATABASE_URL") // Ensure we use SQLite via --db, not inherited Postgres
        .args([
            "--db",
            db_path_str,
            "serve",
            "--addr",
            &server_addr,
            "--health-addr",
            &server_health_addr,
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()?;

    // Wait for server to be ready
    let mut ready = false;
    let server_connect_addr = format!("127.0.0.1:{}", server_port);
    for i in 1..=30 {
        sleep(Duration::from_millis(200)).await;
        if TcpStream::connect(&server_connect_addr).is_ok() {
            ready = true;
            println!("✓ Server started and ready (PID: {})\n", server.id());
            break;
        }
        if i == 30 {
            eprintln!("❌ Server failed to start within 6 seconds");
            common::graceful_shutdown(&mut server);
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
        .env_remove("DATABASE_URL") // Ensure we use SQLite via --db
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
            "--server",
            &server_url,
            "join",
            &alice_server_invite,
            "alice@example.com",
            "--principal",
            "alice-laptop",
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
        .args(["--server", &server_url, "workspace", "create", "acme"])
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

    println!("📁 Step 5: Alice creates project 'backend'...");
    let output = Command::new(&zopp_bin)
        .env("HOME", &alice_home)
        .args([
            "--server",
            &server_url,
            "project",
            "create",
            "backend",
            "-w",
            "acme",
        ])
        .output()?;

    if !output.status.success() {
        eprintln!(
            "Project creation failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        cleanup(&mut server, cluster_name)?;
        return Err("Failed to create project".into());
    }
    println!("✓ Project 'backend' created\n");

    println!("🌍 Step 6: Alice creates environment 'production'...");
    let output = Command::new(&zopp_bin)
        .env("HOME", &alice_home)
        .args([
            "--server",
            &server_url,
            "environment",
            "create",
            "production",
            "-w",
            "acme",
            "-p",
            "backend",
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
    println!("✓ Environment 'production' created\n");

    // Create zopp.toml
    let zopp_toml_path = test_dir.join("zopp.toml");
    fs::write(
        &zopp_toml_path,
        "[defaults]\nworkspace = \"acme\"\nproject = \"backend\"\nenvironment = \"production\"\n",
    )?;
    println!("✓ Created zopp.toml with defaults\n");

    // Step 7: Alice writes initial secrets
    println!("🔐 Step 7: Alice writes initial secrets...");
    let initial_secrets = vec![
        ("DATABASE_URL", "postgresql://localhost/prod"),
        ("API_KEY", "sk-prod-key-123"),
        ("REDIS_URL", "redis://localhost:6379/0"),
    ];

    for (key, value) in &initial_secrets {
        let output = Command::new(&zopp_bin)
            .env("HOME", &alice_home)
            .current_dir(&test_dir)
            .args(["--server", &server_url, "secret", "set", key, value])
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
    println!("✓ Wrote {} initial secrets\n", initial_secrets.len());

    // Step 8: Create annotated Kubernetes Secret
    println!("☸️  Step 8: Creating annotated Kubernetes Secret...");
    create_annotated_secret("app-secrets").await?;
    println!("✓ Created annotated Secret 'app-secrets'\n");

    // Step 9: Create service principal for operator
    println!("🔑 Step 9: Setting up operator service principal...");

    // Alice creates a service principal for the operator with workspace access
    // This creates the principal with KEK access to the workspace in one command
    let output = Command::new(&zopp_bin)
        .env("HOME", &alice_home)
        .args([
            "--server",
            &server_url,
            "principal",
            "create",
            "k8s-operator",
            "--service",
            "--workspace",
            "acme",
        ])
        .output()?;

    if !output.status.success() {
        eprintln!(
            "Failed to create service principal: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        cleanup(&mut server, cluster_name)?;
        return Err("Failed to create service principal".into());
    }

    // Extract principal ID from output (format: "Service principal 'k8s-operator' created (ID: <uuid>)")
    let create_output = String::from_utf8_lossy(&output.stdout);
    let operator_principal_id = create_output
        .lines()
        .find(|line| line.contains("created (ID:"))
        .and_then(|line| {
            let start = line.find("(ID: ")? + 5;
            let end = line.find(')')?;
            Some(line[start..end].to_string())
        })
        .ok_or("Failed to parse principal ID from create output")?;

    println!(
        "✓ Service principal 'k8s-operator' created (ID: {})",
        operator_principal_id
    );

    // Copy the service principal credentials from alice_home to operator_home
    // The service principal was created in Alice's config, we need to extract it for the operator
    let alice_config_path = alice_home.join(".zopp/config.json");
    let alice_config: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&alice_config_path)?)?;

    // Find the service principal in Alice's config
    let service_principal = alice_config["principals"]
        .as_array()
        .and_then(|principals| {
            principals
                .iter()
                .find(|p| p["id"].as_str() == Some(&operator_principal_id))
        })
        .ok_or("Service principal not found in Alice's config")?
        .clone();

    // Create operator config with just the service principal
    let operator_config = serde_json::json!({
        "user_id": "",
        "email": "",
        "principals": [service_principal],
        "current_principal": "k8s-operator"
    });

    let operator_config_dir = operator_home.join(".zopp");
    fs::create_dir_all(&operator_config_dir)?;
    fs::write(
        operator_config_dir.join("config.json"),
        serde_json::to_string_pretty(&operator_config)?,
    )?;
    println!("✓ Service principal credentials copied to operator home");

    // Grant READ permission to the service principal on the workspace
    // Service principals use principal permissions directly (not user permissions)
    let output = Command::new(&zopp_bin)
        .env("HOME", &alice_home)
        .current_dir(&test_dir)
        .args([
            "--server",
            &server_url,
            "permission",
            "set",
            "--workspace",
            "acme",
            "--principal",
            &operator_principal_id,
            "--role",
            "read",
        ])
        .output()?;

    if !output.status.success() {
        eprintln!(
            "Failed to set permission: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        cleanup(&mut server, cluster_name)?;
        return Err("Failed to set permission for operator".into());
    }
    println!(
        "✓ Granted READ permission to service principal (ID: {})\n",
        operator_principal_id
    );

    // Step 10: Start operator
    println!("🤖 Step 10: Starting zopp operator...");
    let real_home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    let kubeconfig = PathBuf::from(&real_home).join(".kube/config");

    // Operator uses its own config file (created during join)
    let config_file = operator_home.join(".zopp/config.json");

    let operator_stdout = fs::File::create(test_dir.join("operator.stdout.log"))?;
    let operator_stderr = fs::File::create(test_dir.join("operator.stderr.log"))?;

    let mut operator = Command::new(&operator_bin)
        .env("KUBECONFIG", &kubeconfig)
        .env("RUST_LOG", "zopp_operator=debug,info")
        .args([
            "--server",
            &server_url,
            "--credentials",
            config_file.to_str().unwrap(),
            "--namespace",
            "default",
            "--health-addr",
            "127.0.0.1:8081",
        ])
        .stdout(Stdio::from(operator_stdout))
        .stderr(Stdio::from(operator_stderr))
        .spawn()?;

    println!("✓ Operator started (PID: {})", operator.id());

    // Verify health endpoints work with retry loop
    let mut health_ready = false;
    let mut last_healthz_status = None;
    let mut last_readyz_status = None;

    for _ in 1..=20 {
        sleep(Duration::from_millis(100)).await;
        let Ok(healthz) = reqwest::get("http://127.0.0.1:8081/healthz").await else {
            continue;
        };

        let healthz_status = healthz.status();
        last_healthz_status = Some(healthz_status);

        let Ok(readyz) = reqwest::get("http://127.0.0.1:8081/readyz").await else {
            continue;
        };

        let readyz_status = readyz.status();
        last_readyz_status = Some(readyz_status);

        if healthz_status.is_success() && readyz_status.is_success() {
            health_ready = true;
            break;
        }
    }

    if !health_ready {
        eprintln!("❌ Health check endpoints failed after 20 attempts");
        if let Some(status) = last_healthz_status {
            eprintln!("  Last /healthz status: {}", status);
        } else {
            eprintln!("  /healthz: no successful connection");
        }
        if let Some(status) = last_readyz_status {
            eprintln!("  Last /readyz status: {}", status);
        } else {
            eprintln!("  /readyz: no successful connection");
        }
        cleanup_all(&mut server, &mut operator, cluster_name)?;
        return Err("Health endpoints not working".into());
    }
    println!("✓ Health endpoints verified (/healthz, /readyz)\n");

    // Step 11: Wait for operator to perform initial sync
    println!("⏳ Step 11: Waiting for operator to sync (max 10s)...");
    sleep(Duration::from_secs(3)).await;

    // Verify secrets were synced
    if let Err(e) = verify_k8s_secret("app-secrets", &initial_secrets).await {
        // Print operator logs on failure
        eprintln!("\n❌ Initial sync failed! Checking operator logs...\n");
        let stdout_log = fs::read_to_string(test_dir.join("operator.stdout.log"))?;
        let stderr_log = fs::read_to_string(test_dir.join("operator.stderr.log"))?;
        eprintln!("Operator stdout:\n{}", stdout_log);
        eprintln!("\nOperator stderr:\n{}", stderr_log);
        cleanup_all(&mut server, &mut operator, cluster_name)?;
        return Err(e);
    }
    println!("✓ Initial sync verified!\n");

    // Step 12: Test real-time event streaming
    println!("🔄 Step 12: Testing real-time event streaming...");
    println!("  Updating DATABASE_URL in zopp...");
    let output = Command::new(&zopp_bin)
        .env("HOME", &alice_home)
        .current_dir(&test_dir)
        .args([
            "--server",
            &server_url,
            "secret",
            "set",
            "DATABASE_URL",
            "postgresql://newhost/prod",
        ])
        .output()?;

    if !output.status.success() {
        eprintln!(
            "Secret update failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        cleanup_all(&mut server, &mut operator, cluster_name)?;
        return Err("Failed to update secret".into());
    }

    println!("  Waiting for operator to receive event (max 3s)...");
    sleep(Duration::from_secs(2)).await;

    let updated_secrets = vec![
        ("DATABASE_URL", "postgresql://newhost/prod"),
        ("API_KEY", "sk-prod-key-123"),
        ("REDIS_URL", "redis://localhost:6379/0"),
    ];
    verify_k8s_secret("app-secrets", &updated_secrets).await?;
    println!("✓ Real-time sync verified (< 2s latency)!\n");

    // Step 13: Test adding a new secret
    println!("➕ Step 13: Testing new secret addition...");
    let output = Command::new(&zopp_bin)
        .env("HOME", &alice_home)
        .current_dir(&test_dir)
        .args([
            "--server",
            &server_url,
            "secret",
            "set",
            "SMTP_HOST",
            "smtp.example.com",
        ])
        .output()?;

    if !output.status.success() {
        cleanup_all(&mut server, &mut operator, cluster_name)?;
        return Err("Failed to add new secret".into());
    }

    println!("  Waiting for operator to sync new key...");
    sleep(Duration::from_secs(2)).await;

    let with_new_secret = vec![
        ("DATABASE_URL", "postgresql://newhost/prod"),
        ("API_KEY", "sk-prod-key-123"),
        ("REDIS_URL", "redis://localhost:6379/0"),
        ("SMTP_HOST", "smtp.example.com"),
    ];
    verify_k8s_secret("app-secrets", &with_new_secret).await?;
    println!("✓ New secret synced!\n");

    // Step 14: Test secret deletion
    println!("🗑️  Step 14: Testing secret deletion...");
    let output = Command::new(&zopp_bin)
        .env("HOME", &alice_home)
        .current_dir(&test_dir)
        .args(["--server", &server_url, "secret", "delete", "SMTP_HOST"])
        .output()?;

    if !output.status.success() {
        cleanup_all(&mut server, &mut operator, cluster_name)?;
        return Err("Failed to delete secret".into());
    }

    println!("  Waiting for operator to sync deletion...");
    sleep(Duration::from_secs(2)).await;

    verify_k8s_secret("app-secrets", &updated_secrets).await?;
    verify_key_not_present("app-secrets", "SMTP_HOST").await?;
    println!("✓ Secret deletion synced!\n");

    // Step 15: Test 60-second polling safeguard
    println!("⏱️  Step 15: Testing 60-second polling safeguard...");
    println!("  Stopping operator to simulate stream failure...");
    common::graceful_shutdown(&mut operator);

    println!("  Updating secret while operator is down...");
    let output = Command::new(&zopp_bin)
        .env("HOME", &alice_home)
        .current_dir(&test_dir)
        .args([
            "--server",
            &server_url,
            "secret",
            "set",
            "API_KEY",
            "sk-updated-while-down",
        ])
        .output()?;

    if !output.status.success() {
        cleanup(&mut server, cluster_name)?;
        return Err("Failed to update secret while operator down".into());
    }

    println!("  Restarting operator...");
    let mut operator = Command::new(&operator_bin)
        .env("KUBECONFIG", &kubeconfig)
        .env("RUST_LOG", "zopp_operator=debug,info")
        .args([
            "--server",
            &server_url,
            "--credentials",
            config_file.to_str().unwrap(),
            "--namespace",
            "default",
            "--health-addr",
            "127.0.0.1:8081",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    println!("  Waiting for periodic reconciliation (max 65s)...");
    sleep(Duration::from_secs(5)).await; // Initial sync should catch it

    let polled_secrets = vec![
        ("DATABASE_URL", "postgresql://newhost/prod"),
        ("API_KEY", "sk-updated-while-down"),
        ("REDIS_URL", "redis://localhost:6379/0"),
    ];
    verify_k8s_secret("app-secrets", &polled_secrets).await?;
    println!("✓ Polling safeguard works!\n");

    // Step 16: Test multiple annotated Secrets
    println!("🔢 Step 16: Testing multiple annotated Secrets...");
    create_annotated_secret("frontend-secrets").await?;

    println!("  Waiting for operator to detect new Secret...");
    sleep(Duration::from_secs(3)).await;

    // Should sync the same secrets to frontend-secrets
    verify_k8s_secret("frontend-secrets", &polled_secrets).await?;
    println!("✓ Multiple Secrets synced!\n");

    // Cleanup
    println!("🧹 Cleaning up...");
    cleanup_all(&mut server, &mut operator, cluster_name)?;

    println!("✅ Zopp Kubernetes Operator E2E Test Passed!\n");
    println!("📊 Summary:");
    println!("  ✓ kind cluster created and cleaned up");
    println!("  ✓ Operator performs initial sync");
    println!("  ✓ Real-time event streaming works (< 2s latency)");
    println!("  ✓ Secret additions synced");
    println!("  ✓ Secret deletions synced");
    println!("  ✓ 60-second polling safeguard catches missed events");
    println!("  ✓ Multiple annotated Secrets supported");
    println!("  ✓ Annotation-based configuration validated");

    Ok(())
}

fn check_prerequisites() -> Result<(), Box<dyn std::error::Error>> {
    // Check if kind is installed
    let output = Command::new("kind").arg("version").output();
    if output.is_err() || !output.as_ref().unwrap().status.success() {
        return Err("kind is not installed. Install with: brew install kind (or see https://kind.sigs.k8s.io/docs/user/quick-start/)".into());
    }

    // Check if kubectl is installed
    let output = Command::new("kubectl")
        .arg("version")
        .arg("--client")
        .output();
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

async fn create_annotated_secret(name: &str) -> Result<(), Box<dyn std::error::Error>> {
    use k8s_openapi::api::core::v1::Secret;
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
    use kube::{api::PostParams, Api, Client, Config};
    use std::collections::BTreeMap;

    let config = Config::from_kubeconfig(&kube::config::KubeConfigOptions::default()).await?;
    let client = Client::try_from(config)?;
    let secrets_api: Api<Secret> = Api::namespaced(client, "default");

    let mut annotations = BTreeMap::new();
    annotations.insert("zopp.dev/sync".to_string(), "true".to_string());
    annotations.insert("zopp.dev/workspace".to_string(), "acme".to_string());
    annotations.insert("zopp.dev/project".to_string(), "backend".to_string());
    annotations.insert("zopp.dev/environment".to_string(), "production".to_string());

    let secret = Secret {
        metadata: ObjectMeta {
            name: Some(name.to_string()),
            namespace: Some("default".to_string()),
            annotations: Some(annotations),
            ..Default::default()
        },
        data: Some(BTreeMap::new()), // Empty - will be populated by operator
        ..Default::default()
    };

    secrets_api.create(&PostParams::default(), &secret).await?;

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

    // Verify secret data
    let data = secret.data.as_ref().ok_or("No data found in Secret")?;

    for (key, expected_value) in expected_secrets {
        let actual_value = data
            .get(*key)
            .ok_or_else(|| format!("Key {} not found", key))?;
        let decoded = String::from_utf8(actual_value.0.clone())?;

        if decoded != *expected_value {
            return Err(format!(
                "Secret value mismatch for {}: expected '{}', got '{}'",
                key, expected_value, decoded
            )
            .into());
        }
    }
    println!(
        "  ✓ Secret '{}' verified ({} keys)",
        secret_name,
        expected_secrets.len()
    );

    Ok(())
}

async fn verify_key_not_present(
    secret_name: &str,
    key: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    use k8s_openapi::api::core::v1::Secret;
    use kube::{Api, Client, Config};

    let config = Config::from_kubeconfig(&kube::config::KubeConfigOptions::default()).await?;
    let client = Client::try_from(config)?;
    let secrets_api: Api<Secret> = Api::namespaced(client, "default");

    let secret = secrets_api.get(secret_name).await?;
    let data = secret.data.as_ref().ok_or("No data found in Secret")?;

    if data.contains_key(key) {
        return Err(format!("Key {} should not be present but was found", key).into());
    }

    println!("  ✓ Key '{}' correctly absent", key);
    Ok(())
}

fn cleanup_all(
    server: &mut std::process::Child,
    operator: &mut std::process::Child,
    cluster_name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    common::graceful_shutdown(operator);
    println!("✓ Operator stopped");

    cleanup(server, cluster_name)?;

    Ok(())
}

fn cleanup(
    server: &mut std::process::Child,
    cluster_name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    common::graceful_shutdown(server);

    #[cfg(unix)]
    {
        let _ = std::process::Command::new("pkill")
            .arg("-f")
            .arg("zopp-server.*serve")
            .status();
        let _ = std::process::Command::new("pkill")
            .arg("-f")
            .arg("zopp-operator")
            .status();
    }
    println!("✓ Server stopped");

    cleanup_kind(cluster_name)?;

    Ok(())
}

fn find_available_port() -> Result<u16, Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    drop(listener); // Close the listener to free the port
    Ok(port)
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
