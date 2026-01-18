//! Consolidated Kubernetes E2E tests.
//!
//! This file contains all K8s-related tests:
//! - CLI K8s sync (zopp sync k8s, zopp diff k8s)
//! - Operator sync (real-time event streaming)
//! - Self-signed TLS support
//!
//! Run with: cargo test --test k8s -- --test-threads=1
//! K8s tests must run sequentially as they use kind clusters.

mod common;

use common::{get_binary_paths, graceful_shutdown, parse_principal_id};
use std::collections::BTreeMap;
use std::fs;
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;
use tokio::time::sleep;

// ═══════════════════════════════════════════════════════════════════════════
// Shared K8s Test Infrastructure
// ═══════════════════════════════════════════════════════════════════════════

/// Find an available port
fn find_available_port() -> Result<u16, Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    drop(listener);
    Ok(port)
}

/// Check if K8s tests should be skipped (e.g., in CI where kind is flaky)
fn should_skip_k8s_tests() -> bool {
    std::env::var("SKIP_K8S_TESTS")
        .map(|v| v == "1")
        .unwrap_or(false)
}

/// Check if K8s prerequisites are available
fn check_k8s_prerequisites() -> Result<(), Box<dyn std::error::Error>> {
    // Check if kind is installed
    let output = Command::new("kind").arg("version").output();
    if output.is_err() || !output.as_ref().unwrap().status.success() {
        return Err("kind is not installed. Install with: brew install kind".into());
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

    Ok(())
}

/// Create a kind cluster
fn create_kind_cluster(name: &str) -> Result<(), Box<dyn std::error::Error>> {
    // Delete cluster if it exists
    let _ = Command::new("kind")
        .args(["delete", "cluster", "--name", name])
        .status();

    // Create cluster
    let status = Command::new("kind")
        .args(["create", "cluster", "--name", name, "--wait", "60s"])
        .status()?;

    if !status.success() {
        return Err("Failed to create kind cluster".into());
    }

    Ok(())
}

/// Delete a kind cluster
fn delete_kind_cluster(name: &str) {
    let _ = Command::new("kind")
        .args(["delete", "cluster", "--name", name])
        .stdout(Stdio::null())
        .status();
}

/// Get the path to kubeconfig (for kind clusters)
fn kubeconfig_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    PathBuf::from(home).join(".kube/config")
}

/// Create an annotated K8s secret for operator sync
async fn create_annotated_secret(
    name: &str,
    workspace: &str,
    project: &str,
    environment: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    use k8s_openapi::api::core::v1::Secret;
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
    use kube::{api::PostParams, Api, Client, Config};

    let config = Config::from_kubeconfig(&kube::config::KubeConfigOptions::default()).await?;
    let client = Client::try_from(config)?;
    let secrets_api: Api<Secret> = Api::namespaced(client, "default");

    let mut annotations = BTreeMap::new();
    annotations.insert("zopp.dev/sync".to_string(), "true".to_string());
    annotations.insert("zopp.dev/workspace".to_string(), workspace.to_string());
    annotations.insert("zopp.dev/project".to_string(), project.to_string());
    annotations.insert("zopp.dev/environment".to_string(), environment.to_string());

    let secret = Secret {
        metadata: ObjectMeta {
            name: Some(name.to_string()),
            namespace: Some("default".to_string()),
            annotations: Some(annotations),
            ..Default::default()
        },
        data: Some(BTreeMap::new()),
        ..Default::default()
    };

    secrets_api.create(&PostParams::default(), &secret).await?;

    Ok(())
}

/// Verify K8s secret has expected values
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

    let annotations = secret
        .metadata
        .annotations
        .as_ref()
        .ok_or("No annotations found")?;
    if !annotations.contains_key("zopp.dev/workspace")
        || !annotations.contains_key("zopp.dev/project")
        || !annotations.contains_key("zopp.dev/environment")
    {
        return Err("Missing zopp annotations".into());
    }

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

    Ok(())
}

/// Verify a key is NOT present in a K8s secret
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

    Ok(())
}

/// Verify K8s secret values (simpler version, returns bool)
async fn verify_k8s_secret_values(
    secret_name: &str,
    expected_secrets: &[(&str, &str)],
) -> Result<bool, Box<dyn std::error::Error>> {
    use k8s_openapi::api::core::v1::Secret;
    use kube::{Api, Client, Config};

    let config = Config::from_kubeconfig(&kube::config::KubeConfigOptions::default()).await?;
    let client = Client::try_from(config)?;
    let secrets_api: Api<Secret> = Api::namespaced(client, "default");

    let secret = secrets_api.get(secret_name).await?;
    let data = secret.data.as_ref().ok_or("No data found in Secret")?;

    for (key, expected_value) in expected_secrets {
        let actual_value = match data.get(*key) {
            Some(v) => v,
            None => return Ok(false),
        };
        let decoded = String::from_utf8(actual_value.0.clone())?;

        if decoded != *expected_value {
            return Ok(false);
        }
    }

    Ok(true)
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 1: CLI K8s Sync
// ═══════════════════════════════════════════════════════════════════════════

async fn cli_k8s_sync() -> Result<(), Box<dyn std::error::Error>> {
    if should_skip_k8s_tests() {
        println!("Skipping K8s tests (SKIP_K8S_TESTS=1)");
        return Ok(());
    }
    println!("🧪 Starting CLI K8s Sync E2E Test\n");

    check_k8s_prerequisites()?;
    let (zopp_server_bin, zopp_bin, _) = get_binary_paths()?;

    let server_port = find_available_port()?;
    let health_port = find_available_port()?;
    let server_url = format!("http://localhost:{}", server_port);

    let test_dir = PathBuf::from("/tmp/zopp-e2e-test-k8s");
    let alice_home = test_dir.join("alice");
    let db_path = test_dir.join("zopp.db");

    if test_dir.exists() {
        fs::remove_dir_all(&test_dir)?;
    }
    fs::create_dir_all(&alice_home)?;

    let cluster_name = "zopp-cli-sync-test";

    // Create kind cluster
    println!("☸️  Creating kind cluster...");
    create_kind_cluster(cluster_name)?;
    println!("✓ kind cluster '{}' created\n", cluster_name);

    // Start server
    println!("📡 Starting zopp server...");
    let mut server = Command::new(&zopp_server_bin)
        .env_remove("DATABASE_URL")
        .args([
            "--db",
            db_path.to_str().unwrap(),
            "serve",
            "--addr",
            &format!("0.0.0.0:{}", server_port),
            "--health-addr",
            &format!("0.0.0.0:{}", health_port),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;

    // Wait for server
    for i in 1..=30 {
        sleep(Duration::from_millis(200)).await;
        if TcpStream::connect(format!("127.0.0.1:{}", server_port)).is_ok() {
            println!("✓ Server started\n");
            break;
        }
        if i == 30 {
            graceful_shutdown(&mut server);
            delete_kind_cluster(cluster_name);
            return Err("Server failed to start".into());
        }
    }

    // Create server invite and setup Alice
    let output = Command::new(&zopp_server_bin)
        .env_remove("DATABASE_URL")
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
        graceful_shutdown(&mut server);
        delete_kind_cluster(cluster_name);
        return Err("Failed to create server invite".into());
    }

    let invite = String::from_utf8_lossy(&output.stdout).trim().to_string();

    // Alice joins
    let output = Command::new(&zopp_bin)
        .env("HOME", &alice_home)
        .env("ZOPP_USE_FILE_STORAGE", "true")
        .args([
            "--server",
            &server_url,
            "join",
            &invite,
            "alice@example.com",
            "--principal",
            "alice-macbook",
        ])
        .output()?;

    if !output.status.success() {
        graceful_shutdown(&mut server);
        delete_kind_cluster(cluster_name);
        return Err("Alice failed to join".into());
    }
    println!("✓ Alice joined\n");

    // Create workspace, project, environment
    for (cmd, args) in [
        ("workspace", vec!["create", "acme"]),
        ("project", vec!["create", "api", "-w", "acme"]),
        (
            "environment",
            vec!["create", "development", "-w", "acme", "-p", "api"],
        ),
    ] {
        let mut full_args = vec!["--server", &server_url, cmd];
        full_args.extend(args.iter().copied());
        let output = Command::new(&zopp_bin)
            .env("HOME", &alice_home)
            .env("ZOPP_USE_FILE_STORAGE", "true")
            .args(&full_args)
            .output()?;
        if !output.status.success() {
            graceful_shutdown(&mut server);
            delete_kind_cluster(cluster_name);
            return Err(format!("{} failed", cmd).into());
        }
    }
    println!("✓ Workspace/project/environment created\n");

    // Create zopp.toml
    fs::write(
        test_dir.join("zopp.toml"),
        "[defaults]\nworkspace = \"acme\"\nproject = \"api\"\nenvironment = \"development\"\n",
    )?;

    // Write secrets
    let secrets = vec![
        ("DATABASE_URL", "postgresql://localhost/mydb"),
        ("API_KEY", "sk-test-1234567890"),
        ("REDIS_URL", "redis://localhost:6379"),
    ];

    for (key, value) in &secrets {
        let output = Command::new(&zopp_bin)
            .env("HOME", &alice_home)
            .env("ZOPP_USE_FILE_STORAGE", "true")
            .current_dir(&test_dir)
            .args(["--server", &server_url, "secret", "set", key, value])
            .output()?;
        if !output.status.success() {
            graceful_shutdown(&mut server);
            delete_kind_cluster(cluster_name);
            return Err("Failed to set secret".into());
        }
    }
    println!("✓ Wrote {} secrets\n", secrets.len());

    // Sync to K8s
    println!("☸️  Syncing secrets to Kubernetes...");
    let kubeconfig = kubeconfig_path();
    let output = Command::new(&zopp_bin)
        .env("HOME", &alice_home)
        .env("ZOPP_USE_FILE_STORAGE", "true")
        .env("KUBECONFIG", &kubeconfig)
        .current_dir(&test_dir)
        .args([
            "--server",
            &server_url,
            "sync",
            "k8s",
            "--namespace",
            "default",
            "--secret",
            "zopp-test-secrets",
        ])
        .output()?;

    if !output.status.success() {
        graceful_shutdown(&mut server);
        delete_kind_cluster(cluster_name);
        return Err("K8s sync failed".into());
    }
    println!("✓ Secrets synced\n");

    // Verify K8s secret
    verify_k8s_secret("zopp-test-secrets", &secrets).await?;
    println!("✓ K8s secret verified\n");

    // Test update and re-sync
    println!("🔄 Testing secret update...");
    let _ = Command::new(&zopp_bin)
        .env("HOME", &alice_home)
        .env("ZOPP_USE_FILE_STORAGE", "true")
        .current_dir(&test_dir)
        .args([
            "--server",
            &server_url,
            "secret",
            "set",
            "DATABASE_URL",
            "postgresql://newhost/newdb",
        ])
        .output()?;

    let _ = Command::new(&zopp_bin)
        .env("HOME", &alice_home)
        .env("ZOPP_USE_FILE_STORAGE", "true")
        .env("KUBECONFIG", &kubeconfig)
        .current_dir(&test_dir)
        .args([
            "--server",
            &server_url,
            "sync",
            "k8s",
            "--namespace",
            "default",
            "--secret",
            "zopp-test-secrets",
        ])
        .output()?;

    let updated_secrets = vec![
        ("DATABASE_URL", "postgresql://newhost/newdb"),
        ("API_KEY", "sk-test-1234567890"),
        ("REDIS_URL", "redis://localhost:6379"),
    ];
    verify_k8s_secret("zopp-test-secrets", &updated_secrets).await?;
    println!("✓ Secret update verified\n");

    // Test dry-run
    println!("🔍 Testing --dry-run...");
    let _ = Command::new(&zopp_bin)
        .env("HOME", &alice_home)
        .env("ZOPP_USE_FILE_STORAGE", "true")
        .current_dir(&test_dir)
        .args([
            "--server",
            &server_url,
            "secret",
            "set",
            "API_KEY",
            "sk-new-key-456",
        ])
        .output()?;

    let output = Command::new(&zopp_bin)
        .env("HOME", &alice_home)
        .env("ZOPP_USE_FILE_STORAGE", "true")
        .env("KUBECONFIG", &kubeconfig)
        .current_dir(&test_dir)
        .args([
            "--server",
            &server_url,
            "sync",
            "k8s",
            "--namespace",
            "default",
            "--secret",
            "zopp-test-secrets",
            "--dry-run",
        ])
        .output()?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    if !stdout.contains("Dry run") {
        graceful_shutdown(&mut server);
        delete_kind_cluster(cluster_name);
        return Err("Dry-run output invalid".into());
    }

    // Verify secret was NOT updated (still old value)
    let still_old_secrets = vec![
        ("DATABASE_URL", "postgresql://newhost/newdb"),
        ("API_KEY", "sk-test-1234567890"), // Old value
        ("REDIS_URL", "redis://localhost:6379"),
    ];
    verify_k8s_secret("zopp-test-secrets", &still_old_secrets).await?;
    println!("✓ Dry-run verified (no changes applied)\n");

    // Test diff command
    println!("🔍 Testing diff command...");
    let output = Command::new(&zopp_bin)
        .env("HOME", &alice_home)
        .env("ZOPP_USE_FILE_STORAGE", "true")
        .env("KUBECONFIG", &kubeconfig)
        .current_dir(&test_dir)
        .args([
            "--server",
            &server_url,
            "diff",
            "k8s",
            "--namespace",
            "default",
            "--secret",
            "zopp-test-secrets",
        ])
        .output()?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    if !stdout.contains("API_KEY") || !stdout.contains("value differs") {
        graceful_shutdown(&mut server);
        delete_kind_cluster(cluster_name);
        return Err("Diff output invalid".into());
    }
    println!("✓ Diff command detected changes\n");

    // Test --force flag
    println!("⚠️  Testing --force flag...");
    let _ = Command::new("kubectl")
        .args([
            "create",
            "secret",
            "generic",
            "manual-secret",
            "--from-literal=foo=bar",
        ])
        .output()?;

    // Try without --force (should fail)
    let output = Command::new(&zopp_bin)
        .env("HOME", &alice_home)
        .env("ZOPP_USE_FILE_STORAGE", "true")
        .env("KUBECONFIG", &kubeconfig)
        .current_dir(&test_dir)
        .args([
            "--server",
            &server_url,
            "sync",
            "k8s",
            "--namespace",
            "default",
            "--secret",
            "manual-secret",
        ])
        .output()?;

    if output.status.success() {
        graceful_shutdown(&mut server);
        delete_kind_cluster(cluster_name);
        return Err("Sync should have failed without --force".into());
    }
    println!("  ✓ Sync correctly failed without --force");

    // Try with --force (should succeed)
    let output = Command::new(&zopp_bin)
        .env("HOME", &alice_home)
        .env("ZOPP_USE_FILE_STORAGE", "true")
        .env("KUBECONFIG", &kubeconfig)
        .current_dir(&test_dir)
        .args([
            "--server",
            &server_url,
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
        graceful_shutdown(&mut server);
        delete_kind_cluster(cluster_name);
        return Err("Sync with --force failed".into());
    }
    println!("  ✓ Sync with --force succeeded\n");

    // Cleanup
    graceful_shutdown(&mut server);
    delete_kind_cluster(cluster_name);

    println!("✅ CLI K8s Sync E2E Test Passed!\n");
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 2: Operator Sync
// ═══════════════════════════════════════════════════════════════════════════

async fn operator_sync() -> Result<(), Box<dyn std::error::Error>> {
    if should_skip_k8s_tests() {
        println!("Skipping K8s tests (SKIP_K8S_TESTS=1)");
        return Ok(());
    }
    println!("🧪 Starting Operator Sync E2E Test\n");

    check_k8s_prerequisites()?;
    let (zopp_server_bin, zopp_bin, operator_bin) = get_binary_paths()?;

    if !operator_bin.exists() {
        return Err("zopp-operator binary not found".into());
    }

    let server_port = find_available_port()?;
    let health_port = find_available_port()?;
    let server_url = format!("http://127.0.0.1:{}", server_port);

    let test_dir = std::env::temp_dir().join("zopp-e2e-operator-test");
    let alice_home = test_dir.join("alice");
    let operator_home = test_dir.join("operator");
    let db_path = test_dir.join("zopp.db");

    if test_dir.exists() {
        fs::remove_dir_all(&test_dir)?;
    }
    fs::create_dir_all(&alice_home)?;
    fs::create_dir_all(&operator_home)?;

    let cluster_name = "zopp-operator-test";

    // Create kind cluster
    println!("☸️  Creating kind cluster...");
    create_kind_cluster(cluster_name)?;
    println!("✓ kind cluster '{}' created\n", cluster_name);

    // Start server
    println!("📡 Starting zopp server...");
    let mut server = Command::new(&zopp_server_bin)
        .env_remove("DATABASE_URL")
        .args([
            "--db",
            db_path.to_str().unwrap(),
            "serve",
            "--addr",
            &format!("0.0.0.0:{}", server_port),
            "--health-addr",
            &format!("0.0.0.0:{}", health_port),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;

    // Wait for server
    for i in 1..=30 {
        sleep(Duration::from_millis(200)).await;
        if TcpStream::connect(format!("127.0.0.1:{}", server_port)).is_ok() {
            println!("✓ Server started\n");
            break;
        }
        if i == 30 {
            graceful_shutdown(&mut server);
            delete_kind_cluster(cluster_name);
            return Err("Server failed to start".into());
        }
    }

    // Setup Alice
    let output = Command::new(&zopp_server_bin)
        .env_remove("DATABASE_URL")
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

    let invite = String::from_utf8_lossy(&output.stdout).trim().to_string();

    let output = Command::new(&zopp_bin)
        .env("HOME", &alice_home)
        .env("ZOPP_USE_FILE_STORAGE", "true")
        .args([
            "--server",
            &server_url,
            "join",
            &invite,
            "alice@example.com",
            "--principal",
            "alice-laptop",
        ])
        .output()?;

    if !output.status.success() {
        graceful_shutdown(&mut server);
        delete_kind_cluster(cluster_name);
        return Err("Alice failed to join".into());
    }
    println!("✓ Alice joined\n");

    // Create workspace/project/environment
    for (cmd, args) in [
        ("workspace", vec!["create", "acme"]),
        ("project", vec!["create", "backend", "-w", "acme"]),
        (
            "environment",
            vec!["create", "production", "-w", "acme", "-p", "backend"],
        ),
    ] {
        let mut full_args = vec!["--server", &server_url, cmd];
        full_args.extend(args.iter().copied());
        let output = Command::new(&zopp_bin)
            .env("HOME", &alice_home)
            .env("ZOPP_USE_FILE_STORAGE", "true")
            .args(&full_args)
            .output()?;
        if !output.status.success() {
            graceful_shutdown(&mut server);
            delete_kind_cluster(cluster_name);
            return Err(format!("{} failed", cmd).into());
        }
    }

    fs::write(
        test_dir.join("zopp.toml"),
        "[defaults]\nworkspace = \"acme\"\nproject = \"backend\"\nenvironment = \"production\"\n",
    )?;
    println!("✓ Workspace/project/environment created\n");

    // Write initial secrets
    let initial_secrets = vec![
        ("DATABASE_URL", "postgresql://localhost/prod"),
        ("API_KEY", "sk-prod-key-123"),
        ("REDIS_URL", "redis://localhost:6379/0"),
    ];

    for (key, value) in &initial_secrets {
        let output = Command::new(&zopp_bin)
            .env("HOME", &alice_home)
            .env("ZOPP_USE_FILE_STORAGE", "true")
            .current_dir(&test_dir)
            .args(["--server", &server_url, "secret", "set", key, value])
            .output()?;
        if !output.status.success() {
            graceful_shutdown(&mut server);
            delete_kind_cluster(cluster_name);
            return Err("Failed to set secret".into());
        }
    }
    println!("✓ Wrote {} initial secrets\n", initial_secrets.len());

    // Create annotated K8s secret
    println!("☸️  Creating annotated Kubernetes Secret...");
    create_annotated_secret("app-secrets", "acme", "backend", "production").await?;
    println!("✓ Created annotated Secret\n");

    // Create service principal for operator
    println!("🔑 Setting up operator service principal...");
    let output = Command::new(&zopp_bin)
        .env("HOME", &alice_home)
        .env("ZOPP_USE_FILE_STORAGE", "true")
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
        graceful_shutdown(&mut server);
        delete_kind_cluster(cluster_name);
        return Err("Failed to create service principal".into());
    }

    let create_output = String::from_utf8_lossy(&output.stdout);
    let operator_principal_id =
        parse_principal_id(&create_output).ok_or("Failed to parse principal ID")?;

    // Copy service principal credentials
    let alice_config_path = alice_home.join(".zopp/config.json");
    let alice_config: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&alice_config_path)?)?;

    let service_principal = alice_config["principals"]
        .as_array()
        .and_then(|principals| {
            principals
                .iter()
                .find(|p| p["id"].as_str() == Some(&operator_principal_id))
        })
        .ok_or("Service principal not found in Alice's config")?
        .clone();

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

    // Grant READ permission
    let output = Command::new(&zopp_bin)
        .env("HOME", &alice_home)
        .env("ZOPP_USE_FILE_STORAGE", "true")
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
        graceful_shutdown(&mut server);
        delete_kind_cluster(cluster_name);
        return Err("Failed to set permission".into());
    }
    println!("✓ Service principal configured\n");

    // Start operator
    println!("🤖 Starting zopp operator...");
    let kubeconfig = kubeconfig_path();
    let config_file = operator_home.join(".zopp/config.json");
    let operator_health_port = find_available_port()?;

    let mut operator = Command::new(&operator_bin)
        .env("KUBECONFIG", &kubeconfig)
        .env("RUST_LOG", "info")
        .args([
            "--server",
            &server_url,
            "--credentials",
            config_file.to_str().unwrap(),
            "--namespace",
            "default",
            "--health-addr",
            &format!("127.0.0.1:{}", operator_health_port),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;

    println!("✓ Operator started\n");

    // Wait for operator health check
    let mut operator_healthy = false;
    for _ in 1..=20 {
        sleep(Duration::from_millis(100)).await;
        if let Ok(resp) = reqwest::get(&format!(
            "http://127.0.0.1:{}/healthz",
            operator_health_port
        ))
        .await
        {
            if resp.status().is_success() {
                operator_healthy = true;
                break;
            }
        }
    }
    if !operator_healthy {
        graceful_shutdown(&mut operator);
        graceful_shutdown(&mut server);
        return Err("Operator health check failed after 20 attempts".into());
    }

    // Wait for initial sync
    println!("⏳ Waiting for operator to sync...");
    sleep(Duration::from_secs(3)).await;

    // Verify secrets were synced (check values only, not labels for annotated secrets)
    match verify_k8s_secret_values("app-secrets", &initial_secrets).await {
        Ok(true) => println!("✓ Initial sync verified!\n"),
        _ => {
            graceful_shutdown(&mut operator);
            graceful_shutdown(&mut server);
            delete_kind_cluster(cluster_name);
            return Err("Initial sync failed".into());
        }
    }

    // Test real-time update
    println!("🔄 Testing real-time event streaming...");
    let _ = Command::new(&zopp_bin)
        .env("HOME", &alice_home)
        .env("ZOPP_USE_FILE_STORAGE", "true")
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

    sleep(Duration::from_secs(2)).await;

    let updated_secrets = vec![
        ("DATABASE_URL", "postgresql://newhost/prod"),
        ("API_KEY", "sk-prod-key-123"),
        ("REDIS_URL", "redis://localhost:6379/0"),
    ];
    match verify_k8s_secret_values("app-secrets", &updated_secrets).await {
        Ok(true) => println!("✓ Real-time sync verified!\n"),
        _ => {
            graceful_shutdown(&mut operator);
            graceful_shutdown(&mut server);
            delete_kind_cluster(cluster_name);
            return Err("Real-time sync failed".into());
        }
    }

    // Test new secret addition
    println!("➕ Testing new secret addition...");
    let _ = Command::new(&zopp_bin)
        .env("HOME", &alice_home)
        .env("ZOPP_USE_FILE_STORAGE", "true")
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

    sleep(Duration::from_secs(2)).await;

    let with_new_secret = vec![
        ("DATABASE_URL", "postgresql://newhost/prod"),
        ("API_KEY", "sk-prod-key-123"),
        ("REDIS_URL", "redis://localhost:6379/0"),
        ("SMTP_HOST", "smtp.example.com"),
    ];
    match verify_k8s_secret_values("app-secrets", &with_new_secret).await {
        Ok(true) => println!("✓ New secret synced!\n"),
        _ => {
            graceful_shutdown(&mut operator);
            graceful_shutdown(&mut server);
            delete_kind_cluster(cluster_name);
            return Err("New secret sync failed".into());
        }
    }

    // Test secret deletion
    println!("🗑️  Testing secret deletion...");
    let _ = Command::new(&zopp_bin)
        .env("HOME", &alice_home)
        .env("ZOPP_USE_FILE_STORAGE", "true")
        .current_dir(&test_dir)
        .args(["--server", &server_url, "secret", "delete", "SMTP_HOST"])
        .output()?;

    sleep(Duration::from_secs(2)).await;

    verify_key_not_present("app-secrets", "SMTP_HOST").await?;
    println!("✓ Secret deletion synced!\n");

    // Cleanup
    graceful_shutdown(&mut operator);
    graceful_shutdown(&mut server);
    delete_kind_cluster(cluster_name);

    println!("✅ Operator Sync E2E Test Passed!\n");
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 3: Self-Signed TLS
// ═══════════════════════════════════════════════════════════════════════════

async fn self_signed_tls() -> Result<(), Box<dyn std::error::Error>> {
    if should_skip_k8s_tests() {
        println!("Skipping K8s tests (SKIP_K8S_TESTS=1)");
        return Ok(());
    }
    println!("🔐 Starting Self-Signed TLS E2E Test\n");

    // Check openssl
    let output = Command::new("openssl").arg("version").output();
    if output.is_err() || !output.as_ref().unwrap().status.success() {
        return Err("openssl is not installed".into());
    }

    check_k8s_prerequisites()?;
    let (zopp_server_bin, zopp_bin, operator_bin) = get_binary_paths()?;

    let server_port = find_available_port()?;
    let health_port = find_available_port()?;
    let operator_health_port = find_available_port()?;
    let server_url = format!("https://localhost:{}", server_port);

    let test_dir = std::env::temp_dir().join("zopp-tls-e2e-test");
    let alice_home = test_dir.join("alice");
    let certs_dir = test_dir.join("certs");
    let db_path = test_dir.join("zopp.db");

    if test_dir.exists() {
        fs::remove_dir_all(&test_dir)?;
    }
    fs::create_dir_all(&alice_home)?;
    fs::create_dir_all(&certs_dir)?;

    // Generate self-signed certificates
    println!("🔑 Generating self-signed certificates...");
    generate_self_signed_certs(&certs_dir)?;
    println!("✓ Certificates generated\n");

    let ca_cert = certs_dir.join("ca.crt");
    let server_cert = certs_dir.join("server.crt");
    let server_key = certs_dir.join("server.key");

    let cluster_name = "zopp-tls-test";

    // Create kind cluster
    println!("☸️  Creating kind cluster...");
    create_kind_cluster(cluster_name)?;
    println!("✓ kind cluster created\n");

    // Start server with TLS
    println!("📡 Starting zopp server with TLS...");
    let mut server = Command::new(&zopp_server_bin)
        .env_remove("DATABASE_URL")
        .args([
            "--db",
            db_path.to_str().unwrap(),
            "serve",
            "--addr",
            &format!("0.0.0.0:{}", server_port),
            "--health-addr",
            &format!("0.0.0.0:{}", health_port),
            "--tls-cert",
            server_cert.to_str().unwrap(),
            "--tls-key",
            server_key.to_str().unwrap(),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;

    // Wait for server
    for i in 1..=30 {
        sleep(Duration::from_millis(200)).await;
        if TcpStream::connect(format!("127.0.0.1:{}", server_port)).is_ok() {
            println!("✓ Server started with TLS\n");
            break;
        }
        if i == 30 {
            graceful_shutdown(&mut server);
            delete_kind_cluster(cluster_name);
            return Err("Server failed to start".into());
        }
    }

    // Create server invite
    let output = Command::new(&zopp_server_bin)
        .env_remove("DATABASE_URL")
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

    let invite = String::from_utf8_lossy(&output.stdout).trim().to_string();

    // Alice joins via TLS
    println!("👩 Alice joining via TLS...");
    let output = Command::new(&zopp_bin)
        .env("HOME", &alice_home)
        .env("ZOPP_USE_FILE_STORAGE", "true")
        .args([
            "--server",
            &server_url,
            "--tls-ca-cert",
            ca_cert.to_str().unwrap(),
            "join",
            &invite,
            "alice@example.com",
            "--principal",
            "alice-laptop",
        ])
        .output()?;

    if !output.status.success() {
        graceful_shutdown(&mut server);
        delete_kind_cluster(cluster_name);
        return Err(format!(
            "Alice failed to join: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    println!("✓ Alice joined via TLS\n");

    // Create workspace/project/environment
    for (cmd, args) in [
        ("workspace", vec!["create", "acme"]),
        ("project", vec!["create", "backend", "-w", "acme"]),
        (
            "environment",
            vec!["create", "prod", "-w", "acme", "-p", "backend"],
        ),
    ] {
        let mut full_args = vec![
            "--server",
            &server_url,
            "--tls-ca-cert",
            ca_cert.to_str().unwrap(),
            cmd,
        ];
        full_args.extend(args.iter().copied());
        let output = Command::new(&zopp_bin)
            .env("HOME", &alice_home)
            .env("ZOPP_USE_FILE_STORAGE", "true")
            .args(&full_args)
            .output()?;
        if !output.status.success() {
            graceful_shutdown(&mut server);
            delete_kind_cluster(cluster_name);
            return Err(format!("{} failed", cmd).into());
        }
    }
    println!("✓ Workspace/project/environment created\n");

    // Set a secret via TLS
    println!("🔐 Setting secret via TLS...");
    let output = Command::new(&zopp_bin)
        .env("HOME", &alice_home)
        .env("ZOPP_USE_FILE_STORAGE", "true")
        .args([
            "--server",
            &server_url,
            "--tls-ca-cert",
            ca_cert.to_str().unwrap(),
            "secret",
            "set",
            "DATABASE_URL",
            "postgresql://localhost/prod",
            "-w",
            "acme",
            "-p",
            "backend",
            "-e",
            "prod",
        ])
        .output()?;

    if !output.status.success() {
        graceful_shutdown(&mut server);
        delete_kind_cluster(cluster_name);
        return Err("Failed to set secret".into());
    }
    println!("✓ Secret set via TLS\n");

    // Get secret via TLS
    println!("🔍 Getting secret via TLS...");
    let output = Command::new(&zopp_bin)
        .env("HOME", &alice_home)
        .env("ZOPP_USE_FILE_STORAGE", "true")
        .args([
            "--server",
            &server_url,
            "--tls-ca-cert",
            ca_cert.to_str().unwrap(),
            "secret",
            "get",
            "DATABASE_URL",
            "-w",
            "acme",
            "-p",
            "backend",
            "-e",
            "prod",
        ])
        .output()?;

    if !output.status.success() {
        graceful_shutdown(&mut server);
        delete_kind_cluster(cluster_name);
        return Err("Failed to get secret".into());
    }

    let secret_value = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if secret_value != "postgresql://localhost/prod" {
        graceful_shutdown(&mut server);
        delete_kind_cluster(cluster_name);
        return Err("Secret value mismatch".into());
    }
    println!("✓ Secret retrieved via TLS: {}\n", secret_value);

    // Create annotated K8s secret for operator
    create_annotated_secret("app-secrets", "acme", "backend", "prod").await?;

    // Start operator with TLS
    println!("🤖 Starting operator with TLS...");
    let kubeconfig = kubeconfig_path();
    let config_file = alice_home.join(".zopp/config.json");

    let mut operator = Command::new(&operator_bin)
        .env("KUBECONFIG", &kubeconfig)
        .env("RUST_LOG", "info")
        .args([
            "--server",
            &server_url,
            "--tls-ca-cert",
            ca_cert.to_str().unwrap(),
            "--credentials",
            config_file.to_str().unwrap(),
            "--namespace",
            "default",
            "--health-addr",
            &format!("127.0.0.1:{}", operator_health_port),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;

    println!("✓ Operator started with TLS\n");

    // Wait for sync
    println!("⏳ Waiting for operator to sync...");
    sleep(Duration::from_secs(10)).await;

    // Verify secret was synced
    match verify_k8s_secret_values(
        "app-secrets",
        &[("DATABASE_URL", "postgresql://localhost/prod")],
    )
    .await
    {
        Ok(true) => println!("✓ Operator synced via TLS!\n"),
        _ => {
            graceful_shutdown(&mut operator);
            graceful_shutdown(&mut server);
            delete_kind_cluster(cluster_name);
            return Err("Secret not synced correctly".into());
        }
    }

    // Cleanup
    graceful_shutdown(&mut operator);
    graceful_shutdown(&mut server);
    delete_kind_cluster(cluster_name);

    println!("✅ Self-Signed TLS E2E Test Passed!\n");
    Ok(())
}

fn generate_self_signed_certs(
    certs_dir: &std::path::Path,
) -> Result<(), Box<dyn std::error::Error>> {
    // Generate CA private key
    let status = Command::new("openssl")
        .args([
            "genrsa",
            "-out",
            certs_dir.join("ca.key").to_str().unwrap(),
            "2048",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    if !status.success() {
        return Err("Failed to generate CA private key".into());
    }

    // Generate CA certificate
    let status = Command::new("openssl")
        .args([
            "req",
            "-x509",
            "-new",
            "-nodes",
            "-key",
            certs_dir.join("ca.key").to_str().unwrap(),
            "-sha256",
            "-days",
            "1",
            "-out",
            certs_dir.join("ca.crt").to_str().unwrap(),
            "-subj",
            "/CN=Zopp Test CA",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    if !status.success() {
        return Err("Failed to generate CA certificate".into());
    }

    // Generate server private key
    let status = Command::new("openssl")
        .args([
            "genrsa",
            "-out",
            certs_dir.join("server.key").to_str().unwrap(),
            "2048",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    if !status.success() {
        return Err("Failed to generate server private key".into());
    }

    // Generate server CSR
    let status = Command::new("openssl")
        .args([
            "req",
            "-new",
            "-key",
            certs_dir.join("server.key").to_str().unwrap(),
            "-out",
            certs_dir.join("server.csr").to_str().unwrap(),
            "-subj",
            "/CN=localhost",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    if !status.success() {
        return Err("Failed to generate server CSR".into());
    }

    // Create SAN config
    let san_config = certs_dir.join("san.cnf");
    fs::write(
        &san_config,
        "subjectAltName=DNS:localhost,DNS:host.docker.internal,IP:127.0.0.1",
    )?;

    // Sign server certificate with CA
    let status = Command::new("openssl")
        .args([
            "x509",
            "-req",
            "-in",
            certs_dir.join("server.csr").to_str().unwrap(),
            "-CA",
            certs_dir.join("ca.crt").to_str().unwrap(),
            "-CAkey",
            certs_dir.join("ca.key").to_str().unwrap(),
            "-CAcreateserial",
            "-out",
            certs_dir.join("server.crt").to_str().unwrap(),
            "-days",
            "1",
            "-sha256",
            "-extfile",
            san_config.to_str().unwrap(),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    if !status.success() {
        return Err("Failed to sign server certificate".into());
    }

    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════
// Main Entry Point (harness = false)
// ═══════════════════════════════════════════════════════════════════════════

fn main() {
    // Check if K8s tests should be skipped
    if should_skip_k8s_tests() {
        println!("Skipping K8s tests (SKIP_K8S_TESTS=1)");
        return;
    }

    // Check prerequisites
    if let Err(e) = check_k8s_prerequisites() {
        println!("Skipping K8s tests: {}", e);
        return;
    }

    // Create tokio runtime
    let rt = tokio::runtime::Runtime::new().expect("Failed to create Tokio runtime");

    // Run tests sequentially
    println!("Running K8s E2E tests...\n");

    println!("=== Test 1: CLI K8s Sync ===");
    if let Err(e) = rt.block_on(cli_k8s_sync()) {
        eprintln!("FAILED: cli_k8s_sync: {}", e);
        std::process::exit(1);
    }
    println!("PASSED: cli_k8s_sync\n");

    println!("=== Test 2: Operator Sync ===");
    if let Err(e) = rt.block_on(operator_sync()) {
        eprintln!("FAILED: operator_sync: {}", e);
        std::process::exit(1);
    }
    println!("PASSED: operator_sync\n");

    println!("=== Test 3: Self-signed TLS ===");
    if let Err(e) = rt.block_on(self_signed_tls()) {
        eprintln!("FAILED: self_signed_tls: {}", e);
        std::process::exit(1);
    }
    println!("PASSED: self_signed_tls\n");

    println!("All K8s tests passed!");
}
