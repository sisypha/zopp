mod common;

use std::fs;
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;
use tokio::time::sleep;

/// E2E test for self-signed TLS certificates
/// Tests: CLI + Server with self-signed TLS, Operator sync with self-signed TLS
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔐 Starting Self-Signed TLS E2E Test\n");

    // Check prerequisites
    check_prerequisites()?;

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

    let zopp_server_bin = bin_dir.join("zopp-server");
    let zopp_bin = bin_dir.join("zopp");
    let operator_bin = bin_dir.join("zopp-operator");

    if !zopp_server_bin.exists() || !zopp_bin.exists() || !operator_bin.exists() {
        eprintln!("❌ Binaries not found. Please run 'cargo build --bins' first.");
        return Err("Binaries not built".into());
    }

    println!("✓ Using prebuilt binaries");

    // Find available ports for server and operator health checks
    let server_port = find_available_port()?;
    let server_health_port = find_available_port()?;
    let operator_health_port = find_available_port()?;
    println!(
        "✓ Allocated ports: server={}, server_health={}, operator_health={}\n",
        server_port, server_health_port, operator_health_port
    );

    // Setup test directories
    let test_dir = std::env::temp_dir().join("zopp-tls-e2e-test");
    let alice_home = test_dir.join("alice");
    let certs_dir = test_dir.join("certs");
    let db_path = test_dir.join("zopp.db");

    // Clean up from previous runs
    if test_dir.exists() {
        fs::remove_dir_all(&test_dir)?;
    }
    fs::create_dir_all(&alice_home)?;
    fs::create_dir_all(&certs_dir)?;

    println!("✓ Test directories created\n");

    // Step 1: Generate self-signed certificates
    println!("🔑 Step 1: Generating self-signed certificates...");
    generate_self_signed_certs(&certs_dir)?;
    println!("✓ Certificates generated\n");

    let ca_cert = certs_dir.join("ca.crt");
    let server_cert = certs_dir.join("server.crt");
    let server_key = certs_dir.join("server.key");

    let server_url = format!("https://localhost:{}", server_port);

    // Step 2: Start server with TLS
    println!("📡 Step 2: Starting zopp server with TLS...");
    let server_log = test_dir.join("server.log");
    let log_file = fs::File::create(&server_log)?;
    let server_addr = format!("0.0.0.0:{}", server_port);
    let health_addr = format!("0.0.0.0:{}", server_health_port);
    let mut server = Command::new(&zopp_server_bin)
        .env("RUST_LOG", "info")
        .args([
            "--db",
            db_path.to_str().unwrap(),
            "serve",
            "--addr",
            &server_addr,
            "--health-addr",
            &health_addr,
            "--tls-cert",
            server_cert.to_str().unwrap(),
            "--tls-key",
            server_key.to_str().unwrap(),
        ])
        .stdout(log_file.try_clone()?)
        .stderr(log_file)
        .spawn()?;

    // Wait for server to be ready
    let mut ready = false;
    let server_connect_addr = format!("127.0.0.1:{}", server_port);
    for i in 1..=30 {
        sleep(Duration::from_millis(200)).await;
        if TcpStream::connect(&server_connect_addr).is_ok() {
            ready = true;
            println!("✓ Server started with TLS (PID: {})\n", server.id());
            break;
        }
        if i == 30 {
            eprintln!("❌ Server failed to start within 6 seconds");
            common::graceful_shutdown(&mut server);
            return Err("Server not ready".into());
        }
    }
    if !ready {
        return Err("Server failed to start".into());
    }

    // Step 3: Create server invite
    println!("🎫 Step 3: Creating server invite...");
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
        common::graceful_shutdown(&mut server);
        return Err("Failed to create server invite".into());
    }

    let alice_invite = String::from_utf8_lossy(&output.stdout).trim().to_string();
    println!("✓ Server invite created\n");

    // Step 4: Alice joins via CLI with TLS
    println!("👩 Step 4: Alice joins server using CLI with TLS...");
    let output = Command::new(&zopp_bin)
        .env("HOME", &alice_home)
        .args([
            "--server",
            &server_url,
            "--tls-ca-cert",
            ca_cert.to_str().unwrap(),
            "join",
            &alice_invite,
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
        eprintln!("\nServer logs:");
        if let Ok(log_contents) = fs::read_to_string(&server_log) {
            eprintln!("{}", log_contents);
        }
        common::graceful_shutdown(&mut server);
        return Err("Alice failed to join".into());
    }
    println!("✓ Alice joined successfully via TLS\n");

    // Step 5: Create workspace, project, environment
    println!("🏢 Step 5: Setting up workspace, project, environment...");

    let output = Command::new(&zopp_bin)
        .env("HOME", &alice_home)
        .args([
            "--server",
            &server_url,
            "--tls-ca-cert",
            ca_cert.to_str().unwrap(),
            "workspace",
            "create",
            "acme",
        ])
        .output()?;
    if !output.status.success() {
        common::graceful_shutdown(&mut server);
        return Err("Failed to create workspace".into());
    }

    let output = Command::new(&zopp_bin)
        .env("HOME", &alice_home)
        .args([
            "--server",
            &server_url,
            "--tls-ca-cert",
            ca_cert.to_str().unwrap(),
            "project",
            "create",
            "backend",
            "-w",
            "acme",
        ])
        .output()?;
    if !output.status.success() {
        common::graceful_shutdown(&mut server);
        return Err("Failed to create project".into());
    }

    let output = Command::new(&zopp_bin)
        .env("HOME", &alice_home)
        .args([
            "--server",
            &server_url,
            "--tls-ca-cert",
            ca_cert.to_str().unwrap(),
            "environment",
            "create",
            "prod",
            "-w",
            "acme",
            "-p",
            "backend",
        ])
        .output()?;
    if !output.status.success() {
        common::graceful_shutdown(&mut server);
        return Err("Failed to create environment".into());
    }
    println!("✓ Workspace/project/environment created\n");

    // Step 6: Set a secret via CLI with TLS
    println!("🔐 Step 6: Setting secret via CLI with TLS...");
    let output = Command::new(&zopp_bin)
        .env("HOME", &alice_home)
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
        common::graceful_shutdown(&mut server);
        return Err("Failed to set secret".into());
    }
    println!("✓ Secret set successfully\n");

    // Step 7: Verify secret retrieval via CLI with TLS
    println!("🔍 Step 7: Retrieving secret via CLI with TLS...");
    let output = Command::new(&zopp_bin)
        .env("HOME", &alice_home)
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
        common::graceful_shutdown(&mut server);
        return Err("Failed to get secret".into());
    }
    let secret_value = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if secret_value != "postgresql://localhost/prod" {
        common::graceful_shutdown(&mut server);
        return Err(format!(
            "Secret mismatch: expected 'postgresql://localhost/prod', got '{}'",
            secret_value
        )
        .into());
    }
    println!("✓ Secret retrieved correctly: {}\n", secret_value);

    // Step 8: Test operator with TLS (requires kind cluster)
    println!("☸️  Step 8: Testing operator sync with TLS...");
    let cluster_name = "zopp-tls-test";

    // Delete cluster if it exists
    let _ = Command::new("kind")
        .args(["delete", "cluster", "--name", cluster_name])
        .status();

    println!("  Creating kind cluster...");
    let status = Command::new("kind")
        .args(["create", "cluster", "--name", cluster_name, "--wait", "60s"])
        .status()?;

    if !status.success() {
        eprintln!("❌ kind cluster creation failed");
        common::graceful_shutdown(&mut server);
        return Err("Failed to create kind cluster".into());
    }
    println!("✓ kind cluster created\n");

    // Create Kubernetes secret for operator
    println!("  Creating K8s secret with operator credentials...");
    create_k8s_secret(
        "default",
        "zopp-operator-creds",
        &alice_home.join(".zopp/config.json"),
    )
    .await?;

    create_k8s_secret_from_file("default", "zopp-server-ca", &ca_cert, "ca.crt").await?;

    // Create annotated K8s secret
    create_annotated_secret("app-secrets", "acme", "backend", "prod").await?;
    println!("✓ K8s secrets created\n");

    // Start operator with TLS
    println!("  Starting operator with TLS...");
    let real_home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    let kubeconfig = PathBuf::from(&real_home).join(".kube/config");

    let operator_log = test_dir.join("operator.log");
    let op_log_file = fs::File::create(&operator_log)?;
    let operator_health_addr = format!("0.0.0.0:{}", operator_health_port);
    let mut operator = Command::new(&operator_bin)
        .env("KUBECONFIG", &kubeconfig)
        .env("RUST_LOG", "info")
        .args([
            "--server",
            &server_url,
            "--tls-ca-cert",
            ca_cert.to_str().unwrap(),
            "--credentials",
            alice_home.join(".zopp/config.json").to_str().unwrap(),
            "--namespace",
            "default",
            "--health-addr",
            &operator_health_addr,
        ])
        .stdout(op_log_file.try_clone()?)
        .stderr(op_log_file)
        .spawn()?;

    println!("✓ Operator started (PID: {})", operator.id());

    // Wait for sync
    println!("  Waiting for operator to sync secret...");
    sleep(Duration::from_secs(10)).await;

    // Verify secret was synced
    match verify_k8s_secret(
        "app-secrets",
        &[("DATABASE_URL", "postgresql://localhost/prod")],
    )
    .await
    {
        Ok(true) => {}
        Ok(false) | Err(_) => {
            eprintln!("\n❌ Secret not synced correctly");
            eprintln!("\nOperator logs:");
            if let Ok(log_contents) = fs::read_to_string(&operator_log) {
                eprintln!("{}", log_contents);
            }
            eprintln!("\nServer logs:");
            if let Ok(log_contents) = fs::read_to_string(&server_log) {
                eprintln!("{}", log_contents);
            }
            common::graceful_shutdown(&mut operator);
            common::graceful_shutdown(&mut server);
            cleanup_kind(cluster_name)?;
            return Err("Secret not synced correctly".into());
        }
    };
    println!("✓ Operator synced secret successfully via TLS!\n");

    // Cleanup
    println!("🧹 Cleaning up...");
    common::graceful_shutdown(&mut operator);
    common::graceful_shutdown(&mut server);
    cleanup_kind(cluster_name)?;

    println!("\n✅ Self-Signed TLS E2E Test Passed!");
    println!("\n📊 Summary:");
    println!("  ✓ Generated self-signed certificates");
    println!("  ✓ Server started with self-signed TLS");
    println!("  ✓ CLI joined server via self-signed TLS");
    println!("  ✓ CLI set/get secret via self-signed TLS");
    println!("  ✓ Operator synced secret via self-signed TLS");

    Ok(())
}

fn check_prerequisites() -> Result<(), Box<dyn std::error::Error>> {
    // Check if openssl is installed
    let output = Command::new("openssl").arg("version").output();
    if output.is_err() || !output.as_ref().unwrap().status.success() {
        return Err("openssl is not installed. Install with: brew install openssl".into());
    }

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

    println!("✓ Prerequisites checked (openssl, kind, kubectl, docker)\n");
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
        .status()?;
    if !status.success() {
        return Err("Failed to sign server certificate".into());
    }

    Ok(())
}

async fn create_k8s_secret(
    namespace: &str,
    name: &str,
    file_path: &std::path::Path,
) -> Result<(), Box<dyn std::error::Error>> {
    Command::new("kubectl")
        .args([
            "create",
            "secret",
            "generic",
            name,
            "-n",
            namespace,
            "--from-file",
            &format!("config.json={}", file_path.to_str().unwrap()),
        ])
        .stdout(Stdio::null())
        .status()?;
    Ok(())
}

async fn create_k8s_secret_from_file(
    namespace: &str,
    name: &str,
    file_path: &std::path::Path,
    key: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let status = Command::new("kubectl")
        .args([
            "create",
            "secret",
            "generic",
            name,
            "-n",
            namespace,
            "--from-file",
            &format!("{}={}", key, file_path.to_str().unwrap()),
        ])
        .stdout(Stdio::null())
        .status()?;
    if !status.success() {
        return Err(format!("Failed to create Kubernetes secret '{}'", name).into());
    }
    Ok(())
}

async fn create_annotated_secret(
    name: &str,
    workspace: &str,
    project: &str,
    environment: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    use k8s_openapi::api::core::v1::Secret;
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
    use kube::{api::PostParams, Api, Client, Config};
    use std::collections::BTreeMap;

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

async fn verify_k8s_secret(
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

fn find_available_port() -> Result<u16, Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    drop(listener); // Close the listener to free the port
    Ok(port)
}

fn cleanup_kind(cluster_name: &str) -> Result<(), Box<dyn std::error::Error>> {
    let _ = Command::new("kind")
        .args(["delete", "cluster", "--name", cluster_name])
        .stdout(Stdio::null())
        .status();
    Ok(())
}
