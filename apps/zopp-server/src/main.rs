mod backend;
mod handlers;
mod server;

use chrono::Utc;
use clap::{Parser, Subcommand};
#[allow(unused_imports)]
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
#[allow(unused_imports)]
use rand_core::OsRng;
use std::sync::Arc;
use tonic::transport::Server;

use backend::StoreBackend;
use server::ZoppServer;
use zopp_events::EventBus;
use zopp_events_memory::MemoryEventBus;
use zopp_proto::zopp_service_server::ZoppServiceServer;
use zopp_storage::{CreateInviteParams, Store};
use zopp_store_postgres::PostgresStore;
use zopp_store_sqlite::SqliteStore;

// ────────────────────────────────────── CLI Types ──────────────────────────────────────

#[derive(Parser)]
#[command(name = "zopp-server")]
#[command(about = "Zopp server CLI for administration and serving")]
struct Cli {
    /// Database URL (sqlite://path/to/db.db or postgres://user:pass@host/db)
    #[arg(long, global = true, env = "DATABASE_URL")]
    database_url: Option<String>,

    /// Legacy: Path to SQLite database file (deprecated, use --database-url instead)
    #[arg(long, global = true, env = "ZOPP_DB_PATH")]
    db: Option<String>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Start the gRPC server
    Serve {
        /// Server address
        #[arg(long, default_value = "0.0.0.0:50051")]
        addr: String,

        /// Health check HTTP server address
        #[arg(long, default_value = "0.0.0.0:8080")]
        health_addr: String,

        /// Path to TLS certificate file (PEM format)
        #[arg(long, env = "ZOPP_TLS_CERT")]
        tls_cert: Option<String>,

        /// Path to TLS private key file (PEM format)
        #[arg(long, env = "ZOPP_TLS_KEY")]
        tls_key: Option<String>,

        /// Path to CA certificate for client verification (enables mTLS)
        #[arg(long, env = "ZOPP_TLS_CLIENT_CA")]
        tls_client_ca: Option<String>,
    },
    /// Invite management commands
    Invite {
        #[command(subcommand)]
        invite_cmd: InviteCommand,
    },
}

#[derive(Subcommand)]
enum InviteCommand {
    /// Create a new server invite token (for bootstrapping)
    Create {
        /// Expiration duration in hours
        #[arg(long, default_value = "24")]
        expires_hours: i64,
        /// Output only the token (for scripts)
        #[arg(long)]
        plain: bool,
    },
    /// List all server invites
    List,
    /// Revoke an invite
    Revoke {
        /// Invite token to revoke
        token: String,
    },
}

// ────────────────────────────────────── CLI Commands ──────────────────────────────────────

async fn cmd_invite_create(
    db_url: &str,
    expires_hours: i64,
    plain: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let backend: StoreBackend = if db_url.starts_with("postgres:") {
        StoreBackend::Postgres(Arc::new(PostgresStore::open(db_url).await?))
    } else {
        StoreBackend::Sqlite(Arc::new(SqliteStore::open(db_url).await?))
    };

    // Generate random token for server invite (32 bytes = 256 bits)
    use rand_core::RngCore;
    let mut token_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut token_bytes);
    let token = hex::encode(token_bytes);

    let expires_at = Utc::now() + chrono::Duration::hours(expires_hours);
    let invite = backend
        .create_invite(&CreateInviteParams {
            workspace_ids: vec![],
            token,
            kek_encrypted: None,
            kek_nonce: None,
            expires_at,
            created_by_user_id: None,
        })
        .await?;

    if plain {
        println!("{}", invite.token);
    } else {
        println!("✓ Server invite created!\n");
        println!("Token:   {}", invite.token);
        println!("Expires: {}", invite.expires_at);
        println!("\nUse this token to join this server using zopp join");
    }

    Ok(())
}

async fn cmd_invite_list(db_url: &str) -> Result<(), Box<dyn std::error::Error>> {
    let backend: StoreBackend = if db_url.starts_with("postgres:") {
        StoreBackend::Postgres(Arc::new(PostgresStore::open(db_url).await?))
    } else {
        StoreBackend::Sqlite(Arc::new(SqliteStore::open(db_url).await?))
    };

    let invites = backend.list_invites(None).await?;

    if invites.is_empty() {
        println!("No active server invites found.");
    } else {
        println!("Active server invites:\n");
        for invite in invites {
            println!("Token:   {}", invite.token);
            println!("Expires: {}", invite.expires_at);
            println!();
        }
    }

    Ok(())
}

async fn cmd_invite_revoke(db_url: &str, token: &str) -> Result<(), Box<dyn std::error::Error>> {
    let backend: StoreBackend = if db_url.starts_with("postgres:") {
        StoreBackend::Postgres(Arc::new(PostgresStore::open(db_url).await?))
    } else {
        StoreBackend::Sqlite(Arc::new(SqliteStore::open(db_url).await?))
    };

    let invite = backend.get_invite_by_token(token).await?;

    backend.revoke_invite(&invite.id).await?;

    println!("✓ Invite token {} revoked", token);

    Ok(())
}

async fn cmd_serve(
    database_url: Option<String>,
    legacy_db_path: Option<String>,
    addr: &str,
    health_addr: &str,
    tls_cert: Option<String>,
    tls_key: Option<String>,
    tls_client_ca: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    cmd_serve_with_ready(
        database_url,
        legacy_db_path,
        addr,
        health_addr,
        tls_cert,
        tls_key,
        tls_client_ca,
        None,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn cmd_serve_with_ready(
    database_url: Option<String>,
    legacy_db_path: Option<String>,
    addr: &str,
    health_addr: &str,
    tls_cert: Option<String>,
    tls_key: Option<String>,
    tls_client_ca: Option<String>,
    ready_tx: Option<tokio::sync::oneshot::Sender<(std::net::SocketAddr, std::net::SocketAddr)>>,
) -> Result<(), Box<dyn std::error::Error>> {
    use axum::{routing::get, Router};

    let addr: std::net::SocketAddr = addr.parse()?;
    let health_addr: std::net::SocketAddr = health_addr.parse()?;

    // Validate TLS configuration BEFORE opening database
    // Validate TLS configuration: both cert and key must be provided together
    match (&tls_cert, &tls_key) {
        (Some(_), None) => {
            return Err("TLS certificate provided without key. Both --tls-cert and --tls-key are required for TLS.".into());
        }
        (None, Some(_)) => {
            return Err("TLS key provided without certificate. Both --tls-cert and --tls-key are required for TLS.".into());
        }
        _ => {}
    }

    // Validate client CA requires TLS to be configured
    if tls_client_ca.is_some() && tls_cert.is_none() {
        return Err("--tls-client-ca requires --tls-cert and --tls-key to be configured".into());
    }

    // Determine database URL
    let db_url = if let Some(url) = database_url {
        url
    } else if let Some(path) = legacy_db_path {
        if path.starts_with("sqlite:") || path.starts_with("postgres:") {
            path
        } else {
            format!("sqlite://{}?mode=rwc", path)
        }
    } else {
        "sqlite://zopp.db?mode=rwc".to_string()
    };

    // Create backend based on URL scheme
    let backend = if db_url.starts_with("postgres:") {
        let store = PostgresStore::open(&db_url).await?;
        StoreBackend::Postgres(Arc::new(store))
    } else {
        let store = SqliteStore::open(&db_url).await?;
        StoreBackend::Sqlite(Arc::new(store))
    };

    let events: Arc<dyn EventBus> = Arc::new(MemoryEventBus::new());
    let server = match backend {
        StoreBackend::Sqlite(ref s) => ZoppServer::new_sqlite(s.clone(), events),
        StoreBackend::Postgres(ref s) => ZoppServer::new_postgres(s.clone(), events),
    };

    // Create gRPC health service (implements gRPC health checking protocol)
    let (health_reporter, health_service) = tonic_health::server::health_reporter();
    health_reporter
        .set_serving::<ZoppServiceServer<ZoppServer>>()
        .await;

    // Create a channel for HTTP readiness probe signaling
    let (readiness_tx, readiness_rx) = tokio::sync::watch::channel(false);
    let readiness_check = ReadinessCheck::new(readiness_rx);

    // Create HTTP health check server for Kubernetes liveness/readiness probes
    // /healthz - simple liveness check (always returns OK)
    // /readyz - readiness check (returns OK once gRPC listener is bound and ready)
    let health_router = Router::new()
        .route("/healthz", get(health_handler))
        .route("/readyz", get(readiness_handler))
        .with_state(readiness_check);

    // Bind listeners to get actual addresses
    let grpc_listener = tokio::net::TcpListener::bind(addr).await?;
    let grpc_actual_addr = grpc_listener.local_addr()?;

    let health_listener = tokio::net::TcpListener::bind(health_addr).await?;
    let health_actual_addr = health_listener.local_addr()?;

    println!("ZoppServer listening on {}", grpc_actual_addr);
    println!("Health checks listening on {}", health_actual_addr);

    // Build gRPC server with optional TLS
    let mut grpc_builder = if let (Some(cert_path), Some(key_path)) = (tls_cert, tls_key) {
        let cert = std::fs::read_to_string(&cert_path)?;
        let key = std::fs::read_to_string(&key_path)?;

        let identity = tonic::transport::Identity::from_pem(cert, key);

        let mut tls_config = tonic::transport::ServerTlsConfig::new().identity(identity);

        if let Some(ca_path) = tls_client_ca {
            let ca = std::fs::read_to_string(&ca_path)?;
            let ca_cert = tonic::transport::Certificate::from_pem(ca);
            tls_config = tls_config.client_ca_root(ca_cert);
        }

        Server::builder().tls_config(tls_config)?
    } else {
        Server::builder()
    };

    // Signal readiness after TLS config is successfully built
    // This ensures TLS configuration errors are caught before reporting ready
    let _ = readiness_tx.send(true);

    // Notify test that servers are ready
    if let Some(tx) = ready_tx {
        let _ = tx.send((grpc_actual_addr, health_actual_addr));
    }

    // Create a broadcast channel for shutdown signaling
    let (shutdown_tx, _) = tokio::sync::broadcast::channel::<()>(1);
    let shutdown_tx_clone = shutdown_tx.clone();

    // Spawn a task to wait for shutdown signal and mark not-ready
    tokio::spawn(async move {
        shutdown_signal(Some(readiness_tx)).await;
        let _ = shutdown_tx_clone.send(());
    });

    // Start health check server with graceful shutdown
    let mut shutdown_rx1 = shutdown_tx.subscribe();
    let health_server =
        axum::serve(health_listener, health_router).with_graceful_shutdown(async move {
            let _ = shutdown_rx1.recv().await;
        });

    // Start gRPC server with graceful shutdown - includes health service
    let mut shutdown_rx2 = shutdown_tx.subscribe();
    let grpc_server = grpc_builder
        .add_service(health_service)
        .add_service(ZoppServiceServer::new(server))
        .serve_with_incoming_shutdown(
            tokio_stream::wrappers::TcpListenerStream::new(grpc_listener),
            async move {
                let _ = shutdown_rx2.recv().await;
            },
        );

    // Run both servers concurrently - ensure both complete their shutdown sequences
    let (grpc_result, health_result) = tokio::join!(grpc_server, health_server);

    grpc_result?;
    health_result?;

    Ok(())
}

#[derive(Clone)]
struct ReadinessCheck {
    ready: tokio::sync::watch::Receiver<bool>,
}

impl ReadinessCheck {
    fn new(ready: tokio::sync::watch::Receiver<bool>) -> Self {
        Self { ready }
    }
}

async fn health_handler() -> &'static str {
    "ok"
}

async fn readiness_handler(
    axum::extract::State(check): axum::extract::State<ReadinessCheck>,
) -> Result<&'static str, axum::http::StatusCode> {
    // Check if gRPC server is ready
    if *check.ready.borrow() {
        Ok("ok")
    } else {
        Err(axum::http::StatusCode::SERVICE_UNAVAILABLE)
    }
}

async fn shutdown_signal(readiness_tx: Option<tokio::sync::watch::Sender<bool>>) {
    use tokio::signal::unix::{signal, SignalKind};

    let mut sigterm = signal(SignalKind::terminate()).expect("failed to install SIGTERM handler");
    let mut sigint = signal(SignalKind::interrupt()).expect("failed to install SIGINT handler");

    tokio::select! {
        _ = sigterm.recv() => {
            println!("Received SIGTERM, shutting down gracefully...");
        }
        _ = sigint.recv() => {
            println!("Received SIGINT, shutting down gracefully...");
        }
    }

    // Mark not ready on shutdown for clean traffic drain in Kubernetes
    if let Some(tx) = readiness_tx {
        let _ = tx.send(false);
    }
}

// ────────────────────────────────────── Main ──────────────────────────────────────

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Command::Serve {
            addr,
            health_addr,
            tls_cert,
            tls_key,
            tls_client_ca,
        } => {
            cmd_serve(
                cli.database_url,
                cli.db,
                &addr,
                &health_addr,
                tls_cert,
                tls_key,
                tls_client_ca,
            )
            .await?;
        }
        Command::Invite { invite_cmd } => {
            let db_url = if let Some(url) = cli.database_url {
                url
            } else if let Some(path) = cli.db {
                if path.starts_with("sqlite:") || path.starts_with("postgres:") {
                    path
                } else {
                    format!("sqlite://{}?mode=rwc", path)
                }
            } else {
                "sqlite://zopp.db?mode=rwc".to_string()
            };

            match invite_cmd {
                InviteCommand::Create {
                    expires_hours,
                    plain,
                } => {
                    cmd_invite_create(&db_url, expires_hours, plain).await?;
                }
                InviteCommand::List => {
                    cmd_invite_list(&db_url).await?;
                }
                InviteCommand::Revoke { token } => {
                    cmd_invite_revoke(&db_url, &token).await?;
                }
            }
        }
    }

    Ok(())
}

// ────────────────────────────────────── Tests ──────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use prost::Message;
    use rand_core::OsRng;
    use sha2::{Digest, Sha256};
    use zopp_proto::{GetPrincipalRequest, JoinRequest};
    use zopp_storage::{CreateInviteParams, CreatePrincipalParams, UserId};

    #[tokio::test]
    async fn test_server_invite_joins_user_without_creating_workspace() {
        use uuid::Uuid;
        use zopp_proto::zopp_service_server::ZoppService;

        let store = Arc::new(SqliteStore::open_in_memory().await.unwrap());
        let events: Arc<dyn EventBus> = Arc::new(MemoryEventBus::new());
        let server = ZoppServer::new_sqlite(store.clone(), events);

        // Create a server invite (no workspaces)
        let mut invite_secret = [0u8; 32];
        rand_core::RngCore::fill_bytes(&mut OsRng, &mut invite_secret);
        let secret_hash = zopp_crypto::hash_sha256(&invite_secret);
        let invite = store
            .create_invite(&CreateInviteParams {
                workspace_ids: vec![],
                token: hex::encode(secret_hash),
                kek_encrypted: None,
                kek_nonce: None,
                expires_at: Utc::now() + chrono::Duration::hours(24),
                created_by_user_id: None,
            })
            .await
            .unwrap();

        // Generate keypair for join
        let signing_key = SigningKey::generate(&mut OsRng);
        let public_key = signing_key.verifying_key().to_bytes().to_vec();

        // Generate X25519 keypair for encryption
        let x25519_keypair = zopp_crypto::Keypair::generate();
        let x25519_public_key = x25519_keypair.public_key_bytes().to_vec();

        // Join using server invite
        let request = tonic::Request::new(JoinRequest {
            invite_token: invite.token.clone(),
            email: "test@example.com".to_string(),
            principal_name: "test-laptop".to_string(),
            public_key,
            x25519_public_key,
            ephemeral_pub: vec![],
            kek_wrapped: vec![],
            kek_nonce: vec![],
        });

        let response = server.join(request).await.unwrap().into_inner();

        assert!(!response.user_id.is_empty());
        assert!(!response.principal_id.is_empty());
        assert_eq!(
            response.workspaces.len(),
            0,
            "No workspaces should be created automatically"
        );

        let user_id = UserId(Uuid::parse_str(&response.user_id).unwrap());

        let workspaces = store.list_workspaces(&user_id).await.unwrap();
        assert_eq!(
            workspaces.len(),
            0,
            "User should not have access to any workspaces yet"
        );
    }

    #[tokio::test]
    async fn test_replay_protection_rejects_old_timestamps() {
        let store = SqliteStore::open_in_memory().await.unwrap();
        let events: Arc<dyn EventBus> = Arc::new(MemoryEventBus::new());
        let server = ZoppServer::new_sqlite(Arc::new(store), events);

        // Create a test keypair
        let signing_key = SigningKey::generate(&mut OsRng);
        let public_key = signing_key.verifying_key().to_bytes().to_vec();

        // Create a test principal
        let principal_id = server
            .store
            .create_principal(&CreatePrincipalParams {
                user_id: None,
                name: "test-principal".to_string(),
                public_key,
                x25519_public_key: None,
            })
            .await
            .unwrap();

        // Create a test request and compute hash
        let method = "/zopp.ZoppService/GetPrincipal";
        let test_request = GetPrincipalRequest {
            principal_id: "test".to_string(),
        };
        let body_bytes = test_request.encode_to_vec();
        let mut hasher = Sha256::new();
        hasher.update(method.as_bytes());
        hasher.update(&body_bytes);
        let request_hash = hasher.finalize().to_vec();

        // Create a timestamp 70 seconds in the past
        let old_timestamp = Utc::now().timestamp() - 70;

        // Sign: method + request_hash + timestamp
        let mut message = Vec::new();
        message.extend_from_slice(method.as_bytes());
        message.extend_from_slice(&request_hash);
        message.extend_from_slice(&old_timestamp.to_le_bytes());
        let signature = signing_key.sign(&message);

        // Should reject old timestamp
        let result = server
            .verify_signature_and_get_principal(
                &principal_id,
                old_timestamp,
                signature.to_bytes().as_ref(),
                method,
                &test_request,
                &request_hash,
            )
            .await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
        assert!(err.message().contains("too old"));
    }

    #[tokio::test]
    async fn test_replay_protection_rejects_future_timestamps() {
        let store = SqliteStore::open_in_memory().await.unwrap();
        let events: Arc<dyn EventBus> = Arc::new(MemoryEventBus::new());
        let server = ZoppServer::new_sqlite(Arc::new(store), events);

        // Create a test keypair
        let signing_key = SigningKey::generate(&mut OsRng);
        let public_key = signing_key.verifying_key().to_bytes().to_vec();

        // Create a test principal
        let principal_id = server
            .store
            .create_principal(&CreatePrincipalParams {
                user_id: None,
                name: "test-principal".to_string(),
                public_key,
                x25519_public_key: None,
            })
            .await
            .unwrap();

        // Create a test request and compute hash
        let method = "/zopp.ZoppService/GetPrincipal";
        let test_request = GetPrincipalRequest {
            principal_id: "test".to_string(),
        };
        let body_bytes = test_request.encode_to_vec();
        let mut hasher = Sha256::new();
        hasher.update(method.as_bytes());
        hasher.update(&body_bytes);
        let request_hash = hasher.finalize().to_vec();

        // Create a timestamp 70 seconds in the future
        let future_timestamp = Utc::now().timestamp() + 70;

        // Sign: method + request_hash + timestamp
        let mut message = Vec::new();
        message.extend_from_slice(method.as_bytes());
        message.extend_from_slice(&request_hash);
        message.extend_from_slice(&future_timestamp.to_le_bytes());
        let signature = signing_key.sign(&message);

        // Should reject future timestamp
        let result = server
            .verify_signature_and_get_principal(
                &principal_id,
                future_timestamp,
                signature.to_bytes().as_ref(),
                method,
                &test_request,
                &request_hash,
            )
            .await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
        assert!(err.message().contains("future"));
    }

    #[tokio::test]
    async fn test_replay_protection_accepts_valid_timestamps() {
        let store = SqliteStore::open_in_memory().await.unwrap();
        let events: Arc<dyn EventBus> = Arc::new(MemoryEventBus::new());
        let server = ZoppServer::new_sqlite(Arc::new(store), events);

        // Create a test keypair
        let signing_key = SigningKey::generate(&mut OsRng);
        let public_key = signing_key.verifying_key().to_bytes().to_vec();

        // Create a test principal
        let principal_id = server
            .store
            .create_principal(&CreatePrincipalParams {
                user_id: None,
                name: "test-principal".to_string(),
                public_key,
                x25519_public_key: None,
            })
            .await
            .unwrap();

        // Create a test request and compute hash
        let method = "/zopp.ZoppService/GetPrincipal";
        let test_request = GetPrincipalRequest {
            principal_id: "test".to_string(),
        };
        let body_bytes = test_request.encode_to_vec();
        let mut hasher = Sha256::new();
        hasher.update(method.as_bytes());
        hasher.update(&body_bytes);
        let request_hash = hasher.finalize().to_vec();

        // Create a current timestamp
        let current_timestamp = Utc::now().timestamp();

        // Sign: method + request_hash + timestamp
        let mut message = Vec::new();
        message.extend_from_slice(method.as_bytes());
        message.extend_from_slice(&request_hash);
        message.extend_from_slice(&current_timestamp.to_le_bytes());
        let signature = signing_key.sign(&message);

        // Should accept current timestamp
        let result = server
            .verify_signature_and_get_principal(
                &principal_id,
                current_timestamp,
                signature.to_bytes().as_ref(),
                method,
                &test_request,
                &request_hash,
            )
            .await;

        assert!(result.is_ok());
    }
}
