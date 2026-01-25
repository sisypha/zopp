mod backend;
mod config;
mod email;
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
use zopp_events_postgres::PostgresEventBus;
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

        /// Event bus backend: "auto" (default), "memory", or "postgres"
        /// - auto: Use postgres if DATABASE_URL is postgres://, otherwise memory
        /// - memory: In-memory only (single replica)
        /// - postgres: PostgreSQL LISTEN/NOTIFY (multi-replica)
        #[arg(long, env = "ZOPP_EVENTS_BACKEND", default_value = "auto")]
        events_backend: String,

        /// Optional separate database URL for events (defaults to DATABASE_URL)
        #[arg(long, env = "ZOPP_EVENTS_DATABASE_URL")]
        events_database_url: Option<String>,
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
    use sha2::{Digest, Sha256};
    let mut token_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut token_bytes);
    let token_hex = hex::encode(token_bytes);

    // Store hash of token (consistent with workspace invites)
    let mut hasher = Sha256::new();
    hasher.update(token_bytes);
    let token_hash = hex::encode(hasher.finalize());

    let expires_at = Utc::now() + chrono::Duration::hours(expires_hours);
    let invite = backend
        .create_invite(&CreateInviteParams {
            workspace_ids: vec![],
            token: token_hash,
            kek_encrypted: None,
            kek_nonce: None,
            expires_at,
            created_by_user_id: None,
        })
        .await?;

    // Output with inv_ prefix for consistency with workspace invites
    let display_token = format!("inv_{}", token_hex);
    if plain {
        println!("{}", display_token);
    } else {
        println!("✓ Server invite created!\n");
        println!("Token:   {}", display_token);
        println!("Expires: {}", invite.expires_at);
        println!("\nUse this token to join via CLI (zopp join) or web UI (/invite)");
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

#[allow(clippy::too_many_arguments)]
async fn cmd_serve(
    database_url: Option<String>,
    legacy_db_path: Option<String>,
    addr: &str,
    health_addr: &str,
    tls_cert: Option<String>,
    tls_key: Option<String>,
    tls_client_ca: Option<String>,
    events_backend: &str,
    events_database_url: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    cmd_serve_with_ready(
        database_url,
        legacy_db_path,
        addr,
        health_addr,
        tls_cert,
        tls_key,
        tls_client_ca,
        events_backend,
        events_database_url,
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
    events_backend: &str,
    events_database_url: Option<String>,
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

    // Create event bus based on configuration
    let events: Arc<dyn EventBus> = match events_backend {
        "memory" => {
            println!("Using in-memory event bus (single replica only)");
            Arc::new(MemoryEventBus::new())
        }
        "postgres" => {
            let events_url = events_database_url.as_deref().unwrap_or(&db_url);
            if !events_url.starts_with("postgres:") {
                return Err("--events-backend=postgres requires a PostgreSQL database URL".into());
            }
            println!("Using PostgreSQL event bus for horizontal scaling");
            Arc::new(PostgresEventBus::connect(events_url).await?)
        }
        _ => {
            // Auto-detect (default): use postgres if available, otherwise memory
            let events_url = events_database_url.as_deref().unwrap_or(&db_url);
            if events_url.starts_with("postgres:") {
                println!("Using PostgreSQL event bus for horizontal scaling (auto-detected)");
                Arc::new(PostgresEventBus::connect(events_url).await?)
            } else {
                println!("Using in-memory event bus (single replica only)");
                Arc::new(MemoryEventBus::new())
            }
        }
    };

    // Load server configuration from environment
    let server_config = config::ServerConfig::from_env()
        .map_err(|e| format!("Failed to load server configuration: {}", e))?;

    // Create email provider if configured
    let email_provider: Option<Arc<dyn email::EmailProvider>> = if let Some(ref email_config) =
        server_config.email
    {
        match email::create_provider(email_config) {
            Ok(provider) => {
                println!("Email verification enabled");
                Some(Arc::from(provider))
            }
            Err(e) => {
                if server_config.is_verification_required() {
                    // If verification is required but provider init failed, abort startup
                    return Err(format!(
                        "Email verification is required but provider initialization failed: {}",
                        e
                    )
                    .into());
                }
                eprintln!("Warning: Failed to create email provider: {}. Email verification will be disabled.", e);
                None
            }
        }
    } else {
        if server_config.is_verification_required() {
            // If verification is required but no provider configured, abort startup
            return Err(
                "Email verification is required but no email provider configured. Set ZOPP_EMAIL_PROVIDER environment variable.".into()
            );
        }
        None
    };

    let server = match backend {
        StoreBackend::Sqlite(ref s) => {
            ZoppServer::new_sqlite(s.clone(), events, server_config, email_provider)
        }
        StoreBackend::Postgres(ref s) => {
            ZoppServer::new_postgres(s.clone(), events, server_config, email_provider)
        }
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
            events_backend,
            events_database_url,
        } => {
            cmd_serve(
                cli.database_url,
                cli.db,
                &addr,
                &health_addr,
                tls_cert,
                tls_key,
                tls_client_ca,
                &events_backend,
                events_database_url,
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
mod tests;
