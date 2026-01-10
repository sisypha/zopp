use clap::Parser;
use futures::StreamExt;
use k8s_openapi::api::core::v1::Secret;
use kube::{
    api::Api,
    runtime::{watcher, watcher::Config, WatchStreamExt},
    Client, ResourceExt,
};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;
use tonic::transport::Channel;
use tracing::{debug, error, info, warn};
use zopp_proto::zopp_service_client::ZoppServiceClient;

mod controller;
mod crd;
mod credentials;
mod reload;
mod sync;
mod watch;

use credentials::OperatorCredentials;
use sync::SecretSyncConfig;

#[derive(Error, Debug)]
pub enum OperatorError {
    #[error("Kubernetes error: {0}")]
    Kube(#[from] kube::Error),
    #[error("gRPC error: {0}")]
    Grpc(#[from] tonic::Status),
    #[error("Transport error: {0}")]
    Transport(#[from] tonic::transport::Error),
    #[error("Invalid annotation: {0}")]
    InvalidAnnotation(String),
    #[error("Missing annotation: {0}")]
    MissingAnnotation(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Decryption error: {0}")]
    Decryption(String),
}

impl From<String> for OperatorError {
    fn from(s: String) -> Self {
        OperatorError::Decryption(s)
    }
}

#[derive(Parser)]
#[command(name = "zopp-operator")]
#[command(about = "Kubernetes operator for syncing zopp secrets")]
struct Args {
    /// Zopp server address
    #[arg(long, env = "ZOPP_SERVER", default_value = "http://127.0.0.1:50051")]
    server: String,

    /// Path to zopp credentials file
    #[arg(long, env = "ZOPP_CREDENTIALS")]
    credentials: Option<PathBuf>,

    /// Kubernetes namespace to watch (empty = all namespaces)
    #[arg(long, env = "ZOPP_NAMESPACE")]
    namespace: Option<String>,

    /// Health check HTTP server address
    #[arg(long, env = "ZOPP_HEALTH_ADDR", default_value = "0.0.0.0:8080")]
    health_addr: String,

    /// Path to TLS CA certificate for server connection
    #[arg(long, env = "ZOPP_TLS_CA_CERT")]
    tls_ca_cert: Option<PathBuf>,
}

/// Operator state tracking active sync tasks
struct OperatorState {
    /// Active sync tasks: Secret namespace/name -> task handle
    active_syncs: RwLock<HashMap<String, tokio::task::JoinHandle<()>>>,
}

impl OperatorState {
    fn new() -> Self {
        Self {
            active_syncs: RwLock::new(HashMap::new()),
        }
    }
}

#[derive(Clone)]
struct ReadinessCheck {
    health_client: tonic_health::pb::health_client::HealthClient<Channel>,
}

impl ReadinessCheck {
    fn new(channel: Channel) -> Self {
        Self {
            health_client: tonic_health::pb::health_client::HealthClient::new(channel),
        }
    }
}

async fn health_handler() -> &'static str {
    "ok"
}

async fn readiness_handler(
    axum::extract::State(mut check): axum::extract::State<ReadinessCheck>,
) -> Result<&'static str, axum::http::StatusCode> {
    // Actually verify we can connect to the gRPC health service
    use tonic_health::pb::HealthCheckRequest;

    match check
        .health_client
        .check(HealthCheckRequest {
            service: "".to_string(),
        })
        .await
    {
        Ok(_) => Ok("ok"),
        Err(e) => {
            debug!("gRPC health check failed: {}", e);
            Err(axum::http::StatusCode::SERVICE_UNAVAILABLE)
        }
    }
}

async fn shutdown_signal() {
    use tokio::signal::unix::{signal, SignalKind};

    let mut sigterm = signal(SignalKind::terminate()).expect("failed to install SIGTERM handler");
    let mut sigint = signal(SignalKind::interrupt()).expect("failed to install SIGINT handler");

    tokio::select! {
        _ = sigterm.recv() => {
            info!("Received SIGTERM, shutting down gracefully...");
        }
        _ = sigint.recv() => {
            info!("Received SIGINT, shutting down gracefully...");
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    use axum::{routing::get, Router};

    tracing_subscriber::fmt::init();

    let args = Args::parse();

    info!("Starting zopp-operator");
    info!("Server: {}", args.server);
    info!("Health checks listening on {}", args.health_addr);

    // Load credentials - try env vars first, then fall back to file
    let credentials = OperatorCredentials::load(args.credentials)?;
    let principal = &credentials.principal;

    info!(
        "Loaded credentials for principal: {} ({})",
        principal.name, principal.id
    );

    let credentials = Arc::new(credentials);

    // Validate TLS configuration
    let uses_tls = args.server.starts_with("https://");
    if !uses_tls && args.tls_ca_cert.is_some() {
        return Err(
            "Error: --tls-ca-cert provided but server URL does not use https://. \
             Either use https:// in the server URL or remove --tls-ca-cert flag."
                .into(),
        );
    }

    // Create gRPC client
    let channel = if uses_tls {
        if let Some(ca_cert_path) = &args.tls_ca_cert {
            info!(
                "Connecting with TLS using custom CA cert: {:?}",
                ca_cert_path
            );
            let ca_cert = std::fs::read(ca_cert_path)?;
            let tls = tonic::transport::ClientTlsConfig::new()
                .ca_certificate(tonic::transport::Certificate::from_pem(ca_cert));
            Channel::from_shared(args.server.clone())?
                .tls_config(tls)?
                .connect()
                .await?
        } else {
            info!("Connecting with TLS using system CA store");
            let tls = tonic::transport::ClientTlsConfig::new();
            Channel::from_shared(args.server.clone())?
                .tls_config(tls)?
                .connect()
                .await?
        }
    } else {
        info!("Connecting without TLS");
        Channel::from_shared(args.server.clone())?.connect().await?
    };
    let grpc_client = Arc::new(ZoppServiceClient::new(channel.clone()));

    // Create Kubernetes client
    let k8s_client = Client::try_default().await?;

    let state = Arc::new(OperatorState::new());

    // Start CRD controller (ZoppSecretSync resources)
    let crd_ctx = Arc::new(controller::ControllerContext {
        k8s_client: k8s_client.clone(),
        grpc_client: grpc_client.clone(),
        credentials: credentials.clone(),
    });
    let crd_namespace = args.namespace.clone();
    tokio::spawn(async move {
        controller::run_controller(crd_ctx, crd_namespace).await;
    });
    info!("Started ZoppSecretSync CRD controller");

    // Health check endpoints - /readyz actually verifies gRPC is working
    let readiness_check = ReadinessCheck::new(channel);
    let health_router = Router::new()
        .route("/healthz", get(health_handler))
        .route("/readyz", get(readiness_handler))
        .with_state(readiness_check);

    let health_addr: std::net::SocketAddr = args.health_addr.parse()?;

    // Create a broadcast channel for coordinating shutdown between watch loop and health server
    let (shutdown_tx, _) = tokio::sync::broadcast::channel::<()>(1);

    // Start health check server with graceful shutdown support
    let health_listener = tokio::net::TcpListener::bind(health_addr).await?;
    let mut shutdown_rx_health = shutdown_tx.subscribe();
    let health_server = async move {
        axum::serve(health_listener, health_router)
            .with_graceful_shutdown(async move {
                let _ = shutdown_rx_health.recv().await;
            })
            .await
    };

    // Spawn a task to wait for shutdown signal and broadcast to all listeners
    let shutdown_tx_clone = shutdown_tx.clone();
    tokio::spawn(async move {
        shutdown_signal().await;
        let _ = shutdown_tx_clone.send(());
    });

    // Watch Secrets with zopp annotations
    let secrets: Api<Secret> = match &args.namespace {
        Some(ns) => Api::namespaced(k8s_client.clone(), ns),
        None => Api::all(k8s_client.clone()),
    };

    // Watch for secrets with zopp.dev/sync annotation
    let stream = watcher(secrets.clone(), Config::default()).applied_objects();

    tokio::pin!(stream);

    info!("Watching for annotated Secrets...");

    let shutdown_tx_watch = shutdown_tx.clone();
    let watch_loop = async move {
        let mut shutdown_rx = shutdown_tx_watch.subscribe();

        let result = loop {
            tokio::select! {
                biased;
                _ = shutdown_rx.recv() => {
                    info!("Watch loop received shutdown signal");
                    break Ok(());
                }
                event_option = stream.next() => {
                    let Some(event) = event_option else {
                        info!("Watch stream ended");
                        break Err("watch stream ended");
                    };

                    match event {
                Ok(secret) => {
                    let ns = secret.namespace().unwrap_or_default();
                    let name = secret.name_any();
                    let key = format!("{}/{}", ns, name);

                    // Check if this Secret has zopp annotations
                    let annotations = secret.metadata.annotations.as_ref();

                    if let Some(annot) = annotations {
                        if annot.get("zopp.dev/sync").map(|s| s.as_str()) == Some("true") {
                            info!("Detected zopp-managed Secret: {}", key);

                            // Parse sync configuration from annotations
                            match SecretSyncConfig::from_annotations(annot) {
                                Ok(config) => {
                                    debug!("Sync config: {:?}", config);

                                    // Cancel existing sync task if any
                                    let mut syncs = state.active_syncs.write().await;
                                    if let Some(handle) = syncs.remove(&key) {
                                        debug!("Canceling previous sync task for {}", key);
                                        handle.abort();
                                    }

                                    // Spawn new sync task
                                    let handle = tokio::spawn({
                                        let grpc_client = grpc_client.clone();
                                        let k8s_client = k8s_client.clone();
                                        let credentials = (*credentials).clone();
                                        let ns = ns.clone();
                                        let name = name.clone();

                                        async move {
                                            if let Err(e) = sync::run_sync(
                                                grpc_client,
                                                k8s_client,
                                                credentials,
                                                ns,
                                                name,
                                                config,
                                            )
                                            .await
                                            {
                                                error!("Sync task failed: {}", e);
                                            }
                                        }
                                    });

                                    syncs.insert(key.clone(), handle);
                                }
                                Err(e) => {
                                    warn!("Invalid zopp annotations on {}: {}", key, e);
                                }
                            }
                        } else {
                            // Secret exists but zopp.dev/sync is not "true"
                            // Cancel sync if it was previously active
                            let mut syncs = state.active_syncs.write().await;
                            if let Some(handle) = syncs.remove(&key) {
                                info!("Stopping sync for {} (annotation removed)", key);
                                handle.abort();
                            }
                        }
                    } else {
                        // No annotations - cancel sync if active
                        let mut syncs = state.active_syncs.write().await;
                        if let Some(handle) = syncs.remove(&key) {
                            info!("Stopping sync for {} (annotations removed)", key);
                            handle.abort();
                        }
                    }
                }
                        Err(e) => {
                            error!("Watch error: {}", e);
                        }
                    }
                }
            }
        };

        // If watch loop exited due to stream ending, trigger shutdown for health server
        if result.is_err() {
            let _ = shutdown_tx_watch.send(());
        }
    };

    tokio::pin!(health_server);
    tokio::pin!(watch_loop);

    // Run both health server and watch loop concurrently
    // Exit when either completes, then wait for the other to gracefully shutdown
    tokio::select! {
        result = &mut health_server => {
            // Health server exited (error or shutdown) - trigger shutdown for watch loop
            let _ = shutdown_tx.send(());
            result?;
            // Wait for watch loop to complete
            watch_loop.await;
        }
        _ = &mut watch_loop => {
            // Watch loop exited (stream end or shutdown) - shutdown already triggered for health server
            info!("Watch loop completed, waiting for health server to shutdown gracefully");
            // Wait for health server to complete graceful shutdown
            health_server.await?;
        }
    }

    Ok(())
}
