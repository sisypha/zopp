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

mod credentials;
mod kek;
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

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let args = Args::parse();

    info!("Starting zopp-operator");
    info!("Server: {}", args.server);

    // Load credentials - use standard CLI config format
    let config_path = args
        .credentials
        .unwrap_or_else(zopp_config::CliConfig::default_path);

    let config = zopp_config::CliConfig::load_from(&config_path)?;
    let principal = config.get_current_principal()?.clone();

    let credentials = Arc::new(OperatorCredentials::new(principal.clone()));

    info!(
        "Loaded credentials for principal: {} ({})",
        principal.name, principal.id
    );

    // Create gRPC client
    let channel = Channel::from_shared(args.server.clone())?.connect().await?;
    let grpc_client = Arc::new(ZoppServiceClient::new(channel));

    // Create Kubernetes client
    let k8s_client = Client::try_default().await?;

    let state = Arc::new(OperatorState::new());

    // Watch Secrets with zopp annotations
    let secrets: Api<Secret> = match &args.namespace {
        Some(ns) => Api::namespaced(k8s_client.clone(), ns),
        None => Api::all(k8s_client.clone()),
    };

    // Watch for secrets with zopp.dev/sync annotation
    let stream = watcher(secrets.clone(), Config::default()).applied_objects();

    tokio::pin!(stream);

    info!("Watching for annotated Secrets...");

    while let Some(event) = stream.next().await {
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

    Ok(())
}
