use crate::OperatorError;
use k8s_openapi::api::core::v1::Secret;
use kube::{api::PatchParams, Api, Client};
use prost::Message;
use std::collections::BTreeMap;
use std::sync::Arc;
use tracing::{debug, error, info, warn};
use zopp_proto::zopp_service_client::ZoppServiceClient;

/// Add authentication metadata to a gRPC request
fn add_auth_metadata<T: Message + Clone>(
    request: &mut tonic::Request<T>,
    credentials: &crate::credentials::OperatorCredentials,
    method: &str,
) {
    let timestamp = chrono::Utc::now().timestamp();
    let req_body = request.get_ref().clone();
    let (signature, request_hash) = crate::watch::create_signature(credentials, method, &req_body, timestamp);

    request.metadata_mut().insert(
        "principal-id",
        credentials.principal.id.to_string().parse().unwrap(),
    );
    request
        .metadata_mut()
        .insert("timestamp", timestamp.to_string().parse().unwrap());
    request
        .metadata_mut()
        .insert("signature", hex::encode(&signature).parse().unwrap());
    request
        .metadata_mut()
        .insert("request-hash", hex::encode(&request_hash).parse().unwrap());
}

#[derive(Debug, Clone)]
pub struct SecretSyncConfig {
    pub workspace: String,
    pub project: String,
    pub environment: String,
}

impl SecretSyncConfig {
    pub fn from_annotations(annotations: &BTreeMap<String, String>) -> Result<Self, OperatorError> {
        let workspace = annotations
            .get("zopp.dev/workspace")
            .ok_or_else(|| OperatorError::MissingAnnotation("zopp.dev/workspace".to_string()))?
            .clone();

        let project = annotations
            .get("zopp.dev/project")
            .ok_or_else(|| OperatorError::MissingAnnotation("zopp.dev/project".to_string()))?
            .clone();

        let environment = annotations
            .get("zopp.dev/environment")
            .ok_or_else(|| OperatorError::MissingAnnotation("zopp.dev/environment".to_string()))?
            .clone();

        Ok(Self {
            workspace,
            project,
            environment,
        })
    }
}

/// Run synchronization for a single Kubernetes Secret.
///
/// This function implements a dual-sync strategy:
///
/// 1. **Event Streaming (Primary)**: Maintains a persistent gRPC stream for real-time updates.
///    - Instant propagation when secrets change in zopp server
///    - Automatic reconnection on stream failures with 5-second backoff
///    - Version tracking for resync detection
///
/// 2. **Periodic Polling (Safeguard)**: Reconciles every 60 seconds regardless of stream state.
///    - Catches any missed events during stream disconnections
///    - Detects version drift and triggers full resync if needed
///    - Continues even if stream is temporarily unavailable
///
/// Both mechanisms run concurrently:
/// - The stream provides low-latency updates (< 1 second)
/// - The polling ensures eventual consistency (worst case: 60 second delay)
///
/// This approach combines the best of both worlds: real-time performance with reliability guarantees.
pub async fn run_sync(
    grpc_client: Arc<ZoppServiceClient<tonic::transport::Channel>>,
    k8s_client: Client,
    credentials: crate::credentials::OperatorCredentials,
    namespace: String,
    name: String,
    config: SecretSyncConfig,
) -> Result<(), OperatorError> {
    info!(
        "Starting dual-sync (stream + 60s poll) for {}/{} -> {}/{}/{}",
        namespace, name, config.workspace, config.project, config.environment
    );

    // Initial full sync
    let mut current_version = match full_resync(
        &grpc_client,
        &k8s_client,
        &credentials,
        &namespace,
        &name,
        &config,
    )
    .await
    {
        Ok(version) => version,
        Err(e) => {
            error!("Initial sync failed: {}", e);
            return Err(e);
        }
    };

    info!(
        "Initial sync complete for {}/{}, version: {}",
        namespace, name, current_version
    );

    // Spawn watch stream task with exponential backoff reconnection
    let _stream_handle = tokio::spawn({
        let grpc_client = grpc_client.clone();
        let k8s_client = k8s_client.clone();
        let credentials = credentials.clone();
        let namespace = namespace.clone();
        let name = name.clone();
        let config = config.clone();
        let current_version = Arc::new(tokio::sync::RwLock::new(current_version));

        async move {
            let mut backoff_seconds = 1;
            const MAX_BACKOFF_SECONDS: u64 = 60;

            loop {
                match start_watch_stream(
                    &grpc_client,
                    &k8s_client,
                    &credentials,
                    &namespace,
                    &name,
                    &config,
                    current_version.clone(),
                )
                .await
                {
                    Ok(_) => {
                        warn!("Watch stream ended for {}/{}", namespace, name);
                        // Reset backoff on successful connection
                        backoff_seconds = 1;
                    }
                    Err(e) => {
                        error!("Watch stream error for {}/{}: {}", namespace, name, e);
                    }
                }

                // Exponential backoff with cap
                info!(
                    "Watch stream reconnecting in {} seconds...",
                    backoff_seconds
                );
                tokio::time::sleep(tokio::time::Duration::from_secs(backoff_seconds)).await;
                backoff_seconds = (backoff_seconds * 2).min(MAX_BACKOFF_SECONDS);
            }
        }
    });

    // Periodic reconciliation loop (every 60 seconds)
    // This acts as a safeguard in case events are missed from the stream
    let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(60));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        interval.tick().await;

        debug!("Periodic reconciliation for {}/{}", namespace, name);

        match full_resync(
            &grpc_client,
            &k8s_client,
            &credentials,
            &namespace,
            &name,
            &config,
        )
        .await
        {
            Ok(version) => {
                current_version = version;
                debug!(
                    "Periodic reconciliation complete for {}/{}, version: {}",
                    namespace, name, current_version
                );
            }
            Err(e) => {
                warn!(
                    "Periodic reconciliation failed for {}/{}: {}",
                    namespace, name, e
                );
                // Continue - the stream might still be working
            }
        }
    }

    // Note: This is unreachable, but if we ever add graceful shutdown:
    // stream_handle.abort();
    // Ok(())
}

async fn full_resync(
    grpc_client: &Arc<ZoppServiceClient<tonic::transport::Channel>>,
    k8s_client: &Client,
    credentials: &crate::credentials::OperatorCredentials,
    namespace: &str,
    name: &str,
    config: &SecretSyncConfig,
) -> Result<i64, OperatorError> {
    info!("Performing full resync for {}/{}", namespace, name);

    let mut client = grpc_client.as_ref().clone();

    // Get environment DEK (unwrap from server using workspace KEK)
    let dek = unwrap_environment_dek(
        &mut client,
        credentials,
        &config.workspace,
        &config.project,
        &config.environment,
    )
    .await?;

    // List all secrets
    let mut request = tonic::Request::new(zopp_proto::ListSecretsRequest {
        workspace_name: config.workspace.clone(),
        project_name: config.project.clone(),
        environment_name: config.environment.clone(),
    });
    add_auth_metadata(&mut request, credentials, "/zopp.ZoppService/ListSecrets");

    let response = client.list_secrets(request).await?;
    let secrets_data = response.into_inner();

    debug!(
        "Fetched {} secrets, version: {}",
        secrets_data.secrets.len(),
        secrets_data.version
    );

    // Decrypt all secrets
    let mut decrypted: BTreeMap<String, String> = BTreeMap::new();

    for secret in secrets_data.secrets {
        match decrypt_secret(&dek, config, &secret) {
            Ok(value) => {
                decrypted.insert(secret.key, value);
            }
            Err(e) => {
                warn!("Failed to decrypt secret {}: {}", secret.key, e);
            }
        }
    }

    // Update K8s Secret
    update_k8s_secret(k8s_client, namespace, name, decrypted).await?;

    Ok(secrets_data.version)
}

async fn unwrap_environment_dek(
    client: &mut ZoppServiceClient<tonic::transport::Channel>,
    credentials: &crate::credentials::OperatorCredentials,
    workspace_name: &str,
    project_name: &str,
    environment_name: &str,
) -> Result<[u8; 32], OperatorError> {
    // Check cache first
    if let Some(cached_dek) = credentials
        .get_cached_dek(workspace_name, project_name, environment_name)
        .await
    {
        return Ok(cached_dek);
    }

    let mut request = tonic::Request::new(zopp_proto::GetEnvironmentRequest {
        workspace_name: workspace_name.to_string(),
        project_name: project_name.to_string(),
        environment_name: environment_name.to_string(),
    });
    add_auth_metadata(&mut request, credentials, "/zopp.ZoppService/GetEnvironment");

    let environment = client.get_environment(request).await?.into_inner();

    // Get workspace keys
    let mut ws_request = tonic::Request::new(zopp_proto::GetWorkspaceKeysRequest {
        workspace_name: workspace_name.to_string(),
    });
    add_auth_metadata(&mut ws_request, credentials, "/zopp.ZoppService/GetWorkspaceKeys");

    let workspace_keys = client.get_workspace_keys(ws_request).await?.into_inner();

    // Extract X25519 private key from principal
    let x25519_private_key = credentials
        .principal
        .x25519_private_key
        .as_ref()
        .ok_or_else(|| {
            OperatorError::Decryption("Principal missing X25519 private key".to_string())
        })?;
    let x25519_private_bytes = hex::decode(x25519_private_key)
        .map_err(|e| OperatorError::Decryption(format!("Invalid X25519 key hex: {}", e)))?;
    let mut x25519_array = [0u8; 32];
    x25519_array.copy_from_slice(&x25519_private_bytes);

    // Use zopp-secrets to unwrap the DEK (hides all crypto details)
    let dek_bytes = zopp_secrets::unwrap_dek(
        &x25519_array,
        &workspace_keys,
        &environment,
        workspace_name,
        project_name,
        environment_name,
    )
    .map_err(|e| OperatorError::Decryption(e.to_string()))?;

    // Cache the DEK for future use
    credentials
        .cache_dek(workspace_name, project_name, environment_name, dek_bytes)
        .await;

    Ok(dek_bytes)
}

async fn start_watch_stream(
    grpc_client: &Arc<ZoppServiceClient<tonic::transport::Channel>>,
    k8s_client: &Client,
    credentials: &crate::credentials::OperatorCredentials,
    namespace: &str,
    name: &str,
    config: &SecretSyncConfig,
    current_version: Arc<tokio::sync::RwLock<i64>>,
) -> Result<(), OperatorError> {
    let mut client = grpc_client.as_ref().clone();

    let version = *current_version.read().await;
    let mut request = tonic::Request::new(zopp_proto::WatchSecretsRequest {
        workspace_name: config.workspace.clone(),
        project_name: config.project.clone(),
        environment_name: config.environment.clone(),
        since_version: Some(version),
    });
    add_auth_metadata(&mut request, credentials, "/zopp.ZoppService/WatchSecrets");

    let mut stream = client.watch_secrets(request).await?.into_inner();

    while let Some(response) = stream.message().await? {
        match response.response {
            Some(zopp_proto::watch_secrets_response::Response::Resync(resync)) => {
                let current = *current_version.read().await;
                warn!(
                    "Resync required: current={}, server={}",
                    current, resync.current_version
                );

                let new_version = full_resync(
                    grpc_client,
                    k8s_client,
                    credentials,
                    namespace,
                    name,
                    config,
                )
                .await?;

                *current_version.write().await = new_version;

                info!("Resync complete, new version: {}", new_version);

                // Reconnect with new version
                return Ok(());
            }
            Some(zopp_proto::watch_secrets_response::Response::Event(event)) => {
                debug!(
                    "Received event: {:?} for key {}",
                    event.event_type, event.key
                );

                *current_version.write().await = event.version;

                // Handle the event
                handle_secret_event(
                    grpc_client,
                    k8s_client,
                    credentials,
                    namespace,
                    name,
                    config,
                    event,
                )
                .await?;
            }
            None => {
                warn!("Received empty response from watch stream");
            }
        }
    }

    Ok(())
}

async fn handle_secret_event(
    grpc_client: &Arc<ZoppServiceClient<tonic::transport::Channel>>,
    k8s_client: &Client,
    credentials: &crate::credentials::OperatorCredentials,
    namespace: &str,
    name: &str,
    config: &SecretSyncConfig,
    event: zopp_proto::SecretChangeEvent,
) -> Result<(), OperatorError> {
    use zopp_proto::secret_change_event::EventType;

    match EventType::try_from(event.event_type) {
        Ok(EventType::Created | EventType::Updated) => {
            // Fetch the updated secret value
            let mut client = grpc_client.as_ref().clone();

            // Get environment DEK
            let dek = unwrap_environment_dek(
                &mut client,
                credentials,
                &config.workspace,
                &config.project,
                &config.environment,
            )
            .await?;

            let mut request = tonic::Request::new(zopp_proto::GetSecretRequest {
                workspace_name: config.workspace.clone(),
                project_name: config.project.clone(),
                environment_name: config.environment.clone(),
                key: event.key.clone(),
            });
            add_auth_metadata(&mut request, credentials, "/zopp.ZoppService/GetSecret");

            let response = client.get_secret(request).await?;
            let secret = response.into_inner();

            // Decrypt
            let value = decrypt_secret(&dek, config, &secret)?;

            // Update K8s Secret
            update_k8s_secret_key(k8s_client, namespace, name, &event.key, value).await?;

            info!("Updated secret key: {}", event.key);
        }
        Ok(EventType::Deleted) => {
            // Remove key from K8s Secret
            delete_k8s_secret_key(k8s_client, namespace, name, &event.key).await?;

            info!("Deleted secret key: {}", event.key);
        }
        Err(_) => {
            warn!("Unknown event type: {}", event.event_type);
        }
    }

    Ok(())
}

fn decrypt_secret(
    dek_bytes: &[u8; 32],
    config: &SecretSyncConfig,
    secret: &zopp_proto::Secret,
) -> Result<String, String> {
    // Use zopp-secrets to decrypt (hides all crypto details)
    zopp_secrets::decrypt_secret_with_dek(
        dek_bytes,
        secret,
        &config.workspace,
        &config.project,
        &config.environment,
    )
    .map_err(|e| e.to_string())
}

async fn update_k8s_secret(
    client: &Client,
    namespace: &str,
    name: &str,
    data: BTreeMap<String, String>,
) -> Result<(), OperatorError> {
    let api: Api<Secret> = Api::namespaced(client.clone(), namespace);

    // Convert String values to base64-encoded bytes (K8s Secret format)
    let encoded_data: BTreeMap<String, String> = data
        .into_iter()
        .map(|(k, v)| {
            (
                k,
                base64::Engine::encode(&base64::engine::general_purpose::STANDARD, v.as_bytes()),
            )
        })
        .collect();

    let patch = serde_json::json!({
        "data": encoded_data
    });

    api.patch(
        name,
        &PatchParams::apply("zopp-operator"),
        &kube::api::Patch::Merge(&patch),
    )
    .await?;

    Ok(())
}

async fn update_k8s_secret_key(
    client: &Client,
    namespace: &str,
    name: &str,
    key: &str,
    value: String,
) -> Result<(), OperatorError> {
    let api: Api<Secret> = Api::namespaced(client.clone(), namespace);

    let encoded_value =
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, value.as_bytes());

    let patch = serde_json::json!({
        "data": {
            key: encoded_value
        }
    });

    api.patch(
        name,
        &PatchParams::apply("zopp-operator"),
        &kube::api::Patch::Merge(&patch),
    )
    .await?;

    Ok(())
}

async fn delete_k8s_secret_key(
    client: &Client,
    namespace: &str,
    name: &str,
    key: &str,
) -> Result<(), OperatorError> {
    let api: Api<Secret> = Api::namespaced(client.clone(), namespace);

    // To delete a key from a K8s resource with Merge patch, set it to null
    let patch = serde_json::json!({
        "data": {
            key: serde_json::Value::Null
        }
    });

    api.patch(
        name,
        &PatchParams::apply("zopp-operator"),
        &kube::api::Patch::Merge(&patch),
    )
    .await?;

    Ok(())
}
