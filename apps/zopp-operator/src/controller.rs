//! CRD Controller for ZoppSecretSync resources.
//!
//! This module implements the reconciliation loop for ZoppSecretSync custom resources,
//! providing a GitOps-friendly way to sync secrets from Zopp to Kubernetes.

use crate::crd::{
    condition_reasons, condition_types, Condition, ZoppSecretSync, ZoppSecretSyncStatus,
};
use crate::credentials::OperatorCredentials;
use crate::reload::trigger_deployment_reloads;
use crate::sync::{self, SecretSyncConfig};
use crate::OperatorError;
use futures::StreamExt;
use k8s_openapi::api::core::v1::Secret;
use kube::api::{Patch, PatchParams, PostParams};
use kube::runtime::controller::{Action, Controller};
use kube::runtime::watcher::Config;
use kube::{Api, Client, ResourceExt};
use std::sync::Arc;
use std::time::Duration;
use tonic::transport::Channel;
use tracing::{debug, error, info, warn};
use zopp_proto::zopp_service_client::ZoppServiceClient;

/// Shared context for the CRD controller.
pub struct ControllerContext {
    pub k8s_client: Client,
    pub grpc_client: Arc<ZoppServiceClient<Channel>>,
    pub credentials: Arc<OperatorCredentials>,
}

/// Error type for controller operations.
#[derive(Debug, thiserror::Error)]
#[allow(dead_code)]
pub enum ControllerError {
    #[error("Kubernetes error: {0}")]
    Kube(#[from] kube::Error),

    #[error("Operator error: {0}")]
    Operator(#[from] OperatorError),

    #[error("Finalizer error: {0}")]
    Finalizer(String),
}

/// Run the CRD controller.
///
/// This starts a reconciliation loop that watches for ZoppSecretSync resources
/// and syncs secrets accordingly.
pub async fn run_controller(ctx: Arc<ControllerContext>, namespace: Option<String>) {
    let client = ctx.k8s_client.clone();

    let crds: Api<ZoppSecretSync> = match &namespace {
        Some(ns) => Api::namespaced(client.clone(), ns),
        None => Api::all(client.clone()),
    };

    // Also watch Secrets so we can react to deletions of managed secrets
    let secrets: Api<Secret> = match &namespace {
        Some(ns) => Api::namespaced(client.clone(), ns),
        None => Api::all(client.clone()),
    };

    info!("Starting ZoppSecretSync controller");

    Controller::new(crds, Config::default())
        .owns(secrets, Config::default())
        .run(reconcile, error_policy, ctx)
        .for_each(|res| async move {
            match res {
                Ok((obj, _action)) => {
                    debug!("Reconciled ZoppSecretSync: {:?}", obj);
                }
                Err(e) => {
                    error!("Reconcile error: {:?}", e);
                }
            }
        })
        .await;
}

/// Reconcile a single ZoppSecretSync resource.
async fn reconcile(
    zss: Arc<ZoppSecretSync>,
    ctx: Arc<ControllerContext>,
) -> Result<Action, ControllerError> {
    let name = zss.name_any();
    let namespace = zss.namespace().unwrap_or_default();

    info!("Reconciling ZoppSecretSync {}/{}", namespace, name);

    // Check if suspended
    if zss.spec.suspend {
        info!(
            "ZoppSecretSync {}/{} is suspended, skipping",
            namespace, name
        );
        update_status(
            &ctx.k8s_client,
            &zss,
            None,
            Condition::new(
                condition_types::READY,
                "False",
                condition_reasons::SUSPENDED,
                "Sync is suspended",
            ),
        )
        .await?;
        return Ok(Action::requeue(Duration::from_secs(300)));
    }

    // Determine target namespace (CRD namespace or explicit)
    let target_ns = zss
        .spec
        .target
        .namespace
        .as_ref()
        .unwrap_or(&namespace)
        .clone();

    // Build sync configuration
    let config = SecretSyncConfig {
        workspace: zss.spec.source.workspace.clone(),
        project: zss.spec.source.project.clone(),
        environment: zss.spec.source.environment.clone(),
    };

    // Ensure target secret exists
    ensure_target_secret_exists(
        &ctx.k8s_client,
        &target_ns,
        &zss.spec.target.secret_name,
        &zss.spec.target.secret_type,
        &zss.spec.target.labels,
        &zss.spec.target.annotations,
    )
    .await?;

    // Perform sync
    let sync_result = sync::full_resync(
        &ctx.grpc_client,
        &ctx.k8s_client,
        &ctx.credentials,
        &target_ns,
        &zss.spec.target.secret_name,
        &config,
    )
    .await;

    match sync_result {
        Ok((version, secret_count)) => {
            info!(
                "Sync successful for {}/{}: version={}, secrets={}",
                namespace, name, version, secret_count
            );

            // Update status
            let mut status = ZoppSecretSyncStatus::new();
            status.last_sync_time = Some(chrono::Utc::now().to_rfc3339());
            status.last_sync_version = Some(version);
            status.secret_count = Some(i32::try_from(secret_count).unwrap_or(i32::MAX));
            status.observed_generation = zss.metadata.generation;

            update_status(
                &ctx.k8s_client,
                &zss,
                Some(status),
                Condition::new(
                    condition_types::READY,
                    "True",
                    condition_reasons::SYNC_SUCCESS,
                    format!("Synced {} secrets", secret_count),
                ),
            )
            .await?;

            // Trigger deployment reloads if any
            match trigger_deployment_reloads(
                &ctx.k8s_client,
                &target_ns,
                &zss.spec.target.secret_name,
            )
            .await
            {
                Ok(restarted) => {
                    if !restarted.is_empty() {
                        info!("Triggered reload for deployments: {:?}", restarted);
                    }
                }
                Err(e) => {
                    warn!("Failed to trigger deployment reloads: {}", e);
                }
            }

            // Requeue based on sync interval
            Ok(Action::requeue(Duration::from_secs(
                zss.spec.sync_interval_seconds,
            )))
        }
        Err(e) => {
            error!("Sync failed for {}/{}: {}", namespace, name, e);

            let reason = match &e {
                OperatorError::Decryption(_) => condition_reasons::DECRYPTION_FAILED,
                OperatorError::Grpc(_) | OperatorError::Transport(_) => {
                    condition_reasons::CONNECTION_FAILED
                }
                _ => condition_reasons::SYNC_FAILED,
            };

            update_status(
                &ctx.k8s_client,
                &zss,
                None,
                Condition::new(
                    condition_types::READY,
                    "False",
                    reason,
                    format!("Sync failed: {}", e),
                ),
            )
            .await?;

            // Requeue with backoff on failure
            Ok(Action::requeue(Duration::from_secs(30)))
        }
    }
}

/// Error policy for the controller.
fn error_policy(
    _zss: Arc<ZoppSecretSync>,
    error: &ControllerError,
    _ctx: Arc<ControllerContext>,
) -> Action {
    error!("Controller error: {:?}", error);
    Action::requeue(Duration::from_secs(60))
}

/// Ensure the target Kubernetes Secret exists.
async fn ensure_target_secret_exists(
    client: &Client,
    namespace: &str,
    name: &str,
    secret_type: &str,
    labels: &std::collections::BTreeMap<String, String>,
    annotations: &std::collections::BTreeMap<String, String>,
) -> Result<(), ControllerError> {
    let api: Api<Secret> = Api::namespaced(client.clone(), namespace);

    // Check if secret exists
    match api.get(name).await {
        Ok(_) => {
            debug!("Target secret {}/{} already exists", namespace, name);
            Ok(())
        }
        Err(kube::Error::Api(err)) if err.code == 404 => {
            info!("Creating target secret {}/{}", namespace, name);

            let mut secret_labels = labels.clone();
            secret_labels.insert(
                "app.kubernetes.io/managed-by".to_string(),
                "zopp-operator".to_string(),
            );

            let mut secret_annotations = annotations.clone();
            secret_annotations.insert("zopp.dev/managed".to_string(), "true".to_string());

            let secret = Secret {
                metadata: kube::api::ObjectMeta {
                    name: Some(name.to_string()),
                    namespace: Some(namespace.to_string()),
                    labels: Some(secret_labels),
                    annotations: Some(secret_annotations),
                    ..Default::default()
                },
                type_: Some(secret_type.to_string()),
                data: Some(std::collections::BTreeMap::new()),
                ..Default::default()
            };

            api.create(&PostParams::default(), &secret).await?;
            Ok(())
        }
        Err(e) => Err(e.into()),
    }
}

/// Update the status of a ZoppSecretSync resource.
async fn update_status(
    client: &Client,
    zss: &ZoppSecretSync,
    status: Option<ZoppSecretSyncStatus>,
    condition: Condition,
) -> Result<(), ControllerError> {
    let name = zss.name_any();
    let namespace = zss.namespace().unwrap_or_default();
    let api: Api<ZoppSecretSync> = Api::namespaced(client.clone(), &namespace);

    let mut new_status = status.unwrap_or_else(|| zss.status.clone().unwrap_or_default());
    new_status.observed_generation = zss.metadata.generation;
    new_status.set_condition(condition.with_generation(zss.metadata.generation.unwrap_or(0)));

    let patch = serde_json::json!({
        "status": new_status
    });

    api.patch_status(
        &name,
        &PatchParams::apply("zopp-operator"),
        &Patch::Merge(&patch),
    )
    .await?;

    Ok(())
}
