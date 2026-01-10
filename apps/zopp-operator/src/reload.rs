//! Deployment reload functionality.
//!
//! This module handles automatic reloading of Deployments when their
//! referenced secrets are updated. Deployments opt-in via annotation.

use k8s_openapi::api::apps::v1::Deployment;
use kube::api::{Patch, PatchParams};
use kube::{Api, Client};
use tracing::{debug, info};

/// Annotation to enable automatic deployment reload.
pub const RELOAD_ANNOTATION: &str = "zopp.dev/reload";

/// Annotation set by the operator to trigger rollout.
const RESTARTED_AT_ANNOTATION: &str = "zopp.dev/restartedAt";

/// Error type for reload operations.
#[derive(Debug, thiserror::Error)]
pub enum ReloadError {
    #[error("Kubernetes error: {0}")]
    Kube(#[from] kube::Error),
}

/// Find and restart Deployments that reference the given Secret.
///
/// Only Deployments with `zopp.dev/reload: "true"` annotation will be restarted.
/// The restart is triggered by updating the pod template annotation.
pub async fn trigger_deployment_reloads(
    client: &Client,
    secret_namespace: &str,
    secret_name: &str,
) -> Result<Vec<String>, ReloadError> {
    let deployments: Api<Deployment> = Api::namespaced(client.clone(), secret_namespace);
    let list = deployments.list(&Default::default()).await?;

    let mut restarted = Vec::new();

    for deployment in list.items {
        let name = match deployment.metadata.name.as_ref() {
            Some(n) => n,
            None => continue,
        };

        if should_reload(&deployment, secret_name) {
            info!(
                "Triggering reload for deployment {}/{}",
                secret_namespace, name
            );
            restart_deployment(&deployments, name).await?;
            restarted.push(name.clone());
        }
    }

    Ok(restarted)
}

/// Check if a Deployment should be reloaded.
///
/// Returns true if:
/// 1. The Deployment has `zopp.dev/reload: "true"` annotation
/// 2. The Deployment references the given secret (via volume or envFrom)
fn should_reload(deployment: &Deployment, secret_name: &str) -> bool {
    let annotations = deployment.metadata.annotations.as_ref();

    // Check if zopp.dev/reload: "true" is set
    let reload_enabled = annotations
        .and_then(|a| a.get(RELOAD_ANNOTATION))
        .is_some_and(|v| v == "true");

    if !reload_enabled {
        return false;
    }

    // Check if Deployment references the secret
    references_secret(deployment, secret_name)
}

/// Check if a Deployment references a specific Secret.
fn references_secret(deployment: &Deployment, secret_name: &str) -> bool {
    let spec = match &deployment.spec {
        Some(s) => s,
        None => return false,
    };

    let pod_spec = match &spec.template.spec {
        Some(s) => s,
        None => return false,
    };

    // Check volumes
    if let Some(volumes) = &pod_spec.volumes {
        for volume in volumes {
            if let Some(secret) = &volume.secret {
                if secret
                    .secret_name
                    .as_ref()
                    .is_some_and(|n| n == secret_name)
                {
                    debug!(
                        "Deployment references secret {} via volume {}",
                        secret_name, volume.name
                    );
                    return true;
                }
            }
        }
    }

    // Check containers for envFrom
    for container in &pod_spec.containers {
        if let Some(env_from) = &container.env_from {
            for env_from_source in env_from {
                if let Some(secret_ref) = &env_from_source.secret_ref {
                    if secret_ref.name == secret_name {
                        debug!(
                            "Deployment references secret {} via envFrom in container {}",
                            secret_name, container.name
                        );
                        return true;
                    }
                }
            }
        }

        // Check individual env vars that reference secrets
        if let Some(env) = &container.env {
            for env_var in env {
                if let Some(value_from) = &env_var.value_from {
                    if let Some(secret_key_ref) = &value_from.secret_key_ref {
                        if secret_key_ref.name == secret_name {
                            debug!(
                                "Deployment references secret {} via env var {} in container {}",
                                secret_name, env_var.name, container.name
                            );
                            return true;
                        }
                    }
                }
            }
        }
    }

    // Check init containers too
    if let Some(init_containers) = &pod_spec.init_containers {
        for container in init_containers {
            if let Some(env_from) = &container.env_from {
                for env_from_source in env_from {
                    if let Some(secret_ref) = &env_from_source.secret_ref {
                        if secret_ref.name == secret_name {
                            return true;
                        }
                    }
                }
            }
        }
    }

    false
}

/// Restart a Deployment by updating its pod template annotation.
async fn restart_deployment(api: &Api<Deployment>, name: &str) -> Result<(), ReloadError> {
    let timestamp = chrono::Utc::now().to_rfc3339();

    let patch = serde_json::json!({
        "spec": {
            "template": {
                "metadata": {
                    "annotations": {
                        RESTARTED_AT_ANNOTATION: timestamp
                    }
                }
            }
        }
    });

    api.patch(
        name,
        &PatchParams::apply("zopp-operator"),
        &Patch::Merge(&patch),
    )
    .await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_annotation_constants() {
        assert_eq!(RELOAD_ANNOTATION, "zopp.dev/reload");
        assert_eq!(RESTARTED_AT_ANNOTATION, "zopp.dev/restartedAt");
    }
}
