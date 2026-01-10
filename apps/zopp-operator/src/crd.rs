//! Custom Resource Definitions for the Zopp operator.
//!
//! This module defines the `ZoppSecretSync` CRD which provides a declarative,
//! GitOps-friendly way to sync secrets from Zopp to Kubernetes.

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// ZoppSecretSync is a Kubernetes Custom Resource that defines how secrets
/// should be synchronized from Zopp to Kubernetes Secrets.
///
/// Example:
/// ```yaml
/// apiVersion: zopp.dev/v1alpha1
/// kind: ZoppSecretSync
/// metadata:
///   name: backend-production
///   namespace: zopp-system
/// spec:
///   source:
///     workspace: acme
///     project: backend
///     environment: production
///   target:
///     secretName: app-secrets
///     namespace: my-app
/// ```
#[derive(CustomResource, Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[kube(
    group = "zopp.dev",
    version = "v1alpha1",
    kind = "ZoppSecretSync",
    namespaced,
    status = "ZoppSecretSyncStatus",
    shortname = "zss",
    printcolumn = r#"{"name":"Workspace","type":"string","jsonPath":".spec.source.workspace"}"#,
    printcolumn = r#"{"name":"Project","type":"string","jsonPath":".spec.source.project"}"#,
    printcolumn = r#"{"name":"Environment","type":"string","jsonPath":".spec.source.environment"}"#,
    printcolumn = r#"{"name":"Target","type":"string","jsonPath":".spec.target.secretName"}"#,
    printcolumn = r#"{"name":"Ready","type":"string","jsonPath":".status.conditions[?(@.type==\"Ready\")].status"}"#,
    printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct ZoppSecretSyncSpec {
    /// Source specifies the Zopp location to sync secrets from.
    pub source: SecretSource,

    /// Target specifies the Kubernetes Secret to sync secrets to.
    pub target: SecretTarget,

    /// Sync interval in seconds. Defaults to 60.
    /// The operator will perform a full sync at this interval in addition
    /// to real-time event streaming.
    #[serde(default = "default_sync_interval")]
    pub sync_interval_seconds: u64,

    /// When true, the operator will not sync secrets for this resource.
    /// Useful for temporarily pausing sync without deleting the resource.
    #[serde(default)]
    pub suspend: bool,
}

fn default_sync_interval() -> u64 {
    60
}

/// SecretSource specifies where to sync secrets from in Zopp.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SecretSource {
    /// Workspace name in Zopp.
    pub workspace: String,

    /// Project name in Zopp.
    pub project: String,

    /// Environment name in Zopp.
    pub environment: String,
}

/// SecretTarget specifies where to sync secrets to in Kubernetes.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SecretTarget {
    /// Name of the Kubernetes Secret to create or update.
    pub secret_name: String,

    /// Namespace of the target Secret.
    /// Defaults to the namespace of the ZoppSecretSync resource.
    #[serde(default)]
    pub namespace: Option<String>,

    /// Type of the Kubernetes Secret to create.
    /// Defaults to "Opaque".
    #[serde(default = "default_secret_type")]
    pub secret_type: String,

    /// Labels to add to the created/updated Secret.
    #[serde(default)]
    pub labels: BTreeMap<String, String>,

    /// Annotations to add to the created/updated Secret.
    #[serde(default)]
    pub annotations: BTreeMap<String, String>,
}

fn default_secret_type() -> String {
    "Opaque".to_string()
}

/// Status of the ZoppSecretSync resource.
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ZoppSecretSyncStatus {
    /// Last time the sync was successfully completed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_sync_time: Option<String>,

    /// Version of the environment at the last successful sync.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_sync_version: Option<i64>,

    /// Number of secrets synced at the last successful sync.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret_count: Option<i32>,

    /// Generation observed by the controller.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_generation: Option<i64>,

    /// Standard Kubernetes conditions.
    #[serde(default)]
    pub conditions: Vec<Condition>,
}

/// Condition represents the state of a ZoppSecretSync resource.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Condition {
    /// Type of condition (e.g., "Ready", "Syncing").
    #[serde(rename = "type")]
    pub type_: String,

    /// Status of the condition: "True", "False", or "Unknown".
    pub status: String,

    /// Machine-readable reason for the condition's state.
    pub reason: String,

    /// Human-readable message explaining the condition.
    pub message: String,

    /// Last time the condition transitioned.
    pub last_transition_time: String,

    /// Generation observed when this condition was set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_generation: Option<i64>,
}

/// Well-known condition types for ZoppSecretSync.
#[allow(dead_code)]
pub mod condition_types {
    /// Ready indicates whether the sync is operational.
    pub const READY: &str = "Ready";

    /// Syncing indicates an active sync operation is in progress.
    pub const SYNCING: &str = "Syncing";
}

/// Well-known condition reasons.
#[allow(dead_code)]
pub mod condition_reasons {
    pub const SYNC_SUCCESS: &str = "SyncSuccess";
    pub const SYNC_FAILED: &str = "SyncFailed";
    pub const SUSPENDED: &str = "Suspended";
    pub const CREDENTIALS_INVALID: &str = "CredentialsInvalid";
    pub const CONNECTION_FAILED: &str = "ConnectionFailed";
    pub const DECRYPTION_FAILED: &str = "DecryptionFailed";
}

#[allow(dead_code)]
impl ZoppSecretSyncStatus {
    /// Create a new status with an empty condition list.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set or update a condition.
    ///
    /// Per Kubernetes convention, `lastTransitionTime` is preserved if the status
    /// hasn't changed (e.g., still "True" → "True"). It's only updated when the
    /// status actually transitions (e.g., "True" → "False").
    pub fn set_condition(&mut self, mut condition: Condition) {
        // Check if existing condition has same status - preserve lastTransitionTime
        if let Some(existing) = self.conditions.iter().find(|c| c.type_ == condition.type_) {
            if existing.status == condition.status {
                condition.last_transition_time = existing.last_transition_time.clone();
            }
        }
        // Remove existing condition of the same type
        self.conditions.retain(|c| c.type_ != condition.type_);
        self.conditions.push(condition);
    }

    /// Get a condition by type.
    pub fn get_condition(&self, type_: &str) -> Option<&Condition> {
        self.conditions.iter().find(|c| c.type_ == type_)
    }

    /// Check if the Ready condition is True.
    pub fn is_ready(&self) -> bool {
        self.get_condition(condition_types::READY)
            .map(|c| c.status == "True")
            .unwrap_or(false)
    }
}

impl Condition {
    /// Create a new condition with the current timestamp.
    pub fn new(
        type_: impl Into<String>,
        status: impl Into<String>,
        reason: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            type_: type_.into(),
            status: status.into(),
            reason: reason.into(),
            message: message.into(),
            last_transition_time: chrono::Utc::now().to_rfc3339(),
            observed_generation: None,
        }
    }

    /// Set the observed generation.
    pub fn with_generation(mut self, generation: i64) -> Self {
        self.observed_generation = Some(generation);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_sync_interval() {
        assert_eq!(default_sync_interval(), 60);
    }

    #[test]
    fn test_default_secret_type() {
        assert_eq!(default_secret_type(), "Opaque");
    }

    #[test]
    fn test_condition_new() {
        let cond = Condition::new("Ready", "True", "SyncSuccess", "Synced 10 secrets");
        assert_eq!(cond.type_, "Ready");
        assert_eq!(cond.status, "True");
        assert_eq!(cond.reason, "SyncSuccess");
        assert!(cond.observed_generation.is_none());
    }

    #[test]
    fn test_status_set_condition() {
        let mut status = ZoppSecretSyncStatus::new();
        let cond1 = Condition::new("Ready", "False", "SyncFailed", "Connection error");
        status.set_condition(cond1);
        assert_eq!(status.conditions.len(), 1);
        assert!(!status.is_ready());

        // Update the same condition type
        let cond2 = Condition::new("Ready", "True", "SyncSuccess", "Synced");
        status.set_condition(cond2);
        assert_eq!(status.conditions.len(), 1);
        assert!(status.is_ready());
    }

    #[test]
    fn test_set_condition_preserves_last_transition_time_when_status_unchanged() {
        let mut status = ZoppSecretSyncStatus::new();

        // Set initial condition
        let mut cond1 = Condition::new("Ready", "True", "SyncSuccess", "Synced 10 secrets");
        cond1.last_transition_time = "2025-01-01T00:00:00Z".to_string();
        status.set_condition(cond1);

        let original_time = status
            .get_condition("Ready")
            .unwrap()
            .last_transition_time
            .clone();

        // Update with same status but different message - should preserve lastTransitionTime
        let cond2 = Condition::new("Ready", "True", "SyncSuccess", "Synced 15 secrets");
        status.set_condition(cond2);

        let preserved_time = &status.get_condition("Ready").unwrap().last_transition_time;
        assert_eq!(preserved_time, &original_time);

        // Update with different status - should update lastTransitionTime
        let cond3 = Condition::new("Ready", "False", "SyncFailed", "Connection error");
        status.set_condition(cond3);

        let new_time = &status.get_condition("Ready").unwrap().last_transition_time;
        assert_ne!(new_time, &original_time);
    }
}
