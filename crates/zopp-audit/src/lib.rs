//! Audit logging abstraction for zopp.
//!
//! This crate defines the `AuditLog` trait for persisting audit events
//! and the types representing auditable actions in the system.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;
use zopp_storage::{EnvironmentId, PrincipalId, ProjectId, UserId, WorkspaceId};

/// Unique identifier for an audit log entry
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AuditLogId(pub Uuid);

impl AuditLogId {
    /// Generate a new audit log ID using UUID v7 (time-ordered)
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }
}

impl Default for AuditLogId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for AuditLogId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::str::FromStr for AuditLogId {
    type Err = uuid::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(Uuid::parse_str(s)?))
    }
}

/// Categories of auditable actions
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditAction {
    // Authentication
    UserJoin,
    UserRegister,
    PrincipalCreate,
    PrincipalRename,
    PrincipalRemove,
    PrincipalRevokeAllPermissions,

    // Workspace operations
    WorkspaceCreate,
    WorkspaceGrantAccess,
    WorkspaceRevokeAccess,

    // Project operations
    ProjectCreate,
    ProjectDelete,

    // Environment operations
    EnvironmentCreate,
    EnvironmentDelete,
    EnvironmentRotateKey,

    // Secret operations
    SecretCreate,
    SecretUpdate,
    SecretRead,
    SecretDelete,
    SecretList,

    // Invite operations
    InviteCreate,
    InviteConsume,
    InviteRevoke,

    // Permission operations (principal-level)
    PermissionSetWorkspace,
    PermissionSetProject,
    PermissionSetEnvironment,
    PermissionRemoveWorkspace,
    PermissionRemoveProject,
    PermissionRemoveEnvironment,

    // User permission operations
    UserPermissionSetWorkspace,
    UserPermissionSetProject,
    UserPermissionSetEnvironment,
    UserPermissionRemoveWorkspace,
    UserPermissionRemoveProject,
    UserPermissionRemoveEnvironment,

    // Group operations
    GroupCreate,
    GroupUpdate,
    GroupDelete,
    GroupMemberAdd,
    GroupMemberRemove,

    // Group permission operations
    GroupPermissionSetWorkspace,
    GroupPermissionSetProject,
    GroupPermissionSetEnvironment,
    GroupPermissionRemoveWorkspace,
    GroupPermissionRemoveProject,
    GroupPermissionRemoveEnvironment,
}

impl std::fmt::Display for AuditAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            AuditAction::UserJoin => "user.join",
            AuditAction::UserRegister => "user.register",
            AuditAction::PrincipalCreate => "principal.create",
            AuditAction::PrincipalRename => "principal.rename",
            AuditAction::PrincipalRemove => "principal.remove",
            AuditAction::PrincipalRevokeAllPermissions => "principal.revoke_all_permissions",
            AuditAction::WorkspaceCreate => "workspace.create",
            AuditAction::WorkspaceGrantAccess => "workspace.grant_access",
            AuditAction::WorkspaceRevokeAccess => "workspace.revoke_access",
            AuditAction::ProjectCreate => "project.create",
            AuditAction::ProjectDelete => "project.delete",
            AuditAction::EnvironmentCreate => "environment.create",
            AuditAction::EnvironmentDelete => "environment.delete",
            AuditAction::EnvironmentRotateKey => "environment.rotate_key",
            AuditAction::SecretCreate => "secret.create",
            AuditAction::SecretUpdate => "secret.update",
            AuditAction::SecretRead => "secret.read",
            AuditAction::SecretDelete => "secret.delete",
            AuditAction::SecretList => "secret.list",
            AuditAction::InviteCreate => "invite.create",
            AuditAction::InviteConsume => "invite.consume",
            AuditAction::InviteRevoke => "invite.revoke",
            AuditAction::PermissionSetWorkspace => "permission.set_workspace",
            AuditAction::PermissionSetProject => "permission.set_project",
            AuditAction::PermissionSetEnvironment => "permission.set_environment",
            AuditAction::PermissionRemoveWorkspace => "permission.remove_workspace",
            AuditAction::PermissionRemoveProject => "permission.remove_project",
            AuditAction::PermissionRemoveEnvironment => "permission.remove_environment",
            AuditAction::UserPermissionSetWorkspace => "user_permission.set_workspace",
            AuditAction::UserPermissionSetProject => "user_permission.set_project",
            AuditAction::UserPermissionSetEnvironment => "user_permission.set_environment",
            AuditAction::UserPermissionRemoveWorkspace => "user_permission.remove_workspace",
            AuditAction::UserPermissionRemoveProject => "user_permission.remove_project",
            AuditAction::UserPermissionRemoveEnvironment => "user_permission.remove_environment",
            AuditAction::GroupCreate => "group.create",
            AuditAction::GroupUpdate => "group.update",
            AuditAction::GroupDelete => "group.delete",
            AuditAction::GroupMemberAdd => "group.member_add",
            AuditAction::GroupMemberRemove => "group.member_remove",
            AuditAction::GroupPermissionSetWorkspace => "group_permission.set_workspace",
            AuditAction::GroupPermissionSetProject => "group_permission.set_project",
            AuditAction::GroupPermissionSetEnvironment => "group_permission.set_environment",
            AuditAction::GroupPermissionRemoveWorkspace => "group_permission.remove_workspace",
            AuditAction::GroupPermissionRemoveProject => "group_permission.remove_project",
            AuditAction::GroupPermissionRemoveEnvironment => "group_permission.remove_environment",
        };
        write!(f, "{}", s)
    }
}

impl std::str::FromStr for AuditAction {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "user.join" => Ok(AuditAction::UserJoin),
            "user.register" => Ok(AuditAction::UserRegister),
            "principal.create" => Ok(AuditAction::PrincipalCreate),
            "principal.rename" => Ok(AuditAction::PrincipalRename),
            "principal.remove" => Ok(AuditAction::PrincipalRemove),
            "principal.revoke_all_permissions" => Ok(AuditAction::PrincipalRevokeAllPermissions),
            "workspace.create" => Ok(AuditAction::WorkspaceCreate),
            "workspace.grant_access" => Ok(AuditAction::WorkspaceGrantAccess),
            "workspace.revoke_access" => Ok(AuditAction::WorkspaceRevokeAccess),
            "project.create" => Ok(AuditAction::ProjectCreate),
            "project.delete" => Ok(AuditAction::ProjectDelete),
            "environment.create" => Ok(AuditAction::EnvironmentCreate),
            "environment.delete" => Ok(AuditAction::EnvironmentDelete),
            "environment.rotate_key" => Ok(AuditAction::EnvironmentRotateKey),
            "secret.create" => Ok(AuditAction::SecretCreate),
            "secret.update" => Ok(AuditAction::SecretUpdate),
            "secret.read" => Ok(AuditAction::SecretRead),
            "secret.delete" => Ok(AuditAction::SecretDelete),
            "secret.list" => Ok(AuditAction::SecretList),
            "invite.create" => Ok(AuditAction::InviteCreate),
            "invite.consume" => Ok(AuditAction::InviteConsume),
            "invite.revoke" => Ok(AuditAction::InviteRevoke),
            "permission.set_workspace" => Ok(AuditAction::PermissionSetWorkspace),
            "permission.set_project" => Ok(AuditAction::PermissionSetProject),
            "permission.set_environment" => Ok(AuditAction::PermissionSetEnvironment),
            "permission.remove_workspace" => Ok(AuditAction::PermissionRemoveWorkspace),
            "permission.remove_project" => Ok(AuditAction::PermissionRemoveProject),
            "permission.remove_environment" => Ok(AuditAction::PermissionRemoveEnvironment),
            "user_permission.set_workspace" => Ok(AuditAction::UserPermissionSetWorkspace),
            "user_permission.set_project" => Ok(AuditAction::UserPermissionSetProject),
            "user_permission.set_environment" => Ok(AuditAction::UserPermissionSetEnvironment),
            "user_permission.remove_workspace" => Ok(AuditAction::UserPermissionRemoveWorkspace),
            "user_permission.remove_project" => Ok(AuditAction::UserPermissionRemoveProject),
            "user_permission.remove_environment" => {
                Ok(AuditAction::UserPermissionRemoveEnvironment)
            }
            "group.create" => Ok(AuditAction::GroupCreate),
            "group.update" => Ok(AuditAction::GroupUpdate),
            "group.delete" => Ok(AuditAction::GroupDelete),
            "group.member_add" => Ok(AuditAction::GroupMemberAdd),
            "group.member_remove" => Ok(AuditAction::GroupMemberRemove),
            "group_permission.set_workspace" => Ok(AuditAction::GroupPermissionSetWorkspace),
            "group_permission.set_project" => Ok(AuditAction::GroupPermissionSetProject),
            "group_permission.set_environment" => Ok(AuditAction::GroupPermissionSetEnvironment),
            "group_permission.remove_workspace" => Ok(AuditAction::GroupPermissionRemoveWorkspace),
            "group_permission.remove_project" => Ok(AuditAction::GroupPermissionRemoveProject),
            "group_permission.remove_environment" => {
                Ok(AuditAction::GroupPermissionRemoveEnvironment)
            }
            _ => Err(format!("Unknown audit action: {}", s)),
        }
    }
}

/// Result of an audited operation
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditResult {
    Success,
    PermissionDenied,
    NotFound,
    InvalidRequest,
    Error,
}

impl std::fmt::Display for AuditResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            AuditResult::Success => "success",
            AuditResult::PermissionDenied => "permission_denied",
            AuditResult::NotFound => "not_found",
            AuditResult::InvalidRequest => "invalid_request",
            AuditResult::Error => "error",
        };
        write!(f, "{}", s)
    }
}

impl std::str::FromStr for AuditResult {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "success" => Ok(AuditResult::Success),
            "permission_denied" => Ok(AuditResult::PermissionDenied),
            "not_found" => Ok(AuditResult::NotFound),
            "invalid_request" => Ok(AuditResult::InvalidRequest),
            "error" => Ok(AuditResult::Error),
            _ => Err(format!("Unknown audit result: {}", s)),
        }
    }
}

/// An audit log entry representing a single auditable action.
///
/// Uses raw UUIDs for serialization compatibility. Use the builder
/// to construct events from typed IDs.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditEvent {
    /// Unique identifier for this audit entry
    pub id: AuditLogId,
    /// When the action occurred
    pub timestamp: DateTime<Utc>,
    /// Principal that performed the action (UUID)
    pub principal_id: Uuid,
    /// User ID if this is a human user (None for service accounts)
    pub user_id: Option<Uuid>,
    /// The action that was performed
    pub action: AuditAction,
    /// Type of resource affected (e.g., "secret", "workspace", "permission")
    pub resource_type: String,
    /// Identifier of the affected resource
    pub resource_id: String,
    /// Workspace context (if applicable)
    pub workspace_id: Option<Uuid>,
    /// Project context (if applicable)
    pub project_id: Option<Uuid>,
    /// Environment context (if applicable)
    pub environment_id: Option<Uuid>,
    /// Result of the operation
    pub result: AuditResult,
    /// Error message or additional context
    pub reason: Option<String>,
    /// Additional details as JSON (e.g., old/new values, role changes)
    pub details: Option<serde_json::Value>,
    /// Client IP address (if available)
    pub client_ip: Option<String>,
}

impl AuditEvent {
    /// Create a new audit event builder
    pub fn builder(principal_id: &PrincipalId, action: AuditAction) -> AuditEventBuilder {
        AuditEventBuilder::new(principal_id, action)
    }

    /// Get the principal ID as a typed ID
    pub fn get_principal_id(&self) -> PrincipalId {
        PrincipalId(self.principal_id)
    }

    /// Get the user ID as a typed ID (if present)
    pub fn get_user_id(&self) -> Option<UserId> {
        self.user_id.map(UserId)
    }

    /// Get the workspace ID as a typed ID (if present)
    pub fn get_workspace_id(&self) -> Option<WorkspaceId> {
        self.workspace_id.map(WorkspaceId)
    }

    /// Get the project ID as a typed ID (if present)
    pub fn get_project_id(&self) -> Option<ProjectId> {
        self.project_id.map(ProjectId)
    }

    /// Get the environment ID as a typed ID (if present)
    pub fn get_environment_id(&self) -> Option<EnvironmentId> {
        self.environment_id.map(EnvironmentId)
    }
}

/// Builder for constructing audit events
pub struct AuditEventBuilder {
    principal_id: Uuid,
    action: AuditAction,
    user_id: Option<Uuid>,
    resource_type: String,
    resource_id: String,
    workspace_id: Option<Uuid>,
    project_id: Option<Uuid>,
    environment_id: Option<Uuid>,
    result: AuditResult,
    reason: Option<String>,
    details: Option<serde_json::Value>,
    client_ip: Option<String>,
}

impl AuditEventBuilder {
    pub fn new(principal_id: &PrincipalId, action: AuditAction) -> Self {
        Self {
            principal_id: principal_id.0,
            action,
            user_id: None,
            resource_type: String::new(),
            resource_id: String::new(),
            workspace_id: None,
            project_id: None,
            environment_id: None,
            result: AuditResult::Success,
            reason: None,
            details: None,
            client_ip: None,
        }
    }

    pub fn user_id(mut self, user_id: Option<&UserId>) -> Self {
        self.user_id = user_id.map(|u| u.0);
        self
    }

    pub fn resource(
        mut self,
        resource_type: impl Into<String>,
        resource_id: impl Into<String>,
    ) -> Self {
        self.resource_type = resource_type.into();
        self.resource_id = resource_id.into();
        self
    }

    pub fn workspace_id(mut self, workspace_id: Option<&WorkspaceId>) -> Self {
        self.workspace_id = workspace_id.map(|w| w.0);
        self
    }

    pub fn project_id(mut self, project_id: Option<&ProjectId>) -> Self {
        self.project_id = project_id.map(|p| p.0);
        self
    }

    pub fn environment_id(mut self, environment_id: Option<&EnvironmentId>) -> Self {
        self.environment_id = environment_id.map(|e| e.0);
        self
    }

    pub fn result(mut self, result: AuditResult) -> Self {
        self.result = result;
        self
    }

    pub fn reason(mut self, reason: impl Into<String>) -> Self {
        self.reason = Some(reason.into());
        self
    }

    pub fn details(mut self, details: serde_json::Value) -> Self {
        self.details = Some(details);
        self
    }

    pub fn client_ip(mut self, client_ip: impl Into<String>) -> Self {
        self.client_ip = Some(client_ip.into());
        self
    }

    pub fn build(self) -> AuditEvent {
        AuditEvent {
            id: AuditLogId::new(),
            timestamp: Utc::now(),
            principal_id: self.principal_id,
            user_id: self.user_id,
            action: self.action,
            resource_type: self.resource_type,
            resource_id: self.resource_id,
            workspace_id: self.workspace_id,
            project_id: self.project_id,
            environment_id: self.environment_id,
            result: self.result,
            reason: self.reason,
            details: self.details,
            client_ip: self.client_ip,
        }
    }
}

/// Filter for querying audit logs
#[derive(Clone, Debug, Default)]
pub struct AuditLogFilter {
    /// Filter by principal ID
    pub principal_id: Option<PrincipalId>,
    /// Filter by user ID
    pub user_id: Option<UserId>,
    /// Filter by workspace ID
    pub workspace_id: Option<WorkspaceId>,
    /// Filter by project ID
    pub project_id: Option<ProjectId>,
    /// Filter by environment ID
    pub environment_id: Option<EnvironmentId>,
    /// Filter by action
    pub action: Option<AuditAction>,
    /// Filter by result
    pub result: Option<AuditResult>,
    /// Filter by start timestamp (inclusive)
    pub from: Option<DateTime<Utc>>,
    /// Filter by end timestamp (exclusive)
    pub to: Option<DateTime<Utc>>,
    /// Maximum number of results to return
    pub limit: Option<u32>,
    /// Number of results to skip (for pagination)
    pub offset: Option<u32>,
}

impl AuditLogFilter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn principal_id(mut self, principal_id: PrincipalId) -> Self {
        self.principal_id = Some(principal_id);
        self
    }

    pub fn user_id(mut self, user_id: UserId) -> Self {
        self.user_id = Some(user_id);
        self
    }

    pub fn workspace_id(mut self, workspace_id: WorkspaceId) -> Self {
        self.workspace_id = Some(workspace_id);
        self
    }

    pub fn project_id(mut self, project_id: ProjectId) -> Self {
        self.project_id = Some(project_id);
        self
    }

    pub fn environment_id(mut self, environment_id: EnvironmentId) -> Self {
        self.environment_id = Some(environment_id);
        self
    }

    pub fn action(mut self, action: AuditAction) -> Self {
        self.action = Some(action);
        self
    }

    pub fn result(mut self, result: AuditResult) -> Self {
        self.result = Some(result);
        self
    }

    pub fn from(mut self, from: DateTime<Utc>) -> Self {
        self.from = Some(from);
        self
    }

    pub fn to(mut self, to: DateTime<Utc>) -> Self {
        self.to = Some(to);
        self
    }

    pub fn limit(mut self, limit: u32) -> Self {
        self.limit = Some(limit);
        self
    }

    pub fn offset(mut self, offset: u32) -> Self {
        self.offset = Some(offset);
        self
    }
}

/// Error type for audit log operations
#[derive(Debug, Error)]
pub enum AuditLogError {
    #[error("database error: {0}")]
    Database(String),

    #[error("audit log not found: {0}")]
    NotFound(AuditLogId),

    #[error("invalid filter: {0}")]
    InvalidFilter(String),
}

/// Trait for audit log persistence.
///
/// Implementations store audit events and provide query capabilities
/// for compliance and security monitoring.
#[async_trait]
pub trait AuditLog: Send + Sync {
    /// Record an audit event.
    ///
    /// This should be called after each auditable operation completes.
    /// Failures to record audit events should be logged but should not
    /// fail the main operation.
    async fn record(&self, event: AuditEvent) -> Result<(), AuditLogError>;

    /// Query audit logs with optional filters.
    ///
    /// Returns events matching the filter criteria, ordered by timestamp descending.
    async fn query(&self, filter: AuditLogFilter) -> Result<Vec<AuditEvent>, AuditLogError>;

    /// Get a specific audit log entry by ID.
    async fn get(&self, id: AuditLogId) -> Result<AuditEvent, AuditLogError>;

    /// Count audit logs matching the filter criteria.
    async fn count(&self, filter: AuditLogFilter) -> Result<u64, AuditLogError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_action_display() {
        assert_eq!(AuditAction::SecretCreate.to_string(), "secret.create");
        assert_eq!(AuditAction::UserJoin.to_string(), "user.join");
        assert_eq!(
            AuditAction::PermissionSetWorkspace.to_string(),
            "permission.set_workspace"
        );
    }

    #[test]
    fn test_audit_action_parse() {
        assert_eq!(
            "secret.create".parse::<AuditAction>().unwrap(),
            AuditAction::SecretCreate
        );
        assert_eq!(
            "user.join".parse::<AuditAction>().unwrap(),
            AuditAction::UserJoin
        );
        assert!("invalid.action".parse::<AuditAction>().is_err());
    }

    #[test]
    fn test_audit_result_display() {
        assert_eq!(AuditResult::Success.to_string(), "success");
        assert_eq!(
            AuditResult::PermissionDenied.to_string(),
            "permission_denied"
        );
    }

    #[test]
    fn test_audit_event_builder() {
        let principal_id = PrincipalId(Uuid::new_v4());
        let event = AuditEvent::builder(&principal_id, AuditAction::SecretCreate)
            .resource("secret", "API_KEY")
            .result(AuditResult::Success)
            .build();

        assert_eq!(event.principal_id, principal_id.0);
        assert_eq!(event.action, AuditAction::SecretCreate);
        assert_eq!(event.resource_type, "secret");
        assert_eq!(event.resource_id, "API_KEY");
        assert_eq!(event.result, AuditResult::Success);
    }

    #[test]
    fn test_audit_log_id_generation() {
        let id1 = AuditLogId::new();
        let id2 = AuditLogId::new();
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_audit_event_serialization() {
        let principal_id = PrincipalId(Uuid::new_v4());
        let event = AuditEvent::builder(&principal_id, AuditAction::SecretCreate)
            .resource("secret", "API_KEY")
            .result(AuditResult::Success)
            .build();

        let json = serde_json::to_string(&event).unwrap();
        let deserialized: AuditEvent = serde_json::from_str(&json).unwrap();

        assert_eq!(event.principal_id, deserialized.principal_id);
        assert_eq!(event.action, deserialized.action);
    }

    // Test all AuditAction variants display/parse roundtrip
    #[test]
    fn test_audit_action_all_variants_roundtrip() {
        let actions = vec![
            AuditAction::UserJoin,
            AuditAction::UserRegister,
            AuditAction::PrincipalCreate,
            AuditAction::PrincipalRename,
            AuditAction::PrincipalRemove,
            AuditAction::PrincipalRevokeAllPermissions,
            AuditAction::WorkspaceCreate,
            AuditAction::WorkspaceGrantAccess,
            AuditAction::WorkspaceRevokeAccess,
            AuditAction::ProjectCreate,
            AuditAction::ProjectDelete,
            AuditAction::EnvironmentCreate,
            AuditAction::EnvironmentDelete,
            AuditAction::EnvironmentRotateKey,
            AuditAction::SecretCreate,
            AuditAction::SecretUpdate,
            AuditAction::SecretRead,
            AuditAction::SecretDelete,
            AuditAction::SecretList,
            AuditAction::InviteCreate,
            AuditAction::InviteConsume,
            AuditAction::InviteRevoke,
            AuditAction::PermissionSetWorkspace,
            AuditAction::PermissionSetProject,
            AuditAction::PermissionSetEnvironment,
            AuditAction::PermissionRemoveWorkspace,
            AuditAction::PermissionRemoveProject,
            AuditAction::PermissionRemoveEnvironment,
            AuditAction::UserPermissionSetWorkspace,
            AuditAction::UserPermissionSetProject,
            AuditAction::UserPermissionSetEnvironment,
            AuditAction::UserPermissionRemoveWorkspace,
            AuditAction::UserPermissionRemoveProject,
            AuditAction::UserPermissionRemoveEnvironment,
            AuditAction::GroupCreate,
            AuditAction::GroupUpdate,
            AuditAction::GroupDelete,
            AuditAction::GroupMemberAdd,
            AuditAction::GroupMemberRemove,
            AuditAction::GroupPermissionSetWorkspace,
            AuditAction::GroupPermissionSetProject,
            AuditAction::GroupPermissionSetEnvironment,
            AuditAction::GroupPermissionRemoveWorkspace,
            AuditAction::GroupPermissionRemoveProject,
            AuditAction::GroupPermissionRemoveEnvironment,
        ];

        for action in actions {
            let display = action.to_string();
            let parsed: AuditAction = display.parse().unwrap();
            assert_eq!(action, parsed, "Roundtrip failed for {:?}", action);
        }
    }

    // Test all AuditResult variants display/parse roundtrip
    #[test]
    fn test_audit_result_all_variants_roundtrip() {
        let results = vec![
            AuditResult::Success,
            AuditResult::PermissionDenied,
            AuditResult::NotFound,
            AuditResult::InvalidRequest,
            AuditResult::Error,
        ];

        for result in results {
            let display = result.to_string();
            let parsed: AuditResult = display.parse().unwrap();
            assert_eq!(result, parsed, "Roundtrip failed for {:?}", result);
        }
    }

    #[test]
    fn test_audit_result_parse_error() {
        let result = "unknown_result".parse::<AuditResult>();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Unknown audit result"));
    }

    #[test]
    fn test_audit_log_id_display() {
        let uuid = Uuid::new_v4();
        let id = AuditLogId(uuid);
        assert_eq!(id.to_string(), uuid.to_string());
    }

    #[test]
    fn test_audit_log_id_parse() {
        let uuid = Uuid::new_v4();
        let id_str = uuid.to_string();
        let parsed: AuditLogId = id_str.parse().unwrap();
        assert_eq!(parsed.0, uuid);
    }

    #[test]
    fn test_audit_log_id_parse_invalid() {
        let result = "not-a-uuid".parse::<AuditLogId>();
        assert!(result.is_err());
    }

    #[test]
    fn test_audit_log_id_default() {
        let id1 = AuditLogId::default();
        let id2 = AuditLogId::default();
        assert_ne!(id1, id2); // Each default creates a new ID
    }

    #[test]
    fn test_audit_event_builder_with_all_fields() {
        let principal_id = PrincipalId(Uuid::new_v4());
        let user_id = UserId(Uuid::new_v4());
        let workspace_id = WorkspaceId(Uuid::new_v4());
        let project_id = ProjectId(Uuid::new_v4());
        let environment_id = EnvironmentId(Uuid::new_v4());

        let event = AuditEvent::builder(&principal_id, AuditAction::SecretCreate)
            .user_id(Some(&user_id))
            .resource("secret", "DATABASE_URL")
            .workspace_id(Some(&workspace_id))
            .project_id(Some(&project_id))
            .environment_id(Some(&environment_id))
            .result(AuditResult::Success)
            .reason("Test reason")
            .details(serde_json::json!({"old_value": "hidden", "new_value": "hidden"}))
            .client_ip("192.168.1.1")
            .build();

        assert_eq!(event.principal_id, principal_id.0);
        assert_eq!(event.user_id, Some(user_id.0));
        assert_eq!(event.resource_type, "secret");
        assert_eq!(event.resource_id, "DATABASE_URL");
        assert_eq!(event.workspace_id, Some(workspace_id.0));
        assert_eq!(event.project_id, Some(project_id.0));
        assert_eq!(event.environment_id, Some(environment_id.0));
        assert_eq!(event.result, AuditResult::Success);
        assert_eq!(event.reason, Some("Test reason".to_string()));
        assert!(event.details.is_some());
        assert_eq!(event.client_ip, Some("192.168.1.1".to_string()));
    }

    #[test]
    fn test_audit_event_builder_with_none_fields() {
        let principal_id = PrincipalId(Uuid::new_v4());

        let event = AuditEvent::builder(&principal_id, AuditAction::UserJoin)
            .user_id(None)
            .workspace_id(None)
            .project_id(None)
            .environment_id(None)
            .build();

        assert!(event.user_id.is_none());
        assert!(event.workspace_id.is_none());
        assert!(event.project_id.is_none());
        assert!(event.environment_id.is_none());
    }

    #[test]
    fn test_audit_event_get_typed_ids() {
        let principal_id = PrincipalId(Uuid::new_v4());
        let user_id = UserId(Uuid::new_v4());
        let workspace_id = WorkspaceId(Uuid::new_v4());
        let project_id = ProjectId(Uuid::new_v4());
        let environment_id = EnvironmentId(Uuid::new_v4());

        let event = AuditEvent::builder(&principal_id, AuditAction::SecretRead)
            .user_id(Some(&user_id))
            .workspace_id(Some(&workspace_id))
            .project_id(Some(&project_id))
            .environment_id(Some(&environment_id))
            .build();

        assert_eq!(event.get_principal_id(), principal_id);
        assert_eq!(event.get_user_id(), Some(user_id));
        assert_eq!(event.get_workspace_id(), Some(workspace_id));
        assert_eq!(event.get_project_id(), Some(project_id));
        assert_eq!(event.get_environment_id(), Some(environment_id));
    }

    #[test]
    fn test_audit_event_get_typed_ids_none() {
        let principal_id = PrincipalId(Uuid::new_v4());

        let event = AuditEvent::builder(&principal_id, AuditAction::UserRegister).build();

        assert_eq!(event.get_principal_id(), principal_id);
        assert!(event.get_user_id().is_none());
        assert!(event.get_workspace_id().is_none());
        assert!(event.get_project_id().is_none());
        assert!(event.get_environment_id().is_none());
    }

    #[test]
    fn test_audit_log_filter_builder() {
        let principal_uuid = Uuid::new_v4();
        let user_uuid = Uuid::new_v4();
        let workspace_uuid = Uuid::new_v4();
        let project_uuid = Uuid::new_v4();
        let environment_uuid = Uuid::new_v4();
        let from_time = Utc::now();
        let to_time = Utc::now();

        let filter = AuditLogFilter::new()
            .principal_id(PrincipalId(principal_uuid))
            .user_id(UserId(user_uuid))
            .workspace_id(WorkspaceId(workspace_uuid))
            .project_id(ProjectId(project_uuid))
            .environment_id(EnvironmentId(environment_uuid))
            .action(AuditAction::SecretCreate)
            .result(AuditResult::Success)
            .from(from_time)
            .to(to_time)
            .limit(100)
            .offset(50);

        assert_eq!(filter.principal_id, Some(PrincipalId(principal_uuid)));
        assert_eq!(filter.user_id, Some(UserId(user_uuid)));
        assert_eq!(filter.workspace_id, Some(WorkspaceId(workspace_uuid)));
        assert_eq!(filter.project_id, Some(ProjectId(project_uuid)));
        assert_eq!(filter.environment_id, Some(EnvironmentId(environment_uuid)));
        assert_eq!(filter.action, Some(AuditAction::SecretCreate));
        assert_eq!(filter.result, Some(AuditResult::Success));
        assert_eq!(filter.from, Some(from_time));
        assert_eq!(filter.to, Some(to_time));
        assert_eq!(filter.limit, Some(100));
        assert_eq!(filter.offset, Some(50));
    }

    #[test]
    fn test_audit_log_filter_default() {
        let filter = AuditLogFilter::default();

        assert!(filter.principal_id.is_none());
        assert!(filter.user_id.is_none());
        assert!(filter.workspace_id.is_none());
        assert!(filter.project_id.is_none());
        assert!(filter.environment_id.is_none());
        assert!(filter.action.is_none());
        assert!(filter.result.is_none());
        assert!(filter.from.is_none());
        assert!(filter.to.is_none());
        assert!(filter.limit.is_none());
        assert!(filter.offset.is_none());
    }

    #[test]
    fn test_audit_log_error_display() {
        let db_err = AuditLogError::Database("connection failed".to_string());
        assert!(db_err.to_string().contains("database error"));
        assert!(db_err.to_string().contains("connection failed"));

        let id = AuditLogId::new();
        let not_found_err = AuditLogError::NotFound(id);
        assert!(not_found_err.to_string().contains("not found"));

        let filter_err = AuditLogError::InvalidFilter("bad limit".to_string());
        assert!(filter_err.to_string().contains("invalid filter"));
        assert!(filter_err.to_string().contains("bad limit"));
    }

    #[test]
    fn test_audit_action_serde() {
        let action = AuditAction::SecretCreate;
        let json = serde_json::to_string(&action).unwrap();
        assert_eq!(json, "\"secret_create\"");

        let deserialized: AuditAction = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, action);
    }

    #[test]
    fn test_audit_result_serde() {
        let result = AuditResult::PermissionDenied;
        let json = serde_json::to_string(&result).unwrap();
        assert_eq!(json, "\"permission_denied\"");

        let deserialized: AuditResult = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, result);
    }

    #[test]
    fn test_audit_event_timestamp_is_recent() {
        let principal_id = PrincipalId(Uuid::new_v4());
        let before = Utc::now();
        let event = AuditEvent::builder(&principal_id, AuditAction::UserJoin).build();
        let after = Utc::now();

        assert!(event.timestamp >= before);
        assert!(event.timestamp <= after);
    }

    #[test]
    fn test_audit_log_id_is_v7() {
        let id = AuditLogId::new();
        // UUID v7 has version 7 in the version field
        assert_eq!(id.0.get_version_num(), 7);
    }
}
