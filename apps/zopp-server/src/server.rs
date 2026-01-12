use crate::backend::StoreBackend;
use chrono::Utc;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use prost::Message;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tonic::Status;
use zopp_audit::{AuditEvent, AuditLog};
use zopp_events::EventBus;
use zopp_storage::{EnvironmentId, Principal, PrincipalId, ProjectId, Store, WorkspaceId};
use zopp_store_postgres::PostgresStore;
use zopp_store_sqlite::SqliteStore;

#[derive(Clone)]
pub struct ZoppServer {
    pub store: StoreBackend,
    pub events: Arc<dyn EventBus>,
}

impl ZoppServer {
    pub fn new_sqlite(store: Arc<SqliteStore>, events: Arc<dyn EventBus>) -> Self {
        Self {
            store: StoreBackend::Sqlite(store),
            events,
        }
    }

    pub fn new_postgres(store: Arc<PostgresStore>, events: Arc<dyn EventBus>) -> Self {
        Self {
            store: StoreBackend::Postgres(store),
            events,
        }
    }

    /// Check if principal has at least the required role on the environment
    ///
    /// Permission hierarchy:
    /// 0. Workspace owners always have Admin access
    /// 1. Service accounts (no user_id): Use principal permission directly, else DENY
    /// 2. Human users:
    ///    a. base_role = max(user_permission, max(group_permissions)) at env/project/workspace levels
    ///    b. If principal permission exists: effective = min(base_role, principal_permission)
    ///    (Principal permissions can only RESTRICT, never expand access)
    ///    c. Use effective role
    /// 3. No permissions found = DENY (secure by default)
    ///
    /// Within each level, checks: environment → project → workspace (takes max)
    pub async fn check_permission(
        &self,
        principal_id: &PrincipalId,
        workspace_id: &WorkspaceId,
        project_id: &ProjectId,
        env_id: &EnvironmentId,
        required_role: zopp_storage::Role,
    ) -> Result<(), Status> {
        // Get the principal to find their user_id
        let principal = self
            .store
            .get_principal(principal_id)
            .await
            .map_err(|e| Status::internal(format!("Failed to get principal: {}", e)))?;

        // STEP 0: Workspace owners always have Admin access
        if let Some(ref uid) = principal.user_id {
            let workspace = self
                .store
                .get_workspace(workspace_id)
                .await
                .map_err(|e| Status::internal(format!("Failed to get workspace: {}", e)))?;
            if workspace.owner_user_id == *uid {
                return Ok(()); // Owner has full access
            }
        }

        // Get principal-level permission (if any) - will be used as ceiling for humans
        let principal_permission = self
            .get_principal_role(principal_id, workspace_id, project_id, env_id)
            .await;

        // STEP 1: Service accounts (no user_id) - principal permission is their only source
        let user_id = match principal.user_id {
            Some(uid) => uid,
            None => {
                // Service account: use principal permission directly
                return match principal_permission {
                    Some(role) if role.includes(&required_role) => Ok(()),
                    Some(_) => Err(Status::permission_denied(
                        "Insufficient service account permissions",
                    )),
                    None => Err(Status::permission_denied(
                        "No permissions found for service account",
                    )),
                };
            }
        };

        // STEP 2: Human user - collect base role from user + group permissions
        let mut base_role: Option<zopp_storage::Role> = None;

        // Check user-level permissions (environment → project → workspace)
        if let Ok(role) = self
            .store
            .get_user_environment_permission(env_id, &user_id)
            .await
        {
            base_role = Some(self.max_role(base_role, role));
        }
        if let Ok(role) = self
            .store
            .get_user_project_permission(project_id, &user_id)
            .await
        {
            base_role = Some(self.max_role(base_role, role));
        }
        if let Ok(role) = self
            .store
            .get_user_workspace_permission(workspace_id, &user_id)
            .await
        {
            base_role = Some(self.max_role(base_role, role));
        }

        // Check group-level permissions
        let groups = self
            .store
            .list_user_groups(&user_id)
            .await
            .map_err(|e| Status::internal(format!("Failed to list user groups: {}", e)))?;

        // Check environment-level group permissions
        for group in &groups {
            if let Ok(role) = self
                .store
                .get_group_environment_permission(env_id, &group.id)
                .await
            {
                base_role = Some(self.max_role(base_role, role));
            }
        }

        // Check project-level group permissions
        for group in &groups {
            if let Ok(role) = self
                .store
                .get_group_project_permission(project_id, &group.id)
                .await
            {
                base_role = Some(self.max_role(base_role, role));
            }
        }

        // Check workspace-level group permissions
        for group in &groups {
            if let Ok(role) = self
                .store
                .get_group_workspace_permission(workspace_id, &group.id)
                .await
            {
                base_role = Some(self.max_role(base_role, role));
            }
        }

        // STEP 3: Apply principal permission as ceiling (can only restrict, never expand)
        let effective_role = match (base_role, principal_permission) {
            (Some(base), Some(ceiling)) => Some(self.min_role(base, ceiling)),
            (Some(base), None) => Some(base),
            (None, Some(_)) => None, // Principal permission cannot grant access to humans, only restrict
            (None, None) => None,
        };

        // Check if the effective role is sufficient
        match effective_role {
            Some(role) if role.includes(&required_role) => Ok(()),
            Some(_) => Err(Status::permission_denied("Insufficient permissions")),
            None => Err(Status::permission_denied("No permissions found")),
        }
    }

    /// Get the maximum role from principal permissions at any level
    async fn get_principal_role(
        &self,
        principal_id: &PrincipalId,
        workspace_id: &WorkspaceId,
        project_id: &ProjectId,
        env_id: &EnvironmentId,
    ) -> Option<zopp_storage::Role> {
        let mut result: Option<zopp_storage::Role> = None;

        if let Ok(role) = self
            .store
            .get_environment_permission(env_id, principal_id)
            .await
        {
            result = Some(self.max_role(result, role));
        }
        if let Ok(role) = self
            .store
            .get_project_permission(project_id, principal_id)
            .await
        {
            result = Some(self.max_role(result, role));
        }
        if let Ok(role) = self
            .store
            .get_workspace_permission(workspace_id, principal_id)
            .await
        {
            result = Some(self.max_role(result, role));
        }

        result
    }

    /// Return the higher of two roles (Admin > Write > Read)
    pub(crate) fn max_role(
        &self,
        a: Option<zopp_storage::Role>,
        b: zopp_storage::Role,
    ) -> zopp_storage::Role {
        match a {
            None => b,
            Some(current) => {
                if b.includes(&current) {
                    b
                } else {
                    current
                }
            }
        }
    }

    /// Return the lower of two roles (Read < Write < Admin)
    pub(crate) fn min_role(
        &self,
        a: zopp_storage::Role,
        b: zopp_storage::Role,
    ) -> zopp_storage::Role {
        if a.includes(&b) {
            b
        } else {
            a
        }
    }

    /// Check if principal has at least the required role at workspace level
    ///
    /// This is used for workspace-level operations like creating projects/groups/invites.
    /// Uses workspace-level permissions only (not project or environment level).
    pub async fn check_workspace_permission(
        &self,
        principal_id: &PrincipalId,
        workspace_id: &WorkspaceId,
        required_role: zopp_storage::Role,
    ) -> Result<(), Status> {
        // Get the principal to find their user_id
        let principal = self
            .store
            .get_principal(principal_id)
            .await
            .map_err(|e| Status::internal(format!("Failed to get principal: {}", e)))?;

        // STEP 0: Workspace owners always have Admin access
        if let Some(ref uid) = principal.user_id {
            let workspace = self
                .store
                .get_workspace(workspace_id)
                .await
                .map_err(|e| Status::internal(format!("Failed to get workspace: {}", e)))?;
            if workspace.owner_user_id == *uid {
                return Ok(()); // Owner has full access
            }
        }

        // Get principal-level workspace permission (if any)
        let principal_permission = self
            .store
            .get_workspace_permission(workspace_id, principal_id)
            .await
            .ok();

        // STEP 1: Service accounts (no user_id) - principal permission is their only source
        let user_id = match principal.user_id {
            Some(uid) => uid,
            None => {
                return match principal_permission {
                    Some(role) if role.includes(&required_role) => Ok(()),
                    Some(_) => Err(Status::permission_denied(
                        "Insufficient service account permissions",
                    )),
                    None => Err(Status::permission_denied(
                        "No permissions found for service account",
                    )),
                };
            }
        };

        // STEP 2: Human user - collect base role from user + group permissions at workspace level
        let mut base_role: Option<zopp_storage::Role> = None;

        // Check user-level workspace permission
        if let Ok(role) = self
            .store
            .get_user_workspace_permission(workspace_id, &user_id)
            .await
        {
            base_role = Some(self.max_role(base_role, role));
        }

        // Check group-level workspace permissions
        let groups = self
            .store
            .list_user_groups(&user_id)
            .await
            .map_err(|e| Status::internal(format!("Failed to list user groups: {}", e)))?;

        for group in &groups {
            if let Ok(role) = self
                .store
                .get_group_workspace_permission(workspace_id, &group.id)
                .await
            {
                base_role = Some(self.max_role(base_role, role));
            }
        }

        // STEP 3: Apply principal permission as ceiling
        let effective_role = match (base_role, principal_permission) {
            (Some(base), Some(ceiling)) => Some(self.min_role(base, ceiling)),
            (Some(base), None) => Some(base),
            (None, Some(_)) => None,
            (None, None) => None,
        };

        // Check if the effective role is sufficient
        match effective_role {
            Some(role) if role.includes(&required_role) => Ok(()),
            Some(_) => Err(Status::permission_denied("Insufficient permissions")),
            None => Err(Status::permission_denied("No permissions found")),
        }
    }

    /// Get the effective role for a principal at workspace level (for delegated authority)
    ///
    /// Returns the effective role the principal has at the workspace level.
    pub async fn get_effective_workspace_role(
        &self,
        principal_id: &PrincipalId,
        workspace_id: &WorkspaceId,
    ) -> Result<Option<zopp_storage::Role>, Status> {
        let principal = self
            .store
            .get_principal(principal_id)
            .await
            .map_err(|e| Status::internal(format!("Failed to get principal: {}", e)))?;

        // Workspace owners always have Admin access
        if let Some(ref uid) = principal.user_id {
            let workspace = self
                .store
                .get_workspace(workspace_id)
                .await
                .map_err(|e| Status::internal(format!("Failed to get workspace: {}", e)))?;
            if workspace.owner_user_id == *uid {
                return Ok(Some(zopp_storage::Role::Admin));
            }
        }

        // Get principal-level workspace permission (if any)
        let principal_permission = self
            .store
            .get_workspace_permission(workspace_id, principal_id)
            .await
            .ok();

        // Service accounts - principal permission is their only source
        let user_id = match principal.user_id {
            Some(uid) => uid,
            None => return Ok(principal_permission),
        };

        // Human user - collect base role from user + group permissions at workspace level
        let mut base_role: Option<zopp_storage::Role> = None;

        if let Ok(role) = self
            .store
            .get_user_workspace_permission(workspace_id, &user_id)
            .await
        {
            base_role = Some(self.max_role(base_role, role));
        }

        // Check group permissions
        let groups = self
            .store
            .list_user_groups(&user_id)
            .await
            .map_err(|e| Status::internal(format!("Failed to list user groups: {}", e)))?;

        for group in &groups {
            if let Ok(role) = self
                .store
                .get_group_workspace_permission(workspace_id, &group.id)
                .await
            {
                base_role = Some(self.max_role(base_role, role));
            }
        }

        // Apply principal permission as ceiling
        let effective_role = match (base_role, principal_permission) {
            (Some(base), Some(ceiling)) => Some(self.min_role(base, ceiling)),
            (Some(base), None) => Some(base),
            (None, Some(_)) => None,
            (None, None) => None,
        };

        Ok(effective_role)
    }

    /// Check if principal has at least the required role at project level
    ///
    /// This is used for project-level operations like creating/deleting environments,
    /// setting project permissions, etc.
    /// Checks permissions at: project level AND workspace level (higher level inherits)
    pub async fn check_project_permission(
        &self,
        principal_id: &PrincipalId,
        workspace_id: &WorkspaceId,
        project_id: &ProjectId,
        required_role: zopp_storage::Role,
    ) -> Result<(), Status> {
        // Get the principal to find their user_id
        let principal = self
            .store
            .get_principal(principal_id)
            .await
            .map_err(|e| Status::internal(format!("Failed to get principal: {}", e)))?;

        // STEP 0: Workspace owners always have Admin access
        if let Some(ref uid) = principal.user_id {
            let workspace = self
                .store
                .get_workspace(workspace_id)
                .await
                .map_err(|e| Status::internal(format!("Failed to get workspace: {}", e)))?;
            if workspace.owner_user_id == *uid {
                return Ok(()); // Owner has full access
            }
        }

        // Get principal-level permissions (project + workspace)
        let mut principal_permission: Option<zopp_storage::Role> = None;
        if let Ok(role) = self
            .store
            .get_project_permission(project_id, principal_id)
            .await
        {
            principal_permission = Some(self.max_role(principal_permission, role));
        }
        if let Ok(role) = self
            .store
            .get_workspace_permission(workspace_id, principal_id)
            .await
        {
            principal_permission = Some(self.max_role(principal_permission, role));
        }

        // STEP 1: Service accounts (no user_id) - principal permission is their only source
        let user_id = match principal.user_id {
            Some(uid) => uid,
            None => {
                return match principal_permission {
                    Some(role) if role.includes(&required_role) => Ok(()),
                    Some(_) => Err(Status::permission_denied(
                        "Insufficient service account permissions",
                    )),
                    None => Err(Status::permission_denied(
                        "No permissions found for service account",
                    )),
                };
            }
        };

        // STEP 2: Human user - collect base role from user + group permissions
        let mut base_role: Option<zopp_storage::Role> = None;

        // Check user-level project permission
        if let Ok(role) = self
            .store
            .get_user_project_permission(project_id, &user_id)
            .await
        {
            base_role = Some(self.max_role(base_role, role));
        }
        // Check user-level workspace permission (higher level inherits)
        if let Ok(role) = self
            .store
            .get_user_workspace_permission(workspace_id, &user_id)
            .await
        {
            base_role = Some(self.max_role(base_role, role));
        }

        // Check group-level permissions
        let groups = self
            .store
            .list_user_groups(&user_id)
            .await
            .map_err(|e| Status::internal(format!("Failed to list user groups: {}", e)))?;

        // Check project-level group permissions
        for group in &groups {
            if let Ok(role) = self
                .store
                .get_group_project_permission(project_id, &group.id)
                .await
            {
                base_role = Some(self.max_role(base_role, role));
            }
        }
        // Check workspace-level group permissions (higher level inherits)
        for group in &groups {
            if let Ok(role) = self
                .store
                .get_group_workspace_permission(workspace_id, &group.id)
                .await
            {
                base_role = Some(self.max_role(base_role, role));
            }
        }

        // STEP 3: Apply principal permission as ceiling
        let effective_role = match (base_role, principal_permission) {
            (Some(base), Some(ceiling)) => Some(self.min_role(base, ceiling)),
            (Some(base), None) => Some(base),
            (None, Some(_)) => None,
            (None, None) => None,
        };

        // Check if the effective role is sufficient
        match effective_role {
            Some(role) if role.includes(&required_role) => Ok(()),
            Some(_) => Err(Status::permission_denied("Insufficient permissions")),
            None => Err(Status::permission_denied("No permissions found")),
        }
    }

    /// Get the effective role for a principal at project level (for delegated authority)
    ///
    /// Returns the effective role the principal has at the project level.
    /// Used to check if they can grant permissions (delegated authority).
    pub async fn get_effective_project_role(
        &self,
        principal_id: &PrincipalId,
        workspace_id: &WorkspaceId,
        project_id: &ProjectId,
    ) -> Result<Option<zopp_storage::Role>, Status> {
        let principal = self
            .store
            .get_principal(principal_id)
            .await
            .map_err(|e| Status::internal(format!("Failed to get principal: {}", e)))?;

        // Workspace owners always have Admin access
        if let Some(ref uid) = principal.user_id {
            let workspace = self
                .store
                .get_workspace(workspace_id)
                .await
                .map_err(|e| Status::internal(format!("Failed to get workspace: {}", e)))?;
            if workspace.owner_user_id == *uid {
                return Ok(Some(zopp_storage::Role::Admin));
            }
        }

        // Get principal-level permissions (project + workspace)
        let mut principal_permission: Option<zopp_storage::Role> = None;
        if let Ok(role) = self
            .store
            .get_project_permission(project_id, principal_id)
            .await
        {
            principal_permission = Some(self.max_role(principal_permission, role));
        }
        if let Ok(role) = self
            .store
            .get_workspace_permission(workspace_id, principal_id)
            .await
        {
            principal_permission = Some(self.max_role(principal_permission, role));
        }

        // Service accounts - principal permission is their only source
        let user_id = match principal.user_id {
            Some(uid) => uid,
            None => return Ok(principal_permission),
        };

        // Human user - collect base role from user + group permissions
        let mut base_role: Option<zopp_storage::Role> = None;

        if let Ok(role) = self
            .store
            .get_user_project_permission(project_id, &user_id)
            .await
        {
            base_role = Some(self.max_role(base_role, role));
        }
        if let Ok(role) = self
            .store
            .get_user_workspace_permission(workspace_id, &user_id)
            .await
        {
            base_role = Some(self.max_role(base_role, role));
        }

        // Check group permissions
        let groups = self
            .store
            .list_user_groups(&user_id)
            .await
            .map_err(|e| Status::internal(format!("Failed to list user groups: {}", e)))?;

        for group in &groups {
            if let Ok(role) = self
                .store
                .get_group_project_permission(project_id, &group.id)
                .await
            {
                base_role = Some(self.max_role(base_role, role));
            }
        }
        for group in &groups {
            if let Ok(role) = self
                .store
                .get_group_workspace_permission(workspace_id, &group.id)
                .await
            {
                base_role = Some(self.max_role(base_role, role));
            }
        }

        // Apply principal permission as ceiling
        let effective_role = match (base_role, principal_permission) {
            (Some(base), Some(ceiling)) => Some(self.min_role(base, ceiling)),
            (Some(base), None) => Some(base),
            (None, Some(_)) => None,
            (None, None) => None,
        };

        Ok(effective_role)
    }

    /// Get the effective role for a principal at environment level (for delegated authority)
    pub async fn get_effective_environment_role(
        &self,
        principal_id: &PrincipalId,
        workspace_id: &WorkspaceId,
        project_id: &ProjectId,
        env_id: &EnvironmentId,
    ) -> Result<Option<zopp_storage::Role>, Status> {
        let principal = self
            .store
            .get_principal(principal_id)
            .await
            .map_err(|e| Status::internal(format!("Failed to get principal: {}", e)))?;

        // Workspace owners always have Admin access
        if let Some(ref uid) = principal.user_id {
            let workspace = self
                .store
                .get_workspace(workspace_id)
                .await
                .map_err(|e| Status::internal(format!("Failed to get workspace: {}", e)))?;
            if workspace.owner_user_id == *uid {
                return Ok(Some(zopp_storage::Role::Admin));
            }
        }

        // Get principal-level permissions (env + project + workspace)
        let mut principal_permission: Option<zopp_storage::Role> = None;
        if let Ok(role) = self
            .store
            .get_environment_permission(env_id, principal_id)
            .await
        {
            principal_permission = Some(self.max_role(principal_permission, role));
        }
        if let Ok(role) = self
            .store
            .get_project_permission(project_id, principal_id)
            .await
        {
            principal_permission = Some(self.max_role(principal_permission, role));
        }
        if let Ok(role) = self
            .store
            .get_workspace_permission(workspace_id, principal_id)
            .await
        {
            principal_permission = Some(self.max_role(principal_permission, role));
        }

        // Service accounts - principal permission is their only source
        let user_id = match principal.user_id {
            Some(uid) => uid,
            None => return Ok(principal_permission),
        };

        // Human user - collect base role from user + group permissions at all levels
        let mut base_role: Option<zopp_storage::Role> = None;

        if let Ok(role) = self
            .store
            .get_user_environment_permission(env_id, &user_id)
            .await
        {
            base_role = Some(self.max_role(base_role, role));
        }
        if let Ok(role) = self
            .store
            .get_user_project_permission(project_id, &user_id)
            .await
        {
            base_role = Some(self.max_role(base_role, role));
        }
        if let Ok(role) = self
            .store
            .get_user_workspace_permission(workspace_id, &user_id)
            .await
        {
            base_role = Some(self.max_role(base_role, role));
        }

        // Check group permissions at all levels
        let groups = self
            .store
            .list_user_groups(&user_id)
            .await
            .map_err(|e| Status::internal(format!("Failed to list user groups: {}", e)))?;

        for group in &groups {
            if let Ok(role) = self
                .store
                .get_group_environment_permission(env_id, &group.id)
                .await
            {
                base_role = Some(self.max_role(base_role, role));
            }
        }
        for group in &groups {
            if let Ok(role) = self
                .store
                .get_group_project_permission(project_id, &group.id)
                .await
            {
                base_role = Some(self.max_role(base_role, role));
            }
        }
        for group in &groups {
            if let Ok(role) = self
                .store
                .get_group_workspace_permission(workspace_id, &group.id)
                .await
            {
                base_role = Some(self.max_role(base_role, role));
            }
        }

        // Apply principal permission as ceiling
        let effective_role = match (base_role, principal_permission) {
            (Some(base), Some(ceiling)) => Some(self.min_role(base, ceiling)),
            (Some(base), None) => Some(base),
            (None, Some(_)) => None,
            (None, None) => None,
        };

        Ok(effective_role)
    }

    /// Check if principal has at least the required role at environment level
    ///
    /// This is used for environment-level operations like setting environment permissions.
    /// Checks permissions at: environment level AND project level AND workspace level (higher levels inherit)
    pub async fn check_environment_permission(
        &self,
        principal_id: &PrincipalId,
        workspace_id: &WorkspaceId,
        project_id: &ProjectId,
        env_id: &EnvironmentId,
        required_role: zopp_storage::Role,
    ) -> Result<(), Status> {
        // Get the principal to find their user_id
        let principal = self
            .store
            .get_principal(principal_id)
            .await
            .map_err(|e| Status::internal(format!("Failed to get principal: {}", e)))?;

        // STEP 0: Workspace owners always have Admin access
        if let Some(ref uid) = principal.user_id {
            let workspace = self
                .store
                .get_workspace(workspace_id)
                .await
                .map_err(|e| Status::internal(format!("Failed to get workspace: {}", e)))?;
            if workspace.owner_user_id == *uid {
                return Ok(()); // Owner has full access
            }
        }

        // Get principal-level permissions (all levels)
        let mut principal_permission: Option<zopp_storage::Role> = None;
        if let Ok(role) = self
            .store
            .get_environment_permission(env_id, principal_id)
            .await
        {
            principal_permission = Some(self.max_role(principal_permission, role));
        }
        if let Ok(role) = self
            .store
            .get_project_permission(project_id, principal_id)
            .await
        {
            principal_permission = Some(self.max_role(principal_permission, role));
        }
        if let Ok(role) = self
            .store
            .get_workspace_permission(workspace_id, principal_id)
            .await
        {
            principal_permission = Some(self.max_role(principal_permission, role));
        }

        // STEP 1: Service accounts (no user_id) - principal permission is their only source
        let user_id = match principal.user_id {
            Some(uid) => uid,
            None => {
                return match principal_permission {
                    Some(role) if role.includes(&required_role) => Ok(()),
                    Some(_) => Err(Status::permission_denied(
                        "Insufficient service account permissions",
                    )),
                    None => Err(Status::permission_denied(
                        "No permissions found for service account",
                    )),
                };
            }
        };

        // STEP 2: Human user - collect base role from user + group permissions
        let mut base_role: Option<zopp_storage::Role> = None;

        // Check user-level environment permission
        if let Ok(role) = self
            .store
            .get_user_environment_permission(env_id, &user_id)
            .await
        {
            base_role = Some(self.max_role(base_role, role));
        }
        // Check user-level project permission (higher level inherits)
        if let Ok(role) = self
            .store
            .get_user_project_permission(project_id, &user_id)
            .await
        {
            base_role = Some(self.max_role(base_role, role));
        }
        // Check user-level workspace permission (higher level inherits)
        if let Ok(role) = self
            .store
            .get_user_workspace_permission(workspace_id, &user_id)
            .await
        {
            base_role = Some(self.max_role(base_role, role));
        }

        // Check group-level permissions
        let groups = self
            .store
            .list_user_groups(&user_id)
            .await
            .map_err(|e| Status::internal(format!("Failed to list user groups: {}", e)))?;

        // Check environment-level group permissions
        for group in &groups {
            if let Ok(role) = self
                .store
                .get_group_environment_permission(env_id, &group.id)
                .await
            {
                base_role = Some(self.max_role(base_role, role));
            }
        }
        // Check project-level group permissions (higher level inherits)
        for group in &groups {
            if let Ok(role) = self
                .store
                .get_group_project_permission(project_id, &group.id)
                .await
            {
                base_role = Some(self.max_role(base_role, role));
            }
        }
        // Check workspace-level group permissions (higher level inherits)
        for group in &groups {
            if let Ok(role) = self
                .store
                .get_group_workspace_permission(workspace_id, &group.id)
                .await
            {
                base_role = Some(self.max_role(base_role, role));
            }
        }

        // STEP 3: Apply principal permission as ceiling
        let effective_role = match (base_role, principal_permission) {
            (Some(base), Some(ceiling)) => Some(self.min_role(base, ceiling)),
            (Some(base), None) => Some(base),
            (None, Some(_)) => None,
            (None, None) => None,
        };

        // Check if the effective role is sufficient
        match effective_role {
            Some(role) if role.includes(&required_role) => Ok(()),
            Some(_) => Err(Status::permission_denied("Insufficient permissions")),
            None => Err(Status::permission_denied("No permissions found")),
        }
    }

    /// Verify the signature and return the principal.
    /// The signature must cover: method_name + request_hash + timestamp
    /// This prevents replay attacks across different methods or with different request bodies.
    pub async fn verify_signature_and_get_principal<T: Message>(
        &self,
        principal_id: &PrincipalId,
        timestamp: i64,
        signature: &[u8],
        method: &str,
        request: &T,
        provided_hash: &[u8],
    ) -> Result<Principal, Status> {
        // Check timestamp freshness (replay protection)
        let now = Utc::now().timestamp();
        let age = now - timestamp;

        if age > 60 {
            return Err(Status::unauthenticated(
                "Request timestamp too old (>60s), possible replay attack",
            ));
        }
        if age < -30 {
            return Err(Status::unauthenticated(
                "Request timestamp too far in future (>30s), check clock sync",
            ));
        }

        // Compute expected hash and verify it matches provided hash
        let body_bytes = request.encode_to_vec();
        let mut hasher = Sha256::new();
        hasher.update(method.as_bytes());
        hasher.update(&body_bytes);
        let expected_hash = hasher.finalize();

        if &expected_hash[..] != provided_hash {
            return Err(Status::unauthenticated(
                "Request hash mismatch - body may have been tampered",
            ));
        }

        let principal = self
            .store
            .get_principal(principal_id)
            .await
            .map_err(|_| Status::unauthenticated("Invalid principal"))?;

        let verifying_key = VerifyingKey::from_bytes(
            principal
                .public_key
                .as_slice()
                .try_into()
                .map_err(|_| Status::unauthenticated("Invalid public key length"))?,
        )
        .map_err(|_| Status::unauthenticated("Invalid public key"))?;

        let sig = Signature::from_bytes(
            signature
                .try_into()
                .map_err(|_| Status::unauthenticated("Invalid signature length"))?,
        );

        // Build the expected signed message: method + hash + timestamp
        let mut message = Vec::new();
        message.extend_from_slice(method.as_bytes());
        message.extend_from_slice(provided_hash);
        message.extend_from_slice(&timestamp.to_le_bytes());

        verifying_key
            .verify(&message, &sig)
            .map_err(|_| Status::unauthenticated("Invalid signature"))?;

        Ok(principal)
    }

    /// Check if principal has at least the required role at the workspace level.
    /// Simplified version of check_permission for operations that only need workspace access.
    pub async fn check_permission_workspace_only(
        &self,
        principal_id: &PrincipalId,
        workspace_id: &WorkspaceId,
        required_role: zopp_storage::Role,
    ) -> Result<(), Status> {
        // Get the principal to find their user_id
        let principal = self
            .store
            .get_principal(principal_id)
            .await
            .map_err(|e| Status::internal(format!("Failed to get principal: {}", e)))?;

        // Workspace owners always have Admin access
        if let Some(ref uid) = principal.user_id {
            let workspace = self
                .store
                .get_workspace(workspace_id)
                .await
                .map_err(|e| Status::internal(format!("Failed to get workspace: {}", e)))?;
            if workspace.owner_user_id == *uid {
                return Ok(());
            }
        }

        // Get principal-level workspace permission (if any) - this acts as a ceiling
        let principal_permission = self
            .store
            .get_workspace_permission(workspace_id, principal_id)
            .await
            .ok();

        // Get workspace permission
        let user_id = match principal.user_id {
            Some(uid) => uid,
            None => {
                // Service account: principal permission is their only source
                return match principal_permission {
                    Some(role) if role.includes(&required_role) => Ok(()),
                    Some(_) => Err(Status::permission_denied(
                        "Insufficient service account permissions",
                    )),
                    None => Err(Status::permission_denied(
                        "No permissions found for service account",
                    )),
                };
            }
        };

        // Human user - check user + group permissions
        let mut base_role: Option<zopp_storage::Role> = None;

        if let Ok(role) = self
            .store
            .get_user_workspace_permission(workspace_id, &user_id)
            .await
        {
            base_role = Some(role);
        }

        // Check group permissions
        if let Ok(groups) = self.store.list_user_groups(&user_id).await {
            for group in &groups {
                if let Ok(role) = self
                    .store
                    .get_group_workspace_permission(workspace_id, &group.id)
                    .await
                {
                    base_role = Some(self.max_role(base_role, role));
                }
            }
        }

        // Apply principal permission as ceiling (same as check_workspace_permission)
        let effective_role = match (base_role, principal_permission) {
            (Some(base), Some(ceiling)) => Some(self.min_role(base, ceiling)),
            (Some(base), None) => Some(base),
            (None, Some(_)) => None, // Principal permission alone doesn't grant access
            (None, None) => None,
        };

        match effective_role {
            Some(role) if role.includes(&required_role) => Ok(()),
            Some(_) => Err(Status::permission_denied("Insufficient permissions")),
            None => Err(Status::permission_denied("No permissions found")),
        }
    }

    /// Record an audit event. Failures are logged but do not fail the operation.
    pub async fn audit(&self, event: AuditEvent) {
        if let Err(e) = self.store.record(event).await {
            // Log the error but don't fail the operation
            eprintln!("Failed to record audit event: {}", e);
        }
    }
}

/// Helper function to extract signature metadata from gRPC request headers.
/// Returns (principal_id, timestamp, signature, request_hash).
pub fn extract_signature<T>(
    request: &tonic::Request<T>,
) -> Result<(PrincipalId, i64, Vec<u8>, Vec<u8>), Status> {
    let metadata = request.metadata();

    let principal_id_str = metadata
        .get("principal-id")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| Status::unauthenticated("Missing principal-id metadata"))?;

    let principal_id = uuid::Uuid::parse_str(principal_id_str)
        .map(PrincipalId)
        .map_err(|_| Status::unauthenticated("Invalid principal-id format"))?;

    let timestamp_str = metadata
        .get("timestamp")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| Status::unauthenticated("Missing timestamp metadata"))?;

    let timestamp = timestamp_str
        .parse::<i64>()
        .map_err(|_| Status::unauthenticated("Invalid timestamp format"))?;

    let signature_str = metadata
        .get("signature")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| Status::unauthenticated("Missing signature metadata"))?;

    let signature = hex::decode(signature_str)
        .map_err(|_| Status::unauthenticated("Invalid signature format"))?;

    let request_hash_str = metadata
        .get("request-hash")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| Status::unauthenticated("Missing request-hash metadata"))?;

    let request_hash = hex::decode(request_hash_str)
        .map_err(|_| Status::unauthenticated("Invalid request-hash format"))?;

    Ok((principal_id, timestamp, signature, request_hash))
}
