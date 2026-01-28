//! Permission types for RBAC at workspace, project, and environment levels.

use chrono::{DateTime, Utc};

use super::{EnvironmentId, GroupId, PrincipalId, ProjectId, Role, UserId, WorkspaceId};

/// Workspace-level permission for a principal
#[derive(Clone, Debug)]
pub struct WorkspacePermission {
    pub workspace_id: WorkspaceId,
    pub principal_id: PrincipalId,
    pub role: Role,
    pub created_at: DateTime<Utc>,
}

/// Project-level permission for a principal
#[derive(Clone, Debug)]
pub struct ProjectPermission {
    pub project_id: ProjectId,
    pub principal_id: PrincipalId,
    pub role: Role,
    pub created_at: DateTime<Utc>,
}

/// Environment-level permission for a principal
#[derive(Clone, Debug)]
pub struct EnvironmentPermission {
    pub environment_id: EnvironmentId,
    pub principal_id: PrincipalId,
    pub role: Role,
    pub created_at: DateTime<Utc>,
}

/// User workspace-level permission
#[derive(Clone, Debug)]
pub struct UserWorkspacePermission {
    pub workspace_id: WorkspaceId,
    pub user_id: UserId,
    pub role: Role,
    pub created_at: DateTime<Utc>,
}

/// User project-level permission
#[derive(Clone, Debug)]
pub struct UserProjectPermission {
    pub project_id: ProjectId,
    pub user_id: UserId,
    pub role: Role,
    pub created_at: DateTime<Utc>,
}

/// User environment-level permission
#[derive(Clone, Debug)]
pub struct UserEnvironmentPermission {
    pub environment_id: EnvironmentId,
    pub user_id: UserId,
    pub role: Role,
    pub created_at: DateTime<Utc>,
}

/// Group workspace-level permission
#[derive(Clone, Debug)]
pub struct GroupWorkspacePermission {
    pub workspace_id: WorkspaceId,
    pub group_id: GroupId,
    pub role: Role,
    pub created_at: DateTime<Utc>,
}

/// Group project-level permission
#[derive(Clone, Debug)]
pub struct GroupProjectPermission {
    pub project_id: ProjectId,
    pub group_id: GroupId,
    pub role: Role,
    pub created_at: DateTime<Utc>,
}

/// Group environment-level permission
#[derive(Clone, Debug)]
pub struct GroupEnvironmentPermission {
    pub environment_id: EnvironmentId,
    pub group_id: GroupId,
    pub role: Role,
    pub created_at: DateTime<Utc>,
}
