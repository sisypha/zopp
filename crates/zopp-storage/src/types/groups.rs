//! Group types for workspace-level user grouping.

use chrono::{DateTime, Utc};

use super::{GroupId, UserId, WorkspaceId};

/// Group record
#[derive(Clone, Debug)]
pub struct Group {
    pub id: GroupId,
    pub workspace_id: WorkspaceId,
    pub name: String,
    pub description: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Group membership record
#[derive(Clone, Debug)]
pub struct GroupMember {
    pub group_id: GroupId,
    pub user_id: UserId,
    pub created_at: DateTime<Utc>,
}

/// Parameters for creating a group
#[derive(Clone, Debug)]
pub struct CreateGroupParams {
    pub workspace_id: WorkspaceId,
    pub name: String,
    pub description: Option<String>,
}
