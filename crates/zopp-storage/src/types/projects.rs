//! Project types.

use chrono::{DateTime, Utc};

use super::{ProjectId, WorkspaceId};

/// Project record
#[derive(Clone, Debug)]
pub struct Project {
    pub id: ProjectId,
    pub workspace_id: WorkspaceId,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Parameters for creating a project
#[derive(Clone, Debug)]
pub struct CreateProjectParams {
    pub workspace_id: WorkspaceId,
    pub name: String,
}
