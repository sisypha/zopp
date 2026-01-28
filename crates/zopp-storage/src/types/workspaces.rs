//! Workspace types.

use chrono::{DateTime, Utc};

use super::{PrincipalId, UserId, WorkspaceId};

/// Workspace record
#[derive(Clone, Debug)]
pub struct Workspace {
    pub id: WorkspaceId,
    pub name: String,
    pub owner_user_id: UserId,
    pub kdf_salt: Vec<u8>,
    pub m_cost_kib: u32,
    pub t_cost: u32,
    pub p_cost: u32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Parameters for creating a workspace
#[derive(Clone, Debug)]
pub struct CreateWorkspaceParams {
    pub id: WorkspaceId, // Client-generated workspace ID
    pub name: String,
    pub owner_user_id: UserId,
    pub kdf_salt: Vec<u8>, // >= 16 bytes
    pub m_cost_kib: u32,   // memory cost (KiB)
    pub t_cost: u32,       // iterations
    pub p_cost: u32,       // parallelism
}

/// Workspace-Principal junction with wrapped KEK
#[derive(Clone, Debug)]
pub struct WorkspacePrincipal {
    pub workspace_id: WorkspaceId,
    pub principal_id: PrincipalId,
    pub ephemeral_pub: Vec<u8>, // Ephemeral X25519 public key for wrapping
    pub kek_wrapped: Vec<u8>,   // Workspace KEK wrapped for this principal
    pub kek_nonce: Vec<u8>,     // 24-byte nonce for wrapping
    pub created_at: DateTime<Utc>,
}

/// Parameters for adding a principal to a workspace with wrapped KEK
#[derive(Clone, Debug)]
pub struct AddWorkspacePrincipalParams {
    pub workspace_id: WorkspaceId,
    pub principal_id: PrincipalId,
    pub ephemeral_pub: Vec<u8>,
    pub kek_wrapped: Vec<u8>,
    pub kek_nonce: Vec<u8>,
}
