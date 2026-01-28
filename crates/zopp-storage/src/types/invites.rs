//! Invite types.

use chrono::{DateTime, Utc};

use super::{InviteId, UserId, WorkspaceId};

/// Invite record
#[derive(Clone, Debug)]
pub struct Invite {
    pub id: InviteId,
    pub token: String,
    pub workspace_ids: Vec<WorkspaceId>,
    pub kek_encrypted: Option<Vec<u8>>, // Workspace KEK encrypted with invite secret
    pub kek_nonce: Option<Vec<u8>>,     // 24-byte nonce for KEK encryption
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub created_by_user_id: Option<UserId>, // None for server-created invites
    pub consumed: bool,                     // Whether invite has been used
}

/// Parameters for creating an invite
#[derive(Clone, Debug)]
pub struct CreateInviteParams {
    pub workspace_ids: Vec<WorkspaceId>,
    pub token: String,                  // Hash of invite secret (for lookup)
    pub kek_encrypted: Option<Vec<u8>>, // Workspace KEK encrypted with invite secret
    pub kek_nonce: Option<Vec<u8>>,     // 24-byte nonce for KEK encryption
    pub expires_at: DateTime<Utc>,
    pub created_by_user_id: Option<UserId>, // None for server-created invites
}
