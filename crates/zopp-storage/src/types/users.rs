//! User types.

use chrono::{DateTime, Utc};

use super::{UserId, WorkspaceId};

/// User record
#[derive(Clone, Debug)]
pub struct User {
    pub id: UserId,
    pub email: String,
    pub verified: bool, // Email verification status
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Parameters for creating a user
#[derive(Clone, Debug)]
pub struct CreateUserParams {
    pub email: String,
    /// Optional principal to create atomically with the user
    pub principal: Option<CreatePrincipalData>,
    /// Workspaces to add this user to (user-level membership)
    pub workspace_ids: Vec<WorkspaceId>,
}

/// Principal data for atomic user creation
#[derive(Clone, Debug)]
pub struct CreatePrincipalData {
    pub name: String,
    pub public_key: Vec<u8>,                // Ed25519 for authentication
    pub x25519_public_key: Option<Vec<u8>>, // X25519 for encryption (ECDH)
    pub is_service: bool,                   // Service principal (user_id will be NULL)
}
