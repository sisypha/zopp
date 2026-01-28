//! Principal (device/service account) types.

use chrono::{DateTime, Utc};

use super::{PrincipalId, UserId};

/// Principal (device or service account) record
#[derive(Clone, Debug)]
pub struct Principal {
    pub id: PrincipalId,
    pub user_id: Option<UserId>, // None for service accounts
    pub name: String,
    pub public_key: Vec<u8>,                // Ed25519 for authentication
    pub x25519_public_key: Option<Vec<u8>>, // X25519 for encryption (ECDH)
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Parameters for creating a principal
#[derive(Clone, Debug)]
pub struct CreatePrincipalParams {
    pub user_id: Option<UserId>, // None for service accounts
    pub name: String,
    pub public_key: Vec<u8>,                // Ed25519 for authentication
    pub x25519_public_key: Option<Vec<u8>>, // X25519 for encryption (ECDH)
}
