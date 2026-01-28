//! Environment and secret types.

use chrono::{DateTime, Utc};

use super::{EnvironmentId, ProjectId};

/// Environment record
#[derive(Clone, Debug)]
pub struct Environment {
    pub id: EnvironmentId,
    pub project_id: ProjectId,
    pub name: String,
    pub dek_wrapped: Vec<u8>,
    pub dek_nonce: Vec<u8>,
    pub version: i64, // Monotonic version counter for change tracking
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Parameters for creating an environment
#[derive(Clone, Debug)]
pub struct CreateEnvParams {
    pub project_id: ProjectId,
    pub name: String,
    pub dek_wrapped: Vec<u8>, // wrapped DEK
    pub dek_nonce: Vec<u8>,   // 24-byte nonce used in wrapping
}

/// Encrypted secret row (nonce + ciphertext); no plaintext in storage.
#[derive(Clone, Debug)]
pub struct SecretRow {
    pub nonce: Vec<u8>,      // 24 bytes (XChaCha20 nonce)
    pub ciphertext: Vec<u8>, // AEAD ciphertext
}
