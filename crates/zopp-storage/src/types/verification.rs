//! Email verification and principal export types.

use chrono::{DateTime, Utc};

use super::{EmailVerificationId, PrincipalExportId, PrincipalId, UserId};

/// Principal export record for multi-device transfer
#[derive(Clone, Debug)]
pub struct PrincipalExport {
    pub id: PrincipalExportId,
    pub export_code: String, // Public identifier for lookup (e.g., "exp_a7k9m2x4")
    pub token_hash: String,  // Argon2id(passphrase, verification_salt) for verification
    pub verification_salt: Vec<u8>, // Salt for passphrase verification (separate from encryption)
    pub user_id: UserId,
    pub principal_id: PrincipalId,
    pub encrypted_data: Vec<u8>, // Encrypted principal JSON
    pub salt: Vec<u8>,           // Argon2id salt for encryption key derivation
    pub nonce: Vec<u8>,          // XChaCha20-Poly1305 nonce
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub consumed: bool,
    pub failed_attempts: i32, // Track failed passphrase attempts (delete after 3)
}

/// Parameters for creating a principal export
#[derive(Clone, Debug)]
pub struct CreatePrincipalExportParams {
    pub export_code: String, // Public identifier for lookup (e.g., "exp_a7k9m2x4")
    pub token_hash: String,  // Argon2id(passphrase, verification_salt) for verification
    pub verification_salt: Vec<u8>, // Salt for passphrase verification (separate from encryption)
    pub user_id: UserId,
    pub principal_id: PrincipalId,
    pub encrypted_data: Vec<u8>, // Encrypted principal JSON
    pub salt: Vec<u8>,           // Argon2id salt for encryption key derivation
    pub nonce: Vec<u8>,          // XChaCha20-Poly1305 nonce
    pub expires_at: DateTime<Utc>,
}

/// Email verification record for verifying email ownership during join
#[derive(Clone, Debug)]
pub struct EmailVerification {
    pub id: EmailVerificationId,
    pub email: String,        // Email being verified (lowercased, unique)
    pub code_hash: String,    // Argon2id hash of verification code (hex-encoded, zero-knowledge)
    pub invite_token: String, // Invite token to consume on verification success
    pub attempts: i32,        // Failed verification attempts
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// Parameters for creating/upserting an email verification
#[derive(Clone, Debug)]
pub struct CreateEmailVerificationParams {
    pub email: String,             // Email being verified (lowercased)
    pub code_hash: String, // Argon2id hash of verification code (hex-encoded, zero-knowledge)
    pub invite_token: String, // Invite token to consume on success
    pub expires_at: DateTime<Utc>, // When the code expires
}
