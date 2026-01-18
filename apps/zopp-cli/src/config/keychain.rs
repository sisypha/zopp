//! Keychain storage backend for principal secrets.
//!
//! This module provides cross-platform keychain access using the `keyring` crate.
//! Secrets are stored with the service name "dev.zopp.cli" and keyed by principal ID.

use thiserror::Error;
use zeroize::Zeroizing;

const SERVICE_NAME: &str = "dev.zopp.cli";

#[derive(Debug, Error)]
pub enum KeychainError {
    #[error("Keychain not available on this system. Use --use-file-storage to store credentials in config file.")]
    NotAvailable,
    #[error("Secret not found in keychain for principal: {0}")]
    NotFound(String),
    #[error("Keychain error: {0}")]
    Backend(String),
}

impl From<keyring::Error> for KeychainError {
    fn from(err: keyring::Error) -> Self {
        match err {
            keyring::Error::NoEntry => KeychainError::NotFound("unknown".to_string()),
            keyring::Error::NoStorageAccess(_) => KeychainError::NotAvailable,
            keyring::Error::PlatformFailure(_) => KeychainError::NotAvailable,
            _ => KeychainError::Backend(err.to_string()),
        }
    }
}

pub type KeychainResult<T> = Result<T, KeychainError>;

fn ed25519_key_name(principal_id: &str) -> String {
    format!("{}:ed25519_private", principal_id)
}

fn x25519_key_name(principal_id: &str) -> String {
    format!("{}:x25519_private", principal_id)
}

/// Store a principal's Ed25519 private key in the keychain.
pub fn store_ed25519_key(principal_id: &str, private_key_hex: &str) -> KeychainResult<()> {
    let entry = keyring::Entry::new(SERVICE_NAME, &ed25519_key_name(principal_id))?;
    entry.set_password(private_key_hex)?;
    Ok(())
}

/// Store a principal's X25519 private key in the keychain.
pub fn store_x25519_key(principal_id: &str, private_key_hex: &str) -> KeychainResult<()> {
    let entry = keyring::Entry::new(SERVICE_NAME, &x25519_key_name(principal_id))?;
    entry.set_password(private_key_hex)?;
    Ok(())
}

/// Retrieve a principal's Ed25519 private key from the keychain.
pub fn get_ed25519_key(principal_id: &str) -> KeychainResult<Zeroizing<String>> {
    let entry = keyring::Entry::new(SERVICE_NAME, &ed25519_key_name(principal_id))?;
    match entry.get_password() {
        Ok(password) => Ok(Zeroizing::new(password)),
        Err(keyring::Error::NoEntry) => Err(KeychainError::NotFound(principal_id.to_string())),
        Err(e) => Err(e.into()),
    }
}

/// Retrieve a principal's X25519 private key from the keychain.
pub fn get_x25519_key(principal_id: &str) -> KeychainResult<Option<Zeroizing<String>>> {
    let entry = keyring::Entry::new(SERVICE_NAME, &x25519_key_name(principal_id))?;
    match entry.get_password() {
        Ok(password) => Ok(Some(Zeroizing::new(password))),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// Delete all keychain entries for a principal.
pub fn delete_principal_keys(principal_id: &str) -> KeychainResult<()> {
    // Delete Ed25519 key
    let ed25519_entry = keyring::Entry::new(SERVICE_NAME, &ed25519_key_name(principal_id))?;
    match ed25519_entry.delete_credential() {
        Ok(()) => {}
        Err(keyring::Error::NoEntry) => {}
        Err(e) => return Err(e.into()),
    }

    // Delete X25519 key
    let x25519_entry = keyring::Entry::new(SERVICE_NAME, &x25519_key_name(principal_id))?;
    match x25519_entry.delete_credential() {
        Ok(()) => {}
        Err(keyring::Error::NoEntry) => {}
        Err(e) => return Err(e.into()),
    }

    Ok(())
}

/// Check if keychain is available on this system.
#[allow(dead_code)]
pub fn is_available() -> bool {
    // Try to create a test entry to see if the keychain is accessible
    keyring::Entry::new(SERVICE_NAME, "availability_test").is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    // Note: These tests require a working keychain on the system.
    // In CI, these may be skipped if keychain is not available.

    #[test]
    fn test_key_name_generation() {
        let principal_id = "550e8400-e29b-41d4-a716-446655440000";
        assert_eq!(
            ed25519_key_name(principal_id),
            "550e8400-e29b-41d4-a716-446655440000:ed25519_private"
        );
        assert_eq!(
            x25519_key_name(principal_id),
            "550e8400-e29b-41d4-a716-446655440000:x25519_private"
        );
    }

    #[test]
    #[ignore = "requires system keychain"]
    fn test_store_and_retrieve_ed25519_key() {
        let principal_id = "test-principal-ed25519";
        let key = "a".repeat(64);

        store_ed25519_key(principal_id, &key).unwrap();
        let retrieved = get_ed25519_key(principal_id).unwrap();
        assert_eq!(*retrieved, key);

        delete_principal_keys(principal_id).unwrap();
    }

    #[test]
    #[ignore = "requires system keychain"]
    fn test_store_and_retrieve_x25519_key() {
        let principal_id = "test-principal-x25519";
        let key = "b".repeat(64);

        store_x25519_key(principal_id, &key).unwrap();
        let retrieved = get_x25519_key(principal_id).unwrap();
        assert_eq!(retrieved.map(|k| (*k).clone()), Some(key));

        delete_principal_keys(principal_id).unwrap();
    }

    #[test]
    #[ignore = "requires system keychain"]
    fn test_get_nonexistent_key() {
        let result = get_ed25519_key("nonexistent-principal-12345");
        assert!(matches!(result, Err(KeychainError::NotFound(_))));
    }

    #[test]
    #[ignore = "requires system keychain"]
    fn test_delete_nonexistent_key_is_ok() {
        // Deleting a key that doesn't exist should not error
        let result = delete_principal_keys("nonexistent-principal-67890");
        assert!(result.is_ok());
    }
}
