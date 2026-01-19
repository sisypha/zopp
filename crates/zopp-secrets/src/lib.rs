use thiserror::Error;
use zopp_crypto::{decrypt, encrypt, public_key_from_bytes, unwrap_key, Dek, Keypair, Nonce};
use zopp_proto::{Environment, Secret, WorkspaceKeys};

#[derive(Debug, Error)]
pub enum SecretsError {
    #[error("Crypto error: {0}")]
    Crypto(String),
    #[error("Invalid data: {0}")]
    InvalidData(String),
}

/// High-level context for encrypting and decrypting secrets.
/// Bundles principal key, workspace keys, and environment to hide all crypto details.
pub struct SecretContext {
    principal_keypair: Keypair,
    workspace_keys: WorkspaceKeys,
    environment: Environment,
    workspace_name: String,
    project_name: String,
    environment_name: String,
}

impl SecretContext {
    /// Create a new SecretContext from principal key, workspace keys, and environment.
    pub fn new(
        principal_x25519_private_key: [u8; 32],
        workspace_keys: WorkspaceKeys,
        environment: Environment,
        workspace_name: String,
        project_name: String,
        environment_name: String,
    ) -> Result<Self, SecretsError> {
        let principal_keypair = Keypair::from_secret_bytes(&principal_x25519_private_key);

        Ok(Self {
            principal_keypair,
            workspace_keys,
            environment,
            workspace_name,
            project_name,
            environment_name,
        })
    }

    /// Decrypt a secret using the bundled context.
    /// Handles all KEK/DEK unwrapping, ECDH, and AAD construction internally.
    pub fn decrypt_secret(&self, secret: &Secret) -> Result<String, SecretsError> {
        // 1. Unwrap KEK using ECDH
        let ephemeral_public = public_key_from_bytes(&self.workspace_keys.ephemeral_pub)
            .map_err(|e| SecretsError::InvalidData(e.to_string()))?;

        let mut nonce_array = [0u8; 24];
        nonce_array.copy_from_slice(&self.workspace_keys.kek_nonce);
        let kek_nonce = Nonce(nonce_array);

        let shared_secret = self.principal_keypair.shared_secret(&ephemeral_public);
        let aad = format!("workspace:{}", self.workspace_keys.workspace_id).into_bytes();

        let kek_unwrapped = unwrap_key(
            &self.workspace_keys.kek_wrapped,
            &kek_nonce,
            &shared_secret,
            &aad,
        )
        .map_err(|e| SecretsError::Crypto(e.to_string()))?;

        let mut kek_bytes = [0u8; 32];
        kek_bytes.copy_from_slice(&kek_unwrapped);
        let kek =
            Dek::from_bytes(&kek_bytes).map_err(|e| SecretsError::InvalidData(e.to_string()))?;

        // 2. Unwrap DEK using KEK
        let mut dek_nonce_array = [0u8; 24];
        dek_nonce_array.copy_from_slice(&self.environment.dek_nonce);
        let dek_nonce = Nonce(dek_nonce_array);

        let dek_aad = format!(
            "environment:{}:{}:{}",
            self.workspace_name, self.project_name, self.environment_name
        )
        .into_bytes();

        let dek_unwrapped = decrypt(&self.environment.dek_wrapped, &dek_nonce, &kek, &dek_aad)
            .map_err(|e| SecretsError::Crypto(e.to_string()))?;

        let mut dek_bytes = [0u8; 32];
        dek_bytes.copy_from_slice(&dek_unwrapped);
        let dek =
            Dek::from_bytes(&dek_bytes).map_err(|e| SecretsError::InvalidData(e.to_string()))?;

        // 3. Decrypt secret using DEK
        let mut secret_nonce_array = [0u8; 24];
        secret_nonce_array.copy_from_slice(&secret.nonce);
        let secret_nonce = Nonce(secret_nonce_array);

        let secret_aad = format!(
            "secret:{}:{}:{}:{}",
            self.workspace_name, self.project_name, self.environment_name, secret.key
        )
        .into_bytes();

        let plaintext = decrypt(&secret.ciphertext, &secret_nonce, &dek, &secret_aad)
            .map_err(|e| SecretsError::Crypto(e.to_string()))?;

        String::from_utf8(plaintext.to_vec())
            .map_err(|e| SecretsError::InvalidData(format!("Invalid UTF-8: {}", e)))
    }

    /// Encrypt a secret using the bundled context.
    /// Handles all KEK/DEK unwrapping, ECDH, nonce generation, and AAD construction internally.
    pub fn encrypt_secret(&self, key: &str, value: &str) -> Result<EncryptedSecret, SecretsError> {
        // 1. Unwrap KEK using ECDH
        let ephemeral_public = public_key_from_bytes(&self.workspace_keys.ephemeral_pub)
            .map_err(|e| SecretsError::InvalidData(e.to_string()))?;

        let mut nonce_array = [0u8; 24];
        nonce_array.copy_from_slice(&self.workspace_keys.kek_nonce);
        let kek_nonce = Nonce(nonce_array);

        let shared_secret = self.principal_keypair.shared_secret(&ephemeral_public);
        let aad = format!("workspace:{}", self.workspace_keys.workspace_id).into_bytes();

        let kek_unwrapped = unwrap_key(
            &self.workspace_keys.kek_wrapped,
            &kek_nonce,
            &shared_secret,
            &aad,
        )
        .map_err(|e| SecretsError::Crypto(e.to_string()))?;

        let mut kek_bytes = [0u8; 32];
        kek_bytes.copy_from_slice(&kek_unwrapped);
        let kek =
            Dek::from_bytes(&kek_bytes).map_err(|e| SecretsError::InvalidData(e.to_string()))?;

        // 2. Unwrap DEK using KEK
        let mut dek_nonce_array = [0u8; 24];
        dek_nonce_array.copy_from_slice(&self.environment.dek_nonce);
        let dek_nonce = Nonce(dek_nonce_array);

        let dek_aad = format!(
            "environment:{}:{}:{}",
            self.workspace_name, self.project_name, self.environment_name
        )
        .into_bytes();

        let dek_unwrapped = decrypt(&self.environment.dek_wrapped, &dek_nonce, &kek, &dek_aad)
            .map_err(|e| SecretsError::Crypto(e.to_string()))?;

        let mut dek_bytes = [0u8; 32];
        dek_bytes.copy_from_slice(&dek_unwrapped);
        let dek =
            Dek::from_bytes(&dek_bytes).map_err(|e| SecretsError::InvalidData(e.to_string()))?;

        // 3. Construct AAD and encrypt value with DEK
        let secret_aad = format!(
            "secret:{}:{}:{}:{}",
            self.workspace_name, self.project_name, self.environment_name, key
        )
        .into_bytes();

        let (nonce, ciphertext) = encrypt(value.as_bytes(), &dek, &secret_aad)
            .map_err(|e| SecretsError::Crypto(e.to_string()))?;

        Ok(EncryptedSecret {
            ciphertext: ciphertext.0,
            nonce: nonce.0.to_vec(),
        })
    }
}

/// Result of encrypting a secret
#[derive(Debug)]
pub struct EncryptedSecret {
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
}

/// Unwrap an environment DEK given workspace keys and environment data.
/// This is a lower-level helper useful for caching DEKs (e.g., in the operator).
/// Returns the raw 32-byte DEK.
pub fn unwrap_dek(
    principal_x25519_private_key: &[u8; 32],
    workspace_keys: &WorkspaceKeys,
    environment: &Environment,
    workspace_name: &str,
    project_name: &str,
    environment_name: &str,
) -> Result<[u8; 32], SecretsError> {
    let principal_keypair = Keypair::from_secret_bytes(principal_x25519_private_key);

    // 1. Unwrap KEK using ECDH
    let ephemeral_public = public_key_from_bytes(&workspace_keys.ephemeral_pub)
        .map_err(|e| SecretsError::InvalidData(e.to_string()))?;

    let mut nonce_array = [0u8; 24];
    nonce_array.copy_from_slice(&workspace_keys.kek_nonce);
    let kek_nonce = Nonce(nonce_array);

    let shared_secret = principal_keypair.shared_secret(&ephemeral_public);
    let aad = format!("workspace:{}", workspace_keys.workspace_id).into_bytes();

    let kek_unwrapped = unwrap_key(
        &workspace_keys.kek_wrapped,
        &kek_nonce,
        &shared_secret,
        &aad,
    )
    .map_err(|e| SecretsError::Crypto(e.to_string()))?;

    let mut kek_bytes = [0u8; 32];
    kek_bytes.copy_from_slice(&kek_unwrapped);
    let kek = Dek::from_bytes(&kek_bytes).map_err(|e| SecretsError::InvalidData(e.to_string()))?;

    // 2. Unwrap DEK using KEK
    let mut dek_nonce_array = [0u8; 24];
    dek_nonce_array.copy_from_slice(&environment.dek_nonce);
    let dek_nonce = Nonce(dek_nonce_array);

    let dek_aad = format!(
        "environment:{}:{}:{}",
        workspace_name, project_name, environment_name
    )
    .into_bytes();

    let dek_unwrapped = decrypt(&environment.dek_wrapped, &dek_nonce, &kek, &dek_aad)
        .map_err(|e| SecretsError::Crypto(e.to_string()))?;

    let mut dek_bytes = [0u8; 32];
    dek_bytes.copy_from_slice(&dek_unwrapped);

    Ok(dek_bytes)
}

/// Decrypt a single secret given a raw DEK and environment context.
/// This is a lower-level helper useful when you have a cached DEK.
pub fn decrypt_secret_with_dek(
    dek_bytes: &[u8; 32],
    secret: &Secret,
    workspace_name: &str,
    project_name: &str,
    environment_name: &str,
) -> Result<String, SecretsError> {
    let dek = Dek::from_bytes(dek_bytes).map_err(|e| SecretsError::InvalidData(e.to_string()))?;

    let mut secret_nonce_array = [0u8; 24];
    secret_nonce_array.copy_from_slice(&secret.nonce);
    let secret_nonce = Nonce(secret_nonce_array);

    let secret_aad = format!(
        "secret:{}:{}:{}:{}",
        workspace_name, project_name, environment_name, secret.key
    )
    .into_bytes();

    let plaintext = decrypt(&secret.ciphertext, &secret_nonce, &dek, &secret_aad)
        .map_err(|e| SecretsError::Crypto(e.to_string()))?;

    String::from_utf8(plaintext.to_vec())
        .map_err(|e| SecretsError::InvalidData(format!("Invalid UTF-8: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use zopp_crypto::{encrypt, generate_dek, wrap_key, Keypair};

    /// Helper to create test workspace keys
    fn create_test_workspace_keys(
        principal_keypair: &Keypair,
        kek: &[u8; 32],
        workspace_id: &str,
    ) -> WorkspaceKeys {
        // Generate ephemeral keypair for wrapping
        let ephemeral = Keypair::generate();
        let shared_secret = ephemeral.shared_secret(principal_keypair.public_key());
        let aad = format!("workspace:{}", workspace_id).into_bytes();
        let (nonce, ciphertext) = wrap_key(kek, &shared_secret, &aad).unwrap();

        WorkspaceKeys {
            workspace_id: workspace_id.to_string(),
            ephemeral_pub: ephemeral.public_key_bytes().to_vec(),
            kek_wrapped: ciphertext.0,
            kek_nonce: nonce.0.to_vec(),
        }
    }

    /// Helper to create test environment
    fn create_test_environment(
        kek: &[u8; 32],
        dek: &[u8; 32],
        workspace_name: &str,
        project_name: &str,
        environment_name: &str,
    ) -> Environment {
        let kek_dek = Dek::from_bytes(kek).unwrap();
        let aad = format!(
            "environment:{}:{}:{}",
            workspace_name, project_name, environment_name
        )
        .into_bytes();
        let (nonce, ciphertext) = encrypt(dek, &kek_dek, &aad).unwrap();

        Environment {
            id: "env-123".to_string(),
            project_id: "proj-456".to_string(),
            name: environment_name.to_string(),
            dek_wrapped: ciphertext.0,
            dek_nonce: nonce.0.to_vec(),
            created_at: 0,
            updated_at: 0,
            secret_count: 0,
        }
    }

    /// Helper to create test secret
    fn create_test_secret(
        dek: &[u8; 32],
        key: &str,
        value: &str,
        workspace_name: &str,
        project_name: &str,
        environment_name: &str,
    ) -> Secret {
        let dek_key = Dek::from_bytes(dek).unwrap();
        let aad = format!(
            "secret:{}:{}:{}:{}",
            workspace_name, project_name, environment_name, key
        )
        .into_bytes();
        let (nonce, ciphertext) = encrypt(value.as_bytes(), &dek_key, &aad).unwrap();

        Secret {
            key: key.to_string(),
            nonce: nonce.0.to_vec(),
            ciphertext: ciphertext.0,
        }
    }

    #[test]
    fn test_secret_context_encrypt_decrypt_roundtrip() {
        // Setup
        let principal_keypair = Keypair::generate();
        let kek = generate_dek();
        let dek = generate_dek();
        let workspace_name = "test-workspace";
        let project_name = "test-project";
        let environment_name = "test-env";
        let workspace_id = "ws-123";

        let workspace_keys =
            create_test_workspace_keys(&principal_keypair, kek.as_bytes(), workspace_id);
        let environment = create_test_environment(
            kek.as_bytes(),
            dek.as_bytes(),
            workspace_name,
            project_name,
            environment_name,
        );

        // Create context
        let ctx = SecretContext::new(
            principal_keypair.secret_key_bytes(),
            workspace_keys,
            environment,
            workspace_name.to_string(),
            project_name.to_string(),
            environment_name.to_string(),
        )
        .unwrap();

        // Test encrypt/decrypt roundtrip
        let key = "DATABASE_URL";
        let value = "postgres://localhost/test";
        let encrypted = ctx.encrypt_secret(key, value).unwrap();

        // Create Secret from encrypted data
        let secret = Secret {
            key: key.to_string(),
            nonce: encrypted.nonce,
            ciphertext: encrypted.ciphertext,
        };

        let decrypted = ctx.decrypt_secret(&secret).unwrap();
        assert_eq!(decrypted, value);
    }

    #[test]
    fn test_secret_context_decrypt_existing_secret() {
        // Setup - simulate server-created secret
        let principal_keypair = Keypair::generate();
        let kek = generate_dek();
        let dek = generate_dek();
        let workspace_name = "acme";
        let project_name = "backend";
        let environment_name = "production";
        let workspace_id = "ws-789";

        let workspace_keys =
            create_test_workspace_keys(&principal_keypair, kek.as_bytes(), workspace_id);
        let environment = create_test_environment(
            kek.as_bytes(),
            dek.as_bytes(),
            workspace_name,
            project_name,
            environment_name,
        );

        // Create a secret the way the server would
        let secret = create_test_secret(
            dek.as_bytes(),
            "API_KEY",
            "super-secret-key-12345",
            workspace_name,
            project_name,
            environment_name,
        );

        // Create context and decrypt
        let ctx = SecretContext::new(
            principal_keypair.secret_key_bytes(),
            workspace_keys,
            environment,
            workspace_name.to_string(),
            project_name.to_string(),
            environment_name.to_string(),
        )
        .unwrap();

        let decrypted = ctx.decrypt_secret(&secret).unwrap();
        assert_eq!(decrypted, "super-secret-key-12345");
    }

    #[test]
    fn test_secret_context_wrong_principal_fails() {
        // Setup with principal A
        let principal_a = Keypair::generate();
        let principal_b = Keypair::generate(); // Different principal
        let kek = generate_dek();
        let dek = generate_dek();
        let workspace_name = "test-workspace";
        let project_name = "test-project";
        let environment_name = "test-env";
        let workspace_id = "ws-999";

        // Workspace keys wrapped for principal A
        let workspace_keys = create_test_workspace_keys(&principal_a, kek.as_bytes(), workspace_id);
        let environment = create_test_environment(
            kek.as_bytes(),
            dek.as_bytes(),
            workspace_name,
            project_name,
            environment_name,
        );

        let secret = create_test_secret(
            dek.as_bytes(),
            "SECRET",
            "value",
            workspace_name,
            project_name,
            environment_name,
        );

        // Try to decrypt with principal B (should fail)
        let ctx = SecretContext::new(
            principal_b.secret_key_bytes(), // Wrong principal!
            workspace_keys,
            environment,
            workspace_name.to_string(),
            project_name.to_string(),
            environment_name.to_string(),
        )
        .unwrap();

        let result = ctx.decrypt_secret(&secret);
        assert!(result.is_err());
    }

    #[test]
    fn test_secret_context_tampered_ciphertext_fails() {
        let principal_keypair = Keypair::generate();
        let kek = generate_dek();
        let dek = generate_dek();
        let workspace_name = "test-workspace";
        let project_name = "test-project";
        let environment_name = "test-env";
        let workspace_id = "ws-111";

        let workspace_keys =
            create_test_workspace_keys(&principal_keypair, kek.as_bytes(), workspace_id);
        let environment = create_test_environment(
            kek.as_bytes(),
            dek.as_bytes(),
            workspace_name,
            project_name,
            environment_name,
        );

        let mut secret = create_test_secret(
            dek.as_bytes(),
            "SECRET",
            "value",
            workspace_name,
            project_name,
            environment_name,
        );

        // Tamper with ciphertext
        secret.ciphertext[0] ^= 0x01;

        let ctx = SecretContext::new(
            principal_keypair.secret_key_bytes(),
            workspace_keys,
            environment,
            workspace_name.to_string(),
            project_name.to_string(),
            environment_name.to_string(),
        )
        .unwrap();

        let result = ctx.decrypt_secret(&secret);
        assert!(result.is_err());
    }

    #[test]
    fn test_secret_context_wrong_workspace_context_fails() {
        let principal_keypair = Keypair::generate();
        let kek = generate_dek();
        let dek = generate_dek();
        let workspace_name = "workspace-a";
        let project_name = "project-a";
        let environment_name = "env-a";
        let workspace_id = "ws-222";

        let workspace_keys =
            create_test_workspace_keys(&principal_keypair, kek.as_bytes(), workspace_id);
        let environment = create_test_environment(
            kek.as_bytes(),
            dek.as_bytes(),
            workspace_name,
            project_name,
            environment_name,
        );

        // Create secret with correct context
        let secret = create_test_secret(
            dek.as_bytes(),
            "SECRET",
            "value",
            workspace_name,
            project_name,
            environment_name,
        );

        // Try to decrypt with WRONG workspace context
        let ctx = SecretContext::new(
            principal_keypair.secret_key_bytes(),
            workspace_keys,
            environment,
            "workspace-b".to_string(), // Wrong workspace!
            project_name.to_string(),
            environment_name.to_string(),
        )
        .unwrap();

        let result = ctx.decrypt_secret(&secret);
        assert!(result.is_err()); // Should fail due to AAD mismatch
    }

    #[test]
    fn test_unwrap_dek_function() {
        let principal_keypair = Keypair::generate();
        let kek = generate_dek();
        let dek = generate_dek();
        let workspace_name = "test-ws";
        let project_name = "test-proj";
        let environment_name = "test-env";
        let workspace_id = "ws-333";

        let workspace_keys =
            create_test_workspace_keys(&principal_keypair, kek.as_bytes(), workspace_id);
        let environment = create_test_environment(
            kek.as_bytes(),
            dek.as_bytes(),
            workspace_name,
            project_name,
            environment_name,
        );

        // Unwrap DEK
        let unwrapped_dek = unwrap_dek(
            &principal_keypair.secret_key_bytes(),
            &workspace_keys,
            &environment,
            workspace_name,
            project_name,
            environment_name,
        )
        .unwrap();

        // Should match original DEK
        assert_eq!(unwrapped_dek, *dek.as_bytes());
    }

    #[test]
    fn test_decrypt_secret_with_dek_function() {
        let dek = generate_dek();
        let workspace_name = "test-ws";
        let project_name = "test-proj";
        let environment_name = "test-env";

        let secret = create_test_secret(
            dek.as_bytes(),
            "MY_SECRET",
            "my-value",
            workspace_name,
            project_name,
            environment_name,
        );

        // Decrypt with raw DEK
        let decrypted = decrypt_secret_with_dek(
            dek.as_bytes(),
            &secret,
            workspace_name,
            project_name,
            environment_name,
        )
        .unwrap();

        assert_eq!(decrypted, "my-value");
    }

    #[test]
    fn test_decrypt_secret_with_dek_wrong_dek_fails() {
        let dek = generate_dek();
        let wrong_dek = generate_dek(); // Different DEK
        let workspace_name = "test-ws";
        let project_name = "test-proj";
        let environment_name = "test-env";

        let secret = create_test_secret(
            dek.as_bytes(),
            "MY_SECRET",
            "my-value",
            workspace_name,
            project_name,
            environment_name,
        );

        // Try to decrypt with wrong DEK
        let result = decrypt_secret_with_dek(
            wrong_dek.as_bytes(), // Wrong DEK!
            &secret,
            workspace_name,
            project_name,
            environment_name,
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_multiple_secrets_same_context() {
        // Test that we can encrypt/decrypt multiple secrets with same context
        let principal_keypair = Keypair::generate();
        let kek = generate_dek();
        let dek = generate_dek();
        let workspace_name = "multi-test";
        let project_name = "multi-proj";
        let environment_name = "multi-env";
        let workspace_id = "ws-444";

        let workspace_keys =
            create_test_workspace_keys(&principal_keypair, kek.as_bytes(), workspace_id);
        let environment = create_test_environment(
            kek.as_bytes(),
            dek.as_bytes(),
            workspace_name,
            project_name,
            environment_name,
        );

        let ctx = SecretContext::new(
            principal_keypair.secret_key_bytes(),
            workspace_keys,
            environment,
            workspace_name.to_string(),
            project_name.to_string(),
            environment_name.to_string(),
        )
        .unwrap();

        // Encrypt multiple secrets
        let secrets = vec![
            ("DATABASE_URL", "postgres://localhost/db"),
            ("API_KEY", "sk-1234567890"),
            ("REDIS_URL", "redis://localhost:6379"),
        ];

        for (key, value) in &secrets {
            let encrypted = ctx.encrypt_secret(key, value).unwrap();
            let secret = Secret {
                key: key.to_string(),
                nonce: encrypted.nonce,
                ciphertext: encrypted.ciphertext,
            };
            let decrypted = ctx.decrypt_secret(&secret).unwrap();
            assert_eq!(&decrypted, value);
        }
    }

    #[test]
    fn test_empty_secret_value() {
        let principal_keypair = Keypair::generate();
        let kek = generate_dek();
        let dek = generate_dek();
        let workspace_name = "test";
        let project_name = "test";
        let environment_name = "test";
        let workspace_id = "ws-555";

        let workspace_keys =
            create_test_workspace_keys(&principal_keypair, kek.as_bytes(), workspace_id);
        let environment = create_test_environment(
            kek.as_bytes(),
            dek.as_bytes(),
            workspace_name,
            project_name,
            environment_name,
        );

        let ctx = SecretContext::new(
            principal_keypair.secret_key_bytes(),
            workspace_keys,
            environment,
            workspace_name.to_string(),
            project_name.to_string(),
            environment_name.to_string(),
        )
        .unwrap();

        // Test empty value
        let encrypted = ctx.encrypt_secret("EMPTY_SECRET", "").unwrap();
        let secret = Secret {
            key: "EMPTY_SECRET".to_string(),
            nonce: encrypted.nonce,
            ciphertext: encrypted.ciphertext,
        };
        let decrypted = ctx.decrypt_secret(&secret).unwrap();
        assert_eq!(decrypted, "");
    }

    #[test]
    fn test_unicode_secret_value() {
        let principal_keypair = Keypair::generate();
        let kek = generate_dek();
        let dek = generate_dek();
        let workspace_name = "test";
        let project_name = "test";
        let environment_name = "test";
        let workspace_id = "ws-666";

        let workspace_keys =
            create_test_workspace_keys(&principal_keypair, kek.as_bytes(), workspace_id);
        let environment = create_test_environment(
            kek.as_bytes(),
            dek.as_bytes(),
            workspace_name,
            project_name,
            environment_name,
        );

        let ctx = SecretContext::new(
            principal_keypair.secret_key_bytes(),
            workspace_keys,
            environment,
            workspace_name.to_string(),
            project_name.to_string(),
            environment_name.to_string(),
        )
        .unwrap();

        // Test unicode value
        let unicode_value = "Hello 世界 🔐 Здравствуй мир";
        let encrypted = ctx.encrypt_secret("UNICODE_SECRET", unicode_value).unwrap();
        let secret = Secret {
            key: "UNICODE_SECRET".to_string(),
            nonce: encrypted.nonce,
            ciphertext: encrypted.ciphertext,
        };
        let decrypted = ctx.decrypt_secret(&secret).unwrap();
        assert_eq!(decrypted, unicode_value);
    }
}
