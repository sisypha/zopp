//! IndexedDB storage service for principal credentials
//!
//! This module handles secure storage of principal keys in the browser.
//! Keys are encrypted at rest using a device-bound AES-GCM key generated
//! via the Web Crypto API.

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("IndexedDB not available")]
    NotAvailable,
    #[error("Storage operation failed: {0}")]
    OperationFailed(String),
    #[error("Principal not found")]
    NotFound,
    #[error("Encryption error: {0}")]
    Encryption(String),
    #[error("Serialization error: {0}")]
    Serialization(String),
}

/// Stored principal credentials (serializable for IndexedDB)
/// Private keys are encrypted with a device-bound AES-GCM key before storage.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StoredPrincipal {
    pub id: String,
    pub name: String,
    pub email: Option<String>,
    pub user_id: Option<String>,
    /// Ed25519 private key (hex-encoded, encrypted at rest with device key)
    pub ed25519_private_key: String,
    /// Ed25519 public key (hex-encoded)
    pub ed25519_public_key: String,
    /// X25519 private key (hex-encoded, encrypted at rest with device key)
    pub x25519_private_key: Option<String>,
    /// X25519 public key (hex-encoded)
    pub x25519_public_key: Option<String>,
    /// Nonce for ed25519 private key encryption (base64)
    #[serde(default)]
    pub ed25519_nonce: Option<String>,
    /// Nonce for x25519 private key encryption (base64)
    #[serde(default)]
    pub x25519_nonce: Option<String>,
    /// Whether the keys are encrypted (for backward compatibility)
    #[serde(default)]
    pub encrypted: bool,
}

/// Principal metadata (without sensitive keys)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrincipalMetadata {
    pub id: String,
    pub name: String,
    pub email: Option<String>,
}

/// Storage trait for principal credentials
/// This abstraction allows for different implementations:
/// - IndexedDB (current)
/// - Browser extension storage (future)
/// - Native keychain via Tauri (future)
///
/// Note: No Send bounds because WASM is single-threaded and JS objects aren't Send
pub trait KeyStorage {
    /// Store a principal's credentials
    fn store_principal(
        &self,
        principal: StoredPrincipal,
    ) -> impl std::future::Future<Output = Result<(), StorageError>>;

    /// Retrieve a principal by ID
    fn get_principal(
        &self,
        id: &str,
    ) -> impl std::future::Future<Output = Result<Option<StoredPrincipal>, StorageError>>;

    /// List all stored principals (metadata only)
    fn list_principals(
        &self,
    ) -> impl std::future::Future<Output = Result<Vec<PrincipalMetadata>, StorageError>>;

    /// Delete a principal
    fn delete_principal(
        &self,
        id: &str,
    ) -> impl std::future::Future<Output = Result<(), StorageError>>;

    /// Check if storage is available
    fn is_available(&self) -> impl std::future::Future<Output = bool>;

    /// Get the current principal ID (if set)
    fn get_current_principal_id(
        &self,
    ) -> impl std::future::Future<Output = Result<Option<String>, StorageError>>;

    /// Set the current principal ID
    fn set_current_principal_id(
        &self,
        id: Option<&str>,
    ) -> impl std::future::Future<Output = Result<(), StorageError>>;
}

// ============================================================================
// WASM Implementation
// ============================================================================

#[cfg(target_arch = "wasm32")]
mod wasm_impl {
    use super::*;
    use js_sys::{Array, ArrayBuffer, Object, Reflect, Uint8Array};
    use serde_wasm_bindgen::{from_value, to_value};
    use wasm_bindgen::prelude::*;
    use wasm_bindgen_futures::JsFuture;
    use web_sys::{
        window, CryptoKey, IdbDatabase, IdbObjectStore, IdbRequest, IdbTransactionMode,
        SubtleCrypto,
    };

    const DB_NAME: &str = "zopp-credentials";
    const DB_VERSION: u32 = 2; // Bumped for encryption support
    const PRINCIPALS_STORE: &str = "principals";
    const META_STORE: &str = "meta";
    const DEVICE_KEY_NAME: &str = "device_encryption_key";

    /// IndexedDB implementation of KeyStorage with Web Crypto encryption
    pub struct IndexedDbStorage {}

    impl IndexedDbStorage {
        pub fn new() -> Self {
            Self {}
        }

        /// Get the SubtleCrypto API
        fn get_subtle_crypto() -> Result<SubtleCrypto, StorageError> {
            let window = window().ok_or(StorageError::NotAvailable)?;
            let crypto = window.crypto().map_err(|_| StorageError::NotAvailable)?;
            Ok(crypto.subtle())
        }

        /// Generate a new device-bound AES-GCM key (non-extractable)
        async fn generate_device_key() -> Result<CryptoKey, StorageError> {
            let subtle = Self::get_subtle_crypto()?;

            // Create AES-GCM key generation params
            let algorithm = Object::new();
            Reflect::set(&algorithm, &"name".into(), &"AES-GCM".into())
                .map_err(|_| StorageError::Encryption("Failed to set algorithm name".into()))?;
            Reflect::set(&algorithm, &"length".into(), &256.into())
                .map_err(|_| StorageError::Encryption("Failed to set key length".into()))?;

            // Key usages
            let usages = Array::new();
            usages.push(&"encrypt".into());
            usages.push(&"decrypt".into());

            // Generate non-extractable key
            let key_promise = subtle
                .generate_key_with_object(&algorithm, false, &usages)
                .map_err(|e| StorageError::Encryption(format!("{:?}", e)))?;

            let key = JsFuture::from(key_promise)
                .await
                .map_err(|e| StorageError::Encryption(format!("{:?}", e)))?;

            Ok(key.unchecked_into())
        }

        /// Get or create the device encryption key (stored in IndexedDB)
        async fn get_or_create_device_key(&self) -> Result<CryptoKey, StorageError> {
            let db = self.open_db().await?;
            let store = Self::get_store(&db, META_STORE, IdbTransactionMode::Readonly)?;

            let request = store
                .get(&JsValue::from_str(DEVICE_KEY_NAME))
                .map_err(|e| StorageError::OperationFailed(format!("{:?}", e)))?;

            let result = Self::await_request(&request).await?;

            if !result.is_undefined() && !result.is_null() {
                // Key already exists
                Ok(result.unchecked_into())
            } else {
                // Generate new key
                let key = Self::generate_device_key().await?;

                // Store it
                let store = Self::get_store(&db, META_STORE, IdbTransactionMode::Readwrite)?;
                let request = store
                    .put_with_key(&key, &JsValue::from_str(DEVICE_KEY_NAME))
                    .map_err(|e| StorageError::OperationFailed(format!("{:?}", e)))?;
                Self::await_request(&request).await?;

                Ok(key)
            }
        }

        /// Encrypt data with the device key
        async fn encrypt_with_device_key(
            &self,
            data: &[u8],
        ) -> Result<(Vec<u8>, Vec<u8>), StorageError> {
            let key = self.get_or_create_device_key().await?;
            let subtle = Self::get_subtle_crypto()?;

            // Generate random IV (12 bytes for AES-GCM)
            let window = window().ok_or(StorageError::NotAvailable)?;
            let crypto = window.crypto().map_err(|_| StorageError::NotAvailable)?;
            let mut iv = [0u8; 12];
            crypto
                .get_random_values_with_u8_array(&mut iv)
                .map_err(|_| StorageError::Encryption("Failed to generate IV".into()))?;

            // Create algorithm params
            let algorithm = Object::new();
            Reflect::set(&algorithm, &"name".into(), &"AES-GCM".into())
                .map_err(|_| StorageError::Encryption("Failed to set algorithm".into()))?;
            let iv_array = Uint8Array::from(&iv[..]);
            Reflect::set(&algorithm, &"iv".into(), &iv_array)
                .map_err(|_| StorageError::Encryption("Failed to set IV".into()))?;

            // Convert data to Uint8Array
            let data_array = Uint8Array::from(data);

            // Encrypt
            let encrypted_promise = subtle
                .encrypt_with_object_and_buffer_source(&algorithm, &key, &data_array)
                .map_err(|e| StorageError::Encryption(format!("{:?}", e)))?;

            let encrypted = JsFuture::from(encrypted_promise)
                .await
                .map_err(|e| StorageError::Encryption(format!("{:?}", e)))?;

            let encrypted_buffer: ArrayBuffer = encrypted.unchecked_into();
            let encrypted_array = Uint8Array::new(&encrypted_buffer);
            let mut encrypted_bytes = vec![0u8; encrypted_array.length() as usize];
            encrypted_array.copy_to(&mut encrypted_bytes);

            Ok((encrypted_bytes, iv.to_vec()))
        }

        /// Decrypt data with the device key
        async fn decrypt_with_device_key(
            &self,
            ciphertext: &[u8],
            iv: &[u8],
        ) -> Result<Vec<u8>, StorageError> {
            let key = self.get_or_create_device_key().await?;
            let subtle = Self::get_subtle_crypto()?;

            // Create algorithm params
            let algorithm = Object::new();
            Reflect::set(&algorithm, &"name".into(), &"AES-GCM".into())
                .map_err(|_| StorageError::Encryption("Failed to set algorithm".into()))?;
            let iv_array = Uint8Array::from(iv);
            Reflect::set(&algorithm, &"iv".into(), &iv_array)
                .map_err(|_| StorageError::Encryption("Failed to set IV".into()))?;

            let data_array = Uint8Array::from(ciphertext);

            // Decrypt
            let decrypted_promise = subtle
                .decrypt_with_object_and_buffer_source(&algorithm, &key, &data_array)
                .map_err(|e| StorageError::Encryption(format!("{:?}", e)))?;

            let decrypted = JsFuture::from(decrypted_promise)
                .await
                .map_err(|e| StorageError::Encryption(format!("{:?}", e)))?;

            let decrypted_buffer: ArrayBuffer = decrypted.unchecked_into();
            let decrypted_array = Uint8Array::new(&decrypted_buffer);
            let mut decrypted_bytes = vec![0u8; decrypted_array.length() as usize];
            decrypted_array.copy_to(&mut decrypted_bytes);

            Ok(decrypted_bytes)
        }

        /// Encrypt a hex-encoded key and return base64-encoded ciphertext + nonce
        async fn encrypt_key(&self, hex_key: &str) -> Result<(String, String), StorageError> {
            let key_bytes = hex::decode(hex_key)
                .map_err(|e| StorageError::Encryption(format!("Invalid hex: {}", e)))?;
            let (ciphertext, nonce) = self.encrypt_with_device_key(&key_bytes).await?;
            Ok((
                base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &ciphertext),
                base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &nonce),
            ))
        }

        /// Decrypt a base64-encoded ciphertext + nonce back to hex-encoded key
        async fn decrypt_key(
            &self,
            ciphertext_b64: &str,
            nonce_b64: &str,
        ) -> Result<String, StorageError> {
            let ciphertext =
                base64::Engine::decode(&base64::engine::general_purpose::STANDARD, ciphertext_b64)
                    .map_err(|e| {
                        StorageError::Encryption(format!("Invalid base64 ciphertext: {}", e))
                    })?;
            let nonce =
                base64::Engine::decode(&base64::engine::general_purpose::STANDARD, nonce_b64)
                    .map_err(|e| {
                        StorageError::Encryption(format!("Invalid base64 nonce: {}", e))
                    })?;
            let plaintext = self.decrypt_with_device_key(&ciphertext, &nonce).await?;
            Ok(hex::encode(plaintext))
        }

        /// Open or create the IndexedDB database
        async fn open_db(&self) -> Result<IdbDatabase, StorageError> {
            let window = window().ok_or(StorageError::NotAvailable)?;
            let idb = window
                .indexed_db()
                .map_err(|e| StorageError::OperationFailed(format!("{:?}", e)))?
                .ok_or(StorageError::NotAvailable)?;

            let open_request = idb
                .open_with_u32(DB_NAME, DB_VERSION)
                .map_err(|e| StorageError::OperationFailed(format!("{:?}", e)))?;

            // Set up upgrade handler
            let onupgradeneeded = Closure::once(Box::new(|event: web_sys::IdbVersionChangeEvent| {
                let target = event.target().unwrap();
                let request: IdbRequest = target.unchecked_into();
                let db: IdbDatabase = request.result().unwrap().unchecked_into();

                let store_names = db.object_store_names();
                // Create principals store
                if !store_names.contains(PRINCIPALS_STORE) {
                    let params = web_sys::IdbObjectStoreParameters::new();
                    params.set_key_path(&JsValue::from_str("id"));
                    let store = db
                        .create_object_store_with_optional_parameters(PRINCIPALS_STORE, &params)
                        .unwrap();
                    // Create name index
                    let index_params = web_sys::IdbIndexParameters::new();
                    store
                        .create_index_with_str_and_optional_parameters(
                            "name",
                            "name",
                            &index_params,
                        )
                        .unwrap();
                }

                // Create meta store for settings like current principal
                if !store_names.contains(META_STORE) {
                    db.create_object_store(META_STORE).unwrap();
                }
            }) as Box<dyn FnOnce(_)>);

            open_request.set_onupgradeneeded(Some(onupgradeneeded.as_ref().unchecked_ref()));
            onupgradeneeded.forget();

            // Wait for request to complete
            let result = Self::await_request(&open_request).await?;
            Ok(result.unchecked_into())
        }

        /// Helper to await an IDB request
        async fn await_request(request: &IdbRequest) -> Result<JsValue, StorageError> {
            let (tx, rx) = futures::channel::oneshot::channel();
            let tx = std::rc::Rc::new(std::cell::RefCell::new(Some(tx)));

            let tx_success = tx.clone();
            let onsuccess = Closure::once(Box::new(move |_event: web_sys::Event| {
                if let Some(tx) = tx_success.borrow_mut().take() {
                    let _ = tx.send(Ok(()));
                }
            }) as Box<dyn FnOnce(_)>);

            let tx_error = tx;
            let onerror = Closure::once(Box::new(move |_event: web_sys::Event| {
                if let Some(tx) = tx_error.borrow_mut().take() {
                    let _ = tx.send(Err(StorageError::OperationFailed(
                        "Request failed".to_string(),
                    )));
                }
            }) as Box<dyn FnOnce(_)>);

            request.set_onsuccess(Some(onsuccess.as_ref().unchecked_ref()));
            request.set_onerror(Some(onerror.as_ref().unchecked_ref()));

            onsuccess.forget();
            onerror.forget();

            rx.await
                .map_err(|_| StorageError::OperationFailed("Channel closed".to_string()))??;

            request
                .result()
                .map_err(|e| StorageError::OperationFailed(format!("{:?}", e)))
        }

        /// Get an object store for a transaction
        fn get_store(
            db: &IdbDatabase,
            store_name: &str,
            mode: IdbTransactionMode,
        ) -> Result<IdbObjectStore, StorageError> {
            let tx = db
                .transaction_with_str_and_mode(store_name, mode)
                .map_err(|e| StorageError::OperationFailed(format!("{:?}", e)))?;
            tx.object_store(store_name)
                .map_err(|e| StorageError::OperationFailed(format!("{:?}", e)))
        }
    }

    impl Default for IndexedDbStorage {
        fn default() -> Self {
            Self::new()
        }
    }

    impl KeyStorage for IndexedDbStorage {
        async fn store_principal(
            &self,
            mut principal: StoredPrincipal,
        ) -> Result<(), StorageError> {
            // Encrypt private keys before storing
            let (ed25519_encrypted, ed25519_nonce) =
                self.encrypt_key(&principal.ed25519_private_key).await?;
            principal.ed25519_private_key = ed25519_encrypted;
            principal.ed25519_nonce = Some(ed25519_nonce);

            if let Some(ref x25519_key) = principal.x25519_private_key {
                let (x25519_encrypted, x25519_nonce) = self.encrypt_key(x25519_key).await?;
                principal.x25519_private_key = Some(x25519_encrypted);
                principal.x25519_nonce = Some(x25519_nonce);
            }

            principal.encrypted = true;

            let db = self.open_db().await?;
            let store = Self::get_store(&db, PRINCIPALS_STORE, IdbTransactionMode::Readwrite)?;

            let value = to_value(&principal)
                .map_err(|e| StorageError::Serialization(format!("{:?}", e)))?;

            let request = store
                .put(&value)
                .map_err(|e| StorageError::OperationFailed(format!("{:?}", e)))?;

            Self::await_request(&request).await?;
            Ok(())
        }

        async fn get_principal(&self, id: &str) -> Result<Option<StoredPrincipal>, StorageError> {
            let db = self.open_db().await?;
            let store = Self::get_store(&db, PRINCIPALS_STORE, IdbTransactionMode::Readonly)?;

            let request = store
                .get(&JsValue::from_str(id))
                .map_err(|e| StorageError::OperationFailed(format!("{:?}", e)))?;

            let result = Self::await_request(&request).await?;

            if result.is_undefined() || result.is_null() {
                return Ok(None);
            }

            let mut principal: StoredPrincipal =
                from_value(result).map_err(|e| StorageError::Serialization(format!("{:?}", e)))?;

            // Decrypt private keys if they were encrypted
            if principal.encrypted {
                if let Some(ref nonce) = principal.ed25519_nonce {
                    principal.ed25519_private_key = self
                        .decrypt_key(&principal.ed25519_private_key, nonce)
                        .await?;
                }
                if let (Some(ref x25519_key), Some(ref nonce)) =
                    (&principal.x25519_private_key, &principal.x25519_nonce)
                {
                    principal.x25519_private_key = Some(self.decrypt_key(x25519_key, nonce).await?);
                }
            }

            Ok(Some(principal))
        }

        async fn list_principals(&self) -> Result<Vec<PrincipalMetadata>, StorageError> {
            let db = self.open_db().await?;
            let store = Self::get_store(&db, PRINCIPALS_STORE, IdbTransactionMode::Readonly)?;

            let request = store
                .get_all()
                .map_err(|e| StorageError::OperationFailed(format!("{:?}", e)))?;

            let result = Self::await_request(&request).await?;
            let array: Array = result.unchecked_into();

            let mut principals = Vec::new();
            for i in 0..array.length() {
                let item = array.get(i);
                if let Ok(stored) = from_value::<StoredPrincipal>(item) {
                    principals.push(PrincipalMetadata {
                        id: stored.id,
                        name: stored.name,
                        email: stored.email,
                    });
                }
            }

            Ok(principals)
        }

        async fn delete_principal(&self, id: &str) -> Result<(), StorageError> {
            let db = self.open_db().await?;
            let store = Self::get_store(&db, PRINCIPALS_STORE, IdbTransactionMode::Readwrite)?;

            let request = store
                .delete(&JsValue::from_str(id))
                .map_err(|e| StorageError::OperationFailed(format!("{:?}", e)))?;

            Self::await_request(&request).await?;
            Ok(())
        }

        async fn is_available(&self) -> bool {
            window()
                .and_then(|w| w.indexed_db().ok())
                .flatten()
                .is_some()
        }

        async fn get_current_principal_id(&self) -> Result<Option<String>, StorageError> {
            let db = self.open_db().await?;
            let store = Self::get_store(&db, META_STORE, IdbTransactionMode::Readonly)?;

            let request = store
                .get(&JsValue::from_str("current_principal_id"))
                .map_err(|e| StorageError::OperationFailed(format!("{:?}", e)))?;

            let result = Self::await_request(&request).await?;

            if result.is_undefined() || result.is_null() {
                return Ok(None);
            }

            Ok(result.as_string())
        }

        async fn set_current_principal_id(&self, id: Option<&str>) -> Result<(), StorageError> {
            let db = self.open_db().await?;
            let store = Self::get_store(&db, META_STORE, IdbTransactionMode::Readwrite)?;

            match id {
                Some(principal_id) => {
                    let request = store
                        .put_with_key(
                            &JsValue::from_str(principal_id),
                            &JsValue::from_str("current_principal_id"),
                        )
                        .map_err(|e| StorageError::OperationFailed(format!("{:?}", e)))?;
                    Self::await_request(&request).await?;
                }
                None => {
                    let request = store
                        .delete(&JsValue::from_str("current_principal_id"))
                        .map_err(|e| StorageError::OperationFailed(format!("{:?}", e)))?;
                    Self::await_request(&request).await?;
                }
            }

            Ok(())
        }
    }
}

#[cfg(target_arch = "wasm32")]
pub use wasm_impl::IndexedDbStorage;

// ============================================================================
// Non-WASM Stub for SSR
// ============================================================================

#[cfg(not(target_arch = "wasm32"))]
pub struct IndexedDbStorage;

#[cfg(not(target_arch = "wasm32"))]
impl IndexedDbStorage {
    pub fn new() -> Self {
        Self
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl Default for IndexedDbStorage {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl KeyStorage for IndexedDbStorage {
    async fn store_principal(&self, _principal: StoredPrincipal) -> Result<(), StorageError> {
        Err(StorageError::NotAvailable)
    }

    async fn get_principal(&self, _id: &str) -> Result<Option<StoredPrincipal>, StorageError> {
        Err(StorageError::NotAvailable)
    }

    async fn list_principals(&self) -> Result<Vec<PrincipalMetadata>, StorageError> {
        Err(StorageError::NotAvailable)
    }

    async fn delete_principal(&self, _id: &str) -> Result<(), StorageError> {
        Err(StorageError::NotAvailable)
    }

    async fn is_available(&self) -> bool {
        false
    }

    async fn get_current_principal_id(&self) -> Result<Option<String>, StorageError> {
        Err(StorageError::NotAvailable)
    }

    async fn set_current_principal_id(&self, _id: Option<&str>) -> Result<(), StorageError> {
        Err(StorageError::NotAvailable)
    }
}
