use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use wasm_bindgen::prelude::*;
use zopp_crypto::{
    decrypt, encrypt, generate_dek, public_key_from_bytes, unwrap_key, wrap_key, Dek, Keypair,
    Nonce,
};

/// X25519 keypair for ECDH operations
#[wasm_bindgen]
pub struct WasmX25519Keypair {
    inner: Keypair,
}

#[wasm_bindgen]
impl WasmX25519Keypair {
    /// Generate a new random X25519 keypair
    #[wasm_bindgen(constructor)]
    pub fn new() -> WasmX25519Keypair {
        WasmX25519Keypair {
            inner: Keypair::generate(),
        }
    }

    /// Create keypair from existing secret key bytes (32 bytes)
    #[wasm_bindgen(js_name = fromSecretBytes)]
    pub fn from_secret_bytes(secret: &[u8]) -> Result<WasmX25519Keypair, JsValue> {
        if secret.len() != 32 {
            return Err(JsValue::from_str("Secret key must be 32 bytes"));
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(secret);
        Ok(WasmX25519Keypair {
            inner: Keypair::from_secret_bytes(&bytes),
        })
    }

    /// Get the public key as bytes
    #[wasm_bindgen(js_name = publicKeyBytes)]
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.inner.public_key_bytes().to_vec()
    }

    /// Get the secret key as bytes
    #[wasm_bindgen(js_name = secretKeyBytes)]
    pub fn secret_key_bytes(&self) -> Vec<u8> {
        self.inner.secret_key_bytes().to_vec()
    }

    /// Compute shared secret with another public key (ECDH)
    #[wasm_bindgen(js_name = sharedSecret)]
    pub fn shared_secret(&self, their_public: &[u8]) -> Result<Vec<u8>, JsValue> {
        if their_public.len() != 32 {
            return Err(JsValue::from_str("Public key must be 32 bytes"));
        }
        Ok(shared_secret_to_bytes(&self.inner, their_public))
    }
}

fn shared_secret_to_bytes(keypair: &Keypair, their_public_bytes: &[u8]) -> Vec<u8> {
    // Compute shared secret using x25519-dalek directly
    use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
    let secret_key = StaticSecret::from(keypair.secret_key_bytes());
    let mut pk_bytes = [0u8; 32];
    pk_bytes.copy_from_slice(their_public_bytes);
    let public_key = X25519PublicKey::from(pk_bytes);
    let shared = secret_key.diffie_hellman(&public_key);
    shared.as_bytes().to_vec()
}

impl Default for WasmX25519Keypair {
    fn default() -> Self {
        Self::new()
    }
}

/// Ed25519 keypair for signing operations
#[wasm_bindgen]
pub struct WasmEd25519Keypair {
    signing_key: SigningKey,
}

#[wasm_bindgen]
impl WasmEd25519Keypair {
    /// Generate a new random Ed25519 keypair
    #[wasm_bindgen(constructor)]
    pub fn new() -> WasmEd25519Keypair {
        let signing_key = SigningKey::generate(&mut rand_core::OsRng);
        WasmEd25519Keypair { signing_key }
    }

    /// Create keypair from existing secret key bytes (32 bytes)
    #[wasm_bindgen(js_name = fromSecretBytes)]
    pub fn from_secret_bytes(secret: &[u8]) -> Result<WasmEd25519Keypair, JsValue> {
        if secret.len() != 32 {
            return Err(JsValue::from_str("Secret key must be 32 bytes"));
        }
        let bytes: [u8; 32] = secret
            .try_into()
            .map_err(|_| JsValue::from_str("Invalid key length"))?;
        let signing_key = SigningKey::from_bytes(&bytes);
        Ok(WasmEd25519Keypair { signing_key })
    }

    /// Create keypair from hex-encoded secret key
    #[wasm_bindgen(js_name = fromSecretHex)]
    pub fn from_secret_hex(hex_str: &str) -> Result<WasmEd25519Keypair, JsValue> {
        let bytes =
            hex::decode(hex_str).map_err(|e| JsValue::from_str(&format!("Invalid hex: {}", e)))?;
        Self::from_secret_bytes(&bytes)
    }

    /// Get the public key as bytes
    #[wasm_bindgen(js_name = publicKeyBytes)]
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.signing_key.verifying_key().to_bytes().to_vec()
    }

    /// Get the public key as hex string
    #[wasm_bindgen(js_name = publicKeyHex)]
    pub fn public_key_hex(&self) -> String {
        hex::encode(self.signing_key.verifying_key().to_bytes())
    }

    /// Get the secret key as bytes
    #[wasm_bindgen(js_name = secretKeyBytes)]
    pub fn secret_key_bytes(&self) -> Vec<u8> {
        self.signing_key.to_bytes().to_vec()
    }

    /// Get the secret key as hex string
    #[wasm_bindgen(js_name = secretKeyHex)]
    pub fn secret_key_hex(&self) -> String {
        hex::encode(self.signing_key.to_bytes())
    }

    /// Sign a message
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        let signature = self.signing_key.sign(message);
        signature.to_bytes().to_vec()
    }

    /// Sign and return hex-encoded signature
    #[wasm_bindgen(js_name = signHex)]
    pub fn sign_hex(&self, message: &[u8]) -> String {
        hex::encode(self.sign(message))
    }
}

impl Default for WasmEd25519Keypair {
    fn default() -> Self {
        Self::new()
    }
}

/// Verify an Ed25519 signature
#[wasm_bindgen(js_name = verifyEd25519)]
pub fn verify_ed25519(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<bool, JsValue> {
    if public_key.len() != 32 {
        return Err(JsValue::from_str("Public key must be 32 bytes"));
    }
    if signature.len() != 64 {
        return Err(JsValue::from_str("Signature must be 64 bytes"));
    }

    let pk_bytes: [u8; 32] = public_key
        .try_into()
        .map_err(|_| JsValue::from_str("Invalid public key"))?;
    let verifying_key =
        VerifyingKey::from_bytes(&pk_bytes).map_err(|e| JsValue::from_str(&e.to_string()))?;

    let sig_bytes: [u8; 64] = signature
        .try_into()
        .map_err(|_| JsValue::from_str("Invalid signature"))?;
    let sig = Signature::from_bytes(&sig_bytes);

    Ok(verifying_key.verify(message, &sig).is_ok())
}

/// Sign a gRPC request (method + body_hash + timestamp)
/// Returns: { timestamp: number, signature: Uint8Array, signatureHex: string }
#[wasm_bindgen(js_name = signGrpcRequest)]
pub fn sign_grpc_request(
    ed25519_secret_hex: &str,
    method: &str,
    request_hash: &[u8],
    timestamp: i64,
) -> Result<JsValue, JsValue> {
    let private_key_bytes = hex::decode(ed25519_secret_hex)
        .map_err(|e| JsValue::from_str(&format!("Invalid hex: {}", e)))?;

    if private_key_bytes.len() != 32 {
        return Err(JsValue::from_str("Private key must be 32 bytes"));
    }

    let key_bytes: [u8; 32] = private_key_bytes
        .try_into()
        .map_err(|_| JsValue::from_str("Invalid key length"))?;
    let signing_key = SigningKey::from_bytes(&key_bytes);

    // Build message: method + request_hash + timestamp
    let mut message = Vec::new();
    message.extend_from_slice(method.as_bytes());
    message.extend_from_slice(request_hash);
    message.extend_from_slice(&timestamp.to_le_bytes());

    let signature = signing_key.sign(&message);

    let result = js_sys::Object::new();
    js_sys::Reflect::set(&result, &"timestamp".into(), &timestamp.into())?;
    js_sys::Reflect::set(
        &result,
        &"signature".into(),
        &js_sys::Uint8Array::from(signature.to_bytes().as_slice()).into(),
    )?;
    js_sys::Reflect::set(
        &result,
        &"signatureHex".into(),
        &hex::encode(signature.to_bytes()).into(),
    )?;

    Ok(result.into())
}

/// Compute SHA256(method + body) for gRPC request signing
#[wasm_bindgen(js_name = computeRequestHash)]
pub fn compute_request_hash(method: &str, body: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(method.as_bytes());
    hasher.update(body);
    hasher.finalize().to_vec()
}

/// Generate a new random DEK (Data Encryption Key)
#[wasm_bindgen(js_name = generateDek)]
pub fn wasm_generate_dek() -> Vec<u8> {
    let dek = generate_dek();
    dek.as_bytes().to_vec()
}

/// Encrypt plaintext with DEK and AAD
/// Returns: { nonce: Uint8Array, ciphertext: Uint8Array }
#[wasm_bindgen(js_name = encrypt)]
pub fn wasm_encrypt(plaintext: &[u8], dek_bytes: &[u8], aad: &[u8]) -> Result<JsValue, JsValue> {
    if dek_bytes.len() != 32 {
        return Err(JsValue::from_str("DEK must be 32 bytes"));
    }

    let mut dek_array = [0u8; 32];
    dek_array.copy_from_slice(dek_bytes);
    let dek = Dek::from_bytes(&dek_array).map_err(JsValue::from_str)?;

    let (nonce, ciphertext) =
        encrypt(plaintext, &dek, aad).map_err(|e| JsValue::from_str(&e.to_string()))?;

    let result = js_sys::Object::new();
    js_sys::Reflect::set(
        &result,
        &"nonce".into(),
        &js_sys::Uint8Array::from(nonce.0.as_slice()).into(),
    )?;
    js_sys::Reflect::set(
        &result,
        &"ciphertext".into(),
        &js_sys::Uint8Array::from(ciphertext.0.as_slice()).into(),
    )?;

    Ok(result.into())
}

/// Decrypt ciphertext with DEK, nonce, and AAD
#[wasm_bindgen(js_name = decrypt)]
pub fn wasm_decrypt(
    ciphertext: &[u8],
    nonce_bytes: &[u8],
    dek_bytes: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, JsValue> {
    if dek_bytes.len() != 32 {
        return Err(JsValue::from_str("DEK must be 32 bytes"));
    }
    if nonce_bytes.len() != 24 {
        return Err(JsValue::from_str("Nonce must be 24 bytes"));
    }

    let mut dek_array = [0u8; 32];
    dek_array.copy_from_slice(dek_bytes);
    let dek = Dek::from_bytes(&dek_array).map_err(JsValue::from_str)?;

    let mut nonce_array = [0u8; 24];
    nonce_array.copy_from_slice(nonce_bytes);
    let nonce = Nonce(nonce_array);

    let plaintext =
        decrypt(ciphertext, &nonce, &dek, aad).map_err(|e| JsValue::from_str(&e.to_string()))?;

    Ok(plaintext.to_vec())
}

/// Wrap a key using a shared secret (for KEK wrapping)
/// Returns: { nonce: Uint8Array, wrapped: Uint8Array }
#[wasm_bindgen(js_name = wrapKey)]
pub fn wasm_wrap_key(
    key: &[u8],
    shared_secret_bytes: &[u8],
    aad: &[u8],
) -> Result<JsValue, JsValue> {
    if shared_secret_bytes.len() != 32 {
        return Err(JsValue::from_str("Shared secret must be 32 bytes"));
    }

    // Reconstruct SharedSecret through Keypair
    // This is a workaround since SharedSecret is not directly constructible
    let mut secret_bytes = [0u8; 32];
    secret_bytes.copy_from_slice(shared_secret_bytes);

    // Use direct XChaCha20Poly1305 for wrapping since we have the raw shared secret
    use chacha20poly1305::{aead::Aead, KeyInit, XChaCha20Poly1305, XNonce};
    use rand_core::RngCore;

    let cipher = XChaCha20Poly1305::new(&secret_bytes.into());

    let mut nonce_bytes = [0u8; 24];
    rand_core::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::from(nonce_bytes);

    let payload = chacha20poly1305::aead::Payload { msg: key, aad };
    let wrapped = cipher
        .encrypt(&nonce, payload)
        .map_err(|_| JsValue::from_str("Encryption failed"))?;

    let result = js_sys::Object::new();
    js_sys::Reflect::set(
        &result,
        &"nonce".into(),
        &js_sys::Uint8Array::from(nonce_bytes.as_slice()).into(),
    )?;
    js_sys::Reflect::set(
        &result,
        &"wrapped".into(),
        &js_sys::Uint8Array::from(wrapped.as_slice()).into(),
    )?;

    Ok(result.into())
}

/// Unwrap a key using a shared secret
#[wasm_bindgen(js_name = unwrapKey)]
pub fn wasm_unwrap_key(
    wrapped: &[u8],
    nonce_bytes: &[u8],
    shared_secret_bytes: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, JsValue> {
    if shared_secret_bytes.len() != 32 {
        return Err(JsValue::from_str("Shared secret must be 32 bytes"));
    }
    if nonce_bytes.len() != 24 {
        return Err(JsValue::from_str("Nonce must be 24 bytes"));
    }

    let mut secret_bytes = [0u8; 32];
    secret_bytes.copy_from_slice(shared_secret_bytes);

    use chacha20poly1305::{aead::Aead, KeyInit, XChaCha20Poly1305, XNonce};

    let cipher = XChaCha20Poly1305::new(&secret_bytes.into());

    let mut nonce_array = [0u8; 24];
    nonce_array.copy_from_slice(nonce_bytes);
    let nonce = XNonce::from(nonce_array);

    let payload = chacha20poly1305::aead::Payload { msg: wrapped, aad };
    let unwrapped = cipher
        .decrypt(&nonce, payload)
        .map_err(|_| JsValue::from_str("Decryption failed"))?;

    Ok(unwrapped)
}

/// Hash data with SHA256
#[wasm_bindgen(js_name = hashSha256)]
pub fn wasm_hash_sha256(data: &[u8]) -> Vec<u8> {
    zopp_crypto::hash_sha256(data).to_vec()
}

/// Hash data with SHA256 and return hex
#[wasm_bindgen(js_name = hashSha256Hex)]
pub fn wasm_hash_sha256_hex(data: &[u8]) -> String {
    hex::encode(zopp_crypto::hash_sha256(data))
}

/// Derive a master key using Argon2id
/// Note: This uses reduced parameters suitable for browsers
#[wasm_bindgen(js_name = deriveMasterKey)]
pub fn wasm_derive_master_key(password: &str, salt: &[u8]) -> Result<Vec<u8>, JsValue> {
    // Use browser-safe Argon2 parameters
    // For production, you might want to make these configurable
    let params = argon2::Params::new(
        19 * 1024, // 19 MiB memory (OWASP minimum recommendation)
        2,         // 2 iterations
        1,         // 1 degree of parallelism
        Some(32),  // 32 byte output
    )
    .map_err(|e| JsValue::from_str(&format!("Invalid Argon2 params: {}", e)))?;

    let argon2 = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

    let mut key = [0u8; 32];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| JsValue::from_str(&format!("Key derivation failed: {}", e)))?;

    Ok(key.to_vec())
}

/// Unwrap workspace KEK for a principal
/// This is the main function for decrypting workspace keys
#[wasm_bindgen(js_name = unwrapWorkspaceKek)]
pub fn unwrap_workspace_kek(
    x25519_secret_bytes: &[u8],
    ephemeral_pub: &[u8],
    kek_wrapped: &[u8],
    kek_nonce: &[u8],
    workspace_id: &str,
) -> Result<Vec<u8>, JsValue> {
    if x25519_secret_bytes.len() != 32 {
        return Err(JsValue::from_str("X25519 secret must be 32 bytes"));
    }
    if ephemeral_pub.len() != 32 {
        return Err(JsValue::from_str("Ephemeral public key must be 32 bytes"));
    }
    if kek_nonce.len() != 24 {
        return Err(JsValue::from_str("KEK nonce must be 24 bytes"));
    }

    let mut secret_array = [0u8; 32];
    secret_array.copy_from_slice(x25519_secret_bytes);
    let keypair = Keypair::from_secret_bytes(&secret_array);

    let ephemeral_public = public_key_from_bytes(ephemeral_pub)
        .map_err(|e| JsValue::from_str(&format!("Invalid ephemeral public key: {}", e)))?;

    let shared_secret = keypair.shared_secret(&ephemeral_public);
    let aad = format!("workspace:{}", workspace_id).into_bytes();

    let mut nonce_array = [0u8; 24];
    nonce_array.copy_from_slice(kek_nonce);
    let nonce = Nonce(nonce_array);

    let unwrapped = unwrap_key(kek_wrapped, &nonce, &shared_secret, &aad)
        .map_err(|e| JsValue::from_str(&format!("Failed to unwrap KEK: {}", e)))?;

    Ok(unwrapped.to_vec())
}

/// Unwrap environment DEK using KEK
#[wasm_bindgen(js_name = unwrapEnvironmentDek)]
pub fn unwrap_environment_dek(
    kek_bytes: &[u8],
    dek_wrapped: &[u8],
    dek_nonce: &[u8],
    workspace_name: &str,
    project_name: &str,
    environment_name: &str,
) -> Result<Vec<u8>, JsValue> {
    if kek_bytes.len() != 32 {
        return Err(JsValue::from_str("KEK must be 32 bytes"));
    }
    if dek_nonce.len() != 24 {
        return Err(JsValue::from_str("DEK nonce must be 24 bytes"));
    }

    let mut kek_array = [0u8; 32];
    kek_array.copy_from_slice(kek_bytes);
    let kek = Dek::from_bytes(&kek_array).map_err(JsValue::from_str)?;

    let aad = format!(
        "environment:{}:{}:{}",
        workspace_name, project_name, environment_name
    )
    .into_bytes();

    let mut nonce_array = [0u8; 24];
    nonce_array.copy_from_slice(dek_nonce);
    let nonce = Nonce(nonce_array);

    let dek_unwrapped =
        decrypt(dek_wrapped, &nonce, &kek, &aad).map_err(|e| JsValue::from_str(&e.to_string()))?;

    Ok(dek_unwrapped.to_vec())
}

/// Decrypt a secret using DEK
#[wasm_bindgen(js_name = decryptSecret)]
pub fn decrypt_secret(
    dek_bytes: &[u8],
    ciphertext: &[u8],
    nonce_bytes: &[u8],
    workspace_name: &str,
    project_name: &str,
    environment_name: &str,
    key: &str,
) -> Result<String, JsValue> {
    if dek_bytes.len() != 32 {
        return Err(JsValue::from_str("DEK must be 32 bytes"));
    }
    if nonce_bytes.len() != 24 {
        return Err(JsValue::from_str("Nonce must be 24 bytes"));
    }

    let mut dek_array = [0u8; 32];
    dek_array.copy_from_slice(dek_bytes);
    let dek = Dek::from_bytes(&dek_array).map_err(JsValue::from_str)?;

    let aad = format!(
        "secret:{}:{}:{}:{}",
        workspace_name, project_name, environment_name, key
    )
    .into_bytes();

    let mut nonce_array = [0u8; 24];
    nonce_array.copy_from_slice(nonce_bytes);
    let nonce = Nonce(nonce_array);

    let plaintext =
        decrypt(ciphertext, &nonce, &dek, &aad).map_err(|e| JsValue::from_str(&e.to_string()))?;

    String::from_utf8(plaintext.to_vec())
        .map_err(|e| JsValue::from_str(&format!("Invalid UTF-8: {}", e)))
}

/// Encrypt a secret value using DEK
/// Returns: { nonce: Uint8Array, ciphertext: Uint8Array }
#[wasm_bindgen(js_name = encryptSecret)]
pub fn encrypt_secret(
    dek_bytes: &[u8],
    value: &str,
    workspace_name: &str,
    project_name: &str,
    environment_name: &str,
    key: &str,
) -> Result<JsValue, JsValue> {
    if dek_bytes.len() != 32 {
        return Err(JsValue::from_str("DEK must be 32 bytes"));
    }

    let mut dek_array = [0u8; 32];
    dek_array.copy_from_slice(dek_bytes);
    let dek = Dek::from_bytes(&dek_array).map_err(JsValue::from_str)?;

    let aad = format!(
        "secret:{}:{}:{}:{}",
        workspace_name, project_name, environment_name, key
    )
    .into_bytes();

    let (nonce, ciphertext) =
        encrypt(value.as_bytes(), &dek, &aad).map_err(|e| JsValue::from_str(&e.to_string()))?;

    let result = js_sys::Object::new();
    js_sys::Reflect::set(
        &result,
        &"nonce".into(),
        &js_sys::Uint8Array::from(nonce.0.as_slice()).into(),
    )?;
    js_sys::Reflect::set(
        &result,
        &"ciphertext".into(),
        &js_sys::Uint8Array::from(ciphertext.0.as_slice()).into(),
    )?;

    Ok(result.into())
}

/// Wrap KEK for a new principal (used when inviting users or creating workspaces)
/// Returns: { ephemeralPub: Uint8Array, wrapped: Uint8Array, nonce: Uint8Array }
#[wasm_bindgen(js_name = wrapKekForPrincipal)]
pub fn wrap_kek_for_principal(
    kek: &[u8],
    principal_x25519_public: &[u8],
    workspace_id: &str,
) -> Result<JsValue, JsValue> {
    if kek.len() != 32 {
        return Err(JsValue::from_str("KEK must be 32 bytes"));
    }
    if principal_x25519_public.len() != 32 {
        return Err(JsValue::from_str("Principal public key must be 32 bytes"));
    }

    // Generate ephemeral keypair
    let ephemeral = Keypair::generate();
    let principal_public = public_key_from_bytes(principal_x25519_public)
        .map_err(|e| JsValue::from_str(&format!("Invalid principal public key: {}", e)))?;

    let shared_secret = ephemeral.shared_secret(&principal_public);
    let aad = format!("workspace:{}", workspace_id).into_bytes();

    let (nonce, wrapped) =
        wrap_key(kek, &shared_secret, &aad).map_err(|e| JsValue::from_str(&e.to_string()))?;

    let result = js_sys::Object::new();
    js_sys::Reflect::set(
        &result,
        &"ephemeralPub".into(),
        &js_sys::Uint8Array::from(ephemeral.public_key_bytes().as_slice()).into(),
    )?;
    js_sys::Reflect::set(
        &result,
        &"wrapped".into(),
        &js_sys::Uint8Array::from(wrapped.0.as_slice()).into(),
    )?;
    js_sys::Reflect::set(
        &result,
        &"nonce".into(),
        &js_sys::Uint8Array::from(nonce.0.as_slice()).into(),
    )?;

    Ok(result.into())
}

/// Wrap DEK with KEK for a new environment
/// Returns: { wrapped: Uint8Array, nonce: Uint8Array }
#[wasm_bindgen(js_name = wrapDekWithKek)]
pub fn wrap_dek_with_kek(
    dek: &[u8],
    kek: &[u8],
    workspace_name: &str,
    project_name: &str,
    environment_name: &str,
) -> Result<JsValue, JsValue> {
    if dek.len() != 32 {
        return Err(JsValue::from_str("DEK must be 32 bytes"));
    }
    if kek.len() != 32 {
        return Err(JsValue::from_str("KEK must be 32 bytes"));
    }

    let mut kek_array = [0u8; 32];
    kek_array.copy_from_slice(kek);
    let kek_dek = Dek::from_bytes(&kek_array).map_err(JsValue::from_str)?;

    let aad = format!(
        "environment:{}:{}:{}",
        workspace_name, project_name, environment_name
    )
    .into_bytes();

    let (nonce, ciphertext) =
        encrypt(dek, &kek_dek, &aad).map_err(|e| JsValue::from_str(&e.to_string()))?;

    let result = js_sys::Object::new();
    js_sys::Reflect::set(
        &result,
        &"wrapped".into(),
        &js_sys::Uint8Array::from(ciphertext.0.as_slice()).into(),
    )?;
    js_sys::Reflect::set(
        &result,
        &"nonce".into(),
        &js_sys::Uint8Array::from(nonce.0.as_slice()).into(),
    )?;

    Ok(result.into())
}

/// Get current timestamp in seconds (for request signing)
#[wasm_bindgen(js_name = getCurrentTimestamp)]
pub fn get_current_timestamp() -> i64 {
    js_sys::Date::now() as i64 / 1000
}

/// Derive export key using Argon2id with CLI-compatible parameters
/// This matches the CLI's derive_export_key function exactly:
/// - 64 MiB memory (64 * 1024 KiB)
/// - 3 iterations
/// - 1 parallelism
/// - 32 byte output
#[wasm_bindgen(js_name = deriveExportKey)]
pub fn derive_export_key(passphrase: &str, salt: &[u8]) -> Result<Vec<u8>, JsValue> {
    if salt.len() != 16 {
        return Err(JsValue::from_str("Salt must be 16 bytes"));
    }

    let params = argon2::Params::new(
        64 * 1024, // 64 MiB memory (same as CLI)
        3,         // 3 iterations (same as CLI)
        1,         // 1 degree of parallelism
        Some(32),  // 32 byte output
    )
    .map_err(|e| JsValue::from_str(&format!("Invalid Argon2 params: {}", e)))?;

    let argon2 = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

    let mut key = [0u8; 32];
    argon2
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|e| JsValue::from_str(&format!("Key derivation failed: {}", e)))?;

    Ok(key.to_vec())
}

/// Compute Argon2id verification hash for export passphrase
/// This matches the CLI's compute_verification_hash function
/// Returns hex-encoded 32-byte hash for server verification
#[wasm_bindgen(js_name = computeVerificationHash)]
pub fn compute_verification_hash(
    passphrase: &str,
    verification_salt: &[u8],
) -> Result<String, JsValue> {
    if verification_salt.len() != 16 {
        return Err(JsValue::from_str("Verification salt must be 16 bytes"));
    }

    // Same Argon2id params as derive_export_key for consistency
    let params = argon2::Params::new(
        64 * 1024, // 64 MiB memory
        3,         // 3 iterations
        1,         // 1 parallelism
        Some(32),  // 32 byte output
    )
    .map_err(|e| JsValue::from_str(&format!("Invalid Argon2 params: {}", e)))?;

    let argon2 = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

    let mut hash = [0u8; 32];
    argon2
        .hash_password_into(passphrase.as_bytes(), verification_salt, &mut hash)
        .map_err(|e| JsValue::from_str(&format!("Hash computation failed: {}", e)))?;

    Ok(hex::encode(hash))
}

/// Decrypt principal export data
/// Returns JSON string of the exported principal
#[wasm_bindgen(js_name = decryptPrincipalExport)]
pub fn decrypt_principal_export(
    encrypted_data: &[u8],
    nonce: &[u8],
    salt: &[u8],
    passphrase: &str,
) -> Result<String, JsValue> {
    if salt.len() != 16 {
        return Err(JsValue::from_str("Salt must be 16 bytes"));
    }
    if nonce.len() != 24 {
        return Err(JsValue::from_str("Nonce must be 24 bytes"));
    }

    // Derive key from passphrase
    let key_bytes = derive_export_key(passphrase, salt)?;

    let mut dek_array = [0u8; 32];
    dek_array.copy_from_slice(&key_bytes);
    let dek = Dek::from_bytes(&dek_array).map_err(JsValue::from_str)?;

    let mut nonce_array = [0u8; 24];
    nonce_array.copy_from_slice(nonce);
    let nonce = Nonce(nonce_array);

    // AAD used by CLI for principal export v2
    let aad = b"zopp-principal-export-v2";

    let plaintext = decrypt(encrypted_data, &nonce, &dek, aad)
        .map_err(|_| JsValue::from_str("Decryption failed - wrong passphrase?"))?;

    String::from_utf8(plaintext.to_vec())
        .map_err(|e| JsValue::from_str(&format!("Invalid UTF-8: {}", e)))
}

/// Decrypt invite KEK using the invite secret
/// Returns the raw KEK bytes
#[wasm_bindgen(js_name = decryptInviteKek)]
pub fn decrypt_invite_kek(
    kek_encrypted: &[u8],
    kek_nonce: &[u8],
    invite_secret: &[u8],
    workspace_id: &str,
) -> Result<Vec<u8>, JsValue> {
    if invite_secret.len() != 32 {
        return Err(JsValue::from_str("Invite secret must be 32 bytes"));
    }
    if kek_nonce.len() != 24 {
        return Err(JsValue::from_str("KEK nonce must be 24 bytes"));
    }

    let mut secret_array = [0u8; 32];
    secret_array.copy_from_slice(invite_secret);
    let dek = Dek::from_bytes(&secret_array).map_err(JsValue::from_str)?;

    let aad = format!("invite:workspace:{}", workspace_id).into_bytes();

    let mut nonce_array = [0u8; 24];
    nonce_array.copy_from_slice(kek_nonce);
    let nonce = Nonce(nonce_array);

    let kek = decrypt(kek_encrypted, &nonce, &dek, &aad)
        .map_err(|_| JsValue::from_str("Failed to decrypt invite KEK"))?;

    Ok(kek.to_vec())
}

/// Re-wrap KEK for joining principal (used during invite flow)
/// Returns: { ephemeralPub: Uint8Array, kekWrapped: Uint8Array, kekNonce: Uint8Array }
#[wasm_bindgen(js_name = rewrapKekForJoin)]
pub fn rewrap_kek_for_join(
    kek: &[u8],
    my_x25519_public: &[u8],
    workspace_id: &str,
) -> Result<JsValue, JsValue> {
    if kek.len() != 32 {
        return Err(JsValue::from_str("KEK must be 32 bytes"));
    }
    if my_x25519_public.len() != 32 {
        return Err(JsValue::from_str("X25519 public key must be 32 bytes"));
    }

    // Generate ephemeral keypair for wrapping
    let ephemeral = Keypair::generate();
    let my_public = public_key_from_bytes(my_x25519_public)
        .map_err(|e| JsValue::from_str(&format!("Invalid public key: {}", e)))?;

    let shared_secret = ephemeral.shared_secret(&my_public);
    let aad = format!("workspace:{}", workspace_id).into_bytes();

    let (nonce, wrapped) =
        wrap_key(kek, &shared_secret, &aad).map_err(|e| JsValue::from_str(&e.to_string()))?;

    let result = js_sys::Object::new();
    js_sys::Reflect::set(
        &result,
        &"ephemeralPub".into(),
        &js_sys::Uint8Array::from(ephemeral.public_key_bytes().as_slice()).into(),
    )?;
    js_sys::Reflect::set(
        &result,
        &"kekWrapped".into(),
        &js_sys::Uint8Array::from(wrapped.0.as_slice()).into(),
    )?;
    js_sys::Reflect::set(
        &result,
        &"kekNonce".into(),
        &js_sys::Uint8Array::from(nonce.0.as_slice()).into(),
    )?;

    Ok(result.into())
}

/// Hex encode bytes
#[wasm_bindgen(js_name = hexEncode)]
pub fn hex_encode(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

/// Hex decode string
#[wasm_bindgen(js_name = hexDecode)]
pub fn hex_decode(hex_str: &str) -> Result<Vec<u8>, JsValue> {
    hex::decode(hex_str).map_err(|e| JsValue::from_str(&format!("Invalid hex: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_x25519_keypair_roundtrip() {
        let kp = WasmX25519Keypair::new();
        let secret = kp.secret_key_bytes();
        let public = kp.public_key_bytes();

        assert_eq!(secret.len(), 32);
        assert_eq!(public.len(), 32);

        let kp2 = WasmX25519Keypair::from_secret_bytes(&secret).unwrap();
        assert_eq!(kp2.public_key_bytes(), public);
    }

    #[test]
    fn test_ed25519_keypair_roundtrip() {
        let kp = WasmEd25519Keypair::new();
        let secret = kp.secret_key_bytes();
        let public = kp.public_key_bytes();

        assert_eq!(secret.len(), 32);
        assert_eq!(public.len(), 32);

        let kp2 = WasmEd25519Keypair::from_secret_bytes(&secret).unwrap();
        assert_eq!(kp2.public_key_bytes(), public);
    }

    #[test]
    fn test_ed25519_sign_verify() {
        let kp = WasmEd25519Keypair::new();
        let message = b"test message";
        let signature = kp.sign(message);

        assert_eq!(signature.len(), 64);

        let valid = verify_ed25519(&kp.public_key_bytes(), message, &signature).unwrap();
        assert!(valid);

        // Wrong message should fail
        let invalid = verify_ed25519(&kp.public_key_bytes(), b"wrong message", &signature).unwrap();
        assert!(!invalid);
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let dek = wasm_generate_dek();
        let plaintext = b"secret data";
        let aad = b"additional data";

        // This test won't work without wasm-bindgen-test because it returns JsValue
        // We test the underlying zopp-crypto functions directly
        let mut dek_array = [0u8; 32];
        dek_array.copy_from_slice(&dek);
        let dek_struct = Dek::from_bytes(&dek_array).unwrap();

        let (nonce, ciphertext) = encrypt(plaintext, &dek_struct, aad).unwrap();
        let decrypted = decrypt(&ciphertext.0, &nonce, &dek_struct, aad).unwrap();

        assert_eq!(plaintext.to_vec(), decrypted.to_vec());
    }

    #[test]
    fn test_sha256_hash() {
        let data = b"hello world";
        let hash = wasm_hash_sha256(data);
        assert_eq!(hash.len(), 32);

        // Known SHA256 hash of "hello world"
        let expected = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";
        assert_eq!(wasm_hash_sha256_hex(data), expected);
    }
}
