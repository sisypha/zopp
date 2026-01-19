//! WASM crypto service wrapper
//!
//! This module provides a high-level interface to the zopp-crypto-wasm module.

#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(module = "/pkg/zopp_crypto_wasm.js")]
extern "C" {
    #[wasm_bindgen(js_name = WasmX25519Keypair)]
    pub type X25519Keypair;

    #[wasm_bindgen(constructor, js_class = "WasmX25519Keypair")]
    pub fn new_x25519() -> X25519Keypair;

    #[wasm_bindgen(method, js_name = publicKeyBytes)]
    pub fn x25519_public_key_bytes(this: &X25519Keypair) -> Vec<u8>;

    #[wasm_bindgen(method, js_name = secretKeyBytes)]
    pub fn x25519_secret_key_bytes(this: &X25519Keypair) -> Vec<u8>;

    #[wasm_bindgen(js_name = WasmEd25519Keypair)]
    pub type Ed25519Keypair;

    #[wasm_bindgen(constructor, js_class = "WasmEd25519Keypair")]
    pub fn new_ed25519() -> Ed25519Keypair;

    #[wasm_bindgen(method, js_name = publicKeyBytes)]
    pub fn ed25519_public_key_bytes(this: &Ed25519Keypair) -> Vec<u8>;

    #[wasm_bindgen(method, js_name = secretKeyBytes)]
    pub fn ed25519_secret_key_bytes(this: &Ed25519Keypair) -> Vec<u8>;

    #[wasm_bindgen(method, js_name = publicKeyHex)]
    pub fn ed25519_public_key_hex(this: &Ed25519Keypair) -> String;

    #[wasm_bindgen(method, js_name = secretKeyHex)]
    pub fn ed25519_secret_key_hex(this: &Ed25519Keypair) -> String;

    #[wasm_bindgen(js_name = signGrpcRequest)]
    pub fn sign_grpc_request(
        ed25519_secret_hex: &str,
        method: &str,
        request_hash: &[u8],
        timestamp: i64,
    ) -> JsValue;

    #[wasm_bindgen(js_name = computeRequestHash)]
    pub fn compute_request_hash(method: &str, body: &[u8]) -> Vec<u8>;

    #[wasm_bindgen(js_name = generateDek)]
    pub fn generate_dek() -> Vec<u8>;

    #[wasm_bindgen(js_name = encrypt)]
    pub fn encrypt(plaintext: &[u8], dek: &[u8], aad: &[u8]) -> JsValue;

    #[wasm_bindgen(js_name = decrypt)]
    pub fn decrypt(ciphertext: &[u8], nonce: &[u8], dek: &[u8], aad: &[u8]) -> Vec<u8>;

    #[wasm_bindgen(js_name = unwrapWorkspaceKek)]
    pub fn unwrap_workspace_kek(
        x25519_secret: &[u8],
        ephemeral_pub: &[u8],
        kek_wrapped: &[u8],
        kek_nonce: &[u8],
        workspace_id: &str,
    ) -> Vec<u8>;

    #[wasm_bindgen(js_name = unwrapEnvironmentDek)]
    pub fn unwrap_environment_dek(
        kek: &[u8],
        dek_wrapped: &[u8],
        dek_nonce: &[u8],
        workspace_name: &str,
        project_name: &str,
        environment_name: &str,
    ) -> Vec<u8>;

    #[wasm_bindgen(js_name = decryptSecret)]
    pub fn decrypt_secret(
        dek: &[u8],
        ciphertext: &[u8],
        nonce: &[u8],
        workspace_name: &str,
        project_name: &str,
        environment_name: &str,
        key: &str,
    ) -> String;

    #[wasm_bindgen(js_name = encryptSecret)]
    pub fn encrypt_secret(
        dek: &[u8],
        value: &str,
        workspace_name: &str,
        project_name: &str,
        environment_name: &str,
        key: &str,
    ) -> JsValue;

    #[wasm_bindgen(js_name = hexEncode)]
    pub fn hex_encode(bytes: &[u8]) -> String;

    #[wasm_bindgen(js_name = hexDecode)]
    pub fn hex_decode(hex: &str) -> Vec<u8>;

    #[wasm_bindgen(js_name = getCurrentTimestamp)]
    pub fn get_current_timestamp() -> i64;
}

// Non-WASM stubs for SSR - use real implementations to avoid silent corruption
#[cfg(all(not(target_arch = "wasm32"), feature = "ssr"))]
pub fn hex_encode(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

#[cfg(all(not(target_arch = "wasm32"), feature = "ssr"))]
pub fn hex_decode(hex_str: &str) -> Vec<u8> {
    hex::decode(hex_str).unwrap_or_default()
}

// Stubs when neither wasm nor ssr (e.g., default feature check)
// These should never be called - panic if they are to avoid silent data corruption
#[cfg(all(not(target_arch = "wasm32"), not(feature = "ssr")))]
pub fn hex_encode(_bytes: &[u8]) -> String {
    panic!("hex_encode called in non-WASM/non-SSR build - this is a configuration error")
}

#[cfg(all(not(target_arch = "wasm32"), not(feature = "ssr")))]
pub fn hex_decode(_hex_str: &str) -> Vec<u8> {
    panic!("hex_decode called in non-WASM/non-SSR build - this is a configuration error")
}
