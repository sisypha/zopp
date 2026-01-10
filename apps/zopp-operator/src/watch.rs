use ed25519_dalek::{Signature, Signer, SigningKey};
use prost::Message;
use sha2::{Digest, Sha256};

/// Create signature for gRPC request authentication
/// The signature covers: method + request_hash + timestamp
pub fn create_signature<T: Message>(
    credentials: &crate::credentials::OperatorCredentials,
    method: &str,
    request: &T,
    timestamp: i64,
) -> (Vec<u8>, Vec<u8>) {
    let signing_key_bytes = credentials
        .principal
        .get_private_key_bytes()
        .expect("Failed to get signing key");
    let signing_key = SigningKey::from_bytes(&signing_key_bytes);

    // Compute request hash
    let body_bytes = request.encode_to_vec();
    let mut hasher = Sha256::new();
    hasher.update(method.as_bytes());
    hasher.update(&body_bytes);
    let request_hash = hasher.finalize().to_vec();

    // Create message to sign: method + hash + timestamp
    let mut message = Vec::new();
    message.extend_from_slice(method.as_bytes());
    message.extend_from_slice(&request_hash);
    message.extend_from_slice(&timestamp.to_le_bytes());

    let signature: Signature = signing_key.sign(&message);
    (signature.to_bytes().to_vec(), request_hash)
}
