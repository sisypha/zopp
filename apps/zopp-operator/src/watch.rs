use ed25519_dalek::{Signature, Signer, SigningKey};

/// Create signature for gRPC request authentication
pub fn create_signature(
    credentials: &crate::credentials::OperatorCredentials,
    timestamp: i64,
) -> Vec<u8> {
    let signing_key_bytes = credentials
        .principal
        .get_private_key_bytes()
        .expect("Failed to get signing key");
    let signing_key = SigningKey::from_bytes(&signing_key_bytes);
    let signature: Signature = signing_key.sign(&timestamp.to_le_bytes());
    signature.to_bytes().to_vec()
}
