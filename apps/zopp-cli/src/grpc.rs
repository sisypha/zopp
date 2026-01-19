use crate::config::{
    get_current_principal, load_config, load_principal_with_secrets, PrincipalConfig,
    PrincipalSecrets,
};
use chrono::Utc;
use ed25519_dalek::{Signer, SigningKey};
use prost::Message;
use sha2::{Digest, Sha256};
use std::path::Path;
use tonic::metadata::MetadataValue;
use tonic::transport::Channel;
use zopp_proto::zopp_service_client::ZoppServiceClient;

pub async fn connect(
    server: &str,
    tls_ca_cert: Option<&Path>,
) -> Result<ZoppServiceClient<Channel>, Box<dyn std::error::Error>> {
    let endpoint = Channel::from_shared(server.to_string())?;

    let endpoint = if server.starts_with("https://") {
        if let Some(ca_cert_path) = tls_ca_cert {
            // Custom CA for self-signed certificates
            let ca_cert = tokio::fs::read(ca_cert_path).await?;
            let tls_config = tonic::transport::ClientTlsConfig::new()
                .ca_certificate(tonic::transport::Certificate::from_pem(ca_cert));
            endpoint.tls_config(tls_config)?
        } else {
            // System CA store for trusted certificates
            let url = url::Url::parse(server)?;
            let domain = url.host_str().ok_or("HTTPS URL must have a valid host")?;
            let tls_config = tonic::transport::ClientTlsConfig::new().domain_name(domain);
            endpoint.tls_config(tls_config)?
        }
    } else {
        endpoint
    };

    let channel = endpoint.connect().await?;
    let client = ZoppServiceClient::new(channel);
    Ok(client)
}

/// Compute SHA256 hash of request body for signature binding
pub fn compute_request_hash<T: Message>(method: &str, request: &T) -> Vec<u8> {
    let body_bytes = request.encode_to_vec();
    let mut hasher = Sha256::new();
    hasher.update(method.as_bytes());
    hasher.update(&body_bytes);
    hasher.finalize().to_vec()
}

/// Sign a request with method name and body hash to prevent replay attacks.
/// The signature covers: method_name + SHA256(method + body) + timestamp
pub fn sign_request_with_body(
    private_key_hex: &str,
    method: &str,
    request_hash: &[u8],
) -> Result<(i64, Vec<u8>), Box<dyn std::error::Error>> {
    let timestamp = Utc::now().timestamp();
    let private_key_bytes = hex::decode(private_key_hex)?;
    let signing_key = SigningKey::from_bytes(
        private_key_bytes
            .as_slice()
            .try_into()
            .map_err(|_| "Invalid private key length")?,
    );

    // Build message: method + request_hash + timestamp
    let mut message = Vec::new();
    message.extend_from_slice(method.as_bytes());
    message.extend_from_slice(request_hash);
    message.extend_from_slice(&timestamp.to_le_bytes());

    let signature = signing_key.sign(&message);
    Ok((timestamp, signature.to_bytes().to_vec()))
}

/// Setup authenticated client: load config, get principal and secrets, connect to server
pub async fn setup_client(
    server: &str,
    tls_ca_cert: Option<&Path>,
) -> Result<
    (
        ZoppServiceClient<Channel>,
        PrincipalConfig,
        PrincipalSecrets,
    ),
    Box<dyn std::error::Error>,
> {
    let config = load_config()?;
    let principal = get_current_principal(&config)?;
    let secrets = load_principal_with_secrets(principal, config.use_file_storage)?;
    let client = connect(server, tls_ca_cert).await?;
    Ok((client, principal.clone(), secrets))
}

/// Add authentication metadata (principal-id, timestamp, signature, request-hash) to a request.
/// The signature binds to the method name and request body to prevent replay attacks.
pub fn add_auth_metadata<T: Message>(
    request: &mut tonic::Request<T>,
    principal: &PrincipalConfig,
    secrets: &PrincipalSecrets,
    method: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let request_hash = compute_request_hash(method, request.get_ref());
    let (timestamp, signature) =
        sign_request_with_body(&secrets.ed25519_private_key, method, &request_hash)?;

    request
        .metadata_mut()
        .insert("principal-id", MetadataValue::try_from(&principal.id)?);
    request
        .metadata_mut()
        .insert("timestamp", MetadataValue::try_from(timestamp.to_string())?);
    request.metadata_mut().insert(
        "signature",
        MetadataValue::try_from(hex::encode(&signature))?,
    );
    request.metadata_mut().insert(
        "request-hash",
        MetadataValue::try_from(hex::encode(&request_hash))?,
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use zopp_proto::Empty;

    #[test]
    fn test_compute_request_hash_deterministic() {
        let request = Empty {};
        let method = "/zopp.ZoppService/TestMethod";

        let hash1 = compute_request_hash(method, &request);
        let hash2 = compute_request_hash(method, &request);

        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 32); // SHA256 produces 32 bytes
    }

    #[test]
    fn test_compute_request_hash_different_methods() {
        let request = Empty {};

        let hash1 = compute_request_hash("/zopp.ZoppService/Method1", &request);
        let hash2 = compute_request_hash("/zopp.ZoppService/Method2", &request);

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_compute_request_hash_different_bodies() {
        // Use GetWorkspaceKeysRequest since it has a string field
        let req1 = zopp_proto::GetWorkspaceKeysRequest {
            workspace_name: "workspace1".to_string(),
        };
        let req2 = zopp_proto::GetWorkspaceKeysRequest {
            workspace_name: "workspace2".to_string(),
        };
        let method = "/zopp.ZoppService/GetWorkspaceKeys";

        let hash1 = compute_request_hash(method, &req1);
        let hash2 = compute_request_hash(method, &req2);

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_sign_request_with_body_valid_key() {
        // Use a fixed known Ed25519 key (32 bytes)
        let private_key_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

        let method = "/zopp.ZoppService/TestMethod";
        let request_hash = vec![0u8; 32];

        let result = sign_request_with_body(private_key_hex, method, &request_hash);
        assert!(result.is_ok());

        let (timestamp, signature) = result.unwrap();
        assert!(timestamp > 0);
        assert_eq!(signature.len(), 64); // Ed25519 signature is 64 bytes
    }

    #[test]
    fn test_sign_request_with_body_different_hashes_different_signatures() {
        let private_key_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let method = "/Method";

        let hash1 = vec![0u8; 32];
        let hash2 = vec![1u8; 32];

        let (_, sig1) = sign_request_with_body(private_key_hex, method, &hash1).unwrap();
        let (_, sig2) = sign_request_with_body(private_key_hex, method, &hash2).unwrap();

        // Different hashes should produce different signatures
        assert_eq!(sig1.len(), 64);
        assert_eq!(sig2.len(), 64);
        assert_ne!(sig1, sig2);
    }

    #[test]
    fn test_sign_request_with_body_invalid_hex() {
        let result = sign_request_with_body("not_valid_hex!", "/Method", &[0u8; 32]);
        assert!(result.is_err());
    }

    #[test]
    fn test_sign_request_with_body_wrong_key_length() {
        // Valid hex but wrong length (only 16 bytes)
        let short_key = hex::encode([0u8; 16]);
        let result = sign_request_with_body(&short_key, "/Method", &[0u8; 32]);
        assert!(result.is_err());
    }

    #[test]
    fn test_sign_request_with_body_empty_key() {
        let result = sign_request_with_body("", "/Method", &[0u8; 32]);
        assert!(result.is_err());
    }

    #[test]
    fn test_sign_request_with_body_signature_verification() {
        use ed25519_dalek::{SigningKey, Verifier};

        // Use a fixed key so we can derive the verifying key
        let private_key_bytes =
            hex::decode("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
                .unwrap();
        let signing_key = SigningKey::from_bytes(private_key_bytes.as_slice().try_into().unwrap());
        let verifying_key = signing_key.verifying_key();
        let private_key_hex = hex::encode(signing_key.to_bytes());

        let method = "/zopp.ZoppService/TestMethod";
        let request_hash = vec![1u8; 32];

        let (timestamp, signature_bytes) =
            sign_request_with_body(&private_key_hex, method, &request_hash).unwrap();

        // Reconstruct the message that was signed
        let mut message = Vec::new();
        message.extend_from_slice(method.as_bytes());
        message.extend_from_slice(&request_hash);
        message.extend_from_slice(&timestamp.to_le_bytes());

        // Verify the signature
        let signature =
            ed25519_dalek::Signature::from_bytes(signature_bytes.as_slice().try_into().unwrap());
        assert!(verifying_key.verify(&message, &signature).is_ok());
    }
}
