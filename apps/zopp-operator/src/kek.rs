use crate::OperatorError;
use zopp_proto::zopp_service_client::ZoppServiceClient;

/// Get workspace KEK for the operator principal
/// Fetches the wrapped KEK from the server and unwraps it using the principal's X25519 key
/// Results are cached to avoid repeated RPC calls
pub async fn get_workspace_kek(
    client: &mut ZoppServiceClient<tonic::transport::Channel>,
    credentials: &crate::credentials::OperatorCredentials,
    workspace_name: &str,
) -> Result<[u8; 32], OperatorError> {
    // Check cache first
    if let Some(cached_kek) = credentials.get_cached_kek(workspace_name).await {
        return Ok(cached_kek);
    }

    // Fetch wrapped KEK from server
    let timestamp = chrono::Utc::now().timestamp();
    let signature = crate::watch::create_signature(credentials, timestamp);

    let mut request = tonic::Request::new(zopp_proto::GetWorkspaceKeysRequest {
        workspace_name: workspace_name.to_string(),
    });

    request.metadata_mut().insert(
        "principal-id",
        credentials.principal.id.to_string().parse().unwrap(),
    );
    request
        .metadata_mut()
        .insert("timestamp", timestamp.to_string().parse().unwrap());
    request
        .metadata_mut()
        .insert("signature", hex::encode(&signature).parse().unwrap());

    let response = client.get_workspace_keys(request).await?;
    let keys_data = response.into_inner();

    // Unwrap the KEK using principal's X25519 private key
    let x25519_private_key = credentials
        .principal
        .x25519_private_key
        .as_ref()
        .ok_or("Principal missing X25519 private key".to_string())?;
    let x25519_private_bytes = hex::decode(x25519_private_key)
        .map_err(|e| OperatorError::Decryption(format!("Invalid X25519 private key: {}", e)))?;
    let mut x25519_array = [0u8; 32];
    x25519_array.copy_from_slice(&x25519_private_bytes);
    let x25519_keypair = zopp_crypto::Keypair::from_secret_bytes(&x25519_array);

    // Derive shared secret from ephemeral public key
    let ephemeral_pub =
        zopp_crypto::public_key_from_bytes(&keys_data.ephemeral_pub).map_err(|_| {
            OperatorError::Decryption("Invalid ephemeral public key length".to_string())
        })?;
    let shared_secret = x25519_keypair.shared_secret(&ephemeral_pub);

    // Unwrap KEK
    let aad = format!("workspace:{}", keys_data.workspace_id).into_bytes();
    let nonce_arr: [u8; 24] = keys_data
        .kek_nonce
        .as_slice()
        .try_into()
        .map_err(|_| OperatorError::Decryption("Invalid nonce length".to_string()))?;
    let nonce = zopp_crypto::Nonce(nonce_arr);

    let kek_bytes_vec =
        zopp_crypto::unwrap_key(&keys_data.kek_wrapped, &nonce, &shared_secret, &aad)
            .map_err(|e| e.to_string())?;

    let kek_bytes: [u8; 32] = (*kek_bytes_vec)
        .as_slice()
        .try_into()
        .map_err(|_| "KEK must be exactly 32 bytes".to_string())?;

    // Cache the KEK
    credentials.cache_kek(workspace_name, kek_bytes).await;

    Ok(kek_bytes)
}
