use crate::config::PrincipalConfig;
use tonic::metadata::MetadataValue;
use tonic::transport::Channel;
use zopp_proto::zopp_service_client::ZoppServiceClient;

/// Unwrap workspace KEK for the current principal
pub async fn unwrap_workspace_kek(
    client: &mut ZoppServiceClient<Channel>,
    principal: &PrincipalConfig,
    workspace_name: &str,
) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let (timestamp, signature) = crate::grpc::sign_request(&principal.private_key)?;

    let mut request = tonic::Request::new(zopp_proto::GetWorkspaceKeysRequest {
        workspace_name: workspace_name.to_string(),
    });
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

    let response = client.get_workspace_keys(request).await?.into_inner();

    let x25519_private_key = principal
        .x25519_private_key
        .as_ref()
        .ok_or("Principal missing X25519 private key")?;
    let x25519_private_bytes = hex::decode(x25519_private_key)?;
    let mut x25519_array = [0u8; 32];
    x25519_array.copy_from_slice(&x25519_private_bytes);
    let x25519_keypair = zopp_crypto::Keypair::from_secret_bytes(&x25519_array);

    let ephemeral_pub = zopp_crypto::public_key_from_bytes(&response.ephemeral_pub)?;
    let shared_secret = x25519_keypair.shared_secret(&ephemeral_pub);

    let aad = format!("workspace:{}", response.workspace_id).into_bytes();
    let mut nonce_array = [0u8; 24];
    nonce_array.copy_from_slice(&response.kek_nonce);
    let nonce = zopp_crypto::Nonce(nonce_array);

    let unwrapped = zopp_crypto::unwrap_key(&response.kek_wrapped, &nonce, &shared_secret, &aad)?;

    if unwrapped.len() != 32 {
        return Err("KEK must be 32 bytes".into());
    }

    let mut kek = [0u8; 32];
    kek.copy_from_slice(&unwrapped);
    Ok(kek)
}

/// Unwrap environment DEK using workspace KEK
pub async fn unwrap_environment_dek(
    client: &mut ZoppServiceClient<Channel>,
    principal: &PrincipalConfig,
    workspace_name: &str,
    project_name: &str,
    environment_name: &str,
    kek: &[u8; 32],
) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let (timestamp, signature) = crate::grpc::sign_request(&principal.private_key)?;

    let mut request = tonic::Request::new(zopp_proto::GetEnvironmentRequest {
        workspace_name: workspace_name.to_string(),
        project_name: project_name.to_string(),
        environment_name: environment_name.to_string(),
    });
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

    let response = client.get_environment(request).await?.into_inner();

    let mut nonce_array = [0u8; 24];
    nonce_array.copy_from_slice(&response.dek_nonce);
    let nonce = zopp_crypto::Nonce(nonce_array);

    let dek_key = zopp_crypto::Dek::from_bytes(kek)?;
    let aad = format!(
        "environment:{}:{}:{}",
        workspace_name, project_name, environment_name
    )
    .into_bytes();

    let unwrapped = zopp_crypto::decrypt(&response.dek_wrapped, &nonce, &dek_key, &aad)?;

    if unwrapped.len() != 32 {
        return Err("DEK must be 32 bytes".into());
    }

    let mut dek = [0u8; 32];
    dek.copy_from_slice(&unwrapped);
    Ok(dek)
}
