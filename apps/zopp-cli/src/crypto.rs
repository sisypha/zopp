use crate::config::PrincipalConfig;
use std::collections::BTreeMap;
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

/// Fetch and decrypt all secrets for an environment
/// Returns a BTreeMap of key -> decrypted plaintext value
pub async fn fetch_and_decrypt_secrets(
    client: &mut ZoppServiceClient<Channel>,
    principal: &PrincipalConfig,
    workspace_name: &str,
    project_name: &str,
    environment_name: &str,
) -> Result<BTreeMap<String, String>, Box<dyn std::error::Error>> {
    // Unwrap KEK and DEK
    let kek = unwrap_workspace_kek(client, principal, workspace_name).await?;
    let dek_bytes = unwrap_environment_dek(
        client,
        principal,
        workspace_name,
        project_name,
        environment_name,
        &kek,
    )
    .await?;
    let dek = zopp_crypto::Dek::from_bytes(&dek_bytes)?;

    // List all secrets
    let (timestamp, signature) = crate::grpc::sign_request(&principal.private_key)?;
    let mut request = tonic::Request::new(zopp_proto::ListSecretsRequest {
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
    let secrets_response = client.list_secrets(request).await?.into_inner();

    // Decrypt all secrets into a map
    let mut secret_data = BTreeMap::new();
    for secret in secrets_response.secrets {
        let mut nonce_array = [0u8; 24];
        nonce_array.copy_from_slice(&secret.nonce);
        let nonce = zopp_crypto::Nonce(nonce_array);
        let aad = format!(
            "secret:{}:{}:{}:{}",
            workspace_name, project_name, environment_name, secret.key
        )
        .into_bytes();
        let plaintext = zopp_crypto::decrypt(&secret.ciphertext, &nonce, &dek, &aad)?;
        let plaintext_str =
            String::from_utf8(plaintext.to_vec()).map_err(|_| "Secret value is not valid UTF-8")?;

        secret_data.insert(secret.key.clone(), plaintext_str);
    }

    Ok(secret_data)
}
