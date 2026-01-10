use crate::config::PrincipalConfig;
use std::collections::BTreeMap;
use tonic::transport::Channel;
use zopp_proto::zopp_service_client::ZoppServiceClient;
use zopp_secrets::SecretContext;

/// Unwrap workspace KEK for the current principal
/// This is a lower-level function needed for operations like creating environments or invites
pub async fn unwrap_workspace_kek(
    client: &mut ZoppServiceClient<Channel>,
    principal: &PrincipalConfig,
    workspace_name: &str,
) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let mut request = tonic::Request::new(zopp_proto::GetWorkspaceKeysRequest {
        workspace_name: workspace_name.to_string(),
    });
    crate::grpc::add_auth_metadata(&mut request, principal, "/zopp.ZoppService/GetWorkspaceKeys")?;

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

/// Fetch and decrypt all secrets for an environment
/// Returns a BTreeMap of key -> decrypted plaintext value
pub async fn fetch_and_decrypt_secrets(
    client: &mut ZoppServiceClient<Channel>,
    principal: &PrincipalConfig,
    workspace_name: &str,
    project_name: &str,
    environment_name: &str,
) -> Result<BTreeMap<String, String>, Box<dyn std::error::Error>> {
    // Get workspace keys
    let mut request = tonic::Request::new(zopp_proto::GetWorkspaceKeysRequest {
        workspace_name: workspace_name.to_string(),
    });
    crate::grpc::add_auth_metadata(&mut request, principal, "/zopp.ZoppService/GetWorkspaceKeys")?;
    let workspace_keys = client.get_workspace_keys(request).await?.into_inner();

    // Get environment
    let mut request = tonic::Request::new(zopp_proto::GetEnvironmentRequest {
        workspace_name: workspace_name.to_string(),
        project_name: project_name.to_string(),
        environment_name: environment_name.to_string(),
    });
    crate::grpc::add_auth_metadata(&mut request, principal, "/zopp.ZoppService/GetEnvironment")?;
    let environment = client.get_environment(request).await?.into_inner();

    // List all secrets
    let mut request = tonic::Request::new(zopp_proto::ListSecretsRequest {
        workspace_name: workspace_name.to_string(),
        project_name: project_name.to_string(),
        environment_name: environment_name.to_string(),
    });
    crate::grpc::add_auth_metadata(&mut request, principal, "/zopp.ZoppService/ListSecrets")?;
    let secrets_response = client.list_secrets(request).await?.into_inner();

    // Create SecretContext to hide all crypto details
    let x25519_private_key = principal
        .x25519_private_key
        .as_ref()
        .ok_or("Principal missing X25519 private key")?;
    let x25519_private_bytes = hex::decode(x25519_private_key)?;
    let mut x25519_array = [0u8; 32];
    x25519_array.copy_from_slice(&x25519_private_bytes);

    let ctx = SecretContext::new(
        x25519_array,
        workspace_keys,
        environment,
        workspace_name.to_string(),
        project_name.to_string(),
        environment_name.to_string(),
    )?;

    // Decrypt all secrets using the context
    let mut secret_data = BTreeMap::new();
    for secret in secrets_response.secrets {
        let plaintext = ctx.decrypt_secret(&secret)?;
        secret_data.insert(secret.key.clone(), plaintext);
    }

    Ok(secret_data)
}
