use crate::config::{get_current_principal, load_config};
use crate::crypto::{unwrap_environment_dek, unwrap_workspace_kek};
use crate::grpc::sign_request;
use k8s_openapi::api::core::v1::Secret;
use kube::{Api, Client, Config};
use std::collections::BTreeMap;
use tonic::metadata::MetadataValue;
use zopp_proto::zopp_service_client::ZoppServiceClient;

#[allow(clippy::too_many_arguments)]
pub async fn cmd_diff_k8s(
    server: &str,
    workspace_name: &str,
    project_name: &str,
    environment_name: &str,
    namespace: &str,
    secret_name: &str,
    kubeconfig_path: Option<&std::path::Path>,
    context: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    // 1. Fetch all secrets from zopp
    let config = load_config()?;
    let principal = get_current_principal(&config)?;
    let mut client = ZoppServiceClient::connect(server.to_string()).await?;

    // Unwrap KEK and DEK
    let kek = unwrap_workspace_kek(&mut client, principal, workspace_name).await?;
    let dek_bytes = unwrap_environment_dek(
        &mut client,
        principal,
        workspace_name,
        project_name,
        environment_name,
        &kek,
    )
    .await?;
    let dek = zopp_crypto::Dek::from_bytes(&dek_bytes)?;

    // List all secrets
    let (timestamp, signature) = sign_request(&principal.private_key)?;
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
    let mut zopp_secrets = BTreeMap::new();
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

        zopp_secrets.insert(secret.key.clone(), plaintext_str);
    }

    // 2. Connect to Kubernetes and fetch existing Secret
    let k8s_config = if kubeconfig_path.is_some() {
        Config::from_kubeconfig(&kube::config::KubeConfigOptions {
            context: context.map(String::from),
            ..Default::default()
        })
        .await?
    } else {
        match Config::from_kubeconfig(&kube::config::KubeConfigOptions {
            context: context.map(String::from),
            ..Default::default()
        })
        .await
        {
            Ok(cfg) => cfg,
            Err(_) => Config::incluster()?,
        }
    };

    let k8s_client = Client::try_from(k8s_config)?;
    let secrets_api: Api<Secret> = Api::namespaced(k8s_client, namespace);

    // 3. Compare and show diff
    println!(
        "Comparing zopp → k8s Secret '{}/{}':\n",
        namespace, secret_name
    );

    match secrets_api.get(secret_name).await {
        Ok(existing) => {
            let existing_data = existing.data.as_ref();
            let mut has_changes = false;

            // Check for new or changed secrets
            for (key, zopp_value) in &zopp_secrets {
                if let Some(existing_data_map) = existing_data {
                    if let Some(existing_value) = existing_data_map.get(key) {
                        let existing_str = String::from_utf8_lossy(&existing_value.0);
                        if existing_str != *zopp_value {
                            println!("  ~ {} (value differs)", key);
                            has_changes = true;
                        }
                    } else {
                        println!("  + {} (exists in zopp, not in k8s)", key);
                        has_changes = true;
                    }
                } else {
                    println!("  + {} (exists in zopp, not in k8s)", key);
                    has_changes = true;
                }
            }

            // Check for secrets in k8s but not in zopp
            if let Some(existing_data_map) = existing_data {
                for key in existing_data_map.keys() {
                    if !zopp_secrets.contains_key(key) {
                        println!("  - {} (exists in k8s, not in zopp)", key);
                        has_changes = true;
                    }
                }
            }

            if !has_changes {
                println!("  ✓ No differences - secrets are in sync");
            }
        }
        Err(kube::Error::Api(api_err)) if api_err.code == 404 => {
            println!(
                "Secret does not exist in k8s. Would create with {} keys:",
                zopp_secrets.len()
            );
            for key in zopp_secrets.keys() {
                println!("  + {}", key);
            }
        }
        Err(e) => return Err(e.into()),
    }

    Ok(())
}
