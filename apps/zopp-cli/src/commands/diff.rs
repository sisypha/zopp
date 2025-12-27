use crate::crypto::fetch_and_decrypt_secrets;
use crate::grpc::setup_client;
use crate::k8s::load_k8s_config;
use k8s_openapi::api::core::v1::Secret;
use kube::{Api, Client};

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
    let (mut client, principal) = setup_client(server).await?;

    let zopp_secrets = fetch_and_decrypt_secrets(
        &mut client,
        &principal,
        workspace_name,
        project_name,
        environment_name,
    )
    .await?;

    let k8s_config = load_k8s_config(kubeconfig_path, context).await?;

    let k8s_client = Client::try_from(k8s_config)?;
    let secrets_api: Api<Secret> = Api::namespaced(k8s_client, namespace);

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
