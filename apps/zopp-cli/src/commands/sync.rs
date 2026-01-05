use crate::crypto::fetch_and_decrypt_secrets;
use crate::grpc::setup_client;
use crate::k8s::load_k8s_config;
use k8s_openapi::api::core::v1::Secret;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use kube::{api::PostParams, Api, Client};
use std::collections::BTreeMap;

#[allow(clippy::too_many_arguments)]
pub async fn cmd_sync_k8s(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    workspace_name: &str,
    project_name: &str,
    environment_name: &str,
    namespace: &str,
    secret_name: &str,
    kubeconfig_path: Option<&std::path::Path>,
    context: Option<&str>,
    force: bool,
    dry_run: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, principal) = setup_client(server, tls_ca_cert).await?;

    let secret_data = fetch_and_decrypt_secrets(
        &mut client,
        &principal,
        workspace_name,
        project_name,
        environment_name,
    )
    .await?;

    println!("✓ Fetched {} secrets from zopp", secret_data.len());

    let k8s_config = load_k8s_config(kubeconfig_path, context).await?;

    let k8s_client = Client::try_from(k8s_config)?;
    let secrets_api: Api<Secret> = Api::namespaced(k8s_client, namespace);

    match secrets_api.get(secret_name).await {
        Ok(existing_secret) => {
            // Secret exists, check if managed by zopp
            let managed_by = existing_secret
                .metadata
                .labels
                .as_ref()
                .and_then(|labels| labels.get("app.kubernetes.io/managed-by"))
                .map(|s| s.as_str());

            if managed_by != Some("zopp") && !force {
                return Err(format!(
                    "Secret '{}' in namespace '{}' exists but is not managed by zopp. Use --force to take ownership.",
                    secret_name, namespace
                )
                .into());
            }

            println!("✓ Secret exists, updating...");
        }
        Err(kube::Error::Api(api_err)) if api_err.code == 404 => {
            println!("✓ Secret does not exist, will create...");
        }
        Err(e) => return Err(e.into()),
    }

    let synced_at = chrono::Utc::now().to_rfc3339();
    let mut labels = BTreeMap::new();
    labels.insert(
        "app.kubernetes.io/managed-by".to_string(),
        "zopp".to_string(),
    );

    let mut annotations = BTreeMap::new();
    annotations.insert("zopp.dev/workspace".to_string(), workspace_name.to_string());
    annotations.insert("zopp.dev/project".to_string(), project_name.to_string());
    annotations.insert(
        "zopp.dev/environment".to_string(),
        environment_name.to_string(),
    );
    annotations.insert("zopp.dev/synced-at".to_string(), synced_at.clone());
    annotations.insert("zopp.dev/synced-by".to_string(), principal.id.clone());

    let secret = Secret {
        metadata: ObjectMeta {
            name: Some(secret_name.to_string()),
            namespace: Some(namespace.to_string()),
            labels: Some(labels),
            annotations: Some(annotations),
            ..Default::default()
        },
        string_data: Some(secret_data),
        ..Default::default()
    };

    if dry_run {
        println!("\n🔍 Dry run - showing what would be synced:\n");

        match secrets_api.get(secret_name).await {
            Ok(existing) => {
                println!(
                    "Would UPDATE existing Secret '{}/{}':",
                    namespace, secret_name
                );

                let existing_data = existing.data.as_ref();
                let new_data = secret.string_data.as_ref().unwrap();

                // Show changes
                for (key, new_value) in new_data {
                    if let Some(existing_data_map) = existing_data {
                        if let Some(existing_value) = existing_data_map.get(key) {
                            let existing_str = String::from_utf8_lossy(&existing_value.0);
                            if existing_str != *new_value {
                                println!("  ~ {} (changed)", key);
                            } else {
                                println!("  = {} (unchanged)", key);
                            }
                        } else {
                            println!("  + {} (new)", key);
                        }
                    } else {
                        println!("  + {} (new)", key);
                    }
                }

                // Show deletions
                if let Some(existing_data_map) = existing_data {
                    for key in existing_data_map.keys() {
                        if !new_data.contains_key(key) {
                            println!("  - {} (would be removed)", key);
                        }
                    }
                }
            }
            Err(_) => {
                println!("Would CREATE new Secret '{}/{}':", namespace, secret_name);
                for key in secret.string_data.as_ref().unwrap().keys() {
                    println!("  + {}", key);
                }
            }
        }

        println!("\nNo changes applied (dry run)");
    } else {
        match secrets_api.get(secret_name).await {
            Ok(_) => {
                // Update existing
                secrets_api
                    .replace(secret_name, &PostParams::default(), &secret)
                    .await?;
                println!(
                    "✓ Updated Secret '{}/{}' with {} secrets",
                    namespace,
                    secret_name,
                    secret.string_data.as_ref().unwrap().len()
                );
            }
            Err(_) => {
                // Create new
                secrets_api.create(&PostParams::default(), &secret).await?;
                println!(
                    "✓ Created Secret '{}/{}' with {} secrets",
                    namespace,
                    secret_name,
                    secret.string_data.as_ref().unwrap().len()
                );
            }
        }

        println!("✓ Synced at: {}", synced_at);
    }

    Ok(())
}
