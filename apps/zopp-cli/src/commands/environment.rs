use crate::crypto::unwrap_workspace_kek;
use crate::grpc::{add_auth_metadata, setup_client};

pub async fn cmd_environment_list(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    workspace_name: &str,
    project_name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, principal) = setup_client(server, tls_ca_cert).await?;

    let mut request = tonic::Request::new(zopp_proto::ListEnvironmentsRequest {
        workspace_name: workspace_name.to_string(),
        project_name: project_name.to_string(),
    });
    add_auth_metadata(&mut request, &principal)?;

    let response = client.list_environments(request).await?.into_inner();

    if response.environments.is_empty() {
        println!("No environments found");
    } else {
        println!("Environments:");
        for env in response.environments {
            println!("  {}", env.name);
        }
    }

    Ok(())
}

pub async fn cmd_environment_create(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    workspace_name: &str,
    project_name: &str,
    name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, principal) = setup_client(server, tls_ca_cert).await?;

    let kek = unwrap_workspace_kek(&mut client, &principal, workspace_name).await?;
    let dek = zopp_crypto::generate_dek();

    let kek_key = zopp_crypto::Dek::from_bytes(&kek)?;
    let aad = format!("environment:{}:{}:{}", workspace_name, project_name, name).into_bytes();
    let (dek_nonce, dek_wrapped) = zopp_crypto::encrypt(dek.as_bytes(), &kek_key, &aad)?;

    let mut request = tonic::Request::new(zopp_proto::CreateEnvironmentRequest {
        workspace_name: workspace_name.to_string(),
        project_name: project_name.to_string(),
        name: name.to_string(),
        dek_wrapped: dek_wrapped.0,
        dek_nonce: dek_nonce.0.to_vec(),
    });
    add_auth_metadata(&mut request, &principal)?;

    let response = client.create_environment(request).await?.into_inner();

    println!(
        "✓ Environment '{}' created (ID: {})",
        response.name, response.id
    );

    Ok(())
}

pub async fn cmd_environment_get(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    workspace_name: &str,
    project_name: &str,
    environment_name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, principal) = setup_client(server, tls_ca_cert).await?;

    let mut request = tonic::Request::new(zopp_proto::GetEnvironmentRequest {
        workspace_name: workspace_name.to_string(),
        project_name: project_name.to_string(),
        environment_name: environment_name.to_string(),
    });
    add_auth_metadata(&mut request, &principal)?;

    let response = client.get_environment(request).await?.into_inner();

    println!("Environment: {}", response.name);
    println!("  ID: {}", response.id);
    println!("  Project ID: {}", response.project_id);
    println!("  DEK Wrapped: {}", hex::encode(&response.dek_wrapped));
    println!("  DEK Nonce: {}", hex::encode(&response.dek_nonce));
    println!(
        "  Created: {}",
        chrono::DateTime::from_timestamp(response.created_at, 0)
            .map(|dt| dt.to_rfc3339())
            .unwrap_or_else(|| "Unknown".to_string())
    );
    println!(
        "  Updated: {}",
        chrono::DateTime::from_timestamp(response.updated_at, 0)
            .map(|dt| dt.to_rfc3339())
            .unwrap_or_else(|| "Unknown".to_string())
    );

    Ok(())
}

pub async fn cmd_environment_delete(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    workspace_name: &str,
    project_name: &str,
    environment_name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, principal) = setup_client(server, tls_ca_cert).await?;

    let mut request = tonic::Request::new(zopp_proto::DeleteEnvironmentRequest {
        workspace_name: workspace_name.to_string(),
        project_name: project_name.to_string(),
        environment_name: environment_name.to_string(),
    });
    add_auth_metadata(&mut request, &principal)?;

    client.delete_environment(request).await?;

    println!("✓ Environment '{}' deleted", environment_name);

    Ok(())
}
