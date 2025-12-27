use crate::config::{get_current_principal, load_config};
use crate::grpc::sign_request;
use tonic::metadata::MetadataValue;
use zopp_proto::zopp_service_client::ZoppServiceClient;

pub async fn cmd_project_list(
    server: &str,
    workspace_name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = load_config()?;
    let principal = get_current_principal(&config)?;

    let mut client = ZoppServiceClient::connect(server.to_string()).await?;

    let (timestamp, signature) = sign_request(&principal.private_key)?;

    let mut request = tonic::Request::new(zopp_proto::ListProjectsRequest {
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

    let response = client.list_projects(request).await?.into_inner();

    if response.projects.is_empty() {
        println!("No projects found");
    } else {
        println!("Projects:");
        for project in response.projects {
            println!("  {}", project.name);
        }
    }

    Ok(())
}

pub async fn cmd_project_create(
    server: &str,
    workspace_name: &str,
    name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = load_config()?;
    let principal = get_current_principal(&config)?;

    let mut client = ZoppServiceClient::connect(server.to_string()).await?;

    let (timestamp, signature) = sign_request(&principal.private_key)?;

    let mut request = tonic::Request::new(zopp_proto::CreateProjectRequest {
        workspace_name: workspace_name.to_string(),
        name: name.to_string(),
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

    let response = client.create_project(request).await?.into_inner();

    println!(
        "✓ Project '{}' created (ID: {})",
        response.name, response.id
    );

    Ok(())
}

pub async fn cmd_project_get(
    server: &str,
    workspace_name: &str,
    project_name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = load_config()?;
    let principal = get_current_principal(&config)?;

    let mut client = ZoppServiceClient::connect(server.to_string()).await?;

    let (timestamp, signature) = sign_request(&principal.private_key)?;

    let mut request = tonic::Request::new(zopp_proto::GetProjectRequest {
        workspace_name: workspace_name.to_string(),
        project_name: project_name.to_string(),
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

    let response = client.get_project(request).await?.into_inner();

    println!("Project: {}", response.name);
    println!("  ID: {}", response.id);
    println!("  Workspace ID: {}", response.workspace_id);
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

pub async fn cmd_project_delete(
    server: &str,
    workspace_name: &str,
    project_name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = load_config()?;
    let principal = get_current_principal(&config)?;

    let mut client = ZoppServiceClient::connect(server.to_string()).await?;

    let (timestamp, signature) = sign_request(&principal.private_key)?;

    let mut request = tonic::Request::new(zopp_proto::DeleteProjectRequest {
        workspace_name: workspace_name.to_string(),
        project_name: project_name.to_string(),
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

    client.delete_project(request).await?;

    println!("✓ Project '{}' deleted", project_name);

    Ok(())
}
