use crate::grpc::{add_auth_metadata, setup_client};

pub async fn cmd_project_list(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    workspace_name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, principal) = setup_client(server, tls_ca_cert).await?;

    let mut request = tonic::Request::new(zopp_proto::ListProjectsRequest {
        workspace_name: workspace_name.to_string(),
    });
    add_auth_metadata(&mut request, &principal, "/zopp.ZoppService/ListProjects")?;

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
    tls_ca_cert: Option<&std::path::Path>,
    workspace_name: &str,
    name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, principal) = setup_client(server, tls_ca_cert).await?;

    let mut request = tonic::Request::new(zopp_proto::CreateProjectRequest {
        workspace_name: workspace_name.to_string(),
        name: name.to_string(),
    });
    add_auth_metadata(&mut request, &principal, "/zopp.ZoppService/CreateProject")?;

    let response = client.create_project(request).await?.into_inner();

    println!(
        "Project '{}' created (ID: {})",
        response.name, response.id
    );

    Ok(())
}

pub async fn cmd_project_get(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    workspace_name: &str,
    project_name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, principal) = setup_client(server, tls_ca_cert).await?;

    let mut request = tonic::Request::new(zopp_proto::GetProjectRequest {
        workspace_name: workspace_name.to_string(),
        project_name: project_name.to_string(),
    });
    add_auth_metadata(&mut request, &principal, "/zopp.ZoppService/GetProject")?;

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
    tls_ca_cert: Option<&std::path::Path>,
    workspace_name: &str,
    project_name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, principal) = setup_client(server, tls_ca_cert).await?;

    let mut request = tonic::Request::new(zopp_proto::DeleteProjectRequest {
        workspace_name: workspace_name.to_string(),
        project_name: project_name.to_string(),
    });
    add_auth_metadata(&mut request, &principal, "/zopp.ZoppService/DeleteProject")?;

    client.delete_project(request).await?;

    println!("Project '{}' deleted", project_name);

    Ok(())
}
