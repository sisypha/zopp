use crate::config::PrincipalConfig;
use crate::grpc::{add_auth_metadata, setup_client};

#[cfg(test)]
use crate::client::MockProjectClient;

use zopp_proto::{CreateProjectRequest, ListProjectsRequest, Project, ProjectList};

/// Inner implementation for project list that accepts a trait-bounded client.
pub async fn project_list_inner<C>(
    client: &mut C,
    principal: &PrincipalConfig,
    workspace_name: &str,
) -> Result<ProjectList, Box<dyn std::error::Error>>
where
    C: crate::client::ProjectClient,
{
    let mut request = tonic::Request::new(ListProjectsRequest {
        workspace_name: workspace_name.to_string(),
    });
    add_auth_metadata(&mut request, principal, "/zopp.ZoppService/ListProjects")?;

    let response = client.list_projects(request).await?.into_inner();
    Ok(response)
}

/// Print project list results.
pub fn print_project_list(projects: &ProjectList) {
    if projects.projects.is_empty() {
        println!("No projects found");
    } else {
        println!("Projects:");
        for project in &projects.projects {
            println!("  {}", project.name);
        }
    }
}

pub async fn cmd_project_list(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    workspace_name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, principal) = setup_client(server, tls_ca_cert).await?;
    let projects = project_list_inner(&mut client, &principal, workspace_name).await?;
    print_project_list(&projects);
    Ok(())
}

/// Inner implementation for project create that accepts a trait-bounded client.
pub async fn project_create_inner<C>(
    client: &mut C,
    principal: &PrincipalConfig,
    workspace_name: &str,
    name: &str,
) -> Result<Project, Box<dyn std::error::Error>>
where
    C: crate::client::ProjectClient,
{
    let mut request = tonic::Request::new(CreateProjectRequest {
        workspace_name: workspace_name.to_string(),
        name: name.to_string(),
    });
    add_auth_metadata(&mut request, principal, "/zopp.ZoppService/CreateProject")?;

    let response = client.create_project(request).await?.into_inner();
    Ok(response)
}

pub async fn cmd_project_create(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    workspace_name: &str,
    name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, principal) = setup_client(server, tls_ca_cert).await?;
    let project = project_create_inner(&mut client, &principal, workspace_name, name).await?;
    println!("Project '{}' created (ID: {})", project.name, project.id);
    Ok(())
}

/// Inner implementation for project get that accepts a trait-bounded client.
pub async fn project_get_inner<C>(
    client: &mut C,
    principal: &PrincipalConfig,
    workspace_name: &str,
    project_name: &str,
) -> Result<Project, Box<dyn std::error::Error>>
where
    C: crate::client::ProjectClient,
{
    let mut request = tonic::Request::new(zopp_proto::GetProjectRequest {
        workspace_name: workspace_name.to_string(),
        project_name: project_name.to_string(),
    });
    add_auth_metadata(&mut request, principal, "/zopp.ZoppService/GetProject")?;

    let response = client.get_project(request).await?.into_inner();
    Ok(response)
}

/// Print project details.
pub fn print_project_details(project: &Project) {
    println!("Project: {}", project.name);
    println!("  ID: {}", project.id);
    println!("  Workspace ID: {}", project.workspace_id);
    println!(
        "  Created: {}",
        chrono::DateTime::from_timestamp(project.created_at, 0)
            .map(|dt| dt.to_rfc3339())
            .unwrap_or_else(|| "Unknown".to_string())
    );
    println!(
        "  Updated: {}",
        chrono::DateTime::from_timestamp(project.updated_at, 0)
            .map(|dt| dt.to_rfc3339())
            .unwrap_or_else(|| "Unknown".to_string())
    );
}

/// Inner implementation for project delete that accepts a trait-bounded client.
pub async fn project_delete_inner<C>(
    client: &mut C,
    principal: &PrincipalConfig,
    workspace_name: &str,
    project_name: &str,
) -> Result<(), Box<dyn std::error::Error>>
where
    C: crate::client::ProjectClient,
{
    let mut request = tonic::Request::new(zopp_proto::DeleteProjectRequest {
        workspace_name: workspace_name.to_string(),
        project_name: project_name.to_string(),
    });
    add_auth_metadata(&mut request, principal, "/zopp.ZoppService/DeleteProject")?;

    client.delete_project(request).await?;
    Ok(())
}

pub async fn cmd_project_get(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    workspace_name: &str,
    project_name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, principal) = setup_client(server, tls_ca_cert).await?;

    let project =
        project_get_inner(&mut client, &principal, workspace_name, project_name).await?;
    print_project_details(&project);

    Ok(())
}

pub async fn cmd_project_delete(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    workspace_name: &str,
    project_name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, principal) = setup_client(server, tls_ca_cert).await?;

    project_delete_inner(&mut client, &principal, workspace_name, project_name).await?;

    println!("Project '{}' deleted", project_name);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tonic::{Response, Status};

    fn create_test_principal() -> PrincipalConfig {
        PrincipalConfig {
            id: "test-principal-id".to_string(),
            name: "test-principal".to_string(),
            private_key: "0".repeat(64),
            public_key: "1".repeat(64),
            x25519_private_key: Some("2".repeat(64)),
            x25519_public_key: Some("3".repeat(64)),
        }
    }

    #[tokio::test]
    async fn test_project_list_inner_success() {
        let mut mock = MockProjectClient::new();

        mock.expect_list_projects().returning(|_| {
            Ok(Response::new(ProjectList {
                projects: vec![
                    Project {
                        id: "proj-1".to_string(),
                        workspace_id: "ws-1".to_string(),
                        name: "project-one".to_string(),
                        created_at: 0,
                        updated_at: 0,
                    },
                    Project {
                        id: "proj-2".to_string(),
                        workspace_id: "ws-1".to_string(),
                        name: "project-two".to_string(),
                        created_at: 0,
                        updated_at: 0,
                    },
                ],
            }))
        });

        let principal = create_test_principal();
        let result = project_list_inner(&mut mock, &principal, "my-workspace").await;

        assert!(result.is_ok());
        let projects = result.unwrap();
        assert_eq!(projects.projects.len(), 2);
        assert_eq!(projects.projects[0].name, "project-one");
        assert_eq!(projects.projects[1].name, "project-two");
    }

    #[tokio::test]
    async fn test_project_list_inner_empty() {
        let mut mock = MockProjectClient::new();

        mock.expect_list_projects()
            .returning(|_| Ok(Response::new(ProjectList { projects: vec![] })));

        let principal = create_test_principal();
        let result = project_list_inner(&mut mock, &principal, "my-workspace").await;

        assert!(result.is_ok());
        let projects = result.unwrap();
        assert!(projects.projects.is_empty());
    }

    #[tokio::test]
    async fn test_project_list_inner_not_found() {
        let mut mock = MockProjectClient::new();

        mock.expect_list_projects()
            .returning(|_| Err(Status::not_found("Workspace not found")));

        let principal = create_test_principal();
        let result = project_list_inner(&mut mock, &principal, "nonexistent").await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_project_create_inner_success() {
        let mut mock = MockProjectClient::new();

        mock.expect_create_project().returning(|_| {
            Ok(Response::new(Project {
                id: "new-proj-id".to_string(),
                workspace_id: "ws-1".to_string(),
                name: "new-project".to_string(),
                created_at: 1234567890,
                updated_at: 1234567890,
            }))
        });

        let principal = create_test_principal();
        let result =
            project_create_inner(&mut mock, &principal, "my-workspace", "new-project").await;

        assert!(result.is_ok());
        let project = result.unwrap();
        assert_eq!(project.name, "new-project");
        assert_eq!(project.id, "new-proj-id");
    }

    #[tokio::test]
    async fn test_project_create_inner_permission_denied() {
        let mut mock = MockProjectClient::new();

        mock.expect_create_project()
            .returning(|_| Err(Status::permission_denied("Not authorized")));

        let principal = create_test_principal();
        let result =
            project_create_inner(&mut mock, &principal, "my-workspace", "new-project").await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_project_create_inner_already_exists() {
        let mut mock = MockProjectClient::new();

        mock.expect_create_project()
            .returning(|_| Err(Status::already_exists("Project already exists")));

        let principal = create_test_principal();
        let result =
            project_create_inner(&mut mock, &principal, "my-workspace", "existing-project").await;

        assert!(result.is_err());
    }

    #[test]
    fn test_print_project_list_empty() {
        let projects = ProjectList { projects: vec![] };
        print_project_list(&projects);
    }

    #[test]
    fn test_print_project_list_with_items() {
        let projects = ProjectList {
            projects: vec![
                Project {
                    id: "1".to_string(),
                    workspace_id: "ws-1".to_string(),
                    name: "first-project".to_string(),
                    created_at: 0,
                    updated_at: 0,
                },
                Project {
                    id: "2".to_string(),
                    workspace_id: "ws-1".to_string(),
                    name: "second-project".to_string(),
                    created_at: 0,
                    updated_at: 0,
                },
            ],
        };
        print_project_list(&projects);
    }

    #[tokio::test]
    async fn test_project_get_inner_success() {
        let mut mock = MockProjectClient::new();

        mock.expect_get_project().returning(|_| {
            Ok(Response::new(Project {
                id: "proj-id".to_string(),
                workspace_id: "ws-1".to_string(),
                name: "my-project".to_string(),
                created_at: 1704067200, // 2024-01-01 00:00:00 UTC
                updated_at: 1704067200,
            }))
        });

        let principal = create_test_principal();
        let result =
            project_get_inner(&mut mock, &principal, "my-workspace", "my-project").await;

        assert!(result.is_ok());
        let project = result.unwrap();
        assert_eq!(project.name, "my-project");
        assert_eq!(project.id, "proj-id");
    }

    #[tokio::test]
    async fn test_project_get_inner_not_found() {
        let mut mock = MockProjectClient::new();

        mock.expect_get_project()
            .returning(|_| Err(Status::not_found("Project not found")));

        let principal = create_test_principal();
        let result =
            project_get_inner(&mut mock, &principal, "my-workspace", "nonexistent").await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_project_get_inner_permission_denied() {
        let mut mock = MockProjectClient::new();

        mock.expect_get_project()
            .returning(|_| Err(Status::permission_denied("Not authorized")));

        let principal = create_test_principal();
        let result =
            project_get_inner(&mut mock, &principal, "my-workspace", "my-project").await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_project_delete_inner_success() {
        let mut mock = MockProjectClient::new();

        mock.expect_delete_project()
            .returning(|_| Ok(Response::new(zopp_proto::Empty {})));

        let principal = create_test_principal();
        let result =
            project_delete_inner(&mut mock, &principal, "my-workspace", "project-to-delete").await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_project_delete_inner_not_found() {
        let mut mock = MockProjectClient::new();

        mock.expect_delete_project()
            .returning(|_| Err(Status::not_found("Project not found")));

        let principal = create_test_principal();
        let result =
            project_delete_inner(&mut mock, &principal, "my-workspace", "nonexistent").await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_project_delete_inner_permission_denied() {
        let mut mock = MockProjectClient::new();

        mock.expect_delete_project()
            .returning(|_| Err(Status::permission_denied("Not authorized")));

        let principal = create_test_principal();
        let result =
            project_delete_inner(&mut mock, &principal, "my-workspace", "some-project").await;

        assert!(result.is_err());
    }

    #[test]
    fn test_print_project_details() {
        let project = Project {
            id: "proj-id".to_string(),
            workspace_id: "ws-1".to_string(),
            name: "my-project".to_string(),
            created_at: 1704067200, // 2024-01-01 00:00:00 UTC
            updated_at: 1704067200,
        };
        print_project_details(&project);
    }

    #[test]
    fn test_print_project_details_unknown_timestamps() {
        let project = Project {
            id: "proj-id".to_string(),
            workspace_id: "ws-1".to_string(),
            name: "my-project".to_string(),
            created_at: 0,
            updated_at: 0,
        };
        print_project_details(&project);
    }
}
