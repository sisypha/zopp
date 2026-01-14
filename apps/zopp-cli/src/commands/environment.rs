use crate::config::PrincipalConfig;
use crate::crypto::unwrap_workspace_kek;
use crate::grpc::{add_auth_metadata, setup_client};

#[cfg(test)]
use crate::client::MockEnvironmentClient;
#[cfg(test)]
use zopp_proto::Environment;

use zopp_proto::{EnvironmentList, ListEnvironmentsRequest};

/// Inner implementation for environment list that accepts a trait-bounded client.
pub async fn environment_list_inner<C>(
    client: &mut C,
    principal: &PrincipalConfig,
    workspace_name: &str,
    project_name: &str,
) -> Result<EnvironmentList, Box<dyn std::error::Error>>
where
    C: crate::client::EnvironmentClient,
{
    let mut request = tonic::Request::new(ListEnvironmentsRequest {
        workspace_name: workspace_name.to_string(),
        project_name: project_name.to_string(),
    });
    add_auth_metadata(
        &mut request,
        principal,
        "/zopp.ZoppService/ListEnvironments",
    )?;

    let response = client.list_environments(request).await?.into_inner();
    Ok(response)
}

/// Print environment list results.
pub fn print_environment_list(environments: &EnvironmentList) {
    if environments.environments.is_empty() {
        println!("No environments found");
    } else {
        println!("Environments:");
        for env in &environments.environments {
            println!("  {}", env.name);
        }
    }
}

/// Inner implementation for environment get that accepts a trait-bounded client.
pub async fn environment_get_inner<C>(
    client: &mut C,
    principal: &PrincipalConfig,
    workspace_name: &str,
    project_name: &str,
    environment_name: &str,
) -> Result<zopp_proto::Environment, Box<dyn std::error::Error>>
where
    C: crate::client::EnvironmentClient,
{
    let mut request = tonic::Request::new(zopp_proto::GetEnvironmentRequest {
        workspace_name: workspace_name.to_string(),
        project_name: project_name.to_string(),
        environment_name: environment_name.to_string(),
    });
    add_auth_metadata(&mut request, principal, "/zopp.ZoppService/GetEnvironment")?;

    let response = client.get_environment(request).await?.into_inner();
    Ok(response)
}

/// Print environment details.
pub fn print_environment_details(env: &zopp_proto::Environment) {
    println!("Environment: {}", env.name);
    println!("  ID: {}", env.id);
    println!("  Project ID: {}", env.project_id);
    println!("  DEK Wrapped: {}", hex::encode(&env.dek_wrapped));
    println!("  DEK Nonce: {}", hex::encode(&env.dek_nonce));
    println!(
        "  Created: {}",
        chrono::DateTime::from_timestamp(env.created_at, 0)
            .map(|dt| dt.to_rfc3339())
            .unwrap_or_else(|| "Unknown".to_string())
    );
    println!(
        "  Updated: {}",
        chrono::DateTime::from_timestamp(env.updated_at, 0)
            .map(|dt| dt.to_rfc3339())
            .unwrap_or_else(|| "Unknown".to_string())
    );
}

/// Inner implementation for environment delete that accepts a trait-bounded client.
pub async fn environment_delete_inner<C>(
    client: &mut C,
    principal: &PrincipalConfig,
    workspace_name: &str,
    project_name: &str,
    environment_name: &str,
) -> Result<(), Box<dyn std::error::Error>>
where
    C: crate::client::EnvironmentClient,
{
    let mut request = tonic::Request::new(zopp_proto::DeleteEnvironmentRequest {
        workspace_name: workspace_name.to_string(),
        project_name: project_name.to_string(),
        environment_name: environment_name.to_string(),
    });
    add_auth_metadata(
        &mut request,
        principal,
        "/zopp.ZoppService/DeleteEnvironment",
    )?;

    client.delete_environment(request).await?;
    Ok(())
}

pub async fn cmd_environment_list(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    workspace_name: &str,
    project_name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, principal) = setup_client(server, tls_ca_cert).await?;
    let environments =
        environment_list_inner(&mut client, &principal, workspace_name, project_name).await?;
    print_environment_list(&environments);
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
    add_auth_metadata(
        &mut request,
        &principal,
        "/zopp.ZoppService/CreateEnvironment",
    )?;

    let response = client.create_environment(request).await?.into_inner();

    println!(
        "Environment '{}' created (ID: {})",
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

    let env = environment_get_inner(
        &mut client,
        &principal,
        workspace_name,
        project_name,
        environment_name,
    )
    .await?;
    print_environment_details(&env);

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

    environment_delete_inner(
        &mut client,
        &principal,
        workspace_name,
        project_name,
        environment_name,
    )
    .await?;

    println!("Environment '{}' deleted", environment_name);

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
    async fn test_environment_list_inner_success() {
        let mut mock = MockEnvironmentClient::new();

        mock.expect_list_environments().returning(|_| {
            Ok(Response::new(EnvironmentList {
                environments: vec![
                    Environment {
                        id: "env-1".to_string(),
                        project_id: "proj-1".to_string(),
                        name: "development".to_string(),
                        dek_wrapped: vec![],
                        dek_nonce: vec![],
                        created_at: 0,
                        updated_at: 0,
                    },
                    Environment {
                        id: "env-2".to_string(),
                        project_id: "proj-1".to_string(),
                        name: "production".to_string(),
                        dek_wrapped: vec![],
                        dek_nonce: vec![],
                        created_at: 0,
                        updated_at: 0,
                    },
                ],
            }))
        });

        let principal = create_test_principal();
        let result =
            environment_list_inner(&mut mock, &principal, "my-workspace", "my-project").await;

        assert!(result.is_ok());
        let environments = result.unwrap();
        assert_eq!(environments.environments.len(), 2);
        assert_eq!(environments.environments[0].name, "development");
        assert_eq!(environments.environments[1].name, "production");
    }

    #[tokio::test]
    async fn test_environment_list_inner_empty() {
        let mut mock = MockEnvironmentClient::new();

        mock.expect_list_environments().returning(|_| {
            Ok(Response::new(EnvironmentList {
                environments: vec![],
            }))
        });

        let principal = create_test_principal();
        let result =
            environment_list_inner(&mut mock, &principal, "my-workspace", "my-project").await;

        assert!(result.is_ok());
        let environments = result.unwrap();
        assert!(environments.environments.is_empty());
    }

    #[tokio::test]
    async fn test_environment_list_inner_workspace_not_found() {
        let mut mock = MockEnvironmentClient::new();

        mock.expect_list_environments()
            .returning(|_| Err(Status::not_found("Workspace not found")));

        let principal = create_test_principal();
        let result =
            environment_list_inner(&mut mock, &principal, "nonexistent", "my-project").await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_environment_list_inner_project_not_found() {
        let mut mock = MockEnvironmentClient::new();

        mock.expect_list_environments()
            .returning(|_| Err(Status::not_found("Project not found")));

        let principal = create_test_principal();
        let result =
            environment_list_inner(&mut mock, &principal, "my-workspace", "nonexistent").await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_environment_list_inner_permission_denied() {
        let mut mock = MockEnvironmentClient::new();

        mock.expect_list_environments()
            .returning(|_| Err(Status::permission_denied("Not authorized")));

        let principal = create_test_principal();
        let result =
            environment_list_inner(&mut mock, &principal, "my-workspace", "my-project").await;

        assert!(result.is_err());
    }

    #[test]
    fn test_print_environment_list_empty() {
        let environments = EnvironmentList {
            environments: vec![],
        };
        print_environment_list(&environments);
    }

    #[test]
    fn test_print_environment_list_with_items() {
        let environments = EnvironmentList {
            environments: vec![
                Environment {
                    id: "1".to_string(),
                    project_id: "proj-1".to_string(),
                    name: "dev".to_string(),
                    dek_wrapped: vec![],
                    dek_nonce: vec![],
                    created_at: 0,
                    updated_at: 0,
                },
                Environment {
                    id: "2".to_string(),
                    project_id: "proj-1".to_string(),
                    name: "prod".to_string(),
                    dek_wrapped: vec![],
                    dek_nonce: vec![],
                    created_at: 0,
                    updated_at: 0,
                },
            ],
        };
        print_environment_list(&environments);
    }

    #[tokio::test]
    async fn test_environment_get_inner_success() {
        let mut mock = MockEnvironmentClient::new();

        mock.expect_get_environment().returning(|_| {
            Ok(Response::new(Environment {
                id: "env-id".to_string(),
                project_id: "proj-1".to_string(),
                name: "development".to_string(),
                dek_wrapped: vec![1, 2, 3],
                dek_nonce: vec![4, 5, 6],
                created_at: 1704067200, // 2024-01-01 00:00:00 UTC
                updated_at: 1704067200,
            }))
        });

        let principal = create_test_principal();
        let result = environment_get_inner(
            &mut mock,
            &principal,
            "my-workspace",
            "my-project",
            "development",
        )
        .await;

        assert!(result.is_ok());
        let env = result.unwrap();
        assert_eq!(env.name, "development");
        assert_eq!(env.id, "env-id");
    }

    #[tokio::test]
    async fn test_environment_get_inner_not_found() {
        let mut mock = MockEnvironmentClient::new();

        mock.expect_get_environment()
            .returning(|_| Err(Status::not_found("Environment not found")));

        let principal = create_test_principal();
        let result = environment_get_inner(
            &mut mock,
            &principal,
            "my-workspace",
            "my-project",
            "nonexistent",
        )
        .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_environment_get_inner_permission_denied() {
        let mut mock = MockEnvironmentClient::new();

        mock.expect_get_environment()
            .returning(|_| Err(Status::permission_denied("Not authorized")));

        let principal = create_test_principal();
        let result = environment_get_inner(
            &mut mock,
            &principal,
            "my-workspace",
            "my-project",
            "development",
        )
        .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_environment_delete_inner_success() {
        let mut mock = MockEnvironmentClient::new();

        mock.expect_delete_environment()
            .returning(|_| Ok(Response::new(zopp_proto::Empty {})));

        let principal = create_test_principal();
        let result = environment_delete_inner(
            &mut mock,
            &principal,
            "my-workspace",
            "my-project",
            "env-to-delete",
        )
        .await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_environment_delete_inner_not_found() {
        let mut mock = MockEnvironmentClient::new();

        mock.expect_delete_environment()
            .returning(|_| Err(Status::not_found("Environment not found")));

        let principal = create_test_principal();
        let result = environment_delete_inner(
            &mut mock,
            &principal,
            "my-workspace",
            "my-project",
            "nonexistent",
        )
        .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_environment_delete_inner_permission_denied() {
        let mut mock = MockEnvironmentClient::new();

        mock.expect_delete_environment()
            .returning(|_| Err(Status::permission_denied("Not authorized")));

        let principal = create_test_principal();
        let result = environment_delete_inner(
            &mut mock,
            &principal,
            "my-workspace",
            "my-project",
            "some-env",
        )
        .await;

        assert!(result.is_err());
    }

    #[test]
    fn test_print_environment_details() {
        let env = Environment {
            id: "env-id".to_string(),
            project_id: "proj-1".to_string(),
            name: "development".to_string(),
            dek_wrapped: vec![1, 2, 3],
            dek_nonce: vec![4, 5, 6],
            created_at: 1704067200, // 2024-01-01 00:00:00 UTC
            updated_at: 1704067200,
        };
        print_environment_details(&env);
    }

    #[test]
    fn test_print_environment_details_unknown_timestamps() {
        let env = Environment {
            id: "env-id".to_string(),
            project_id: "proj-1".to_string(),
            name: "development".to_string(),
            dek_wrapped: vec![],
            dek_nonce: vec![],
            created_at: 0,
            updated_at: 0,
        };
        print_environment_details(&env);
    }
}
