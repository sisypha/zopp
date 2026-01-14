//! Client traits for testability.
//!
//! This module provides trait abstractions over the gRPC client to enable
//! unit testing of CLI commands without requiring a real server connection.

use async_trait::async_trait;
use tonic::{Request, Response, Status};
use zopp_proto::{
    CreateEnvironmentRequest, CreateGroupRequest, CreateInviteRequest, CreateProjectRequest,
    CreateWorkspaceRequest, DeleteEnvironmentRequest, DeleteGroupRequest, DeleteProjectRequest,
    DeleteSecretRequest, Empty, Environment, EnvironmentList, GetEnvironmentRequest,
    GetInviteRequest, GetPrincipalRequest, GetProjectRequest, GetSecretRequest,
    GetWorkspaceKeysRequest, Group, GroupList, InviteToken, ListEnvironmentsRequest,
    ListGroupsRequest, ListProjectsRequest, ListSecretsRequest, Principal, Project, ProjectList,
    Secret, SecretList, UpsertSecretRequest, Workspace, WorkspaceKeys, WorkspaceList,
};

#[cfg(test)]
use mockall::automock;

/// Trait for workspace-related operations.
#[cfg_attr(test, automock)]
#[async_trait]
pub trait WorkspaceClient: Send + Sync {
    async fn create_workspace(
        &mut self,
        request: Request<CreateWorkspaceRequest>,
    ) -> Result<Response<Workspace>, Status>;

    async fn list_workspaces(
        &mut self,
        request: Request<Empty>,
    ) -> Result<Response<WorkspaceList>, Status>;

    async fn get_workspace_keys(
        &mut self,
        request: Request<GetWorkspaceKeysRequest>,
    ) -> Result<Response<WorkspaceKeys>, Status>;
}

/// Trait for project-related operations.
#[cfg_attr(test, automock)]
#[async_trait]
pub trait ProjectClient: Send + Sync {
    async fn create_project(
        &mut self,
        request: Request<CreateProjectRequest>,
    ) -> Result<Response<Project>, Status>;

    async fn get_project(
        &mut self,
        request: Request<GetProjectRequest>,
    ) -> Result<Response<Project>, Status>;

    async fn list_projects(
        &mut self,
        request: Request<ListProjectsRequest>,
    ) -> Result<Response<ProjectList>, Status>;

    async fn delete_project(
        &mut self,
        request: Request<DeleteProjectRequest>,
    ) -> Result<Response<Empty>, Status>;
}

/// Trait for environment-related operations.
#[cfg_attr(test, automock)]
#[async_trait]
pub trait EnvironmentClient: Send + Sync {
    async fn create_environment(
        &mut self,
        request: Request<CreateEnvironmentRequest>,
    ) -> Result<Response<Environment>, Status>;

    async fn get_environment(
        &mut self,
        request: Request<GetEnvironmentRequest>,
    ) -> Result<Response<Environment>, Status>;

    async fn list_environments(
        &mut self,
        request: Request<ListEnvironmentsRequest>,
    ) -> Result<Response<EnvironmentList>, Status>;

    async fn delete_environment(
        &mut self,
        request: Request<DeleteEnvironmentRequest>,
    ) -> Result<Response<Empty>, Status>;
}

/// Trait for secret-related operations.
#[cfg_attr(test, automock)]
#[async_trait]
pub trait SecretClient: Send + Sync {
    async fn get_secret(
        &mut self,
        request: Request<GetSecretRequest>,
    ) -> Result<Response<Secret>, Status>;

    async fn upsert_secret(
        &mut self,
        request: Request<UpsertSecretRequest>,
    ) -> Result<Response<Empty>, Status>;

    async fn list_secrets(
        &mut self,
        request: Request<ListSecretsRequest>,
    ) -> Result<Response<SecretList>, Status>;

    async fn delete_secret(
        &mut self,
        request: Request<DeleteSecretRequest>,
    ) -> Result<Response<Empty>, Status>;
}

/// Trait for principal-related operations.
#[cfg_attr(test, automock)]
#[async_trait]
pub trait PrincipalClient: Send + Sync {
    async fn get_principal(
        &mut self,
        request: Request<GetPrincipalRequest>,
    ) -> Result<Response<Principal>, Status>;
}

/// Trait for invite-related operations.
#[cfg_attr(test, automock)]
#[async_trait]
pub trait InviteClient: Send + Sync {
    async fn create_invite(
        &mut self,
        request: Request<CreateInviteRequest>,
    ) -> Result<Response<InviteToken>, Status>;

    async fn get_invite(
        &mut self,
        request: Request<GetInviteRequest>,
    ) -> Result<Response<InviteToken>, Status>;
}

/// Trait for group-related operations.
#[cfg_attr(test, automock)]
#[async_trait]
pub trait GroupClient: Send + Sync {
    async fn create_group(
        &mut self,
        request: Request<CreateGroupRequest>,
    ) -> Result<Response<Group>, Status>;

    async fn list_groups(
        &mut self,
        request: Request<ListGroupsRequest>,
    ) -> Result<Response<GroupList>, Status>;

    async fn delete_group(
        &mut self,
        request: Request<DeleteGroupRequest>,
    ) -> Result<Response<Empty>, Status>;
}

// Implementation for the real gRPC client
use tonic::transport::Channel;
use zopp_proto::zopp_service_client::ZoppServiceClient;

#[async_trait]
impl WorkspaceClient for ZoppServiceClient<Channel> {
    async fn create_workspace(
        &mut self,
        request: Request<CreateWorkspaceRequest>,
    ) -> Result<Response<Workspace>, Status> {
        self.create_workspace(request).await
    }

    async fn list_workspaces(
        &mut self,
        request: Request<Empty>,
    ) -> Result<Response<WorkspaceList>, Status> {
        self.list_workspaces(request).await
    }

    async fn get_workspace_keys(
        &mut self,
        request: Request<GetWorkspaceKeysRequest>,
    ) -> Result<Response<WorkspaceKeys>, Status> {
        self.get_workspace_keys(request).await
    }
}

#[async_trait]
impl ProjectClient for ZoppServiceClient<Channel> {
    async fn create_project(
        &mut self,
        request: Request<CreateProjectRequest>,
    ) -> Result<Response<zopp_proto::Project>, Status> {
        self.create_project(request).await
    }

    async fn get_project(
        &mut self,
        request: Request<GetProjectRequest>,
    ) -> Result<Response<Project>, Status> {
        self.get_project(request).await
    }

    async fn list_projects(
        &mut self,
        request: Request<ListProjectsRequest>,
    ) -> Result<Response<ProjectList>, Status> {
        self.list_projects(request).await
    }

    async fn delete_project(
        &mut self,
        request: Request<DeleteProjectRequest>,
    ) -> Result<Response<Empty>, Status> {
        self.delete_project(request).await
    }
}

#[async_trait]
impl EnvironmentClient for ZoppServiceClient<Channel> {
    async fn create_environment(
        &mut self,
        request: Request<CreateEnvironmentRequest>,
    ) -> Result<Response<Environment>, Status> {
        self.create_environment(request).await
    }

    async fn get_environment(
        &mut self,
        request: Request<GetEnvironmentRequest>,
    ) -> Result<Response<Environment>, Status> {
        self.get_environment(request).await
    }

    async fn list_environments(
        &mut self,
        request: Request<ListEnvironmentsRequest>,
    ) -> Result<Response<EnvironmentList>, Status> {
        self.list_environments(request).await
    }

    async fn delete_environment(
        &mut self,
        request: Request<DeleteEnvironmentRequest>,
    ) -> Result<Response<Empty>, Status> {
        self.delete_environment(request).await
    }
}

#[async_trait]
impl SecretClient for ZoppServiceClient<Channel> {
    async fn get_secret(
        &mut self,
        request: Request<GetSecretRequest>,
    ) -> Result<Response<Secret>, Status> {
        self.get_secret(request).await
    }

    async fn upsert_secret(
        &mut self,
        request: Request<UpsertSecretRequest>,
    ) -> Result<Response<Empty>, Status> {
        self.upsert_secret(request).await
    }

    async fn list_secrets(
        &mut self,
        request: Request<ListSecretsRequest>,
    ) -> Result<Response<SecretList>, Status> {
        self.list_secrets(request).await
    }

    async fn delete_secret(
        &mut self,
        request: Request<DeleteSecretRequest>,
    ) -> Result<Response<Empty>, Status> {
        self.delete_secret(request).await
    }
}

#[async_trait]
impl PrincipalClient for ZoppServiceClient<Channel> {
    async fn get_principal(
        &mut self,
        request: Request<GetPrincipalRequest>,
    ) -> Result<Response<Principal>, Status> {
        self.get_principal(request).await
    }
}

#[async_trait]
impl InviteClient for ZoppServiceClient<Channel> {
    async fn create_invite(
        &mut self,
        request: Request<CreateInviteRequest>,
    ) -> Result<Response<InviteToken>, Status> {
        self.create_invite(request).await
    }

    async fn get_invite(
        &mut self,
        request: Request<GetInviteRequest>,
    ) -> Result<Response<InviteToken>, Status> {
        self.get_invite(request).await
    }
}

#[async_trait]
impl GroupClient for ZoppServiceClient<Channel> {
    async fn create_group(
        &mut self,
        request: Request<CreateGroupRequest>,
    ) -> Result<Response<Group>, Status> {
        self.create_group(request).await
    }

    async fn list_groups(
        &mut self,
        request: Request<ListGroupsRequest>,
    ) -> Result<Response<GroupList>, Status> {
        self.list_groups(request).await
    }

    async fn delete_group(
        &mut self,
        request: Request<DeleteGroupRequest>,
    ) -> Result<Response<Empty>, Status> {
        self.delete_group(request).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_mock_workspace_client() {
        let mut mock = MockWorkspaceClient::new();

        mock.expect_list_workspaces().returning(|_| {
            Ok(Response::new(WorkspaceList {
                workspaces: vec![Workspace {
                    id: "test-id".to_string(),
                    name: "test-workspace".to_string(),
                }],
            }))
        });

        let result = mock.list_workspaces(Request::new(Empty {})).await;
        assert!(result.is_ok());
        let response = result.unwrap().into_inner();
        assert_eq!(response.workspaces.len(), 1);
        assert_eq!(response.workspaces[0].name, "test-workspace");
    }

    #[tokio::test]
    async fn test_mock_secret_client_not_found() {
        let mut mock = MockSecretClient::new();

        mock.expect_get_secret()
            .returning(|_| Err(Status::not_found("Secret not found")));

        let request = Request::new(GetSecretRequest {
            workspace_name: "ws".to_string(),
            project_name: "proj".to_string(),
            environment_name: "dev".to_string(),
            key: "API_KEY".to_string(),
        });

        let result = mock.get_secret(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn test_mock_secret_client_get_success() {
        let mut mock = MockSecretClient::new();

        mock.expect_get_secret().returning(|_| {
            Ok(Response::new(Secret {
                key: "API_KEY".to_string(),
                nonce: vec![1, 2, 3],
                ciphertext: vec![4, 5, 6],
            }))
        });

        let request = Request::new(GetSecretRequest {
            workspace_name: "ws".to_string(),
            project_name: "proj".to_string(),
            environment_name: "dev".to_string(),
            key: "API_KEY".to_string(),
        });

        let result = mock.get_secret(request).await;
        assert!(result.is_ok());
        let response = result.unwrap().into_inner();
        assert_eq!(response.key, "API_KEY");
    }

    #[tokio::test]
    async fn test_mock_secret_client_upsert() {
        let mut mock = MockSecretClient::new();

        mock.expect_upsert_secret()
            .returning(|_| Ok(Response::new(Empty {})));

        let request = Request::new(UpsertSecretRequest {
            workspace_name: "ws".to_string(),
            project_name: "proj".to_string(),
            environment_name: "dev".to_string(),
            key: "NEW_SECRET".to_string(),
            nonce: vec![1, 2, 3],
            ciphertext: vec![4, 5, 6],
        });

        let result = mock.upsert_secret(request).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_mock_secret_client_list() {
        let mut mock = MockSecretClient::new();

        mock.expect_list_secrets().returning(|_| {
            Ok(Response::new(SecretList {
                secrets: vec![
                    Secret {
                        key: "API_KEY".to_string(),
                        nonce: vec![],
                        ciphertext: vec![],
                    },
                    Secret {
                        key: "DB_PASSWORD".to_string(),
                        nonce: vec![],
                        ciphertext: vec![],
                    },
                ],
                version: 1,
            }))
        });

        let request = Request::new(ListSecretsRequest {
            workspace_name: "ws".to_string(),
            project_name: "proj".to_string(),
            environment_name: "dev".to_string(),
        });

        let result = mock.list_secrets(request).await;
        assert!(result.is_ok());
        let response = result.unwrap().into_inner();
        assert_eq!(response.secrets.len(), 2);
        assert_eq!(response.secrets[0].key, "API_KEY");
        assert_eq!(response.secrets[1].key, "DB_PASSWORD");
    }

    #[tokio::test]
    async fn test_mock_secret_client_delete() {
        let mut mock = MockSecretClient::new();

        mock.expect_delete_secret()
            .returning(|_| Ok(Response::new(Empty {})));

        let request = Request::new(DeleteSecretRequest {
            workspace_name: "ws".to_string(),
            project_name: "proj".to_string(),
            environment_name: "dev".to_string(),
            key: "SECRET_TO_DELETE".to_string(),
        });

        let result = mock.delete_secret(request).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_mock_secret_client_permission_denied() {
        let mut mock = MockSecretClient::new();

        mock.expect_upsert_secret()
            .returning(|_| Err(Status::permission_denied("Not authorized")));

        let request = Request::new(UpsertSecretRequest {
            workspace_name: "ws".to_string(),
            project_name: "proj".to_string(),
            environment_name: "dev".to_string(),
            key: "SECRET".to_string(),
            nonce: vec![],
            ciphertext: vec![],
        });

        let result = mock.upsert_secret(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::PermissionDenied);
    }

    #[tokio::test]
    async fn test_mock_project_client() {
        let mut mock = MockProjectClient::new();

        mock.expect_list_projects().returning(|_| {
            Ok(Response::new(ProjectList {
                projects: vec![Project {
                    id: "proj-id".to_string(),
                    workspace_id: "ws-id".to_string(),
                    name: "my-project".to_string(),
                    created_at: 0,
                    updated_at: 0,
                }],
            }))
        });

        let request = Request::new(ListProjectsRequest {
            workspace_name: "ws".to_string(),
        });

        let result = mock.list_projects(request).await;
        assert!(result.is_ok());
        let response = result.unwrap().into_inner();
        assert_eq!(response.projects.len(), 1);
        assert_eq!(response.projects[0].name, "my-project");
    }

    #[tokio::test]
    async fn test_mock_environment_client() {
        let mut mock = MockEnvironmentClient::new();

        mock.expect_list_environments().returning(|_| {
            Ok(Response::new(EnvironmentList {
                environments: vec![Environment {
                    id: "env-id".to_string(),
                    project_id: "proj-id".to_string(),
                    name: "production".to_string(),
                    dek_wrapped: vec![],
                    dek_nonce: vec![],
                    created_at: 0,
                    updated_at: 0,
                }],
            }))
        });

        let request = Request::new(ListEnvironmentsRequest {
            workspace_name: "ws".to_string(),
            project_name: "proj".to_string(),
        });

        let result = mock.list_environments(request).await;
        assert!(result.is_ok());
        let response = result.unwrap().into_inner();
        assert_eq!(response.environments.len(), 1);
        assert_eq!(response.environments[0].name, "production");
    }

    #[tokio::test]
    async fn test_mock_invite_client() {
        let mut mock = MockInviteClient::new();

        mock.expect_get_invite().returning(|_| {
            Ok(Response::new(InviteToken {
                id: "invite-id".to_string(),
                token: "test-token".to_string(),
                workspace_ids: vec!["ws-id".to_string()],
                created_at: 0,
                expires_at: 0,
                kek_encrypted: vec![],
                kek_nonce: vec![],
                invite_secret: String::new(),
            }))
        });

        let request = Request::new(GetInviteRequest {
            token: "test-token".to_string(),
        });

        let result = mock.get_invite(request).await;
        assert!(result.is_ok());
        let response = result.unwrap().into_inner();
        assert_eq!(response.token, "test-token");
    }

    #[tokio::test]
    async fn test_mock_group_client_list() {
        let mut mock = MockGroupClient::new();

        mock.expect_list_groups().returning(|_| {
            Ok(Response::new(GroupList {
                groups: vec![Group {
                    id: "group-id".to_string(),
                    workspace_id: "ws-id".to_string(),
                    name: "developers".to_string(),
                    description: "Developer team".to_string(),
                    created_at: "2024-01-01T00:00:00Z".to_string(),
                    updated_at: "2024-01-01T00:00:00Z".to_string(),
                }],
            }))
        });

        let request = Request::new(ListGroupsRequest {
            workspace_name: "ws".to_string(),
        });

        let result = mock.list_groups(request).await;
        assert!(result.is_ok());
        let response = result.unwrap().into_inner();
        assert_eq!(response.groups.len(), 1);
        assert_eq!(response.groups[0].name, "developers");
    }

    #[tokio::test]
    async fn test_mock_group_client_create() {
        let mut mock = MockGroupClient::new();

        mock.expect_create_group().returning(|_| {
            Ok(Response::new(Group {
                id: "new-group-id".to_string(),
                workspace_id: "ws-id".to_string(),
                name: "new-group".to_string(),
                description: "New group".to_string(),
                created_at: "2024-01-01T00:00:00Z".to_string(),
                updated_at: "2024-01-01T00:00:00Z".to_string(),
            }))
        });

        let request = Request::new(CreateGroupRequest {
            workspace_name: "ws".to_string(),
            name: "new-group".to_string(),
            description: "New group".to_string(),
        });

        let result = mock.create_group(request).await;
        assert!(result.is_ok());
        let response = result.unwrap().into_inner();
        assert_eq!(response.name, "new-group");
        assert_eq!(response.id, "new-group-id");
    }

    #[tokio::test]
    async fn test_mock_group_client_delete() {
        let mut mock = MockGroupClient::new();

        mock.expect_delete_group()
            .returning(|_| Ok(Response::new(Empty {})));

        let request = Request::new(DeleteGroupRequest {
            workspace_name: "ws".to_string(),
            group_name: "group-to-delete".to_string(),
        });

        let result = mock.delete_group(request).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_mock_group_client_not_found() {
        let mut mock = MockGroupClient::new();

        mock.expect_list_groups()
            .returning(|_| Err(Status::not_found("Workspace not found")));

        let request = Request::new(ListGroupsRequest {
            workspace_name: "nonexistent".to_string(),
        });

        let result = mock.list_groups(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }
}
