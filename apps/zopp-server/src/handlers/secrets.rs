//! Secret handlers: upsert, get, list, delete, watch

use chrono::Utc;
use futures::StreamExt;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};
use zopp_proto::{
    DeleteSecretRequest, Empty, GetSecretRequest, ListSecretsRequest, Secret, SecretList,
    UpsertSecretRequest, WatchSecretsRequest, WatchSecretsResponse,
};
use zopp_events::{EventType, SecretChangeEvent};
use zopp_storage::Store;

use crate::server::{extract_signature, ZoppServer};

pub async fn upsert_secret(
    server: &ZoppServer,
    request: Request<UpsertSecretRequest>,
) -> Result<Response<Empty>, Status> {
    let (principal_id, timestamp, signature) = extract_signature(&request)?;
    let principal = server
        .verify_signature_and_get_principal(&principal_id, timestamp, &signature)
        .await?;
    let user_id = principal
        .user_id
        .ok_or_else(|| Status::unauthenticated("Service accounts cannot upsert secrets"))?;

    let req = request.into_inner();

    // Look up workspace by name
    let workspace = server
        .store
        .get_workspace_by_name(&user_id, &req.workspace_name)
        .await
        .map_err(|e| match e {
            zopp_storage::StoreError::NotFound => {
                Status::not_found("Workspace not found or access denied")
            }
            _ => Status::internal(format!("Failed to get workspace: {}", e)),
        })?;

    // Look up project by name in workspace
    let project = server
        .store
        .get_project_by_name(&workspace.id, &req.project_name)
        .await
        .map_err(|e| match e {
            zopp_storage::StoreError::NotFound => Status::not_found("Project not found"),
            _ => Status::internal(format!("Failed to get project: {}", e)),
        })?;

    // Look up environment by name in project
    let env = server
        .store
        .get_environment_by_name(&project.id, &req.environment_name)
        .await
        .map_err(|e| match e {
            zopp_storage::StoreError::NotFound => Status::not_found("Environment not found"),
            _ => Status::internal(format!("Failed to get environment: {}", e)),
        })?;

    // Check RBAC permission - upsert requires Write
    server
        .check_permission(
            &principal_id,
            &workspace.id,
            &project.id,
            &env.id,
            zopp_storage::Role::Write,
        )
        .await?;

    let new_version = server
        .store
        .upsert_secret(&env.id, &req.key, &req.nonce, &req.ciphertext)
        .await
        .map_err(|e| Status::internal(format!("Failed to upsert secret: {}", e)))?;

    // Broadcast event to watchers
    let event = SecretChangeEvent {
        event_type: EventType::Updated,
        key: req.key.clone(),
        version: new_version,
        timestamp: Utc::now().timestamp(),
    };
    let _ = server.events.publish(&env.id, event).await;

    Ok(Response::new(Empty {}))
}

pub async fn get_secret(
    server: &ZoppServer,
    request: Request<GetSecretRequest>,
) -> Result<Response<Secret>, Status> {
    let (principal_id, timestamp, signature) = extract_signature(&request)?;
    let principal = server
        .verify_signature_and_get_principal(&principal_id, timestamp, &signature)
        .await?;
    let user_id = principal
        .user_id
        .ok_or_else(|| Status::unauthenticated("Service accounts cannot get secrets"))?;

    let req = request.into_inner();

    // Look up workspace by name
    let workspace = server
        .store
        .get_workspace_by_name(&user_id, &req.workspace_name)
        .await
        .map_err(|e| match e {
            zopp_storage::StoreError::NotFound => {
                Status::not_found("Workspace not found or access denied")
            }
            _ => Status::internal(format!("Failed to get workspace: {}", e)),
        })?;

    // Look up project by name in workspace
    let project = server
        .store
        .get_project_by_name(&workspace.id, &req.project_name)
        .await
        .map_err(|e| match e {
            zopp_storage::StoreError::NotFound => Status::not_found("Project not found"),
            _ => Status::internal(format!("Failed to get project: {}", e)),
        })?;

    // Look up environment by name in project
    let env = server
        .store
        .get_environment_by_name(&project.id, &req.environment_name)
        .await
        .map_err(|e| match e {
            zopp_storage::StoreError::NotFound => Status::not_found("Environment not found"),
            _ => Status::internal(format!("Failed to get environment: {}", e)),
        })?;

    // Check RBAC permission - get requires Read
    server
        .check_permission(
            &principal_id,
            &workspace.id,
            &project.id,
            &env.id,
            zopp_storage::Role::Read,
        )
        .await?;

    let secret = server
        .store
        .get_secret(&env.id, &req.key)
        .await
        .map_err(|e| match e {
            zopp_storage::StoreError::NotFound => Status::not_found("Secret not found"),
            _ => Status::internal(format!("Failed to get secret: {}", e)),
        })?;

    Ok(Response::new(Secret {
        key: req.key,
        nonce: secret.nonce,
        ciphertext: secret.ciphertext,
    }))
}

pub async fn list_secrets(
    server: &ZoppServer,
    request: Request<ListSecretsRequest>,
) -> Result<Response<SecretList>, Status> {
    let (principal_id, timestamp, signature) = extract_signature(&request)?;
    let principal = server
        .verify_signature_and_get_principal(&principal_id, timestamp, &signature)
        .await?;
    let user_id = principal
        .user_id
        .ok_or_else(|| Status::unauthenticated("Service accounts cannot list secrets"))?;

    let req = request.into_inner();

    // Look up workspace by name
    let workspace = server
        .store
        .get_workspace_by_name(&user_id, &req.workspace_name)
        .await
        .map_err(|e| match e {
            zopp_storage::StoreError::NotFound => {
                Status::not_found("Workspace not found or access denied")
            }
            _ => Status::internal(format!("Failed to get workspace: {}", e)),
        })?;

    // Look up project by name in workspace
    let project = server
        .store
        .get_project_by_name(&workspace.id, &req.project_name)
        .await
        .map_err(|e| match e {
            zopp_storage::StoreError::NotFound => Status::not_found("Project not found"),
            _ => Status::internal(format!("Failed to get project: {}", e)),
        })?;

    // Look up environment by name in project
    let env = server
        .store
        .get_environment_by_name(&project.id, &req.environment_name)
        .await
        .map_err(|e| match e {
            zopp_storage::StoreError::NotFound => Status::not_found("Environment not found"),
            _ => Status::internal(format!("Failed to get environment: {}", e)),
        })?;

    // Check RBAC permission - list requires Read
    server
        .check_permission(
            &principal_id,
            &workspace.id,
            &project.id,
            &env.id,
            zopp_storage::Role::Read,
        )
        .await?;

    let keys = server
        .store
        .list_secret_keys(&env.id)
        .await
        .map_err(|e| Status::internal(format!("Failed to list secrets: {}", e)))?;

    // For each key, fetch the secret
    let mut secrets = Vec::new();
    for key in keys {
        let secret = server
            .store
            .get_secret(&env.id, &key)
            .await
            .map_err(|e| Status::internal(format!("Failed to get secret: {}", e)))?;
        secrets.push(Secret {
            key,
            nonce: secret.nonce,
            ciphertext: secret.ciphertext,
        });
    }

    Ok(Response::new(SecretList {
        secrets,
        version: env.version,
    }))
}

pub async fn delete_secret(
    server: &ZoppServer,
    request: Request<DeleteSecretRequest>,
) -> Result<Response<Empty>, Status> {
    let (principal_id, timestamp, signature) = extract_signature(&request)?;
    let principal = server
        .verify_signature_and_get_principal(&principal_id, timestamp, &signature)
        .await?;
    let user_id = principal
        .user_id
        .ok_or_else(|| Status::unauthenticated("Service accounts cannot delete secrets"))?;

    let req = request.into_inner();

    // Look up workspace by name
    let workspace = server
        .store
        .get_workspace_by_name(&user_id, &req.workspace_name)
        .await
        .map_err(|e| match e {
            zopp_storage::StoreError::NotFound => {
                Status::not_found("Workspace not found or access denied")
            }
            _ => Status::internal(format!("Failed to get workspace: {}", e)),
        })?;

    // Look up project by name in workspace
    let project = server
        .store
        .get_project_by_name(&workspace.id, &req.project_name)
        .await
        .map_err(|e| match e {
            zopp_storage::StoreError::NotFound => Status::not_found("Project not found"),
            _ => Status::internal(format!("Failed to get project: {}", e)),
        })?;

    // Look up environment by name in project
    let env = server
        .store
        .get_environment_by_name(&project.id, &req.environment_name)
        .await
        .map_err(|e| match e {
            zopp_storage::StoreError::NotFound => Status::not_found("Environment not found"),
            _ => Status::internal(format!("Failed to get environment: {}", e)),
        })?;

    // Check RBAC permission - delete requires Write
    server
        .check_permission(
            &principal_id,
            &workspace.id,
            &project.id,
            &env.id,
            zopp_storage::Role::Write,
        )
        .await?;

    let new_version = server
        .store
        .delete_secret(&env.id, &req.key)
        .await
        .map_err(|e| match e {
            zopp_storage::StoreError::NotFound => Status::not_found("Secret not found"),
            _ => Status::internal(format!("Failed to delete secret: {}", e)),
        })?;

    // Broadcast event to watchers
    let event = SecretChangeEvent {
        event_type: EventType::Deleted,
        key: req.key.clone(),
        version: new_version,
        timestamp: Utc::now().timestamp(),
    };
    let _ = server.events.publish(&env.id, event).await;

    Ok(Response::new(Empty {}))
}

pub async fn watch_secrets(
    server: &ZoppServer,
    request: Request<WatchSecretsRequest>,
) -> Result<Response<ReceiverStream<Result<WatchSecretsResponse, Status>>>, Status> {
    let (principal_id, timestamp, signature) = extract_signature(&request)?;
    let principal = server
        .verify_signature_and_get_principal(&principal_id, timestamp, &signature)
        .await?;
    let user_id = principal
        .user_id
        .ok_or_else(|| Status::unauthenticated("Service accounts cannot watch secrets"))?;

    let req = request.into_inner();

    // Look up workspace by name
    let workspace = server
        .store
        .get_workspace_by_name(&user_id, &req.workspace_name)
        .await
        .map_err(|e| match e {
            zopp_storage::StoreError::NotFound => {
                Status::not_found("Workspace not found or access denied")
            }
            _ => Status::internal(format!("Failed to get workspace: {}", e)),
        })?;

    // Look up project by name in workspace
    let project = server
        .store
        .get_project_by_name(&workspace.id, &req.project_name)
        .await
        .map_err(|e| match e {
            zopp_storage::StoreError::NotFound => Status::not_found("Project not found"),
            _ => Status::internal(format!("Failed to get project: {}", e)),
        })?;

    // Look up environment by name in project
    let env = server
        .store
        .get_environment_by_name(&project.id, &req.environment_name)
        .await
        .map_err(|e| match e {
            zopp_storage::StoreError::NotFound => Status::not_found("Environment not found"),
            _ => Status::internal(format!("Failed to get environment: {}", e)),
        })?;

    // Check RBAC permission - watch requires Read
    server
        .check_permission(
            &principal_id,
            &workspace.id,
            &project.id,
            &env.id,
            zopp_storage::Role::Read,
        )
        .await?;

    // Create channel for streaming events
    let (tx, rx) = tokio::sync::mpsc::channel(32);

    // Subscribe to events for this environment
    let mut subscriber = server
        .events
        .subscribe(&env.id)
        .await
        .map_err(|e| Status::internal(format!("Failed to subscribe to events: {}", e)))?;

    // Spawn task to forward events
    tokio::spawn(async move {
        while let Some(event) = subscriber.next().await {
            let proto_event_type = match event.event_type {
                EventType::Created => zopp_proto::secret_change_event::EventType::Created,
                EventType::Updated => zopp_proto::secret_change_event::EventType::Updated,
                EventType::Deleted => zopp_proto::secret_change_event::EventType::Deleted,
            };

            let response = WatchSecretsResponse {
                response: Some(zopp_proto::watch_secrets_response::Response::Event(
                    zopp_proto::SecretChangeEvent {
                        event_type: proto_event_type as i32,
                        key: event.key,
                        version: event.version,
                        timestamp: event.timestamp,
                    },
                )),
            };

            if tx.send(Ok(response)).await.is_err() {
                break; // Client disconnected
            }
        }
    });

    Ok(Response::new(ReceiverStream::new(rx)))
}
