//! Secret handlers: upsert, get, list, delete, watch

use chrono::Utc;
use futures::StreamExt;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};
use zopp_audit::{AuditAction, AuditEvent, AuditResult};
use zopp_events::{EventType, SecretChangeEvent};
use zopp_proto::{
    DeleteSecretRequest, Empty, GetSecretRequest, ListSecretsRequest, Secret, SecretList,
    UpsertSecretRequest, WatchSecretsRequest, WatchSecretsResponse,
};
use zopp_storage::Store;

use crate::server::{extract_signature, ZoppServer};

pub async fn upsert_secret(
    server: &ZoppServer,
    request: Request<UpsertSecretRequest>,
) -> Result<Response<Empty>, Status> {
    let (principal_id, timestamp, signature, request_hash) = extract_signature(&request)?;
    let req_for_verify = request.get_ref().clone();
    let principal = server
        .verify_signature_and_get_principal(
            &principal_id,
            timestamp,
            &signature,
            "/zopp.ZoppService/UpsertSecret",
            &req_for_verify,
            &request_hash,
        )
        .await?;

    let req = request.into_inner();

    // Look up workspace by name - use different lookup for service principals
    let workspace = if let Some(user_id) = &principal.user_id {
        server
            .store
            .get_workspace_by_name(user_id, &req.workspace_name)
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::NotFound => {
                    Status::not_found("Workspace not found or access denied")
                }
                _ => Status::internal(format!("Failed to get workspace: {}", e)),
            })?
    } else {
        // Service principal - use principal-based lookup
        server
            .store
            .get_workspace_by_name_for_principal(&principal_id, &req.workspace_name)
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::NotFound => {
                    Status::not_found("Workspace not found or access denied")
                }
                _ => Status::internal(format!("Failed to get workspace: {}", e)),
            })?
    };

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

    // Audit log - determine if this was a create or update based on version
    let action = if new_version == 1 {
        AuditAction::SecretCreate
    } else {
        AuditAction::SecretUpdate
    };
    server
        .audit(
            AuditEvent::builder(&principal_id, action)
                .user_id(principal.user_id.as_ref())
                .resource("secret", &req.key)
                .workspace_id(Some(&workspace.id))
                .project_id(Some(&project.id))
                .environment_id(Some(&env.id))
                .result(AuditResult::Success)
                .build(),
        )
        .await;

    Ok(Response::new(Empty {}))
}

pub async fn get_secret(
    server: &ZoppServer,
    request: Request<GetSecretRequest>,
) -> Result<Response<Secret>, Status> {
    let (principal_id, timestamp, signature, request_hash) = extract_signature(&request)?;
    let req_for_verify = request.get_ref().clone();
    let principal = server
        .verify_signature_and_get_principal(
            &principal_id,
            timestamp,
            &signature,
            "/zopp.ZoppService/GetSecret",
            &req_for_verify,
            &request_hash,
        )
        .await?;
    let req = request.into_inner();

    // Look up workspace by name - use different lookup for service principals
    let workspace = if let Some(user_id) = &principal.user_id {
        server
            .store
            .get_workspace_by_name(user_id, &req.workspace_name)
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::NotFound => {
                    Status::not_found("Workspace not found or access denied")
                }
                _ => Status::internal(format!("Failed to get workspace: {}", e)),
            })?
    } else {
        // Service principal - use principal-based lookup
        server
            .store
            .get_workspace_by_name_for_principal(&principal_id, &req.workspace_name)
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::NotFound => {
                    Status::not_found("Workspace not found or access denied")
                }
                _ => Status::internal(format!("Failed to get workspace: {}", e)),
            })?
    };

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

    // Audit log - secret read
    server
        .audit(
            AuditEvent::builder(&principal_id, AuditAction::SecretRead)
                .user_id(principal.user_id.as_ref())
                .resource("secret", &req.key)
                .workspace_id(Some(&workspace.id))
                .project_id(Some(&project.id))
                .environment_id(Some(&env.id))
                .result(AuditResult::Success)
                .build(),
        )
        .await;

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
    let (principal_id, timestamp, signature, request_hash) = extract_signature(&request)?;
    let req_for_verify = request.get_ref().clone();
    let principal = server
        .verify_signature_and_get_principal(
            &principal_id,
            timestamp,
            &signature,
            "/zopp.ZoppService/ListSecrets",
            &req_for_verify,
            &request_hash,
        )
        .await?;

    let req = request.into_inner();

    // Look up workspace by name - use different lookup for service principals
    let workspace = if let Some(user_id) = &principal.user_id {
        server
            .store
            .get_workspace_by_name(user_id, &req.workspace_name)
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::NotFound => {
                    Status::not_found("Workspace not found or access denied")
                }
                _ => Status::internal(format!("Failed to get workspace: {}", e)),
            })?
    } else {
        // Service principal - use principal-based lookup
        server
            .store
            .get_workspace_by_name_for_principal(&principal_id, &req.workspace_name)
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::NotFound => {
                    Status::not_found("Workspace not found or access denied")
                }
                _ => Status::internal(format!("Failed to get workspace: {}", e)),
            })?
    };

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

    // TODO: This is an N+1 query pattern. Consider adding a batch method to the storage
    // trait that fetches all secrets at once for better performance.
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

    // Audit log - secret list
    server
        .audit(
            AuditEvent::builder(&principal_id, AuditAction::SecretList)
                .user_id(principal.user_id.as_ref())
                .resource("environment", env.id.0.to_string())
                .workspace_id(Some(&workspace.id))
                .project_id(Some(&project.id))
                .environment_id(Some(&env.id))
                .result(AuditResult::Success)
                .details(serde_json::json!({ "count": secrets.len() }))
                .build(),
        )
        .await;

    Ok(Response::new(SecretList {
        secrets,
        version: env.version,
    }))
}

pub async fn delete_secret(
    server: &ZoppServer,
    request: Request<DeleteSecretRequest>,
) -> Result<Response<Empty>, Status> {
    let (principal_id, timestamp, signature, request_hash) = extract_signature(&request)?;
    let req_for_verify = request.get_ref().clone();
    let principal = server
        .verify_signature_and_get_principal(
            &principal_id,
            timestamp,
            &signature,
            "/zopp.ZoppService/DeleteSecret",
            &req_for_verify,
            &request_hash,
        )
        .await?;

    let req = request.into_inner();

    // Look up workspace by name - use different lookup for service principals
    let workspace = if let Some(user_id) = &principal.user_id {
        server
            .store
            .get_workspace_by_name(user_id, &req.workspace_name)
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::NotFound => {
                    Status::not_found("Workspace not found or access denied")
                }
                _ => Status::internal(format!("Failed to get workspace: {}", e)),
            })?
    } else {
        // Service principal - use principal-based lookup
        server
            .store
            .get_workspace_by_name_for_principal(&principal_id, &req.workspace_name)
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::NotFound => {
                    Status::not_found("Workspace not found or access denied")
                }
                _ => Status::internal(format!("Failed to get workspace: {}", e)),
            })?
    };

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

    // Audit log - secret delete
    server
        .audit(
            AuditEvent::builder(&principal_id, AuditAction::SecretDelete)
                .user_id(principal.user_id.as_ref())
                .resource("secret", &req.key)
                .workspace_id(Some(&workspace.id))
                .project_id(Some(&project.id))
                .environment_id(Some(&env.id))
                .result(AuditResult::Success)
                .build(),
        )
        .await;

    Ok(Response::new(Empty {}))
}

pub async fn watch_secrets(
    server: &ZoppServer,
    request: Request<WatchSecretsRequest>,
) -> Result<Response<ReceiverStream<Result<WatchSecretsResponse, Status>>>, Status> {
    let (principal_id, timestamp, signature, request_hash) = extract_signature(&request)?;
    let req_for_verify = request.get_ref().clone();
    let principal = server
        .verify_signature_and_get_principal(
            &principal_id,
            timestamp,
            &signature,
            "/zopp.ZoppService/WatchSecrets",
            &req_for_verify,
            &request_hash,
        )
        .await?;

    let req = request.into_inner();

    // Look up workspace by name - use different lookup for service principals
    let workspace = if let Some(user_id) = &principal.user_id {
        server
            .store
            .get_workspace_by_name(user_id, &req.workspace_name)
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::NotFound => {
                    Status::not_found("Workspace not found or access denied")
                }
                _ => Status::internal(format!("Failed to get workspace: {}", e)),
            })?
    } else {
        // Service principal - use principal-based lookup
        server
            .store
            .get_workspace_by_name_for_principal(&principal_id, &req.workspace_name)
            .await
            .map_err(|e| match e {
                zopp_storage::StoreError::NotFound => {
                    Status::not_found("Workspace not found or access denied")
                }
                _ => Status::internal(format!("Failed to get workspace: {}", e)),
            })?
    };

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

    // Clone what we need for the spawned task
    let server_clone = server.clone();
    let principal_id_clone = principal_id.clone();
    let workspace_id_clone = workspace.id.clone();
    let project_id_clone = project.id.clone();
    let env_id_clone = env.id.clone();

    // Spawn task to forward events with permission re-validation
    tokio::spawn(async move {
        while let Some(event) = subscriber.next().await {
            // Re-check permissions before forwarding each event
            // This ensures revoked permissions are respected immediately
            if server_clone
                .check_permission(
                    &principal_id_clone,
                    &workspace_id_clone,
                    &project_id_clone,
                    &env_id_clone,
                    zopp_storage::Role::Read,
                )
                .await
                .is_err()
            {
                // Permission revoked - close the stream
                let _ = tx
                    .send(Err(Status::permission_denied(
                        "Permission revoked - closing watch stream",
                    )))
                    .await;
                break;
            }

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
