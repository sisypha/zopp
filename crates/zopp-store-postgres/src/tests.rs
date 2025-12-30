use super::*;
use rand_core::RngCore;
use sqlx::postgres::PgConnection;
use sqlx::{Connection, Executor};
use zopp_storage::{
    CreateEnvParams, CreateInviteParams, CreatePrincipalData, CreateProjectParams,
    CreateUserParams, CreateWorkspaceParams, Store, StoreError, UserId, WorkspaceId,
};

/// Create a unique test database and return the PostgresStore
async fn test_store() -> (PostgresStore, String) {
    let test_id = std::process::id();
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let random: u64 = rand_core::OsRng.next_u64();
    let db_name = format!("zopp_test_{}_{}_{}", test_id, timestamp, random);

    // Allow overriding credentials via environment variables for CI/different setups
    let pg_user = std::env::var("POSTGRES_USER").unwrap_or_else(|_| "postgres".to_string());
    let pg_pass = std::env::var("POSTGRES_PASSWORD").unwrap_or_else(|_| "postgres".to_string());
    let pg_host = std::env::var("POSTGRES_HOST").unwrap_or_else(|_| "localhost".to_string());
    let pg_port = std::env::var("POSTGRES_PORT").unwrap_or_else(|_| "5433".to_string());

    let admin_url = format!(
        "postgres://{}:{}@{}:{}/postgres",
        pg_user, pg_pass, pg_host, pg_port
    );
    let mut conn = PgConnection::connect(&admin_url).await.unwrap();

    // Drop if exists
    let drop_query = format!("DROP DATABASE IF EXISTS {}", db_name);
    let _ = conn.execute(drop_query.as_str()).await;

    // Create test database
    let create_query = format!("CREATE DATABASE {}", db_name);
    conn.execute(create_query.as_str()).await.unwrap();
    drop(conn);

    let db_url = format!(
        "postgres://{}:{}@{}:{}/{}",
        pg_user, pg_pass, pg_host, pg_port, db_name
    );
    let store = PostgresStore::open(&db_url).await.unwrap();

    (store, db_name)
}

/// Cleanup test database
async fn cleanup_db(db_name: &str) {
    let pg_user = std::env::var("POSTGRES_USER").unwrap_or_else(|_| "postgres".to_string());
    let pg_pass = std::env::var("POSTGRES_PASSWORD").unwrap_or_else(|_| "postgres".to_string());
    let pg_host = std::env::var("POSTGRES_HOST").unwrap_or_else(|_| "localhost".to_string());
    let pg_port = std::env::var("POSTGRES_PORT").unwrap_or_else(|_| "5433".to_string());

    let admin_url = format!(
        "postgres://{}:{}@{}:{}/postgres",
        pg_user, pg_pass, pg_host, pg_port
    );
    match PgConnection::connect(&admin_url).await {
        Ok(mut conn) => {
            let drop_query = format!("DROP DATABASE IF EXISTS {}", db_name);
            if let Err(e) = conn.execute(drop_query.as_str()).await {
                eprintln!("Warning: Failed to drop test database {}: {}", db_name, e);
            }
        }
        Err(e) => {
            eprintln!("Warning: Failed to connect to database for cleanup: {}", e);
        }
    }
}

fn workspace_params(owner_user_id: UserId, name: &str) -> CreateWorkspaceParams {
    CreateWorkspaceParams {
        id: WorkspaceId(uuid::Uuid::now_v7()),
        name: name.to_string(),
        owner_user_id,
        kdf_salt: b"test_salt_16byte".to_vec(),
        m_cost_kib: 2048,
        t_cost: 3,
        p_cost: 2,
    }
}

#[tokio::test]
async fn test_user_creation_and_retrieval() {
    let (store, db_name) = test_store().await;

    let (user_id, principal_id) = store
        .create_user(&CreateUserParams {
            email: "alice@example.com".to_string(),
            principal: Some(CreatePrincipalData {
                name: "laptop".to_string(),
                public_key: vec![1, 2, 3],
                x25519_public_key: Some(vec![4, 5, 6]),
                is_service: false,
            }),
            workspace_ids: vec![],
        })
        .await
        .unwrap();

    assert!(principal_id.is_some());

    let user = store.get_user_by_id(&user_id).await.unwrap();
    assert_eq!(user.email, "alice@example.com");

    cleanup_db(&db_name).await;
}

#[tokio::test]
async fn test_workspace_creation_and_kdf_params() {
    let (store, db_name) = test_store().await;

    let (user_id, _) = store
        .create_user(&CreateUserParams {
            email: "bob@example.com".to_string(),
            principal: None,
            workspace_ids: vec![],
        })
        .await
        .unwrap();

    let ws_id = store
        .create_workspace(&workspace_params(user_id, "acme"))
        .await
        .unwrap();

    let workspace = store.get_workspace(&ws_id).await.unwrap();
    assert_eq!(workspace.name, "acme");
    assert_eq!(workspace.kdf_salt, b"test_salt_16byte");
    assert_eq!(workspace.m_cost_kib, 2048);
    assert_eq!(workspace.t_cost, 3);
    assert_eq!(workspace.p_cost, 2);

    cleanup_db(&db_name).await;
}

#[tokio::test]
async fn test_project_creation_and_duplicate_error() {
    let (store, db_name) = test_store().await;

    let (user_id, _) = store
        .create_user(&CreateUserParams {
            email: "user@test.com".to_string(),
            principal: None,
            workspace_ids: vec![],
        })
        .await
        .unwrap();

    let ws_id = store
        .create_workspace(&workspace_params(user_id, "workspace"))
        .await
        .unwrap();

    // Create project
    let project_id = store
        .create_project(&CreateProjectParams {
            workspace_id: ws_id.clone(),
            name: "api".to_string(),
        })
        .await
        .unwrap();

    assert!(project_id.0 != uuid::Uuid::nil());

    // Duplicate should fail
    let err = store
        .create_project(&CreateProjectParams {
            workspace_id: ws_id,
            name: "api".to_string(),
        })
        .await
        .unwrap_err();

    assert!(matches!(err, StoreError::AlreadyExists));

    cleanup_db(&db_name).await;
}

#[tokio::test]
async fn test_environment_creation_and_duplicate_error() {
    let (store, db_name) = test_store().await;

    let (user_id, _) = store
        .create_user(&CreateUserParams {
            email: "dev@test.com".to_string(),
            principal: None,
            workspace_ids: vec![],
        })
        .await
        .unwrap();

    let ws_id = store
        .create_workspace(&workspace_params(user_id, "workspace"))
        .await
        .unwrap();

    let project_id = store
        .create_project(&CreateProjectParams {
            workspace_id: ws_id,
            name: "backend".to_string(),
        })
        .await
        .unwrap();

    // Create environment
    let env_id = store
        .create_env(&CreateEnvParams {
            project_id: project_id.clone(),
            name: "production".to_string(),
            dek_wrapped: vec![10; 32],
            dek_nonce: vec![20; 24],
        })
        .await
        .unwrap();

    assert!(env_id.0 != uuid::Uuid::nil());

    // Duplicate should fail
    let err = store
        .create_env(&CreateEnvParams {
            project_id,
            name: "production".to_string(),
            dek_wrapped: vec![99; 32],
            dek_nonce: vec![88; 24],
        })
        .await
        .unwrap_err();

    assert!(matches!(err, StoreError::AlreadyExists));

    cleanup_db(&db_name).await;
}

#[tokio::test]
async fn test_secret_upsert_and_retrieval() {
    let (store, db_name) = test_store().await;

    let (user_id, _) = store
        .create_user(&CreateUserParams {
            email: "secret@test.com".to_string(),
            principal: None,
            workspace_ids: vec![],
        })
        .await
        .unwrap();

    let ws_id = store
        .create_workspace(&workspace_params(user_id, "workspace"))
        .await
        .unwrap();

    let project_id = store
        .create_project(&CreateProjectParams {
            workspace_id: ws_id,
            name: "app".to_string(),
        })
        .await
        .unwrap();

    let env_id = store
        .create_env(&CreateEnvParams {
            project_id,
            name: "dev".to_string(),
            dek_wrapped: vec![1; 32],
            dek_nonce: vec![2; 24],
        })
        .await
        .unwrap();

    // Insert secret (nonce=24 bytes, ciphertext=variable)
    store
        .upsert_secret(&env_id, "API_KEY", &[4; 24], &[3; 48])
        .await
        .unwrap();

    // Retrieve secret
    let secret = store.get_secret(&env_id, "API_KEY").await.unwrap();
    assert_eq!(secret.nonce, vec![4; 24]);
    assert_eq!(secret.ciphertext, vec![3; 48]);

    // Update secret
    store
        .upsert_secret(&env_id, "API_KEY", &[6; 24], &[5; 48])
        .await
        .unwrap();

    let updated = store.get_secret(&env_id, "API_KEY").await.unwrap();
    assert_eq!(updated.nonce, vec![6; 24]);
    assert_eq!(updated.ciphertext, vec![5; 48]);

    cleanup_db(&db_name).await;
}

#[tokio::test]
async fn test_workspace_isolation() {
    let (store, db_name) = test_store().await;

    let (user_id, _) = store
        .create_user(&CreateUserParams {
            email: "isolation@test.com".to_string(),
            principal: None,
            workspace_ids: vec![],
        })
        .await
        .unwrap();

    // Create two workspaces
    let ws1 = store
        .create_workspace(&workspace_params(user_id.clone(), "workspace1"))
        .await
        .unwrap();

    let ws2 = store
        .create_workspace(&workspace_params(user_id, "workspace2"))
        .await
        .unwrap();

    // Create identical project/env structure in both
    let p1 = store
        .create_project(&CreateProjectParams {
            workspace_id: ws1,
            name: "app".to_string(),
        })
        .await
        .unwrap();

    let e1 = store
        .create_env(&CreateEnvParams {
            project_id: p1,
            name: "prod".to_string(),
            dek_wrapped: vec![1; 32],
            dek_nonce: vec![2; 24],
        })
        .await
        .unwrap();

    let p2 = store
        .create_project(&CreateProjectParams {
            workspace_id: ws2,
            name: "app".to_string(),
        })
        .await
        .unwrap();

    let e2 = store
        .create_env(&CreateEnvParams {
            project_id: p2,
            name: "prod".to_string(),
            dek_wrapped: vec![3; 32],
            dek_nonce: vec![4; 24],
        })
        .await
        .unwrap();

    // Insert secret in workspace1
    store
        .upsert_secret(&e1, "TOKEN", &[11; 24], &[10; 48])
        .await
        .unwrap();

    // workspace2 should NOT see workspace1's secret
    let err = store.get_secret(&e2, "TOKEN").await.unwrap_err();
    assert!(matches!(err, StoreError::NotFound));

    cleanup_db(&db_name).await;
}

#[tokio::test]
async fn test_list_secrets_sorted() {
    let (store, db_name) = test_store().await;

    let (user_id, _) = store
        .create_user(&CreateUserParams {
            email: "list@test.com".to_string(),
            principal: None,
            workspace_ids: vec![],
        })
        .await
        .unwrap();

    let ws_id = store
        .create_workspace(&workspace_params(user_id, "workspace"))
        .await
        .unwrap();

    let project_id = store
        .create_project(&CreateProjectParams {
            workspace_id: ws_id,
            name: "app".to_string(),
        })
        .await
        .unwrap();

    let env_id = store
        .create_env(&CreateEnvParams {
            project_id,
            name: "staging".to_string(),
            dek_wrapped: vec![1; 32],
            dek_nonce: vec![2; 24],
        })
        .await
        .unwrap();

    // Insert secrets in non-alphabetical order
    store
        .upsert_secret(&env_id, "ZEBRA", &[1; 24], &[1; 48])
        .await
        .unwrap();
    store
        .upsert_secret(&env_id, "ALPHA", &[2; 24], &[2; 48])
        .await
        .unwrap();
    store
        .upsert_secret(&env_id, "BETA", &[3; 24], &[3; 48])
        .await
        .unwrap();

    let keys = store.list_secret_keys(&env_id).await.unwrap();
    assert_eq!(keys, vec!["ALPHA", "BETA", "ZEBRA"]);

    cleanup_db(&db_name).await;
}

#[tokio::test]
async fn test_unicode_handling() {
    let (store, db_name) = test_store().await;

    let (user_id, _) = store
        .create_user(&CreateUserParams {
            email: "unicode@测试.com".to_string(),
            principal: None,
            workspace_ids: vec![],
        })
        .await
        .unwrap();

    let ws_id = store
        .create_workspace(&workspace_params(user_id, "工作区"))
        .await
        .unwrap();

    let project_id = store
        .create_project(&CreateProjectParams {
            workspace_id: ws_id.clone(),
            name: "プロジェクト".to_string(),
        })
        .await
        .unwrap();

    let env_id = store
        .create_env(&CreateEnvParams {
            project_id,
            name: "환경".to_string(),
            dek_wrapped: vec![1; 32],
            dek_nonce: vec![2; 24],
        })
        .await
        .unwrap();

    store
        .upsert_secret(&env_id, "🔑_KEY", &[6; 24], &[5; 48])
        .await
        .unwrap();

    let secret = store.get_secret(&env_id, "🔑_KEY").await.unwrap();
    assert_eq!(secret.nonce, vec![6; 24]);
    assert_eq!(secret.ciphertext, vec![5; 48]);

    let workspace = store.get_workspace(&ws_id).await.unwrap();
    assert_eq!(workspace.name, "工作区");

    cleanup_db(&db_name).await;
}

#[tokio::test]
async fn test_invite_creation_and_revocation() {
    let (store, db_name) = test_store().await;

    let (user_id, _) = store
        .create_user(&CreateUserParams {
            email: "inviter@test.com".to_string(),
            principal: None,
            workspace_ids: vec![],
        })
        .await
        .unwrap();

    let ws_id = store
        .create_workspace(&workspace_params(user_id.clone(), "team"))
        .await
        .unwrap();

    // Create invite token (hash of invite secret)
    let invite_secret = b"supersecretinvite123";
    let token_hash = {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(invite_secret);
        hex::encode(hasher.finalize())
    };

    let expires_at = chrono::Utc::now() + chrono::Duration::hours(24);
    let invite = store
        .create_invite(&CreateInviteParams {
            workspace_ids: vec![ws_id.clone()],
            token: token_hash.clone(),
            kek_encrypted: Some(vec![7; 48]),
            kek_nonce: Some(vec![8; 24]),
            expires_at,
            created_by_user_id: Some(user_id.clone()),
        })
        .await
        .unwrap();

    // Get invite by token
    let retrieved = store.get_invite_by_token(&token_hash).await.unwrap();
    assert_eq!(retrieved.workspace_ids, vec![ws_id]);
    assert_eq!(retrieved.kek_encrypted, Some(vec![7; 48]));

    // List invites for user
    let invites = store.list_invites(Some(&user_id)).await.unwrap();
    assert_eq!(invites.len(), 1);
    assert_eq!(invites[0].token, token_hash);

    // Revoke invite
    store.revoke_invite(&invite.id).await.unwrap();

    // Getting revoked invite should fail
    let err = store.get_invite_by_token(&token_hash).await.unwrap_err();
    assert!(matches!(err, StoreError::NotFound));

    cleanup_db(&db_name).await;
}

#[tokio::test]
async fn test_sequential_secret_updates() {
    let (store, db_name) = test_store().await;

    let (user_id, _) = store
        .create_user(&CreateUserParams {
            email: "sequential@test.com".to_string(),
            principal: None,
            workspace_ids: vec![],
        })
        .await
        .unwrap();

    let ws_id = store
        .create_workspace(&workspace_params(user_id, "workspace"))
        .await
        .unwrap();

    let project_id = store
        .create_project(&CreateProjectParams {
            workspace_id: ws_id,
            name: "test".to_string(),
        })
        .await
        .unwrap();

    let env_id = store
        .create_env(&CreateEnvParams {
            project_id,
            name: "test".to_string(),
            dek_wrapped: vec![1; 32],
            dek_nonce: vec![2; 24],
        })
        .await
        .unwrap();

    // Perform multiple upserts - last one should win
    store
        .upsert_secret(&env_id, "KEY", &[1; 24], &[1; 48])
        .await
        .unwrap();

    store
        .upsert_secret(&env_id, "KEY", &[2; 24], &[2; 48])
        .await
        .unwrap();

    store
        .upsert_secret(&env_id, "KEY", &[3; 24], &[3; 48])
        .await
        .unwrap();

    let final_secret = store.get_secret(&env_id, "KEY").await.unwrap();
    assert_eq!(final_secret.nonce, vec![3; 24]);
    assert_eq!(final_secret.ciphertext, vec![3; 48]);

    cleanup_db(&db_name).await;
}
