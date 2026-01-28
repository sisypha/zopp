//! StoreBackend tests.
//!
//! Tests for the storage backend abstraction layer.

use super::common::*;
use crate::backend::StoreBackend;
use std::sync::Arc;
use zopp_storage::*;
use zopp_store_sqlite::SqliteStore;

#[tokio::test]
async fn store_backend_create_user() {
    let store = Arc::new(SqliteStore::open_in_memory().await.unwrap());
    let backend = StoreBackend::Sqlite(store);

    let (public_key, _) = generate_keypair();
    let (x25519_public, _) = generate_x25519_keypair();

    let (user_id, principal_id) = backend
        .create_user(&CreateUserParams {
            email: "test@example.com".to_string(),
            principal: Some(CreatePrincipalData {
                name: "laptop".to_string(),
                public_key,
                x25519_public_key: Some(x25519_public),
                is_service: false,
            }),
            workspace_ids: vec![],
        })
        .await
        .unwrap();

    // Verify user was created
    let user = backend.get_user_by_id(&user_id).await.unwrap();
    assert_eq!(user.email, "test@example.com");

    // Verify principal was created
    let principal = backend.get_principal(&principal_id.unwrap()).await.unwrap();
    assert_eq!(principal.name, "laptop");
}
