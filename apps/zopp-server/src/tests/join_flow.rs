//! Join flow tests.
//!
//! Tests for server invite and join functionality.

use super::common::*;
use chrono::Utc;
use zopp_proto::zopp_service_server::ZoppService;
use zopp_proto::JoinRequest;
use zopp_storage::*;

#[tokio::test]
async fn test_server_invite_joins_user_without_creating_workspace() {
    let server = create_test_server().await;

    // Create a server invite (no workspaces)
    let mut invite_secret = [0u8; 32];
    rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut invite_secret);
    let secret_hash = zopp_crypto::hash_sha256(&invite_secret);
    let invite = server
        .store
        .create_invite(&CreateInviteParams {
            workspace_ids: vec![],
            token: hex::encode(secret_hash),
            kek_encrypted: None,
            kek_nonce: None,
            expires_at: Utc::now() + chrono::Duration::hours(24),
            created_by_user_id: None,
        })
        .await
        .unwrap();

    // Generate keypair for join
    let (public_key, _signing_key) = generate_keypair();
    let (x25519_public_key, _) = generate_x25519_keypair();

    // Join using server invite
    let request = tonic::Request::new(JoinRequest {
        invite_token: invite.token.clone(),
        email: "test@example.com".to_string(),
        principal_name: "test-laptop".to_string(),
        public_key,
        x25519_public_key,
        ephemeral_pub: vec![],
        kek_wrapped: vec![],
        kek_nonce: vec![],
    });

    let response = server.join(request).await.unwrap().into_inner();

    assert!(!response.user_id.is_empty());
    assert!(!response.principal_id.as_ref().is_none_or(|s| s.is_empty()));
    assert_eq!(
        response.workspaces.len(),
        0,
        "No workspaces should be created automatically"
    );

    let principal_id =
        PrincipalId(uuid::Uuid::parse_str(response.principal_id.as_ref().unwrap()).unwrap());

    let workspaces = server.store.list_workspaces(&principal_id).await.unwrap();
    assert_eq!(
        workspaces.len(),
        0,
        "Principal should not have access to any workspaces yet"
    );
}
