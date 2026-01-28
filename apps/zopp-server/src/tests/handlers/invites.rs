//! Invite handler tests.
//!
//! Tests for invite-related gRPC handlers.

use super::super::common::*;
use zopp_proto::zopp_service_server::ZoppService;
use zopp_storage::{Store, *};

#[tokio::test]
async fn handler_create_and_list_invites() {
    let server = create_test_server().await;
    let (user_id, principal_id, signing_key) =
        create_test_user(&server, "test@example.com", "laptop").await;

    let ws_id = create_test_workspace(&server, &user_id, "ws").await;

    // Set principal wrapping so keys can be retrieved
    server
        .store
        .add_workspace_principal(&AddWorkspacePrincipalParams {
            workspace_id: ws_id.clone(),
            principal_id: principal_id.clone(),
            ephemeral_pub: vec![0u8; 32],
            kek_wrapped: vec![0u8; 48],
            kek_nonce: vec![0u8; 24],
        })
        .await
        .unwrap();

    // Create invite (need to compute token hash)
    let invite_secret = [42u8; 32];
    let token_hash = hex::encode(zopp_crypto::hash_sha256(&invite_secret));

    let request = create_signed_request(
        &principal_id,
        &signing_key,
        "/zopp.ZoppService/CreateInvite",
        zopp_proto::CreateInviteRequest {
            workspace_ids: vec![ws_id.0.to_string()],
            expires_at: chrono::Utc::now().timestamp() + 3600,
            token: token_hash.clone(),
            kek_encrypted: vec![0u8; 48],
            kek_nonce: vec![0u8; 24],
        },
    );

    let response = server.create_invite(request).await.unwrap().into_inner();
    assert_eq!(response.token, token_hash);

    // List invites
    let list_request = create_signed_request(
        &principal_id,
        &signing_key,
        "/zopp.ZoppService/ListInvites",
        zopp_proto::Empty {},
    );

    let list_response = server
        .list_invites(list_request)
        .await
        .unwrap()
        .into_inner();
    assert!(!list_response.invites.is_empty());
}
