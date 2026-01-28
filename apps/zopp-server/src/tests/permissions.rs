//! Permission checking unit tests.
//!
//! Tests for the permission system including:
//! - Workspace owner permissions
//! - User-level permissions (read, write, admin)
//! - Workspace-level permission inheritance
//! - Principal-level permission restrictions
//! - Service account permissions
//! - Group-based permissions

use super::common::*;
use zopp_storage::*;

// ================== Permission checking tests ==================

#[tokio::test]
async fn check_permission_workspace_owner_has_admin() {
    let server = create_test_server().await;
    let (user_id, principal_id, _) = create_test_user(&server, "owner@example.com", "laptop").await;
    let workspace_id = create_test_workspace(&server, &user_id, "my-workspace").await;
    let project_id = create_test_project(&server, &workspace_id, "my-project").await;
    let env_id = create_test_environment(&server, &project_id, "production").await;

    // Owner should have Admin access even without explicit permissions
    let result = server
        .check_permission(
            &principal_id,
            &workspace_id,
            &project_id,
            &env_id,
            Role::Admin,
        )
        .await;

    assert!(result.is_ok());
}

#[tokio::test]
async fn check_permission_user_permission_read() {
    let server = create_test_server().await;

    // Create owner
    let (owner_user_id, _, _) = create_test_user(&server, "owner@example.com", "laptop").await;
    let workspace_id = create_test_workspace(&server, &owner_user_id, "my-workspace").await;
    let project_id = create_test_project(&server, &workspace_id, "my-project").await;
    let env_id = create_test_environment(&server, &project_id, "production").await;

    // Create another user with Read permission
    let (other_user_id, other_principal_id, _) =
        create_test_user(&server, "other@example.com", "phone").await;

    // Add user to workspace
    server
        .store
        .add_user_to_workspace(&workspace_id, &other_user_id)
        .await
        .unwrap();

    // Grant user Read permission on environment
    server
        .store
        .set_user_environment_permission(&env_id, &other_user_id, Role::Read)
        .await
        .unwrap();

    // Check Read permission - should succeed
    let result = server
        .check_permission(
            &other_principal_id,
            &workspace_id,
            &project_id,
            &env_id,
            Role::Read,
        )
        .await;
    assert!(result.is_ok());

    // Check Write permission - should fail
    let result = server
        .check_permission(
            &other_principal_id,
            &workspace_id,
            &project_id,
            &env_id,
            Role::Write,
        )
        .await;
    assert!(result.is_err());
}

#[tokio::test]
async fn check_permission_user_permission_write() {
    let server = create_test_server().await;

    // Create owner
    let (owner_user_id, _, _) = create_test_user(&server, "owner@example.com", "laptop").await;
    let workspace_id = create_test_workspace(&server, &owner_user_id, "my-workspace").await;
    let project_id = create_test_project(&server, &workspace_id, "my-project").await;
    let env_id = create_test_environment(&server, &project_id, "production").await;

    // Create another user with Write permission
    let (other_user_id, other_principal_id, _) =
        create_test_user(&server, "other@example.com", "phone").await;

    server
        .store
        .add_user_to_workspace(&workspace_id, &other_user_id)
        .await
        .unwrap();
    server
        .store
        .set_user_environment_permission(&env_id, &other_user_id, Role::Write)
        .await
        .unwrap();

    // Check Write permission - should succeed
    let result = server
        .check_permission(
            &other_principal_id,
            &workspace_id,
            &project_id,
            &env_id,
            Role::Write,
        )
        .await;
    assert!(result.is_ok());

    // Check Read permission - should also succeed (Write includes Read)
    let result = server
        .check_permission(
            &other_principal_id,
            &workspace_id,
            &project_id,
            &env_id,
            Role::Read,
        )
        .await;
    assert!(result.is_ok());

    // Check Admin permission - should fail
    let result = server
        .check_permission(
            &other_principal_id,
            &workspace_id,
            &project_id,
            &env_id,
            Role::Admin,
        )
        .await;
    assert!(result.is_err());
}

#[tokio::test]
async fn check_permission_no_permission_denied() {
    let server = create_test_server().await;

    // Create owner
    let (owner_user_id, _, _) = create_test_user(&server, "owner@example.com", "laptop").await;
    let workspace_id = create_test_workspace(&server, &owner_user_id, "my-workspace").await;
    let project_id = create_test_project(&server, &workspace_id, "my-project").await;
    let env_id = create_test_environment(&server, &project_id, "production").await;

    // Create another user without any permissions
    let (_, other_principal_id, _) = create_test_user(&server, "other@example.com", "phone").await;

    // Should be denied
    let result = server
        .check_permission(
            &other_principal_id,
            &workspace_id,
            &project_id,
            &env_id,
            Role::Read,
        )
        .await;
    assert!(result.is_err());
    assert!(result.unwrap_err().message().contains("No permissions"));
}

#[tokio::test]
async fn check_permission_workspace_level_inherits() {
    let server = create_test_server().await;

    // Create owner
    let (owner_user_id, _, _) = create_test_user(&server, "owner@example.com", "laptop").await;
    let workspace_id = create_test_workspace(&server, &owner_user_id, "my-workspace").await;
    let project_id = create_test_project(&server, &workspace_id, "my-project").await;
    let env_id = create_test_environment(&server, &project_id, "production").await;

    // Create another user with workspace-level Write
    let (other_user_id, other_principal_id, _) =
        create_test_user(&server, "other@example.com", "phone").await;

    server
        .store
        .add_user_to_workspace(&workspace_id, &other_user_id)
        .await
        .unwrap();
    server
        .store
        .set_user_workspace_permission(&workspace_id, &other_user_id, Role::Write)
        .await
        .unwrap();

    // Workspace Write should inherit to environment
    let result = server
        .check_permission(
            &other_principal_id,
            &workspace_id,
            &project_id,
            &env_id,
            Role::Write,
        )
        .await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn check_permission_principal_restricts_user() {
    let server = create_test_server().await;

    // Create owner
    let (owner_user_id, _, _) = create_test_user(&server, "owner@example.com", "laptop").await;
    let workspace_id = create_test_workspace(&server, &owner_user_id, "my-workspace").await;
    let project_id = create_test_project(&server, &workspace_id, "my-project").await;
    let env_id = create_test_environment(&server, &project_id, "production").await;

    // Create user with workspace-level Admin
    let (other_user_id, other_principal_id, _) =
        create_test_user(&server, "other@example.com", "phone").await;

    server
        .store
        .add_user_to_workspace(&workspace_id, &other_user_id)
        .await
        .unwrap();
    server
        .store
        .set_user_workspace_permission(&workspace_id, &other_user_id, Role::Admin)
        .await
        .unwrap();

    // Grant principal only Read (this should RESTRICT the effective permission)
    server
        .store
        .set_workspace_permission(&workspace_id, &other_principal_id, Role::Read)
        .await
        .unwrap();

    // Should only have Read despite user having Admin
    // (principal permission acts as ceiling)
    let result = server
        .check_permission(
            &other_principal_id,
            &workspace_id,
            &project_id,
            &env_id,
            Role::Write,
        )
        .await;
    assert!(result.is_err());

    // Read should work
    let result = server
        .check_permission(
            &other_principal_id,
            &workspace_id,
            &project_id,
            &env_id,
            Role::Read,
        )
        .await;
    assert!(result.is_ok());
}

// ================== Service account permission tests ==================

#[tokio::test]
async fn check_permission_service_account_with_permission() {
    let server = create_test_server().await;

    // Create owner
    let (owner_user_id, _, _) = create_test_user(&server, "owner@example.com", "laptop").await;
    let workspace_id = create_test_workspace(&server, &owner_user_id, "my-workspace").await;
    let project_id = create_test_project(&server, &workspace_id, "my-project").await;
    let env_id = create_test_environment(&server, &project_id, "production").await;

    // Create service principal (no user_id)
    let (public_key, _) = generate_keypair();
    let (x25519_public, _) = generate_x25519_keypair();
    let service_principal_id = server
        .store
        .create_principal(&CreatePrincipalParams {
            user_id: None,
            name: "ci-service".to_string(),
            public_key,
            x25519_public_key: Some(x25519_public),
        })
        .await
        .unwrap();

    // Add service principal to workspace
    server
        .store
        .add_workspace_principal(&AddWorkspacePrincipalParams {
            workspace_id: workspace_id.clone(),
            principal_id: service_principal_id.clone(),
            ephemeral_pub: vec![0u8; 32],
            kek_wrapped: vec![0u8; 32],
            kek_nonce: vec![0u8; 24],
        })
        .await
        .unwrap();

    // Grant service principal Write permission
    server
        .store
        .set_workspace_permission(&workspace_id, &service_principal_id, Role::Write)
        .await
        .unwrap();

    // Should have Write access
    let result = server
        .check_permission(
            &service_principal_id,
            &workspace_id,
            &project_id,
            &env_id,
            Role::Write,
        )
        .await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn check_permission_service_account_without_permission() {
    let server = create_test_server().await;

    // Create owner
    let (owner_user_id, _, _) = create_test_user(&server, "owner@example.com", "laptop").await;
    let workspace_id = create_test_workspace(&server, &owner_user_id, "my-workspace").await;
    let project_id = create_test_project(&server, &workspace_id, "my-project").await;
    let env_id = create_test_environment(&server, &project_id, "production").await;

    // Create service principal without any permissions
    let (public_key, _) = generate_keypair();
    let (x25519_public, _) = generate_x25519_keypair();
    let service_principal_id = server
        .store
        .create_principal(&CreatePrincipalParams {
            user_id: None,
            name: "ci-service".to_string(),
            public_key,
            x25519_public_key: Some(x25519_public),
        })
        .await
        .unwrap();

    // Should be denied
    let result = server
        .check_permission(
            &service_principal_id,
            &workspace_id,
            &project_id,
            &env_id,
            Role::Read,
        )
        .await;
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .message()
        .contains("No permissions found for service account"));
}

// ================== check_workspace_permission tests ==================

#[tokio::test]
async fn check_workspace_permission_owner() {
    let server = create_test_server().await;
    let (user_id, principal_id, _) = create_test_user(&server, "owner@example.com", "laptop").await;
    let workspace_id = create_test_workspace(&server, &user_id, "my-workspace").await;

    let result = server
        .check_workspace_permission(&principal_id, &workspace_id, Role::Admin)
        .await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn check_workspace_permission_user_with_permission() {
    let server = create_test_server().await;

    let (owner_user_id, _, _) = create_test_user(&server, "owner@example.com", "laptop").await;
    let workspace_id = create_test_workspace(&server, &owner_user_id, "my-workspace").await;

    let (other_user_id, other_principal_id, _) =
        create_test_user(&server, "other@example.com", "phone").await;

    server
        .store
        .add_user_to_workspace(&workspace_id, &other_user_id)
        .await
        .unwrap();
    server
        .store
        .set_user_workspace_permission(&workspace_id, &other_user_id, Role::Write)
        .await
        .unwrap();

    let result = server
        .check_workspace_permission(&other_principal_id, &workspace_id, Role::Write)
        .await;
    assert!(result.is_ok());
}

// ================== Group permission tests ==================

#[tokio::test]
async fn check_permission_via_group() {
    let server = create_test_server().await;

    // Create owner and workspace
    let (owner_user_id, _, _) = create_test_user(&server, "owner@example.com", "laptop").await;
    let workspace_id = create_test_workspace(&server, &owner_user_id, "my-workspace").await;
    let project_id = create_test_project(&server, &workspace_id, "my-project").await;
    let env_id = create_test_environment(&server, &project_id, "production").await;

    // Create a group
    let group_id = server
        .store
        .create_group(&CreateGroupParams {
            workspace_id: workspace_id.clone(),
            name: "developers".to_string(),
            description: Some("Dev team".to_string()),
        })
        .await
        .unwrap();

    // Create user and add to group
    let (other_user_id, other_principal_id, _) =
        create_test_user(&server, "other@example.com", "phone").await;
    server
        .store
        .add_user_to_workspace(&workspace_id, &other_user_id)
        .await
        .unwrap();
    server
        .store
        .add_group_member(&group_id, &other_user_id)
        .await
        .unwrap();

    // Grant group Write permission on environment
    server
        .store
        .set_group_environment_permission(&env_id, &group_id, Role::Write)
        .await
        .unwrap();

    // User should have Write permission via group
    let result = server
        .check_permission(
            &other_principal_id,
            &workspace_id,
            &project_id,
            &env_id,
            Role::Write,
        )
        .await;
    assert!(result.is_ok());
}
