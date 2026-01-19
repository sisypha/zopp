use chrono::{Duration, Utc};
use zopp_storage::{
    AddWorkspacePrincipalParams, CreateEnvParams, CreateGroupParams, CreateInviteParams,
    CreatePrincipalData, CreatePrincipalParams, CreateProjectParams, CreateUserParams,
    CreateWorkspaceParams, EnvName, EnvironmentId, GroupId, PrincipalId, ProjectId, ProjectName,
    Role, Store, StoreError, UserId, WorkspaceId,
};
use zopp_store_sqlite::SqliteStore;

fn workspace_params(owner_user_id: UserId, name: &str) -> CreateWorkspaceParams {
    CreateWorkspaceParams {
        id: WorkspaceId(uuid::Uuid::now_v7()),
        name: name.to_string(),
        owner_user_id,
        kdf_salt: b"0123456789abcdef".to_vec(),
        m_cost_kib: 64 * 1024,
        t_cost: 3,
        p_cost: 1,
    }
}

#[tokio::test]
async fn end_to_end_happy_path_and_updates() {
    let s = SqliteStore::open_in_memory().await.unwrap();

    // Create user first
    let (user_id, _) = s
        .create_user(&CreateUserParams {
            email: "test@example.com".to_string(),
            principal: None,
            workspace_ids: vec![],
        })
        .await
        .unwrap();

    // workspace + project + env
    let ws = s
        .create_workspace(&workspace_params(user_id, "test-workspace"))
        .await
        .unwrap();
    let p = ProjectName("p1".into());
    let e = EnvName("prod".into());
    let project_id = s
        .create_project(&CreateProjectParams {
            workspace_id: ws.clone(),
            name: p.0.clone(),
        })
        .await
        .unwrap();

    let dek_wrapped = vec![1, 2, 3, 4];
    let dek_nonce = vec![9u8; 24];
    let env_id = s
        .create_env(&CreateEnvParams {
            project_id: project_id.clone(),
            name: e.0.clone(),
            dek_wrapped: dek_wrapped.clone(),
            dek_nonce: dek_nonce.clone(),
        })
        .await
        .unwrap();

    // env wrap round-trip (legacy name-based method)
    let (got_wrap, got_nonce) = s.get_env_wrap(&ws, &p, &e).await.unwrap();
    assert_eq!(got_wrap, dek_wrapped);
    assert_eq!(got_nonce, dek_nonce);

    // secret upsert + read
    let k = "DB_PASSWORD";
    let nonce = vec![7u8; 24];
    let ct1 = vec![8u8; 32];

    s.upsert_secret(&env_id, k, &nonce, &ct1).await.unwrap();
    let row1 = s.get_secret(&env_id, k).await.unwrap();
    assert_eq!(row1.nonce, nonce);
    assert_eq!(row1.ciphertext, ct1);

    // overwrite same key: new ciphertext should appear
    let ct2 = vec![42u8; 48];
    s.upsert_secret(&env_id, k, &nonce, &ct2).await.unwrap();
    let row2 = s.get_secret(&env_id, k).await.unwrap();
    assert_eq!(
        row2.ciphertext, ct2,
        "upsert should update the value in-place"
    );

    // add a few more keys out-of-order and verify sorted listing
    s.upsert_secret(&env_id, "z_last", &nonce, b"Z")
        .await
        .unwrap();
    s.upsert_secret(&env_id, "a_first", &nonce, b"A")
        .await
        .unwrap();
    s.upsert_secret(&env_id, "m_middle", &nonce, b"M")
        .await
        .unwrap();

    let keys = s.list_secret_keys(&env_id).await.unwrap();
    assert_eq!(keys, vec!["DB_PASSWORD", "a_first", "m_middle", "z_last"]);
}

#[tokio::test]
async fn workspace_isolation_end_to_end() {
    let s = SqliteStore::open_in_memory().await.unwrap();

    let (user_id, _) = s
        .create_user(&CreateUserParams {
            email: "test@example.com".to_string(),
            principal: None,
            workspace_ids: vec![],
        })
        .await
        .unwrap();

    let ws1 = s
        .create_workspace(&workspace_params(user_id.clone(), "test-workspace-1"))
        .await
        .unwrap();
    let ws2 = s
        .create_workspace(&workspace_params(user_id, "test-workspace-2"))
        .await
        .unwrap();

    let p = ProjectName("app".into());
    let e = EnvName("prod".into());

    // same names in both workspaces
    let project_id1 = s
        .create_project(&CreateProjectParams {
            workspace_id: ws1.clone(),
            name: p.0.clone(),
        })
        .await
        .unwrap();
    let env_id1 = s
        .create_env(&CreateEnvParams {
            project_id: project_id1,
            name: e.0.clone(),
            dek_wrapped: vec![1],
            dek_nonce: vec![9; 24],
        })
        .await
        .unwrap();

    let project_id2 = s
        .create_project(&CreateProjectParams {
            workspace_id: ws2.clone(),
            name: p.0.clone(),
        })
        .await
        .unwrap();
    let env_id2 = s
        .create_env(&CreateEnvParams {
            project_id: project_id2,
            name: e.0.clone(),
            dek_wrapped: vec![2],
            dek_nonce: vec![9; 24],
        })
        .await
        .unwrap();

    // only write secret in env1
    s.upsert_secret(&env_id1, "TOKEN", &[7; 24], &[1; 8])
        .await
        .unwrap();

    // env2 cannot read env1's data
    let err = s.get_secret(&env_id2, "TOKEN").await.unwrap_err();
    matches!(err, StoreError::NotFound);
}

#[tokio::test]
async fn common_error_mapping_paths() {
    let s = SqliteStore::open_in_memory().await.unwrap();

    let (user_id, _) = s
        .create_user(&CreateUserParams {
            email: "test@example.com".to_string(),
            principal: None,
            workspace_ids: vec![],
        })
        .await
        .unwrap();

    let ws = s
        .create_workspace(&workspace_params(user_id, "test-workspace"))
        .await
        .unwrap();
    let p = ProjectName("dup".into());

    // Duplicate project → AlreadyExists
    s.create_project(&CreateProjectParams {
        workspace_id: ws.clone(),
        name: p.0.clone(),
    })
    .await
    .unwrap();
    let err = s
        .create_project(&CreateProjectParams {
            workspace_id: ws.clone(),
            name: p.0.clone(),
        })
        .await
        .unwrap_err();
    matches!(err, StoreError::AlreadyExists);

    // Reading a secret from a non-existent environment → NotFound
    let fake_env_id = EnvironmentId(uuid::Uuid::new_v4());
    let err = s.get_secret(&fake_env_id, "NOPE").await.unwrap_err();
    matches!(err, StoreError::NotFound);
}

#[tokio::test]
async fn project_crud_operations() {
    let s = SqliteStore::open_in_memory().await.unwrap();

    // Create user and workspace
    let (user_id, _) = s
        .create_user(&CreateUserParams {
            email: "test@example.com".to_string(),
            principal: None,
            workspace_ids: vec![],
        })
        .await
        .unwrap();

    let ws = s
        .create_workspace(&workspace_params(user_id, "test-workspace"))
        .await
        .unwrap();

    // Test create_project returns ProjectId
    let project_id = s
        .create_project(&CreateProjectParams {
            workspace_id: ws.clone(),
            name: "api".to_string(),
        })
        .await
        .unwrap();

    // Test get_project
    let project = s.get_project(&project_id).await.unwrap();
    assert_eq!(project.id, project_id);
    assert_eq!(project.workspace_id, ws);
    assert_eq!(project.name, "api");

    // Test list_projects with one project
    let projects = s.list_projects(&ws).await.unwrap();
    assert_eq!(projects.len(), 1);
    assert_eq!(projects[0].name, "api");

    // Create more projects
    let project_id2 = s
        .create_project(&CreateProjectParams {
            workspace_id: ws.clone(),
            name: "frontend".to_string(),
        })
        .await
        .unwrap();

    let _project_id3 = s
        .create_project(&CreateProjectParams {
            workspace_id: ws.clone(),
            name: "mobile".to_string(),
        })
        .await
        .unwrap();

    // Test list_projects with multiple projects
    let projects = s.list_projects(&ws).await.unwrap();
    assert_eq!(projects.len(), 3);
    // Projects are ordered by created_at DESC, but they may have same timestamp
    // Just verify all three are present
    let project_names: Vec<String> = projects.iter().map(|p| p.name.clone()).collect();
    assert!(project_names.contains(&"api".to_string()));
    assert!(project_names.contains(&"frontend".to_string()));
    assert!(project_names.contains(&"mobile".to_string()));

    // Test delete_project
    s.delete_project(&project_id2).await.unwrap();

    let projects = s.list_projects(&ws).await.unwrap();
    assert_eq!(projects.len(), 2);
    let project_names: Vec<String> = projects.iter().map(|p| p.name.clone()).collect();
    assert!(project_names.contains(&"api".to_string()));
    assert!(project_names.contains(&"mobile".to_string()));
    assert!(!project_names.contains(&"frontend".to_string()));

    // Test deleting non-existent project returns NotFound
    let fake_id = ProjectId(uuid::Uuid::new_v4());
    let err = s.delete_project(&fake_id).await.unwrap_err();
    matches!(err, StoreError::NotFound);

    // Test getting non-existent project returns NotFound
    let err = s.get_project(&fake_id).await.unwrap_err();
    matches!(err, StoreError::NotFound);

    // Test duplicate project name in same workspace returns AlreadyExists
    let err = s
        .create_project(&CreateProjectParams {
            workspace_id: ws.clone(),
            name: "api".to_string(),
        })
        .await
        .unwrap_err();
    matches!(err, StoreError::AlreadyExists);
}

#[tokio::test]
async fn project_isolation_across_workspaces() {
    let s = SqliteStore::open_in_memory().await.unwrap();

    // Create user and two workspaces
    let (user_id, _) = s
        .create_user(&CreateUserParams {
            email: "test@example.com".to_string(),
            principal: None,
            workspace_ids: vec![],
        })
        .await
        .unwrap();

    let ws1 = s
        .create_workspace(&workspace_params(user_id.clone(), "test-workspace-1"))
        .await
        .unwrap();

    let ws2 = s
        .create_workspace(&workspace_params(user_id, "test-workspace-2"))
        .await
        .unwrap();

    // Create project with same name in both workspaces
    let project_id1 = s
        .create_project(&CreateProjectParams {
            workspace_id: ws1.clone(),
            name: "api".to_string(),
        })
        .await
        .unwrap();

    let project_id2 = s
        .create_project(&CreateProjectParams {
            workspace_id: ws2.clone(),
            name: "api".to_string(),
        })
        .await
        .unwrap();

    // Projects should have different IDs
    assert_ne!(project_id1, project_id2);

    // Each workspace should only see its own project
    let ws1_projects = s.list_projects(&ws1).await.unwrap();
    assert_eq!(ws1_projects.len(), 1);
    assert_eq!(ws1_projects[0].id, project_id1);

    let ws2_projects = s.list_projects(&ws2).await.unwrap();
    assert_eq!(ws2_projects.len(), 1);
    assert_eq!(ws2_projects[0].id, project_id2);
}

#[tokio::test]
async fn environment_crud_operations() {
    let s = SqliteStore::open_in_memory().await.unwrap();

    // Create user, workspace, and project
    let (user_id, _) = s
        .create_user(&CreateUserParams {
            email: "test@example.com".to_string(),
            principal: None,
            workspace_ids: vec![],
        })
        .await
        .unwrap();

    let ws = s
        .create_workspace(&workspace_params(user_id, "test-workspace"))
        .await
        .unwrap();

    let project_id = s
        .create_project(&CreateProjectParams {
            workspace_id: ws.clone(),
            name: "api".to_string(),
        })
        .await
        .unwrap();

    // Test create_env returns EnvironmentId
    let env_id = s
        .create_env(&CreateEnvParams {
            project_id: project_id.clone(),
            name: "production".to_string(),
            dek_wrapped: vec![1, 2, 3],
            dek_nonce: vec![9; 24],
        })
        .await
        .unwrap();

    // Test get_environment
    let env = s.get_environment(&env_id).await.unwrap();
    assert_eq!(env.id, env_id);
    assert_eq!(env.project_id, project_id);
    assert_eq!(env.name, "production");
    assert_eq!(env.dek_wrapped, vec![1, 2, 3]);
    assert_eq!(env.dek_nonce, vec![9; 24]);

    // Test list_environments with one environment
    let envs = s.list_environments(&project_id).await.unwrap();
    assert_eq!(envs.len(), 1);
    assert_eq!(envs[0].name, "production");

    // Create more environments
    let env_id2 = s
        .create_env(&CreateEnvParams {
            project_id: project_id.clone(),
            name: "staging".to_string(),
            dek_wrapped: vec![4, 5, 6],
            dek_nonce: vec![8; 24],
        })
        .await
        .unwrap();

    let _env_id3 = s
        .create_env(&CreateEnvParams {
            project_id: project_id.clone(),
            name: "development".to_string(),
            dek_wrapped: vec![7, 8, 9],
            dek_nonce: vec![7; 24],
        })
        .await
        .unwrap();

    // Test list_environments with multiple environments
    let envs = s.list_environments(&project_id).await.unwrap();
    assert_eq!(envs.len(), 3);
    let env_names: Vec<String> = envs.iter().map(|e| e.name.clone()).collect();
    assert!(env_names.contains(&"production".to_string()));
    assert!(env_names.contains(&"staging".to_string()));
    assert!(env_names.contains(&"development".to_string()));

    // Test delete_environment
    s.delete_environment(&env_id2).await.unwrap();

    let envs = s.list_environments(&project_id).await.unwrap();
    assert_eq!(envs.len(), 2);
    let env_names: Vec<String> = envs.iter().map(|e| e.name.clone()).collect();
    assert!(env_names.contains(&"production".to_string()));
    assert!(env_names.contains(&"development".to_string()));
    assert!(!env_names.contains(&"staging".to_string()));

    // Test deleting non-existent environment returns NotFound
    let fake_id = EnvironmentId(uuid::Uuid::new_v4());
    let err = s.delete_environment(&fake_id).await.unwrap_err();
    matches!(err, StoreError::NotFound);

    // Test getting non-existent environment returns NotFound
    let err = s.get_environment(&fake_id).await.unwrap_err();
    matches!(err, StoreError::NotFound);

    // Test duplicate environment name in same project returns AlreadyExists
    let err = s
        .create_env(&CreateEnvParams {
            project_id: project_id.clone(),
            name: "production".to_string(),
            dek_wrapped: vec![1, 2, 3],
            dek_nonce: vec![9; 24],
        })
        .await
        .unwrap_err();
    matches!(err, StoreError::AlreadyExists);
}

#[tokio::test]
async fn environment_isolation_across_projects() {
    let s = SqliteStore::open_in_memory().await.unwrap();

    // Create user and workspace
    let (user_id, _) = s
        .create_user(&CreateUserParams {
            email: "test@example.com".to_string(),
            principal: None,
            workspace_ids: vec![],
        })
        .await
        .unwrap();

    let ws = s
        .create_workspace(&workspace_params(user_id, "test-workspace"))
        .await
        .unwrap();

    // Create two projects
    let project_id1 = s
        .create_project(&CreateProjectParams {
            workspace_id: ws.clone(),
            name: "api".to_string(),
        })
        .await
        .unwrap();

    let project_id2 = s
        .create_project(&CreateProjectParams {
            workspace_id: ws.clone(),
            name: "web".to_string(),
        })
        .await
        .unwrap();

    // Create environment with same name in both projects
    let env_id1 = s
        .create_env(&CreateEnvParams {
            project_id: project_id1.clone(),
            name: "production".to_string(),
            dek_wrapped: vec![1],
            dek_nonce: vec![9; 24],
        })
        .await
        .unwrap();

    let env_id2 = s
        .create_env(&CreateEnvParams {
            project_id: project_id2.clone(),
            name: "production".to_string(),
            dek_wrapped: vec![2],
            dek_nonce: vec![8; 24],
        })
        .await
        .unwrap();

    // Environments should have different IDs
    assert_ne!(env_id1, env_id2);

    // Each project should only see its own environment
    let proj1_envs = s.list_environments(&project_id1).await.unwrap();
    assert_eq!(proj1_envs.len(), 1);
    assert_eq!(proj1_envs[0].id, env_id1);
    assert_eq!(proj1_envs[0].dek_wrapped, vec![1]);

    let proj2_envs = s.list_environments(&project_id2).await.unwrap();
    assert_eq!(proj2_envs.len(), 1);
    assert_eq!(proj2_envs[0].id, env_id2);
    assert_eq!(proj2_envs[0].dek_wrapped, vec![2]);
}

// ==================== Principal Tests ====================

#[tokio::test]
async fn principal_crud_operations() {
    let s = SqliteStore::open_in_memory().await.unwrap();

    // Create user first
    let (user_id, _) = s
        .create_user(&CreateUserParams {
            email: "test@example.com".to_string(),
            principal: None,
            workspace_ids: vec![],
        })
        .await
        .unwrap();

    // Create principal
    let principal_id = s
        .create_principal(&CreatePrincipalParams {
            user_id: Some(user_id.clone()),
            name: "my-laptop".to_string(),
            public_key: vec![1; 32],
            x25519_public_key: Some(vec![2; 32]),
        })
        .await
        .unwrap();

    // Get principal
    let principal = s.get_principal(&principal_id).await.unwrap();
    assert_eq!(principal.id, principal_id);
    assert_eq!(principal.user_id, Some(user_id.clone()));
    assert_eq!(principal.name, "my-laptop");
    assert_eq!(principal.public_key, vec![1; 32]);
    assert_eq!(principal.x25519_public_key, Some(vec![2; 32]));

    // List principals for user
    let principals = s.list_principals(&user_id).await.unwrap();
    assert_eq!(principals.len(), 1);
    assert_eq!(principals[0].name, "my-laptop");

    // Create another principal
    let _principal_id2 = s
        .create_principal(&CreatePrincipalParams {
            user_id: Some(user_id.clone()),
            name: "my-phone".to_string(),
            public_key: vec![3; 32],
            x25519_public_key: Some(vec![4; 32]),
        })
        .await
        .unwrap();

    // List should show both
    let principals = s.list_principals(&user_id).await.unwrap();
    assert_eq!(principals.len(), 2);

    // Rename principal
    s.rename_principal(&principal_id, "renamed-laptop")
        .await
        .unwrap();
    let principal = s.get_principal(&principal_id).await.unwrap();
    assert_eq!(principal.name, "renamed-laptop");

    // Get non-existent principal
    let fake_id = PrincipalId(uuid::Uuid::new_v4());
    let err = s.get_principal(&fake_id).await.unwrap_err();
    assert!(matches!(err, StoreError::NotFound));

    // Rename non-existent principal
    let err = s.rename_principal(&fake_id, "nope").await.unwrap_err();
    assert!(matches!(err, StoreError::NotFound));
}

#[tokio::test]
async fn create_user_with_principal_atomically() {
    let s = SqliteStore::open_in_memory().await.unwrap();

    // Create user with principal in one transaction
    let (user_id, principal_id) = s
        .create_user(&CreateUserParams {
            email: "atomic@example.com".to_string(),
            principal: Some(CreatePrincipalData {
                name: "default-device".to_string(),
                public_key: vec![5; 32],
                x25519_public_key: Some(vec![6; 32]),
                is_service: false,
            }),
            workspace_ids: vec![],
        })
        .await
        .unwrap();

    assert!(principal_id.is_some());
    let principal_id = principal_id.unwrap();

    // Verify principal was created
    let principal = s.get_principal(&principal_id).await.unwrap();
    assert_eq!(principal.user_id, Some(user_id.clone()));
    assert_eq!(principal.name, "default-device");

    // Verify user was created
    let user = s.get_user_by_id(&user_id).await.unwrap();
    assert_eq!(user.email, "atomic@example.com");
}

#[tokio::test]
async fn service_principal_without_user() {
    let s = SqliteStore::open_in_memory().await.unwrap();

    // Create service principal (no user_id)
    let principal_id = s
        .create_principal(&CreatePrincipalParams {
            user_id: None,
            name: "ci-service".to_string(),
            public_key: vec![7; 32],
            x25519_public_key: Some(vec![8; 32]),
        })
        .await
        .unwrap();

    let principal = s.get_principal(&principal_id).await.unwrap();
    assert_eq!(principal.user_id, None);
    assert_eq!(principal.name, "ci-service");
}

// ==================== Invite Tests ====================

#[tokio::test]
async fn invite_crud_operations() {
    let s = SqliteStore::open_in_memory().await.unwrap();

    // Create user and workspace
    let (user_id, _) = s
        .create_user(&CreateUserParams {
            email: "test@example.com".to_string(),
            principal: None,
            workspace_ids: vec![],
        })
        .await
        .unwrap();

    let ws = s
        .create_workspace(&workspace_params(user_id.clone(), "test-workspace"))
        .await
        .unwrap();

    // Create invite
    let expires_at = Utc::now() + Duration::days(7);
    let invite = s
        .create_invite(&CreateInviteParams {
            workspace_ids: vec![ws.clone()],
            token: "hashed-token-123".to_string(),
            kek_encrypted: Some(vec![1, 2, 3]),
            kek_nonce: Some(vec![9; 24]),
            expires_at,
            created_by_user_id: Some(user_id.clone()),
        })
        .await
        .unwrap();

    assert_eq!(invite.token, "hashed-token-123");
    assert_eq!(invite.workspace_ids, vec![ws.clone()]);
    assert_eq!(invite.kek_encrypted, Some(vec![1, 2, 3]));
    assert_eq!(invite.created_by_user_id, Some(user_id.clone()));

    // Get invite by token
    let fetched = s.get_invite_by_token("hashed-token-123").await.unwrap();
    assert_eq!(fetched.id, invite.id);

    // List invites for user
    let invites = s.list_invites(Some(user_id.clone())).await.unwrap();
    assert_eq!(invites.len(), 1);

    // Create server invite (no user)
    let server_invite = s
        .create_invite(&CreateInviteParams {
            workspace_ids: vec![],
            token: "server-invite".to_string(),
            kek_encrypted: None,
            kek_nonce: None,
            expires_at: Utc::now() + Duration::days(1),
            created_by_user_id: None,
        })
        .await
        .unwrap();

    // List server invites
    let server_invites = s.list_invites(None).await.unwrap();
    assert_eq!(server_invites.len(), 1);
    assert_eq!(server_invites[0].id, server_invite.id);

    // Revoke invite
    s.revoke_invite(&invite.id).await.unwrap();

    // Should no longer be found
    let err = s.get_invite_by_token("hashed-token-123").await.unwrap_err();
    assert!(matches!(err, StoreError::NotFound));

    // List should be empty now
    let invites = s.list_invites(Some(user_id)).await.unwrap();
    assert_eq!(invites.len(), 0);
}

// ==================== Workspace Principal Tests ====================

#[tokio::test]
async fn workspace_principal_wrapping() {
    let s = SqliteStore::open_in_memory().await.unwrap();

    // Create user, principal, and workspace
    let (user_id, _) = s
        .create_user(&CreateUserParams {
            email: "test@example.com".to_string(),
            principal: None,
            workspace_ids: vec![],
        })
        .await
        .unwrap();

    let principal_id = s
        .create_principal(&CreatePrincipalParams {
            user_id: Some(user_id.clone()),
            name: "my-device".to_string(),
            public_key: vec![1; 32],
            x25519_public_key: Some(vec![2; 32]),
        })
        .await
        .unwrap();

    let ws = s
        .create_workspace(&workspace_params(user_id.clone(), "test-workspace"))
        .await
        .unwrap();

    // Add principal to workspace with wrapped KEK
    s.add_workspace_principal(&AddWorkspacePrincipalParams {
        workspace_id: ws.clone(),
        principal_id: principal_id.clone(),
        ephemeral_pub: vec![10; 32],
        kek_wrapped: vec![20; 48],
        kek_nonce: vec![30; 24],
    })
    .await
    .unwrap();

    // Get workspace principal
    let wp = s.get_workspace_principal(&ws, &principal_id).await.unwrap();
    assert_eq!(wp.workspace_id, ws);
    assert_eq!(wp.principal_id, principal_id);
    assert_eq!(wp.ephemeral_pub, vec![10; 32]);
    assert_eq!(wp.kek_wrapped, vec![20; 48]);
    assert_eq!(wp.kek_nonce, vec![30; 24]);

    // List workspace principals
    let principals = s.list_workspace_principals(&ws).await.unwrap();
    assert_eq!(principals.len(), 1);

    // Add another principal
    let principal_id2 = s
        .create_principal(&CreatePrincipalParams {
            user_id: Some(user_id.clone()),
            name: "second-device".to_string(),
            public_key: vec![3; 32],
            x25519_public_key: Some(vec![4; 32]),
        })
        .await
        .unwrap();

    s.add_workspace_principal(&AddWorkspacePrincipalParams {
        workspace_id: ws.clone(),
        principal_id: principal_id2.clone(),
        ephemeral_pub: vec![11; 32],
        kek_wrapped: vec![21; 48],
        kek_nonce: vec![31; 24],
    })
    .await
    .unwrap();

    let principals = s.list_workspace_principals(&ws).await.unwrap();
    assert_eq!(principals.len(), 2);

    // Remove principal from workspace
    s.remove_workspace_principal(&ws, &principal_id)
        .await
        .unwrap();

    let principals = s.list_workspace_principals(&ws).await.unwrap();
    assert_eq!(principals.len(), 1);
    assert_eq!(principals[0].principal_id, principal_id2);

    // Getting removed principal should fail
    let err = s
        .get_workspace_principal(&ws, &principal_id)
        .await
        .unwrap_err();
    assert!(matches!(err, StoreError::NotFound));
}

// ==================== Group Tests ====================

#[tokio::test]
async fn group_crud_operations() {
    let s = SqliteStore::open_in_memory().await.unwrap();

    // Create user and workspace
    let (user_id, _) = s
        .create_user(&CreateUserParams {
            email: "test@example.com".to_string(),
            principal: None,
            workspace_ids: vec![],
        })
        .await
        .unwrap();

    let ws = s
        .create_workspace(&workspace_params(user_id.clone(), "test-workspace"))
        .await
        .unwrap();

    // Create group
    let group_id = s
        .create_group(&CreateGroupParams {
            workspace_id: ws.clone(),
            name: "developers".to_string(),
            description: Some("Dev team".to_string()),
        })
        .await
        .unwrap();

    // Get group by ID
    let group = s.get_group(&group_id).await.unwrap();
    assert_eq!(group.name, "developers");
    assert_eq!(group.description, Some("Dev team".to_string()));
    assert_eq!(group.workspace_id, ws);

    // Get group by name
    let group = s.get_group_by_name(&ws, "developers").await.unwrap();
    assert_eq!(group.id, group_id);

    // List groups
    let groups = s.list_groups(&ws).await.unwrap();
    assert_eq!(groups.len(), 1);

    // Create more groups
    let group_id2 = s
        .create_group(&CreateGroupParams {
            workspace_id: ws.clone(),
            name: "admins".to_string(),
            description: None,
        })
        .await
        .unwrap();

    let groups = s.list_groups(&ws).await.unwrap();
    assert_eq!(groups.len(), 2);

    // Update group
    s.update_group(
        &group_id,
        "senior-developers",
        Some("Senior dev team".to_string()),
    )
    .await
    .unwrap();
    let group = s.get_group(&group_id).await.unwrap();
    assert_eq!(group.name, "senior-developers");
    assert_eq!(group.description, Some("Senior dev team".to_string()));

    // Delete group
    s.delete_group(&group_id2).await.unwrap();
    let groups = s.list_groups(&ws).await.unwrap();
    assert_eq!(groups.len(), 1);

    // Get non-existent group
    let fake_id = GroupId(uuid::Uuid::new_v4());
    let err = s.get_group(&fake_id).await.unwrap_err();
    assert!(matches!(err, StoreError::NotFound));

    // Duplicate group name
    let err = s
        .create_group(&CreateGroupParams {
            workspace_id: ws.clone(),
            name: "senior-developers".to_string(),
            description: None,
        })
        .await
        .unwrap_err();
    assert!(matches!(err, StoreError::AlreadyExists));
}

#[tokio::test]
async fn group_membership_operations() {
    let s = SqliteStore::open_in_memory().await.unwrap();

    // Create users and workspace
    let (user_id1, _) = s
        .create_user(&CreateUserParams {
            email: "user1@example.com".to_string(),
            principal: None,
            workspace_ids: vec![],
        })
        .await
        .unwrap();

    let (user_id2, _) = s
        .create_user(&CreateUserParams {
            email: "user2@example.com".to_string(),
            principal: None,
            workspace_ids: vec![],
        })
        .await
        .unwrap();

    let ws = s
        .create_workspace(&workspace_params(user_id1.clone(), "test-workspace"))
        .await
        .unwrap();

    // Create group
    let group_id = s
        .create_group(&CreateGroupParams {
            workspace_id: ws.clone(),
            name: "team".to_string(),
            description: None,
        })
        .await
        .unwrap();

    // Add members
    s.add_group_member(&group_id, &user_id1).await.unwrap();
    s.add_group_member(&group_id, &user_id2).await.unwrap();

    // List members
    let members = s.list_group_members(&group_id).await.unwrap();
    assert_eq!(members.len(), 2);

    // List user's groups
    let groups = s.list_user_groups(&user_id1).await.unwrap();
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].id, group_id);

    // Remove member
    s.remove_group_member(&group_id, &user_id2).await.unwrap();
    let members = s.list_group_members(&group_id).await.unwrap();
    assert_eq!(members.len(), 1);

    // User2 should no longer be in any groups
    let groups = s.list_user_groups(&user_id2).await.unwrap();
    assert_eq!(groups.len(), 0);
}

// ==================== Permission Tests (Principal) ====================

#[tokio::test]
async fn workspace_permission_operations() {
    let s = SqliteStore::open_in_memory().await.unwrap();

    // Setup
    let (user_id, _) = s
        .create_user(&CreateUserParams {
            email: "test@example.com".to_string(),
            principal: None,
            workspace_ids: vec![],
        })
        .await
        .unwrap();

    let principal_id = s
        .create_principal(&CreatePrincipalParams {
            user_id: Some(user_id.clone()),
            name: "device".to_string(),
            public_key: vec![1; 32],
            x25519_public_key: None,
        })
        .await
        .unwrap();

    let ws = s
        .create_workspace(&workspace_params(user_id.clone(), "test-workspace"))
        .await
        .unwrap();

    // Set workspace permission
    s.set_workspace_permission(&ws, &principal_id, Role::Admin)
        .await
        .unwrap();

    // Get permission
    let role = s
        .get_workspace_permission(&ws, &principal_id)
        .await
        .unwrap();
    assert_eq!(role, Role::Admin);

    // Update permission
    s.set_workspace_permission(&ws, &principal_id, Role::Read)
        .await
        .unwrap();
    let role = s
        .get_workspace_permission(&ws, &principal_id)
        .await
        .unwrap();
    assert_eq!(role, Role::Read);

    // List permissions for principal
    let perms = s
        .list_workspace_permissions_for_principal(&principal_id)
        .await
        .unwrap();
    assert_eq!(perms.len(), 1);
    assert_eq!(perms[0].role, Role::Read);

    // List all workspace permissions
    let perms = s.list_workspace_permissions(&ws).await.unwrap();
    assert_eq!(perms.len(), 1);

    // Remove permission
    s.remove_workspace_permission(&ws, &principal_id)
        .await
        .unwrap();
    let err = s
        .get_workspace_permission(&ws, &principal_id)
        .await
        .unwrap_err();
    assert!(matches!(err, StoreError::NotFound));
}

#[tokio::test]
async fn project_permission_operations() {
    let s = SqliteStore::open_in_memory().await.unwrap();

    // Setup
    let (user_id, _) = s
        .create_user(&CreateUserParams {
            email: "test@example.com".to_string(),
            principal: None,
            workspace_ids: vec![],
        })
        .await
        .unwrap();

    let principal_id = s
        .create_principal(&CreatePrincipalParams {
            user_id: Some(user_id.clone()),
            name: "device".to_string(),
            public_key: vec![1; 32],
            x25519_public_key: None,
        })
        .await
        .unwrap();

    let ws = s
        .create_workspace(&workspace_params(user_id.clone(), "test-workspace"))
        .await
        .unwrap();

    let project_id = s
        .create_project(&CreateProjectParams {
            workspace_id: ws.clone(),
            name: "api".to_string(),
        })
        .await
        .unwrap();

    // Set project permission
    s.set_project_permission(&project_id, &principal_id, Role::Write)
        .await
        .unwrap();

    // Get permission
    let role = s
        .get_project_permission(&project_id, &principal_id)
        .await
        .unwrap();
    assert_eq!(role, Role::Write);

    // List permissions
    let perms = s.list_project_permissions(&project_id).await.unwrap();
    assert_eq!(perms.len(), 1);

    // Remove permission
    s.remove_project_permission(&project_id, &principal_id)
        .await
        .unwrap();
    let err = s
        .get_project_permission(&project_id, &principal_id)
        .await
        .unwrap_err();
    assert!(matches!(err, StoreError::NotFound));
}

#[tokio::test]
async fn environment_permission_operations() {
    let s = SqliteStore::open_in_memory().await.unwrap();

    // Setup
    let (user_id, _) = s
        .create_user(&CreateUserParams {
            email: "test@example.com".to_string(),
            principal: None,
            workspace_ids: vec![],
        })
        .await
        .unwrap();

    let principal_id = s
        .create_principal(&CreatePrincipalParams {
            user_id: Some(user_id.clone()),
            name: "device".to_string(),
            public_key: vec![1; 32],
            x25519_public_key: None,
        })
        .await
        .unwrap();

    let ws = s
        .create_workspace(&workspace_params(user_id.clone(), "test-workspace"))
        .await
        .unwrap();

    let project_id = s
        .create_project(&CreateProjectParams {
            workspace_id: ws.clone(),
            name: "api".to_string(),
        })
        .await
        .unwrap();

    let env_id = s
        .create_env(&CreateEnvParams {
            project_id: project_id.clone(),
            name: "prod".to_string(),
            dek_wrapped: vec![1, 2, 3],
            dek_nonce: vec![9; 24],
        })
        .await
        .unwrap();

    // Set environment permission
    s.set_environment_permission(&env_id, &principal_id, Role::Read)
        .await
        .unwrap();

    // Get permission
    let role = s
        .get_environment_permission(&env_id, &principal_id)
        .await
        .unwrap();
    assert_eq!(role, Role::Read);

    // List permissions
    let perms = s.list_environment_permissions(&env_id).await.unwrap();
    assert_eq!(perms.len(), 1);

    // Remove permission
    s.remove_environment_permission(&env_id, &principal_id)
        .await
        .unwrap();
    let err = s
        .get_environment_permission(&env_id, &principal_id)
        .await
        .unwrap_err();
    assert!(matches!(err, StoreError::NotFound));
}

// ==================== Permission Tests (User) ====================

#[tokio::test]
async fn user_workspace_permission_operations() {
    let s = SqliteStore::open_in_memory().await.unwrap();

    // Setup
    let (user_id, _) = s
        .create_user(&CreateUserParams {
            email: "test@example.com".to_string(),
            principal: None,
            workspace_ids: vec![],
        })
        .await
        .unwrap();

    let ws = s
        .create_workspace(&workspace_params(user_id.clone(), "test-workspace"))
        .await
        .unwrap();

    // Set user workspace permission
    s.set_user_workspace_permission(&ws, &user_id, Role::Admin)
        .await
        .unwrap();

    // Get permission
    let role = s
        .get_user_workspace_permission(&ws, &user_id)
        .await
        .unwrap();
    assert_eq!(role, Role::Admin);

    // List permissions
    let perms = s.list_user_workspace_permissions(&ws).await.unwrap();
    assert_eq!(perms.len(), 1);

    // Remove permission
    s.remove_user_workspace_permission(&ws, &user_id)
        .await
        .unwrap();
    let err = s
        .get_user_workspace_permission(&ws, &user_id)
        .await
        .unwrap_err();
    assert!(matches!(err, StoreError::NotFound));
}

#[tokio::test]
async fn user_project_permission_operations() {
    let s = SqliteStore::open_in_memory().await.unwrap();

    // Setup
    let (user_id, _) = s
        .create_user(&CreateUserParams {
            email: "test@example.com".to_string(),
            principal: None,
            workspace_ids: vec![],
        })
        .await
        .unwrap();

    let ws = s
        .create_workspace(&workspace_params(user_id.clone(), "test-workspace"))
        .await
        .unwrap();

    let project_id = s
        .create_project(&CreateProjectParams {
            workspace_id: ws.clone(),
            name: "api".to_string(),
        })
        .await
        .unwrap();

    // Set user project permission
    s.set_user_project_permission(&project_id, &user_id, Role::Write)
        .await
        .unwrap();

    // Get permission
    let role = s
        .get_user_project_permission(&project_id, &user_id)
        .await
        .unwrap();
    assert_eq!(role, Role::Write);

    // List permissions
    let perms = s.list_user_project_permissions(&project_id).await.unwrap();
    assert_eq!(perms.len(), 1);

    // Remove permission
    s.remove_user_project_permission(&project_id, &user_id)
        .await
        .unwrap();
    let err = s
        .get_user_project_permission(&project_id, &user_id)
        .await
        .unwrap_err();
    assert!(matches!(err, StoreError::NotFound));
}

#[tokio::test]
async fn user_environment_permission_operations() {
    let s = SqliteStore::open_in_memory().await.unwrap();

    // Setup
    let (user_id, _) = s
        .create_user(&CreateUserParams {
            email: "test@example.com".to_string(),
            principal: None,
            workspace_ids: vec![],
        })
        .await
        .unwrap();

    let ws = s
        .create_workspace(&workspace_params(user_id.clone(), "test-workspace"))
        .await
        .unwrap();

    let project_id = s
        .create_project(&CreateProjectParams {
            workspace_id: ws.clone(),
            name: "api".to_string(),
        })
        .await
        .unwrap();

    let env_id = s
        .create_env(&CreateEnvParams {
            project_id: project_id.clone(),
            name: "prod".to_string(),
            dek_wrapped: vec![1, 2, 3],
            dek_nonce: vec![9; 24],
        })
        .await
        .unwrap();

    // Set user environment permission
    s.set_user_environment_permission(&env_id, &user_id, Role::Read)
        .await
        .unwrap();

    // Get permission
    let role = s
        .get_user_environment_permission(&env_id, &user_id)
        .await
        .unwrap();
    assert_eq!(role, Role::Read);

    // List permissions
    let perms = s.list_user_environment_permissions(&env_id).await.unwrap();
    assert_eq!(perms.len(), 1);

    // Remove permission
    s.remove_user_environment_permission(&env_id, &user_id)
        .await
        .unwrap();
    let err = s
        .get_user_environment_permission(&env_id, &user_id)
        .await
        .unwrap_err();
    assert!(matches!(err, StoreError::NotFound));
}

// ==================== Permission Tests (Group) ====================

#[tokio::test]
async fn group_workspace_permission_operations() {
    let s = SqliteStore::open_in_memory().await.unwrap();

    // Setup
    let (user_id, _) = s
        .create_user(&CreateUserParams {
            email: "test@example.com".to_string(),
            principal: None,
            workspace_ids: vec![],
        })
        .await
        .unwrap();

    let ws = s
        .create_workspace(&workspace_params(user_id.clone(), "test-workspace"))
        .await
        .unwrap();

    let group_id = s
        .create_group(&CreateGroupParams {
            workspace_id: ws.clone(),
            name: "developers".to_string(),
            description: None,
        })
        .await
        .unwrap();

    // Set group workspace permission
    s.set_group_workspace_permission(&ws, &group_id, Role::Write)
        .await
        .unwrap();

    // Get permission
    let role = s
        .get_group_workspace_permission(&ws, &group_id)
        .await
        .unwrap();
    assert_eq!(role, Role::Write);

    // List permissions
    let perms = s.list_group_workspace_permissions(&ws).await.unwrap();
    assert_eq!(perms.len(), 1);

    // Remove permission
    s.remove_group_workspace_permission(&ws, &group_id)
        .await
        .unwrap();
    let err = s
        .get_group_workspace_permission(&ws, &group_id)
        .await
        .unwrap_err();
    assert!(matches!(err, StoreError::NotFound));
}

#[tokio::test]
async fn group_project_permission_operations() {
    let s = SqliteStore::open_in_memory().await.unwrap();

    // Setup
    let (user_id, _) = s
        .create_user(&CreateUserParams {
            email: "test@example.com".to_string(),
            principal: None,
            workspace_ids: vec![],
        })
        .await
        .unwrap();

    let ws = s
        .create_workspace(&workspace_params(user_id.clone(), "test-workspace"))
        .await
        .unwrap();

    let project_id = s
        .create_project(&CreateProjectParams {
            workspace_id: ws.clone(),
            name: "api".to_string(),
        })
        .await
        .unwrap();

    let group_id = s
        .create_group(&CreateGroupParams {
            workspace_id: ws.clone(),
            name: "developers".to_string(),
            description: None,
        })
        .await
        .unwrap();

    // Set group project permission
    s.set_group_project_permission(&project_id, &group_id, Role::Admin)
        .await
        .unwrap();

    // Get permission
    let role = s
        .get_group_project_permission(&project_id, &group_id)
        .await
        .unwrap();
    assert_eq!(role, Role::Admin);

    // List permissions
    let perms = s.list_group_project_permissions(&project_id).await.unwrap();
    assert_eq!(perms.len(), 1);

    // Remove permission
    s.remove_group_project_permission(&project_id, &group_id)
        .await
        .unwrap();
    let err = s
        .get_group_project_permission(&project_id, &group_id)
        .await
        .unwrap_err();
    assert!(matches!(err, StoreError::NotFound));
}

#[tokio::test]
async fn group_environment_permission_operations() {
    let s = SqliteStore::open_in_memory().await.unwrap();

    // Setup
    let (user_id, _) = s
        .create_user(&CreateUserParams {
            email: "test@example.com".to_string(),
            principal: None,
            workspace_ids: vec![],
        })
        .await
        .unwrap();

    let ws = s
        .create_workspace(&workspace_params(user_id.clone(), "test-workspace"))
        .await
        .unwrap();

    let project_id = s
        .create_project(&CreateProjectParams {
            workspace_id: ws.clone(),
            name: "api".to_string(),
        })
        .await
        .unwrap();

    let env_id = s
        .create_env(&CreateEnvParams {
            project_id: project_id.clone(),
            name: "prod".to_string(),
            dek_wrapped: vec![1, 2, 3],
            dek_nonce: vec![9; 24],
        })
        .await
        .unwrap();

    let group_id = s
        .create_group(&CreateGroupParams {
            workspace_id: ws.clone(),
            name: "developers".to_string(),
            description: None,
        })
        .await
        .unwrap();

    // Set group environment permission
    s.set_group_environment_permission(&env_id, &group_id, Role::Read)
        .await
        .unwrap();

    // Get permission
    let role = s
        .get_group_environment_permission(&env_id, &group_id)
        .await
        .unwrap();
    assert_eq!(role, Role::Read);

    // List permissions
    let perms = s.list_group_environment_permissions(&env_id).await.unwrap();
    assert_eq!(perms.len(), 1);

    // Remove permission
    s.remove_group_environment_permission(&env_id, &group_id)
        .await
        .unwrap();
    let err = s
        .get_group_environment_permission(&env_id, &group_id)
        .await
        .unwrap_err();
    assert!(matches!(err, StoreError::NotFound));
}

// ==================== Additional Edge Cases ====================

#[tokio::test]
async fn principal_workspace_access() {
    let s = SqliteStore::open_in_memory().await.unwrap();

    // Create user and principal
    let (user_id, _) = s
        .create_user(&CreateUserParams {
            email: "owner@example.com".to_string(),
            principal: None,
            workspace_ids: vec![],
        })
        .await
        .unwrap();

    let principal_id = s
        .create_principal(&CreatePrincipalParams {
            user_id: Some(user_id.clone()),
            name: "device".to_string(),
            public_key: vec![1; 32],
            x25519_public_key: Some(vec![2; 32]),
        })
        .await
        .unwrap();

    let ws = s
        .create_workspace(&workspace_params(user_id.clone(), "test-workspace"))
        .await
        .unwrap();

    // Principal should not see workspace before KEK access is granted
    let workspaces = s.list_workspaces(&principal_id).await.unwrap();
    assert!(
        workspaces.is_empty(),
        "Principal should not see workspace without KEK access"
    );

    // Grant principal KEK access to workspace
    s.add_workspace_principal(&AddWorkspacePrincipalParams {
        workspace_id: ws.clone(),
        principal_id: principal_id.clone(),
        ephemeral_pub: vec![3; 32],
        kek_wrapped: vec![4; 48],
        kek_nonce: vec![5; 24],
    })
    .await
    .unwrap();

    // Principal should now see the workspace
    let workspaces = s.list_workspaces(&principal_id).await.unwrap();
    assert!(
        workspaces.iter().any(|w| w.id == ws),
        "Principal with KEK access should see the workspace"
    );
}

#[tokio::test]
async fn remove_all_permissions_for_principal() {
    let s = SqliteStore::open_in_memory().await.unwrap();

    // Setup
    let (user_id, _) = s
        .create_user(&CreateUserParams {
            email: "test@example.com".to_string(),
            principal: None,
            workspace_ids: vec![],
        })
        .await
        .unwrap();

    let principal_id = s
        .create_principal(&CreatePrincipalParams {
            user_id: Some(user_id.clone()),
            name: "device".to_string(),
            public_key: vec![1; 32],
            x25519_public_key: None,
        })
        .await
        .unwrap();

    let ws = s
        .create_workspace(&workspace_params(user_id.clone(), "test-workspace"))
        .await
        .unwrap();

    let project_id = s
        .create_project(&CreateProjectParams {
            workspace_id: ws.clone(),
            name: "api".to_string(),
        })
        .await
        .unwrap();

    let env_id = s
        .create_env(&CreateEnvParams {
            project_id: project_id.clone(),
            name: "prod".to_string(),
            dek_wrapped: vec![1, 2, 3],
            dek_nonce: vec![9; 24],
        })
        .await
        .unwrap();

    // Set permissions at all levels
    s.set_project_permission(&project_id, &principal_id, Role::Write)
        .await
        .unwrap();
    s.set_environment_permission(&env_id, &principal_id, Role::Read)
        .await
        .unwrap();

    // Remove all project permissions
    let removed = s
        .remove_all_project_permissions_for_principal(&ws, &principal_id)
        .await
        .unwrap();
    assert_eq!(removed, 1);

    // Remove all environment permissions
    let removed = s
        .remove_all_environment_permissions_for_principal(&ws, &principal_id)
        .await
        .unwrap();
    assert_eq!(removed, 1);

    // Verify permissions are gone
    let err = s
        .get_project_permission(&project_id, &principal_id)
        .await
        .unwrap_err();
    assert!(matches!(err, StoreError::NotFound));

    let err = s
        .get_environment_permission(&env_id, &principal_id)
        .await
        .unwrap_err();
    assert!(matches!(err, StoreError::NotFound));
}

#[tokio::test]
async fn get_workspace_by_name_operations() {
    let s = SqliteStore::open_in_memory().await.unwrap();

    // Setup
    let (user_id, principal_id) = s
        .create_user(&CreateUserParams {
            email: "test@example.com".to_string(),
            principal: Some(CreatePrincipalData {
                name: "device".to_string(),
                public_key: vec![1; 32],
                x25519_public_key: Some(vec![2; 32]),
                is_service: false,
            }),
            workspace_ids: vec![],
        })
        .await
        .unwrap();

    let principal_id = principal_id.unwrap();

    let ws = s
        .create_workspace(&workspace_params(user_id.clone(), "my-workspace"))
        .await
        .unwrap();

    // Add principal to workspace
    s.add_workspace_principal(&AddWorkspacePrincipalParams {
        workspace_id: ws.clone(),
        principal_id: principal_id.clone(),
        ephemeral_pub: vec![10; 32],
        kek_wrapped: vec![20; 48],
        kek_nonce: vec![30; 24],
    })
    .await
    .unwrap();

    // Get workspace by name for user
    let workspace = s
        .get_workspace_by_name(&user_id, "my-workspace")
        .await
        .unwrap();
    assert_eq!(workspace.id, ws);

    // Get workspace by name for principal
    let workspace = s
        .get_workspace_by_name_for_principal(&principal_id, "my-workspace")
        .await
        .unwrap();
    assert_eq!(workspace.id, ws);

    // Non-existent workspace
    let err = s
        .get_workspace_by_name(&user_id, "nonexistent")
        .await
        .unwrap_err();
    assert!(matches!(err, StoreError::NotFound));
}

#[tokio::test]
async fn get_project_by_name_operations() {
    let s = SqliteStore::open_in_memory().await.unwrap();

    let (user_id, _) = s
        .create_user(&CreateUserParams {
            email: "test@example.com".to_string(),
            principal: None,
            workspace_ids: vec![],
        })
        .await
        .unwrap();

    let ws = s
        .create_workspace(&workspace_params(user_id.clone(), "workspace"))
        .await
        .unwrap();

    let project_id = s
        .create_project(&CreateProjectParams {
            workspace_id: ws.clone(),
            name: "my-project".to_string(),
        })
        .await
        .unwrap();

    // Get by name
    let project = s.get_project_by_name(&ws, "my-project").await.unwrap();
    assert_eq!(project.id, project_id);

    // Non-existent
    let err = s.get_project_by_name(&ws, "nonexistent").await.unwrap_err();
    assert!(matches!(err, StoreError::NotFound));
}

#[tokio::test]
async fn get_environment_by_name_operations() {
    let s = SqliteStore::open_in_memory().await.unwrap();

    let (user_id, _) = s
        .create_user(&CreateUserParams {
            email: "test@example.com".to_string(),
            principal: None,
            workspace_ids: vec![],
        })
        .await
        .unwrap();

    let ws = s
        .create_workspace(&workspace_params(user_id.clone(), "workspace"))
        .await
        .unwrap();

    let project_id = s
        .create_project(&CreateProjectParams {
            workspace_id: ws.clone(),
            name: "project".to_string(),
        })
        .await
        .unwrap();

    let env_id = s
        .create_env(&CreateEnvParams {
            project_id: project_id.clone(),
            name: "production".to_string(),
            dek_wrapped: vec![1],
            dek_nonce: vec![9; 24],
        })
        .await
        .unwrap();

    // Get by name
    let env = s
        .get_environment_by_name(&project_id, "production")
        .await
        .unwrap();
    assert_eq!(env.id, env_id);

    // Non-existent
    let err = s
        .get_environment_by_name(&project_id, "nonexistent")
        .await
        .unwrap_err();
    assert!(matches!(err, StoreError::NotFound));
}

#[tokio::test]
async fn secret_delete_operations() {
    let s = SqliteStore::open_in_memory().await.unwrap();

    let (user_id, _) = s
        .create_user(&CreateUserParams {
            email: "test@example.com".to_string(),
            principal: None,
            workspace_ids: vec![],
        })
        .await
        .unwrap();

    let ws = s
        .create_workspace(&workspace_params(user_id.clone(), "workspace"))
        .await
        .unwrap();

    let project_id = s
        .create_project(&CreateProjectParams {
            workspace_id: ws.clone(),
            name: "project".to_string(),
        })
        .await
        .unwrap();

    let env_id = s
        .create_env(&CreateEnvParams {
            project_id: project_id.clone(),
            name: "prod".to_string(),
            dek_wrapped: vec![1],
            dek_nonce: vec![9; 24],
        })
        .await
        .unwrap();

    // Add secrets
    s.upsert_secret(&env_id, "KEY1", &[7; 24], &[1; 32])
        .await
        .unwrap();
    s.upsert_secret(&env_id, "KEY2", &[7; 24], &[2; 32])
        .await
        .unwrap();

    // Delete secret
    let version = s.delete_secret(&env_id, "KEY1").await.unwrap();
    assert!(version > 0);

    // Verify it's gone
    let err = s.get_secret(&env_id, "KEY1").await.unwrap_err();
    assert!(matches!(err, StoreError::NotFound));

    // KEY2 still exists
    let secret = s.get_secret(&env_id, "KEY2").await.unwrap();
    assert_eq!(secret.ciphertext, vec![2; 32]);

    // Delete non-existent secret
    let err = s.delete_secret(&env_id, "NONEXISTENT").await.unwrap_err();
    assert!(matches!(err, StoreError::NotFound));
}
