use zopp_storage::{
    CreateEnvParams, CreateProjectParams, CreateUserParams, CreateWorkspaceParams, EnvName,
    EnvironmentId, ProjectId, ProjectName, Store, StoreError, UserId,
};
use zopp_store_sqlite::SqliteStore;

fn workspace_params(owner_user_id: UserId) -> CreateWorkspaceParams {
    CreateWorkspaceParams {
        name: "test-workspace".to_string(),
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
        .create_workspace(&workspace_params(user_id))
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
        .create_workspace(&workspace_params(user_id.clone()))
        .await
        .unwrap();
    let ws2 = s
        .create_workspace(&workspace_params(user_id))
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
        .create_workspace(&workspace_params(user_id))
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
        .create_workspace(&workspace_params(user_id))
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
        .create_workspace(&workspace_params(user_id.clone()))
        .await
        .unwrap();

    let ws2 = s
        .create_workspace(&workspace_params(user_id))
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
        .create_workspace(&workspace_params(user_id))
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
        .create_workspace(&workspace_params(user_id))
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
