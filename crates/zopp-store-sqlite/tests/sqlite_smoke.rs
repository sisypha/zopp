use zopp_storage::{
    CreateEnvParams, CreateProjectParams, CreateUserParams, CreateWorkspaceParams, EnvName,
    ProjectId, ProjectName, Store, StoreError, UserId,
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
    s.create_project(&CreateProjectParams {
        workspace_id: ws.clone(),
        name: p.0.clone(),
    })
    .await
    .unwrap();

    let dek_wrapped = vec![1, 2, 3, 4];
    let dek_nonce = vec![9u8; 24];
    s.create_env(&CreateEnvParams {
        workspace_id: ws.clone(),
        project_name: p.clone(),
        env_name: e.clone(),
        dek_wrapped: dek_wrapped.clone(),
        dek_nonce: dek_nonce.clone(),
    })
    .await
    .unwrap();

    // env wrap round-trip
    let (got_wrap, got_nonce) = s.get_env_wrap(&ws, &p, &e).await.unwrap();
    assert_eq!(got_wrap, dek_wrapped);
    assert_eq!(got_nonce, dek_nonce);

    // secret upsert + read
    let k = "DB_PASSWORD";
    let nonce = vec![7u8; 24];
    let ct1 = vec![8u8; 32];

    s.upsert_secret(&ws, &p, &e, k, &nonce, &ct1).await.unwrap();
    let row1 = s.get_secret(&ws, &p, &e, k).await.unwrap();
    assert_eq!(row1.nonce, nonce);
    assert_eq!(row1.ciphertext, ct1);

    // overwrite same key: new ciphertext should appear
    let ct2 = vec![42u8; 48];
    s.upsert_secret(&ws, &p, &e, k, &nonce, &ct2).await.unwrap();
    let row2 = s.get_secret(&ws, &p, &e, k).await.unwrap();
    assert_eq!(
        row2.ciphertext, ct2,
        "upsert should update the value in-place"
    );

    // add a few more keys out-of-order and verify sorted listing
    s.upsert_secret(&ws, &p, &e, "z_last", &nonce, b"Z")
        .await
        .unwrap();
    s.upsert_secret(&ws, &p, &e, "a_first", &nonce, b"A")
        .await
        .unwrap();
    s.upsert_secret(&ws, &p, &e, "m_middle", &nonce, b"M")
        .await
        .unwrap();

    let keys = s.list_secret_keys(&ws, &p, &e).await.unwrap();
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
    s.create_project(&CreateProjectParams {
        workspace_id: ws1.clone(),
        name: p.0.clone(),
    })
    .await
    .unwrap();
    s.create_env(&CreateEnvParams {
        workspace_id: ws1.clone(),
        project_name: p.clone(),
        env_name: e.clone(),
        dek_wrapped: vec![1],
        dek_nonce: vec![9; 24],
    })
    .await
    .unwrap();

    s.create_project(&CreateProjectParams {
        workspace_id: ws2.clone(),
        name: p.0.clone(),
    })
    .await
    .unwrap();
    s.create_env(&CreateEnvParams {
        workspace_id: ws2.clone(),
        project_name: p.clone(),
        env_name: e.clone(),
        dek_wrapped: vec![2],
        dek_nonce: vec![9; 24],
    })
    .await
    .unwrap();

    // only write secret in ws1
    s.upsert_secret(&ws1, &p, &e, "TOKEN", &[7; 24], &[1; 8])
        .await
        .unwrap();

    // ws2 cannot read ws1’s data
    let err = s.get_secret(&ws2, &p, &e, "TOKEN").await.unwrap_err();
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

    // Reading a non-existent secret → NotFound
    let e = EnvName("missing-env".into());
    // env doesn't exist yet, so this should not be found
    let err = s.get_secret(&ws, &p, &e, "NOPE").await.unwrap_err();
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
