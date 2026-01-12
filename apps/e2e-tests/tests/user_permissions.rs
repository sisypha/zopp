//! User permission E2E tests
//!
//! Tests user-level permissions (by email) at workspace, project, and environment levels.

#[macro_use]
mod common;

use common::{BackendConfig, TestHarness};

// ═══════════════════════════════════════════════════════════════════════════
// User Permission Tests
// ═══════════════════════════════════════════════════════════════════════════

backend_test!(
    test_user_workspace_permission,
    run_test_user_workspace_permission
);
backend_test!(
    test_user_project_permission,
    run_test_user_project_permission
);
backend_test!(test_user_env_permission, run_test_user_env_permission);

// ═══════════════════════════════════════════════════════════════════════════
// Test Implementations
// ═══════════════════════════════════════════════════════════════════════════

/// Test user workspace permission CRUD
async fn run_test_user_workspace_permission(
    config: BackendConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let harness = TestHarness::new("user_ws_perm", config).await?;

    // Setup: create admin and member users
    let invite = harness.create_server_invite()?;
    let alice = harness.create_user("alice");
    alice.join(&invite, &alice.email(), &alice.principal())?;
    alice.exec(&["workspace", "create", "acme"]).success()?;

    // Create workspace invite for bob
    harness.create_zopp_toml("acme", "", "")?;
    let ws_invite = alice
        .exec_in(harness.test_dir(), &["invite", "create", "--plain"])
        .success()?;
    let invite_token = ws_invite.trim();

    let bob = harness.create_user("bob");
    bob.join(invite_token, &bob.email(), &bob.principal())?;

    // Test 1: Set workspace permission for bob
    println!("  Test 1: Set user workspace permission...");
    alice
        .exec(&[
            "permission",
            "user-set",
            "-w",
            "acme",
            "--email",
            &bob.email(),
            "--role",
            "write",
        ])
        .success()?;

    // Test 2: Get user workspace permission
    println!("  Test 2: Get user workspace permission...");
    let output = alice
        .exec(&[
            "permission",
            "user-get",
            "-w",
            "acme",
            "--email",
            &bob.email(),
        ])
        .success()?;
    assert!(
        output.to_lowercase().contains("write"),
        "Should have write permission, got: {}",
        output
    );

    // Test 3: List user workspace permissions
    println!("  Test 3: List user workspace permissions...");
    let output = alice
        .exec(&["permission", "user-list", "-w", "acme"])
        .success()?;
    assert!(
        output.contains(&bob.email()) || output.contains("bob"),
        "Should list bob in permissions, got: {}",
        output
    );

    // Test 4: Remove user workspace permission
    println!("  Test 4: Remove user workspace permission...");
    alice
        .exec(&[
            "permission",
            "user-remove",
            "-w",
            "acme",
            "--email",
            &bob.email(),
        ])
        .success()?;

    // Verify permission is removed
    let result = alice.exec(&[
        "permission",
        "user-get",
        "-w",
        "acme",
        "--email",
        &bob.email(),
    ]);
    assert!(
        result.failed() || result.stdout().to_lowercase().contains("not found"),
        "Should fail to get removed permission"
    );

    println!("test_user_workspace_permission PASSED");
    Ok(())
}

/// Test user project permission CRUD
async fn run_test_user_project_permission(
    config: BackendConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let harness = TestHarness::new("user_proj_perm", config).await?;

    // Setup
    let invite = harness.create_server_invite()?;
    let alice = harness.create_user("alice");
    alice.join(&invite, &alice.email(), &alice.principal())?;
    alice.exec(&["workspace", "create", "acme"]).success()?;
    alice
        .exec(&["project", "create", "api", "-w", "acme"])
        .success()?;

    // Create workspace invite for bob
    harness.create_zopp_toml("acme", "api", "")?;
    let ws_invite = alice
        .exec_in(harness.test_dir(), &["invite", "create", "--plain"])
        .success()?;
    let invite_token = ws_invite.trim();

    let bob = harness.create_user("bob");
    bob.join(invite_token, &bob.email(), &bob.principal())?;

    // Test 1: Set project permission
    println!("  Test 1: Set user project permission...");
    alice
        .exec(&[
            "permission",
            "user-project-set",
            "-w",
            "acme",
            "-p",
            "api",
            "--email",
            &bob.email(),
            "--role",
            "read",
        ])
        .success()?;

    // Test 2: Get project permission
    println!("  Test 2: Get user project permission...");
    let output = alice
        .exec(&[
            "permission",
            "user-project-get",
            "-w",
            "acme",
            "-p",
            "api",
            "--email",
            &bob.email(),
        ])
        .success()?;
    assert!(
        output.to_lowercase().contains("read"),
        "Should have read permission, got: {}",
        output
    );

    // Test 3: List project permissions
    println!("  Test 3: List user project permissions...");
    let output = alice
        .exec(&["permission", "user-project-list", "-w", "acme", "-p", "api"])
        .success()?;
    assert!(
        output.contains(&bob.email()) || output.contains("bob"),
        "Should list bob in permissions, got: {}",
        output
    );

    // Test 4: Remove project permission
    println!("  Test 4: Remove user project permission...");
    alice
        .exec(&[
            "permission",
            "user-project-remove",
            "-w",
            "acme",
            "-p",
            "api",
            "--email",
            &bob.email(),
        ])
        .success()?;

    // Verify permission is removed
    let result = alice.exec(&[
        "permission",
        "user-project-get",
        "-w",
        "acme",
        "-p",
        "api",
        "--email",
        &bob.email(),
    ]);
    assert!(
        result.failed() || result.stdout().to_lowercase().contains("not found"),
        "Should fail to get removed permission"
    );

    println!("test_user_project_permission PASSED");
    Ok(())
}

/// Test user environment permission CRUD
async fn run_test_user_env_permission(
    config: BackendConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let harness = TestHarness::new("user_env_perm", config).await?;

    // Setup
    let invite = harness.create_server_invite()?;
    let alice = harness.create_user("alice");
    alice.join(&invite, &alice.email(), &alice.principal())?;
    alice.exec(&["workspace", "create", "acme"]).success()?;
    alice
        .exec(&["project", "create", "api", "-w", "acme"])
        .success()?;
    alice
        .exec(&["environment", "create", "dev", "-w", "acme", "-p", "api"])
        .success()?;

    // Create workspace invite for bob
    harness.create_zopp_toml("acme", "api", "dev")?;
    let ws_invite = alice
        .exec_in(harness.test_dir(), &["invite", "create", "--plain"])
        .success()?;
    let invite_token = ws_invite.trim();

    let bob = harness.create_user("bob");
    bob.join(invite_token, &bob.email(), &bob.principal())?;

    // Test 1: Set environment permission
    println!("  Test 1: Set user environment permission...");
    alice
        .exec(&[
            "permission",
            "user-env-set",
            "-w",
            "acme",
            "-p",
            "api",
            "-e",
            "dev",
            "--email",
            &bob.email(),
            "--role",
            "admin",
        ])
        .success()?;

    // Test 2: Get environment permission
    println!("  Test 2: Get user environment permission...");
    let output = alice
        .exec(&[
            "permission",
            "user-env-get",
            "-w",
            "acme",
            "-p",
            "api",
            "-e",
            "dev",
            "--email",
            &bob.email(),
        ])
        .success()?;
    assert!(
        output.to_lowercase().contains("admin"),
        "Should have admin permission, got: {}",
        output
    );

    // Test 3: List environment permissions
    println!("  Test 3: List user environment permissions...");
    let output = alice
        .exec(&[
            "permission",
            "user-env-list",
            "-w",
            "acme",
            "-p",
            "api",
            "-e",
            "dev",
        ])
        .success()?;
    assert!(
        output.contains(&bob.email()) || output.contains("bob"),
        "Should list bob in permissions, got: {}",
        output
    );

    // Test 4: Remove environment permission
    println!("  Test 4: Remove user environment permission...");
    alice
        .exec(&[
            "permission",
            "user-env-remove",
            "-w",
            "acme",
            "-p",
            "api",
            "-e",
            "dev",
            "--email",
            &bob.email(),
        ])
        .success()?;

    // Verify permission is removed
    let result = alice.exec(&[
        "permission",
        "user-env-get",
        "-w",
        "acme",
        "-p",
        "api",
        "-e",
        "dev",
        "--email",
        &bob.email(),
    ]);
    assert!(
        result.failed() || result.stdout().to_lowercase().contains("not found"),
        "Should fail to get removed permission"
    );

    println!("test_user_env_permission PASSED");
    Ok(())
}
