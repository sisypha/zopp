//! Group E2E tests
//!
//! Tests group CRUD operations, membership management, and group permissions.

#[macro_use]
mod common;

use common::{BackendConfig, TestHarness};

// ═══════════════════════════════════════════════════════════════════════════
// Group CRUD Tests
// ═══════════════════════════════════════════════════════════════════════════

backend_test!(test_group_crud, run_test_group_crud);
backend_test!(test_group_membership, run_test_group_membership);
backend_test!(
    test_group_workspace_permissions,
    run_test_group_workspace_permissions
);
backend_test!(
    test_group_project_permissions,
    run_test_group_project_permissions
);
backend_test!(
    test_group_environment_permissions,
    run_test_group_environment_permissions
);

// ═══════════════════════════════════════════════════════════════════════════
// Test Implementations
// ═══════════════════════════════════════════════════════════════════════════

/// Test basic group CRUD operations: create, get, list, update, delete
async fn run_test_group_crud(config: BackendConfig) -> Result<(), Box<dyn std::error::Error>> {
    let harness = TestHarness::new("group_crud", config).await?;

    // Setup: create user and workspace
    let invite = harness.create_server_invite()?;
    let alice = harness.create_user("alice");
    alice.join(&invite, &alice.email(), &alice.principal())?;
    alice.exec(&["workspace", "create", "testws"]).success()?;

    // Test 1: Create a group
    println!("  Test 1: Create group...");
    alice
        .exec(&[
            "group",
            "create",
            "-w",
            "testws",
            "developers",
            "-d",
            "Development team",
        ])
        .success()?;

    // Test 2: List groups
    println!("  Test 2: List groups...");
    let output = alice.exec(&["group", "list", "-w", "testws"]).success()?;
    assert!(
        output.contains("developers"),
        "Should list the created group, got: {}",
        output
    );

    // Test 3: Update group (rename)
    println!("  Test 3: Update group...");
    alice
        .exec(&[
            "group",
            "update",
            "-w",
            "testws",
            "developers",
            "--new-name",
            "devs",
            "-d",
            "Dev team",
        ])
        .success()?;

    let output = alice.exec(&["group", "list", "-w", "testws"]).success()?;
    assert!(output.contains("devs"), "Should show renamed group");

    // Test 4: Create another group to test listing multiple
    println!("  Test 4: Create second group...");
    alice
        .exec(&["group", "create", "-w", "testws", "ops"])
        .success()?;

    let output = alice.exec(&["group", "list", "-w", "testws"]).success()?;
    assert!(output.contains("devs"), "Should list devs group");
    assert!(output.contains("ops"), "Should list ops group");

    // Test 5: Delete group
    println!("  Test 5: Delete group...");
    alice
        .exec(&["group", "delete", "-w", "testws", "ops"])
        .success()?;

    let output = alice.exec(&["group", "list", "-w", "testws"]).success()?;
    assert!(!output.contains("ops"), "ops group should be deleted");
    assert!(output.contains("devs"), "devs group should still exist");

    println!("test_group_crud PASSED");
    Ok(())
}

/// Test group membership: add member, list members, remove member
async fn run_test_group_membership(
    config: BackendConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let harness = TestHarness::new("group_member", config).await?;

    // Setup: create admin user and workspace
    let invite = harness.create_server_invite()?;
    let admin = harness.create_user("admin");
    admin.join(&invite, &admin.email(), &admin.principal())?;
    admin.exec(&["workspace", "create", "teamws"]).success()?;

    // Create a second user who will be added to the group
    let ws_invite = admin
        .exec(&["invite", "create", "-w", "teamws", "--plain"])
        .success()?;
    let token = ws_invite.trim();

    let bob = harness.create_user("bob");
    bob.join(token, &bob.email(), &bob.principal())?;

    // Create a group
    println!("  Test 1: Create group...");
    admin
        .exec(&["group", "create", "-w", "teamws", "engineers"])
        .success()?;

    // Add bob to the group
    println!("  Test 2: Add member to group...");
    admin
        .exec(&[
            "group",
            "add-member",
            "-w",
            "teamws",
            "-g",
            "engineers",
            &bob.email(),
        ])
        .success()?;

    // List group members
    println!("  Test 3: List group members...");
    let output = admin
        .exec(&["group", "list-members", "-w", "teamws", "-g", "engineers"])
        .success()?;
    assert!(
        output.contains(&bob.email()),
        "Should list bob as member, got: {}",
        output
    );

    // Remove bob from the group
    println!("  Test 4: Remove member from group...");
    admin
        .exec(&[
            "group",
            "remove-member",
            "-w",
            "teamws",
            "-g",
            "engineers",
            &bob.email(),
        ])
        .success()?;

    // Verify bob is removed
    let output = admin
        .exec(&["group", "list-members", "-w", "teamws", "-g", "engineers"])
        .success()?;
    assert!(
        !output.contains(&bob.email()),
        "Bob should be removed from group, got: {}",
        output
    );

    println!("test_group_membership PASSED");
    Ok(())
}

/// Test group workspace permissions: set, get, list, remove
async fn run_test_group_workspace_permissions(
    config: BackendConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let harness = TestHarness::new("group_ws_perm", config).await?;

    // Setup
    let invite = harness.create_server_invite()?;
    let alice = harness.create_user("alice");
    alice.join(&invite, &alice.email(), &alice.principal())?;
    alice.exec(&["workspace", "create", "permws"]).success()?;

    // Create a group
    alice
        .exec(&["group", "create", "-w", "permws", "readers"])
        .success()?;

    // Test 1: Set workspace permission for group
    println!("  Test 1: Set workspace permission for group...");
    alice
        .exec(&[
            "group",
            "set-permission",
            "-w",
            "permws",
            "-g",
            "readers",
            "--role",
            "read",
        ])
        .success()?;

    // Test 2: Get workspace permission for group
    println!("  Test 2: Get workspace permission for group...");
    let output = alice
        .exec(&["group", "get-permission", "-w", "permws", "-g", "readers"])
        .success()?;
    assert!(
        output.to_lowercase().contains("read"),
        "Should have read permission, got: {}",
        output
    );

    // Test 3: List all group permissions on workspace
    println!("  Test 3: List group permissions on workspace...");
    let output = alice
        .exec(&["group", "list-permissions", "-w", "permws"])
        .success()?;
    assert!(
        output.contains("readers") || output.to_lowercase().contains("read"),
        "Should list readers group permission, got: {}",
        output
    );

    // Test 4: Update permission (change role)
    println!("  Test 4: Update permission (change role)...");
    alice
        .exec(&[
            "group",
            "set-permission",
            "-w",
            "permws",
            "-g",
            "readers",
            "--role",
            "write",
        ])
        .success()?;

    let output = alice
        .exec(&["group", "get-permission", "-w", "permws", "-g", "readers"])
        .success()?;
    assert!(
        output.to_lowercase().contains("write"),
        "Should have write permission now, got: {}",
        output
    );

    // Test 5: Remove permission
    println!("  Test 5: Remove workspace permission for group...");
    alice
        .exec(&[
            "group",
            "remove-permission",
            "-w",
            "permws",
            "-g",
            "readers",
        ])
        .success()?;

    // Verify permission is removed
    let result = alice.exec(&["group", "get-permission", "-w", "permws", "-g", "readers"]);
    let is_removed = result.failed()
        || result.stdout().is_empty()
        || result.stdout().to_lowercase().contains("none")
        || result.stdout().to_lowercase().contains("no permission");
    assert!(is_removed, "Permission should be removed");

    println!("test_group_workspace_permissions PASSED");
    Ok(())
}

/// Test group project permissions: set, get, list, remove
async fn run_test_group_project_permissions(
    config: BackendConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let harness = TestHarness::new("group_proj_perm", config).await?;

    // Setup
    let invite = harness.create_server_invite()?;
    let alice = harness.create_user("alice");
    alice.join(&invite, &alice.email(), &alice.principal())?;
    alice.exec(&["workspace", "create", "projws"]).success()?;
    alice
        .exec(&["project", "create", "api", "-w", "projws"])
        .success()?;

    // Create a group
    alice
        .exec(&["group", "create", "-w", "projws", "devs"])
        .success()?;

    // Test 1: Set project permission for group
    println!("  Test 1: Set project permission for group...");
    alice
        .exec(&[
            "group",
            "set-project-permission",
            "-w",
            "projws",
            "-p",
            "api",
            "-g",
            "devs",
            "--role",
            "admin",
        ])
        .success()?;

    // Test 2: Get project permission for group
    println!("  Test 2: Get project permission for group...");
    let output = alice
        .exec(&[
            "group",
            "get-project-permission",
            "-w",
            "projws",
            "-p",
            "api",
            "-g",
            "devs",
        ])
        .success()?;
    assert!(
        output.to_lowercase().contains("admin"),
        "Should have admin permission, got: {}",
        output
    );

    // Test 3: List project permissions
    println!("  Test 3: List project permissions for groups...");
    let output = alice
        .exec(&[
            "group",
            "list-project-permissions",
            "-w",
            "projws",
            "-p",
            "api",
        ])
        .success()?;
    assert!(
        output.contains("devs") || output.to_lowercase().contains("admin"),
        "Should list devs group permission, got: {}",
        output
    );

    // Test 4: Remove project permission
    println!("  Test 4: Remove project permission for group...");
    alice
        .exec(&[
            "group",
            "remove-project-permission",
            "-w",
            "projws",
            "-p",
            "api",
            "-g",
            "devs",
        ])
        .success()?;

    // Verify permission is removed
    let result = alice.exec(&[
        "group",
        "get-project-permission",
        "-w",
        "projws",
        "-p",
        "api",
        "-g",
        "devs",
    ]);
    let is_removed = result.failed()
        || result.stdout().is_empty()
        || result.stdout().to_lowercase().contains("none")
        || result.stdout().to_lowercase().contains("no permission");
    assert!(is_removed, "Project permission should be removed");

    println!("test_group_project_permissions PASSED");
    Ok(())
}

/// Test group environment permissions: set, get, list, remove
async fn run_test_group_environment_permissions(
    config: BackendConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let harness = TestHarness::new("group_env_perm", config).await?;

    // Setup
    let invite = harness.create_server_invite()?;
    let alice = harness.create_user("alice");
    alice.join(&invite, &alice.email(), &alice.principal())?;
    alice.exec(&["workspace", "create", "envws"]).success()?;
    alice
        .exec(&["project", "create", "svc", "-w", "envws"])
        .success()?;
    alice
        .exec(&["environment", "create", "prod", "-w", "envws", "-p", "svc"])
        .success()?;

    // Create a group
    alice
        .exec(&["group", "create", "-w", "envws", "operators"])
        .success()?;

    // Test 1: Set environment permission for group
    println!("  Test 1: Set environment permission for group...");
    alice
        .exec(&[
            "group",
            "set-env-permission",
            "-w",
            "envws",
            "-p",
            "svc",
            "-e",
            "prod",
            "-g",
            "operators",
            "--role",
            "write",
        ])
        .success()?;

    // Test 2: Get environment permission for group
    println!("  Test 2: Get environment permission for group...");
    let output = alice
        .exec(&[
            "group",
            "get-env-permission",
            "-w",
            "envws",
            "-p",
            "svc",
            "-e",
            "prod",
            "-g",
            "operators",
        ])
        .success()?;
    assert!(
        output.to_lowercase().contains("write"),
        "Should have write permission, got: {}",
        output
    );

    // Test 3: List environment permissions
    println!("  Test 3: List environment permissions for groups...");
    let output = alice
        .exec(&[
            "group",
            "list-env-permissions",
            "-w",
            "envws",
            "-p",
            "svc",
            "-e",
            "prod",
        ])
        .success()?;
    assert!(
        output.contains("operators") || output.to_lowercase().contains("write"),
        "Should list operators group permission, got: {}",
        output
    );

    // Test 4: Remove environment permission
    println!("  Test 4: Remove environment permission for group...");
    alice
        .exec(&[
            "group",
            "remove-env-permission",
            "-w",
            "envws",
            "-p",
            "svc",
            "-e",
            "prod",
            "-g",
            "operators",
        ])
        .success()?;

    // Verify permission is removed
    let result = alice.exec(&[
        "group",
        "get-env-permission",
        "-w",
        "envws",
        "-p",
        "svc",
        "-e",
        "prod",
        "-g",
        "operators",
    ]);
    let is_removed = result.failed()
        || result.stdout().is_empty()
        || result.stdout().to_lowercase().contains("none")
        || result.stdout().to_lowercase().contains("no permission");
    assert!(is_removed, "Environment permission should be removed");

    println!("test_group_environment_permissions PASSED");
    Ok(())
}
