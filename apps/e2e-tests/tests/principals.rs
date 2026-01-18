//! Principal management E2E tests
//!
//! Tests service principal creation, permissions, and lifecycle.

#[macro_use]
mod common;

use common::{parse_principal_id, BackendConfig, TestHarness};

// Generate tests for all 4 backend combinations
backend_test!(principals_crud, run_principals_test);
backend_test!(principals_rename, run_principals_rename_test);
backend_test!(principals_service_list, run_principals_service_list_test);
backend_test!(principals_workspace_ops, run_principals_workspace_ops_test);
backend_test!(
    principals_grant_workspace_access,
    run_principals_grant_workspace_access_test
);
backend_test!(principals_current, run_principals_current_test);
backend_test!(principals_use, run_principals_use_test);
backend_test!(principals_export_import, run_principals_export_import_test);
backend_test!(
    principals_multi_user_identity,
    run_principals_multi_user_identity_test
);

/// Test service principal creation and management
async fn run_principals_test(config: BackendConfig) -> Result<(), Box<dyn std::error::Error>> {
    let harness = TestHarness::new("principals", config).await?;

    // Setup: Create admin user with workspace
    let invite = harness.create_server_invite()?;
    let admin = harness.create_user("admin");
    admin.join(&invite, "admin@example.com", "admin-device")?;
    admin.exec(&["workspace", "create", "acme"]).success()?;
    admin
        .exec(&["project", "create", "api", "-w", "acme"])
        .success()?;
    admin
        .exec(&["environment", "create", "dev", "-w", "acme", "-p", "api"])
        .success()?;

    harness.create_zopp_toml("acme", "api", "dev")?;

    // Write a secret so we can test service principal access
    admin
        .exec_in(
            harness.test_dir(),
            &["secret", "set", "DB_URL", "postgres://localhost/db"],
        )
        .success()?;

    // Test 1: Create service principal
    println!("  Test 1: Create service principal...");
    let output = admin
        .exec(&[
            "principal",
            "create",
            "ci-bot",
            "--service",
            "--workspace",
            "acme",
        ])
        .success()?;
    assert!(output.contains("ci-bot"), "Should contain principal name");

    // Extract principal ID from output
    let principal_id = parse_principal_id(&output).ok_or("Failed to parse principal ID")?;

    // Test 2: List principals - verify service principal shows without user identity
    println!("  Test 2: List principals...");
    let output = admin.exec(&["principal", "list"]).success()?;
    assert!(output.contains("ci-bot"), "Should list ci-bot principal");
    assert!(
        output.contains("admin-device"),
        "Should list admin principal"
    );
    // Service principals show "service principal" instead of email
    assert!(
        output.contains("service principal"),
        "Service principal should show 'service principal' instead of email, got: {}",
        output
    );
    // Human principals still show their email
    assert!(
        output.contains("admin@example.com"),
        "Human principal should show email, got: {}",
        output
    );

    // Test 3: Grant READ permission to service principal
    println!("  Test 3: Grant permission to service principal...");
    admin
        .exec(&[
            "permission",
            "set",
            "--workspace",
            "acme",
            "--principal",
            &principal_id,
            "--role",
            "read",
        ])
        .success()?;

    // Test 4: Verify permission was granted using permission get
    println!("  Test 4: Verify permission with get...");
    let output = admin
        .exec(&[
            "permission",
            "get",
            "--workspace",
            "acme",
            "--principal",
            &principal_id,
        ])
        .success()?;
    assert!(
        output.to_lowercase().contains("read"),
        "Should have READ permission, got: {}",
        output
    );

    // Test 5: Verify permission appears in list
    println!("  Test 5: Verify permission in list...");
    let output = admin
        .exec(&["permission", "list", "--workspace", "acme"])
        .success()?;
    assert!(
        output.contains("ci-bot") || output.contains(&principal_id),
        "Permission list should show ci-bot"
    );

    // Test 6: Revoke permission
    println!("  Test 6: Revoke permission...");
    admin
        .exec(&[
            "permission",
            "remove",
            "--workspace",
            "acme",
            "--principal",
            &principal_id,
        ])
        .success()?;

    // Verify permission is gone - get should fail or return no permission
    let result = admin.exec(&[
        "permission",
        "get",
        "--workspace",
        "acme",
        "--principal",
        &principal_id,
    ]);
    // After remove, either the command fails or returns empty/none
    let is_removed = result.failed()
        || result.stdout().is_empty()
        || result.stdout().to_lowercase().contains("none");
    assert!(is_removed, "Permission should be removed after revoke");

    // Test 7: Delete principal (by name, not ID)
    println!("  Test 7: Delete principal...");
    admin.exec(&["principal", "delete", "ci-bot"]).success()?;

    // Verify deleted - principal should not appear in list
    let output = admin.exec(&["principal", "list"]).success()?;
    assert!(
        !output.contains("ci-bot"),
        "ci-bot should be deleted from principal list"
    );

    // Test 8: Create another service principal and test project/env permissions
    println!("  Test 8: Create and test project/env permissions...");
    let output = admin
        .exec(&[
            "principal",
            "create",
            "deploy-bot",
            "--service",
            "--workspace",
            "acme",
        ])
        .success()?;
    let deploy_id = parse_principal_id(&output).ok_or("Failed to parse principal ID")?;

    // Grant project permission
    admin
        .exec(&[
            "permission",
            "project-set",
            "--workspace",
            "acme",
            "--project",
            "api",
            "--principal",
            &deploy_id,
            "--role",
            "admin",
        ])
        .success()?;

    // Verify project permission
    let proj_perm = admin
        .exec(&[
            "permission",
            "project-get",
            "--workspace",
            "acme",
            "--project",
            "api",
            "--principal",
            &deploy_id,
        ])
        .success()?;
    assert!(
        proj_perm.to_lowercase().contains("admin"),
        "Should have ADMIN project permission, got: {}",
        proj_perm
    );

    // Grant environment permission
    admin
        .exec(&[
            "permission",
            "env-set",
            "--workspace",
            "acme",
            "--project",
            "api",
            "--environment",
            "dev",
            "--principal",
            &deploy_id,
            "--role",
            "write",
        ])
        .success()?;

    // Verify environment permission
    let env_perm = admin
        .exec(&[
            "permission",
            "env-get",
            "--workspace",
            "acme",
            "--project",
            "api",
            "--environment",
            "dev",
            "--principal",
            &deploy_id,
        ])
        .success()?;
    assert!(
        env_perm.to_lowercase().contains("write"),
        "Should have WRITE environment permission, got: {}",
        env_perm
    );

    // Remove project permission
    admin
        .exec(&[
            "permission",
            "project-remove",
            "--workspace",
            "acme",
            "--project",
            "api",
            "--principal",
            &deploy_id,
        ])
        .success()?;

    // Verify project permission is removed
    let proj_result = admin.exec(&[
        "permission",
        "project-get",
        "--workspace",
        "acme",
        "--project",
        "api",
        "--principal",
        &deploy_id,
    ]);
    let proj_removed = proj_result.failed()
        || proj_result.stdout().is_empty()
        || proj_result.stdout().to_lowercase().contains("none")
        || proj_result
            .stdout()
            .to_lowercase()
            .contains("no permission");
    assert!(proj_removed, "Project permission should be removed");

    // Remove environment permission
    admin
        .exec(&[
            "permission",
            "env-remove",
            "--workspace",
            "acme",
            "--project",
            "api",
            "--environment",
            "dev",
            "--principal",
            &deploy_id,
        ])
        .success()?;

    // Verify environment permission is removed
    let env_result = admin.exec(&[
        "permission",
        "env-get",
        "--workspace",
        "acme",
        "--project",
        "api",
        "--environment",
        "dev",
        "--principal",
        &deploy_id,
    ]);
    let env_removed = env_result.failed()
        || env_result.stdout().is_empty()
        || env_result.stdout().to_lowercase().contains("none")
        || env_result.stdout().to_lowercase().contains("no permission");
    assert!(env_removed, "Environment permission should be removed");

    // Test 9: Test effective permissions (aggregated view)
    println!("  Test 9: Test effective permissions...");
    // Grant workspace permission first
    admin
        .exec(&[
            "permission",
            "set",
            "--workspace",
            "acme",
            "--principal",
            &deploy_id,
            "--role",
            "read",
        ])
        .success()?;

    let effective = admin
        .exec(&[
            "permission",
            "effective",
            "--workspace",
            "acme",
            "--principal",
            &deploy_id,
        ])
        .success()?;
    assert!(
        effective.to_lowercase().contains("read"),
        "Effective permissions should show read, got: {}",
        effective
    );

    println!("  All principal tests passed!");
    Ok(())
}

/// Test principal rename functionality (renames user's own principal, not service principals)
async fn run_principals_rename_test(
    config: BackendConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let harness = TestHarness::new("prin_rename", config).await?;

    // Setup - alice joins with a specific principal name
    let invite = harness.create_server_invite()?;
    let alice = harness.create_user("alice");
    alice.join(&invite, &alice.email(), "my-device")?;

    // Verify the principal exists with original name
    println!("  Test 1: Verify original principal name...");
    let output = alice.exec(&["principal", "list"]).success()?;
    assert!(
        output.contains("my-device"),
        "Should have my-device principal"
    );

    // Rename the principal (user's own principal stored in local config)
    println!("  Test 2: Rename principal...");
    alice
        .exec(&["principal", "rename", "my-device", "renamed-device"])
        .success()?;

    // Verify rename
    let output = alice.exec(&["principal", "list"]).success()?;
    assert!(
        output.contains("renamed-device"),
        "Should have renamed-device principal"
    );

    println!("test_principals_rename PASSED");
    Ok(())
}

/// Test service principal list in workspace
async fn run_principals_service_list_test(
    config: BackendConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let harness = TestHarness::new("prin_svc_list", config).await?;

    // Setup
    let invite = harness.create_server_invite()?;
    let alice = harness.create_user("alice");
    alice.join(&invite, &alice.email(), &alice.principal())?;
    alice.exec(&["workspace", "create", "svcws"]).success()?;

    // Create service principals
    println!("  Test 1: Create service principals...");
    alice
        .exec(&["principal", "create", "svc-one", "--service", "-w", "svcws"])
        .success()?;
    alice
        .exec(&["principal", "create", "svc-two", "--service", "-w", "svcws"])
        .success()?;

    // List service principals in workspace
    println!("  Test 2: List service principals...");
    let output = alice
        .exec(&["principal", "service-list", "-w", "svcws"])
        .success()?;
    assert!(
        output.contains("svc-one"),
        "Should list svc-one, got: {}",
        output
    );
    assert!(
        output.contains("svc-two"),
        "Should list svc-two, got: {}",
        output
    );

    println!("test_principals_service_list PASSED");
    Ok(())
}

/// Test principal workspace operations: workspace-remove, revoke-all
async fn run_principals_workspace_ops_test(
    config: BackendConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let harness = TestHarness::new("prin_ws_ops", config).await?;

    // Setup
    let invite = harness.create_server_invite()?;
    let admin = harness.create_user("admin");
    admin.join(&invite, &admin.email(), &admin.principal())?;
    admin.exec(&["workspace", "create", "opsws"]).success()?;
    admin
        .exec(&["project", "create", "proj", "-w", "opsws"])
        .success()?;

    // Create service principal with permissions
    println!("  Test 1: Create service principal with permissions...");
    let output = admin
        .exec(&["principal", "create", "worker", "--service", "-w", "opsws"])
        .success()?;
    let worker_id = parse_principal_id(&output).ok_or("Failed to parse principal ID")?;

    // Grant permissions
    admin
        .exec(&[
            "permission",
            "set",
            "-w",
            "opsws",
            "--principal",
            &worker_id,
            "--role",
            "write",
        ])
        .success()?;
    admin
        .exec(&[
            "permission",
            "project-set",
            "-w",
            "opsws",
            "-p",
            "proj",
            "--principal",
            &worker_id,
            "--role",
            "admin",
        ])
        .success()?;

    // Test revoke-all
    println!("  Test 2: Revoke all permissions...");
    admin
        .exec(&[
            "principal",
            "revoke-all",
            "-w",
            "opsws",
            "--principal",
            &worker_id,
        ])
        .success()?;

    // Verify permissions are gone
    let result = admin.exec(&[
        "permission",
        "get",
        "-w",
        "opsws",
        "--principal",
        &worker_id,
    ]);
    // After revoke-all, permission get might return empty, "none", "no permission", or error
    let output = result.stdout();
    let ws_perm_gone = result.failed()
        || output.is_empty()
        || output.to_lowercase().contains("none")
        || output.to_lowercase().contains("no permission")
        || !output.to_lowercase().contains("write");
    assert!(
        ws_perm_gone,
        "Workspace permission should be revoked, got: {}",
        output
    );

    // Create another principal to test workspace-remove
    println!("  Test 3: Test workspace-remove...");
    let output = admin
        .exec(&[
            "principal",
            "create",
            "temp-bot",
            "--service",
            "-w",
            "opsws",
        ])
        .success()?;
    let temp_id = parse_principal_id(&output).ok_or("Failed to parse principal ID")?;

    // Verify it's in service list
    let output = admin
        .exec(&["principal", "service-list", "-w", "opsws"])
        .success()?;
    assert!(output.contains("temp-bot"), "Should list temp-bot");

    // Remove from workspace
    admin
        .exec(&[
            "principal",
            "workspace-remove",
            "-w",
            "opsws",
            "--principal",
            &temp_id,
        ])
        .success()?;

    // Verify it's no longer in workspace service list
    let output = admin
        .exec(&["principal", "service-list", "-w", "opsws"])
        .success()?;
    assert!(
        !output.contains("temp-bot"),
        "temp-bot should be removed from workspace"
    );

    println!("test_principals_workspace_ops PASSED");
    Ok(())
}

/// Test workspace grant-principal-access command and workspace list
async fn run_principals_grant_workspace_access_test(
    config: BackendConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let harness = TestHarness::new("prin_grant_ws", config).await?;

    // Setup - alice creates a workspace
    let invite = harness.create_server_invite()?;
    let alice = harness.create_user("alice");
    alice.join(&invite, &alice.email(), &alice.principal())?;
    alice.exec(&["workspace", "create", "grantws"]).success()?;

    // Test 1: List workspaces (tests cmd_workspace_list)
    println!("  Test 1: List workspaces...");
    let output = alice.exec(&["workspace", "list"]).success()?;
    assert!(
        output.contains("grantws"),
        "Should list grantws workspace, got: {}",
        output
    );

    // Test 2: Create service principal with workspace access
    println!("  Test 2: Create service principal...");
    let output = alice
        .exec(&[
            "principal",
            "create",
            "test-bot",
            "--service",
            "-w",
            "grantws",
        ])
        .success()?;

    // Extract the principal ID
    let bot_id = parse_principal_id(&output).ok_or("Failed to parse principal ID")?;

    // Test 3: Grant workspace access to principal that already has access
    // This exercises the grant-principal-access command's error handling path
    println!("  Test 3: Grant workspace access to existing principal (expect error)...");
    let result = alice.exec(&[
        "workspace",
        "grant-principal-access",
        "--workspace",
        "grantws",
        "--principal",
        &bot_id,
    ]);
    // This should fail because the principal already has access
    assert!(
        result.failed(),
        "Should fail when granting access to principal that already has it"
    );

    println!("test_principals_grant_workspace_access PASSED");
    Ok(())
}

/// Test principal current command
async fn run_principals_current_test(
    config: BackendConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let harness = TestHarness::new("prin_current", config).await?;

    // Setup - alice registers
    let invite = harness.create_server_invite()?;
    let alice = harness.create_user("alice");
    alice.join(&invite, &alice.email(), &alice.principal())?;

    // Test: Check current principal
    println!("  Test: Check current principal...");
    let output = alice.exec(&["principal", "current"]).success()?;
    assert!(
        output.contains(&alice.principal()),
        "Should show current principal name, got: {}",
        output
    );

    println!("test_principals_current PASSED");
    Ok(())
}

/// Test principal use command to switch between principals
async fn run_principals_use_test(config: BackendConfig) -> Result<(), Box<dyn std::error::Error>> {
    let harness = TestHarness::new("prin_use", config).await?;

    // Setup - alice registers with first principal
    let invite = harness.create_server_invite()?;
    let alice = harness.create_user("alice");
    let first_principal = "device-one";
    alice.join(&invite, &alice.email(), first_principal)?;

    // Create a second principal for alice
    println!("  Test 1: Create second principal...");
    let second_principal = "device-two";
    alice
        .exec(&["principal", "create", second_principal])
        .success()?;

    // Verify both principals exist
    let output = alice.exec(&["principal", "list"]).success()?;
    assert!(
        output.contains(first_principal),
        "Should list first principal, got: {}",
        output
    );
    assert!(
        output.contains(second_principal),
        "Should list second principal, got: {}",
        output
    );

    // Test 2: Switch to second principal
    println!("  Test 2: Switch to second principal...");
    alice
        .exec(&["principal", "use", second_principal])
        .success()?;

    // Verify current principal changed
    let output = alice.exec(&["principal", "current"]).success()?;
    assert!(
        output.contains(second_principal),
        "Current principal should be {}, got: {}",
        second_principal,
        output
    );

    // Test 3: Switch back to first principal
    println!("  Test 3: Switch back to first principal...");
    alice
        .exec(&["principal", "use", first_principal])
        .success()?;

    // Verify current principal changed back
    let output = alice.exec(&["principal", "current"]).success()?;
    assert!(
        output.contains(first_principal),
        "Current principal should be {}, got: {}",
        first_principal,
        output
    );

    println!("test_principals_use PASSED");
    Ok(())
}

/// Extract export code from CLI output (e.g., "exp_a7k9m2x4")
fn extract_export_code(output: &str) -> Option<String> {
    // Look for "exp_" followed by 8 alphanumeric characters
    for line in output.lines() {
        let line = line.trim();
        if line.starts_with("exp_") && line.len() >= 12 {
            return Some(line[..12].to_string());
        }
    }
    None
}

/// Test principal export/import for multi-device support (server-mediated)
async fn run_principals_export_import_test(
    config: BackendConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let harness = TestHarness::new("prin_export", config).await?;

    // Setup - alice joins with a principal
    let invite = harness.create_server_invite()?;
    let alice = harness.create_user("alice");
    alice.join(&invite, &alice.email(), "alice-laptop")?;

    // Create a workspace so we can verify access after import
    alice.exec(&["workspace", "create", "exportws"]).success()?;

    // Test 1: Export the principal to server
    // The passphrase env var controls the generated passphrase for deterministic testing
    println!("  Test 1: Export principal...");
    let passphrase = "correct horse battery staple purple llama";

    let result = alice.exec_with_env(
        &["principal", "export", "alice-laptop"],
        &[("ZOPP_EXPORT_PASSPHRASE", passphrase)],
    );
    let output = result.success()?;
    assert!(
        output.contains("export created") || output.contains("Passphrase"),
        "Export should succeed, got: {}",
        output
    );

    // Extract export code from output
    let export_code = extract_export_code(&output)
        .ok_or_else(|| format!("Could not find export code in output: {}", output))?;

    // Test 2: Create a second user (simulating new device) and import
    // Note: This simulates a fresh device with no config
    println!("  Test 2: Import principal on new device...");
    let bob = harness.create_user("bob");

    // Bob imports alice's principal using the export code and passphrase
    let result = bob.exec_with_env(
        &["principal", "import"],
        &[
            ("ZOPP_EXPORT_CODE", &export_code),
            ("ZOPP_EXPORT_PASSPHRASE", passphrase),
        ],
    );
    result.success()?;

    // Test 3: Verify bob can use the imported principal
    println!("  Test 3: Verify imported principal works...");
    let output = bob.exec(&["principal", "list"]).success()?;
    assert!(
        output.contains("alice-laptop"),
        "Bob should have alice-laptop principal, got: {}",
        output
    );

    // Test 4: Verify bob can access alice's workspace
    println!("  Test 4: Verify workspace access...");
    let output = bob.exec(&["workspace", "list"]).success()?;
    assert!(
        output.contains("exportws"),
        "Bob should see exportws workspace, got: {}",
        output
    );

    // Test 5: Test wrong passphrase (with failed attempts tracking)
    println!("  Test 5: Test wrong passphrase with self-destruct...");
    // Create a fresh export for wrong passphrase test
    let passphrase2 = "another test passphrase words here";
    let output = alice
        .exec_with_env(
            &["principal", "export", "alice-laptop"],
            &[("ZOPP_EXPORT_PASSPHRASE", passphrase2)],
        )
        .success()?;
    let export_code2 = extract_export_code(&output)
        .ok_or_else(|| format!("Could not find export code in output: {}", output))?;

    let carol = harness.create_user("carol");

    // First wrong attempt
    let result = carol.exec_with_env(
        &["principal", "import"],
        &[
            ("ZOPP_EXPORT_CODE", &export_code2),
            ("ZOPP_EXPORT_PASSPHRASE", "wrong-passphrase-1"),
        ],
    );
    assert!(result.failed(), "Import with wrong passphrase should fail");

    // Second wrong attempt
    let result = carol.exec_with_env(
        &["principal", "import"],
        &[
            ("ZOPP_EXPORT_CODE", &export_code2),
            ("ZOPP_EXPORT_PASSPHRASE", "wrong-passphrase-2"),
        ],
    );
    assert!(result.failed(), "Import with wrong passphrase should fail");

    // Third wrong attempt - should trigger self-destruct
    let result = carol.exec_with_env(
        &["principal", "import"],
        &[
            ("ZOPP_EXPORT_CODE", &export_code2),
            ("ZOPP_EXPORT_PASSPHRASE", "wrong-passphrase-3"),
        ],
    );
    assert!(result.failed(), "Import with wrong passphrase should fail");

    // Fourth attempt - export should be deleted
    let result = carol.exec_with_env(
        &["principal", "import"],
        &[
            ("ZOPP_EXPORT_CODE", &export_code2),
            ("ZOPP_EXPORT_PASSPHRASE", passphrase2),
        ],
    );
    assert!(
        result.failed(),
        "Import should fail because export was deleted after 3 failed attempts"
    );

    // Test 6: Test that export is consumed after successful import
    println!("  Test 6: Test export is consumed after import...");
    // Create a fresh export for this test
    let passphrase3 = "yet another passphrase for testing";
    let output = alice
        .exec_with_env(
            &["principal", "export", "alice-laptop"],
            &[("ZOPP_EXPORT_PASSPHRASE", passphrase3)],
        )
        .success()?;
    let export_code3 = extract_export_code(&output)
        .ok_or_else(|| format!("Could not find export code in output: {}", output))?;

    // Carol imports it (fresh config)
    carol
        .exec_with_env(
            &["principal", "import"],
            &[
                ("ZOPP_EXPORT_CODE", &export_code3),
                ("ZOPP_EXPORT_PASSPHRASE", passphrase3),
            ],
        )
        .success()?;

    // Dan tries to import the same export - should fail because it's consumed
    let dan = harness.create_user("dan");
    let result = dan.exec_with_env(
        &["principal", "import"],
        &[
            ("ZOPP_EXPORT_CODE", &export_code3),
            ("ZOPP_EXPORT_PASSPHRASE", passphrase3),
        ],
    );
    assert!(
        result.failed(),
        "Import should fail because export was already consumed"
    );

    println!("test_principals_export_import PASSED");
    Ok(())
}

/// Test multi-user identity support (Issue #40)
/// Verifies that a single config can contain principals from different users
async fn run_principals_multi_user_identity_test(
    config: BackendConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let harness = TestHarness::new("prin_multi_user", config).await?;

    // Setup - alice and bob are DIFFERENT users with DIFFERENT emails
    let invite = harness.create_server_invite()?;
    let alice = harness.create_user("alice");
    alice.join(&invite, "alice@company-a.com", "alice-laptop")?;

    let invite2 = harness.create_server_invite()?;
    let bob = harness.create_user("bob");
    bob.join(&invite2, "bob@company-b.com", "bob-laptop")?;

    // Alice creates a workspace
    alice.exec(&["workspace", "create", "alice-ws"]).success()?;

    // Test 1: Verify principal list shows email per principal
    println!("  Test 1: Verify principal list shows email...");
    let output = alice.exec(&["principal", "list"]).success()?;
    assert!(
        output.contains("alice@company-a.com"),
        "Should show alice's email, got: {}",
        output
    );

    // Test 2: Export alice's principal
    println!("  Test 2: Export alice's principal...");
    let passphrase = "multi user identity test passphrase";
    let result = alice.exec_with_env(
        &["principal", "export", "alice-laptop"],
        &[("ZOPP_EXPORT_PASSPHRASE", passphrase)],
    );
    let output = result.success()?;
    let export_code = extract_export_code(&output)
        .ok_or_else(|| format!("Could not find export code in output: {}", output))?;

    // Test 3: Bob imports alice's principal (different user!)
    // This was previously blocked with "Cannot import: principal belongs to user..."
    // Now it should work due to Issue #40 fix
    println!("  Test 3: Bob imports alice's principal (multi-user config)...");
    let result = bob.exec_with_env(
        &["principal", "import"],
        &[
            ("ZOPP_EXPORT_CODE", &export_code),
            ("ZOPP_EXPORT_PASSPHRASE", passphrase),
        ],
    );
    result.success()?;

    // Test 4: Bob's config now has principals from TWO different users
    println!("  Test 4: Verify bob has principals from both users...");
    let output = bob.exec(&["principal", "list"]).success()?;
    assert!(
        output.contains("bob-laptop"),
        "Bob should still have bob-laptop, got: {}",
        output
    );
    assert!(
        output.contains("alice-laptop"),
        "Bob should now also have alice-laptop, got: {}",
        output
    );

    // The output should show both emails since principals now have per-principal user info
    // (This is the key feature of Issue #40)

    // Test 5: Bob can switch between principals (multi-identity switching)
    println!("  Test 5: Switch to alice's principal...");
    bob.exec(&["principal", "use", "alice-laptop"]).success()?;

    let output = bob.exec(&["principal", "current"]).success()?;
    assert!(
        output.contains("alice-laptop"),
        "Current should be alice-laptop, got: {}",
        output
    );

    // Test 6: Using alice's principal, bob can access alice's workspace
    println!("  Test 6: Access alice's workspace using imported principal...");
    let output = bob.exec(&["workspace", "list"]).success()?;
    assert!(
        output.contains("alice-ws"),
        "Bob should see alice-ws when using alice's principal, got: {}",
        output
    );

    // Test 7: Switch back to bob's principal
    println!("  Test 7: Switch back to bob's principal...");
    bob.exec(&["principal", "use", "bob-laptop"]).success()?;

    let output = bob.exec(&["principal", "current"]).success()?;
    assert!(
        output.contains("bob-laptop"),
        "Current should be bob-laptop, got: {}",
        output
    );

    // Using bob's principal, bob should NOT see alice's workspace
    // (different user, no workspace access for bob's own principal)
    let output = bob.exec(&["workspace", "list"]).success()?;
    assert!(
        !output.contains("alice-ws"),
        "Bob should NOT see alice-ws when using bob's own principal, got: {}",
        output
    );

    println!("test_principals_multi_user_identity PASSED");
    Ok(())
}
