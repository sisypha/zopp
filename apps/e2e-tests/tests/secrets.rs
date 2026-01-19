//! E2E tests for secret operations including create, read, update, delete.

mod common;

use common::harness::{BackendConfig, TestHarness};

// ═══════════════════════════════════════════════════════════════════════════
// Secret Update (Edit) Tests
// ═══════════════════════════════════════════════════════════════════════════

backend_test!(test_secret_update, run_secret_update_test);

async fn run_secret_update_test(config: BackendConfig) -> Result<(), Box<dyn std::error::Error>> {
    let harness = TestHarness::new("secret_update", config).await?;

    // Create user and setup
    let invite = harness.create_server_invite()?;
    let alice = harness.create_user("alice");
    alice.join(&invite, &alice.email(), &alice.principal())?;

    // Create workspace, project, environment
    alice.exec(&["workspace", "create", "test-ws"]).success()?;
    alice
        .exec(&["project", "create", "-w", "test-ws", "test-proj"])
        .success()?;
    alice
        .exec(&[
            "environment",
            "create",
            "-w",
            "test-ws",
            "-p",
            "test-proj",
            "dev",
        ])
        .success()?;

    // Create initial secret
    let initial_value = "initial-secret-value";
    alice
        .exec(&[
            "secret",
            "set",
            "-w",
            "test-ws",
            "-p",
            "test-proj",
            "-e",
            "dev",
            "MY_SECRET",
            initial_value,
        ])
        .success()?;

    // Verify initial value
    let retrieved = alice
        .exec(&[
            "secret",
            "get",
            "-w",
            "test-ws",
            "-p",
            "test-proj",
            "-e",
            "dev",
            "MY_SECRET",
        ])
        .success()?;
    assert_eq!(retrieved, initial_value, "Initial secret value mismatch");

    // Update the secret with a new value
    let updated_value = "updated-secret-value";
    alice
        .exec(&[
            "secret",
            "set",
            "-w",
            "test-ws",
            "-p",
            "test-proj",
            "-e",
            "dev",
            "MY_SECRET",
            updated_value,
        ])
        .success()?;

    // Verify updated value
    let retrieved_after_update = alice
        .exec(&[
            "secret",
            "get",
            "-w",
            "test-ws",
            "-p",
            "test-proj",
            "-e",
            "dev",
            "MY_SECRET",
        ])
        .success()?;
    assert_eq!(
        retrieved_after_update, updated_value,
        "Updated secret value mismatch: expected '{}', got '{}'",
        updated_value, retrieved_after_update
    );

    println!("✓ Secret update test passed");
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════
// Secret Update Preserves Other Secrets
// ═══════════════════════════════════════════════════════════════════════════

backend_test!(
    test_secret_update_preserves_others,
    run_secret_update_preserves_others_test
);

async fn run_secret_update_preserves_others_test(
    config: BackendConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let harness = TestHarness::new("secret_update_preserves", config).await?;

    // Create user and setup
    let invite = harness.create_server_invite()?;
    let alice = harness.create_user("alice");
    alice.join(&invite, &alice.email(), &alice.principal())?;

    // Create workspace, project, environment
    alice.exec(&["workspace", "create", "test-ws"]).success()?;
    alice
        .exec(&["project", "create", "-w", "test-ws", "test-proj"])
        .success()?;
    alice
        .exec(&[
            "environment",
            "create",
            "-w",
            "test-ws",
            "-p",
            "test-proj",
            "dev",
        ])
        .success()?;

    // Create multiple secrets
    alice
        .exec(&[
            "secret",
            "set",
            "-w",
            "test-ws",
            "-p",
            "test-proj",
            "-e",
            "dev",
            "SECRET_A",
            "value-a",
        ])
        .success()?;
    alice
        .exec(&[
            "secret",
            "set",
            "-w",
            "test-ws",
            "-p",
            "test-proj",
            "-e",
            "dev",
            "SECRET_B",
            "value-b",
        ])
        .success()?;
    alice
        .exec(&[
            "secret",
            "set",
            "-w",
            "test-ws",
            "-p",
            "test-proj",
            "-e",
            "dev",
            "SECRET_C",
            "value-c",
        ])
        .success()?;

    // Update only SECRET_B
    alice
        .exec(&[
            "secret",
            "set",
            "-w",
            "test-ws",
            "-p",
            "test-proj",
            "-e",
            "dev",
            "SECRET_B",
            "updated-value-b",
        ])
        .success()?;

    // Verify SECRET_A is unchanged
    let secret_a = alice
        .exec(&[
            "secret",
            "get",
            "-w",
            "test-ws",
            "-p",
            "test-proj",
            "-e",
            "dev",
            "SECRET_A",
        ])
        .success()?;
    assert_eq!(secret_a, "value-a", "SECRET_A should be unchanged");

    // Verify SECRET_B is updated
    let secret_b = alice
        .exec(&[
            "secret",
            "get",
            "-w",
            "test-ws",
            "-p",
            "test-proj",
            "-e",
            "dev",
            "SECRET_B",
        ])
        .success()?;
    assert_eq!(secret_b, "updated-value-b", "SECRET_B should be updated");

    // Verify SECRET_C is unchanged
    let secret_c = alice
        .exec(&[
            "secret",
            "get",
            "-w",
            "test-ws",
            "-p",
            "test-proj",
            "-e",
            "dev",
            "SECRET_C",
        ])
        .success()?;
    assert_eq!(secret_c, "value-c", "SECRET_C should be unchanged");

    println!("✓ Secret update preserves other secrets test passed");
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════
// Secret Update With Special Characters
// ═══════════════════════════════════════════════════════════════════════════

backend_test!(
    test_secret_update_special_chars,
    run_secret_update_special_chars_test
);

async fn run_secret_update_special_chars_test(
    config: BackendConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let harness = TestHarness::new("secret_update_special", config).await?;

    // Create user and setup
    let invite = harness.create_server_invite()?;
    let alice = harness.create_user("alice");
    alice.join(&invite, &alice.email(), &alice.principal())?;

    // Create workspace, project, environment
    alice.exec(&["workspace", "create", "test-ws"]).success()?;
    alice
        .exec(&["project", "create", "-w", "test-ws", "test-proj"])
        .success()?;
    alice
        .exec(&[
            "environment",
            "create",
            "-w",
            "test-ws",
            "-p",
            "test-proj",
            "dev",
        ])
        .success()?;

    // Create secret with simple value
    alice
        .exec(&[
            "secret",
            "set",
            "-w",
            "test-ws",
            "-p",
            "test-proj",
            "-e",
            "dev",
            "CONNECTION_STRING",
            "simple-value",
        ])
        .success()?;

    // Update with value containing special characters
    let special_value = "postgres://user:p@ss=word!@localhost:5432/db?ssl=true&timeout=30";
    alice
        .exec(&[
            "secret",
            "set",
            "-w",
            "test-ws",
            "-p",
            "test-proj",
            "-e",
            "dev",
            "CONNECTION_STRING",
            special_value,
        ])
        .success()?;

    // Verify special characters are preserved
    let retrieved = alice
        .exec(&[
            "secret",
            "get",
            "-w",
            "test-ws",
            "-p",
            "test-proj",
            "-e",
            "dev",
            "CONNECTION_STRING",
        ])
        .success()?;
    assert_eq!(
        retrieved, special_value,
        "Special characters not preserved in update"
    );

    println!("✓ Secret update with special characters test passed");
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════
// Multi-User Secret Update
// ═══════════════════════════════════════════════════════════════════════════

backend_test!(
    test_secret_update_multi_user,
    run_secret_update_multi_user_test
);

async fn run_secret_update_multi_user_test(
    config: BackendConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let harness = TestHarness::new("secret_update_multi", config).await?;

    // Create first user (Alice - workspace owner)
    let invite = harness.create_server_invite()?;
    let alice = harness.create_user("alice");
    alice.join(&invite, &alice.email(), &alice.principal())?;

    // Create workspace, project, environment
    alice
        .exec(&["workspace", "create", "shared-ws"])
        .success()?;
    alice
        .exec(&["project", "create", "-w", "shared-ws", "shared-proj"])
        .success()?;
    alice
        .exec(&[
            "environment",
            "create",
            "-w",
            "shared-ws",
            "-p",
            "shared-proj",
            "dev",
        ])
        .success()?;

    // Alice creates a secret
    alice
        .exec(&[
            "secret",
            "set",
            "-w",
            "shared-ws",
            "-p",
            "shared-proj",
            "-e",
            "dev",
            "SHARED_SECRET",
            "alice-initial-value",
        ])
        .success()?;

    // Create workspace invite for Bob
    harness.create_zopp_toml("shared-ws", "shared-proj", "dev")?;
    let ws_invite_output = alice
        .exec_in(harness.test_dir(), &["invite", "create", "--plain"])
        .success()?;
    let ws_invite = ws_invite_output.trim();

    // Bob joins the workspace
    let bob = harness.create_user("bob");
    bob.join(ws_invite, &bob.email(), &bob.principal())?;

    // Alice grants Bob write permission
    alice
        .exec(&[
            "permission",
            "user-set",
            "-w",
            "shared-ws",
            "--email",
            &bob.email(),
            "--role",
            "write",
        ])
        .success()?;

    // Bob reads the secret (verifies access)
    let bob_read = bob
        .exec(&[
            "secret",
            "get",
            "-w",
            "shared-ws",
            "-p",
            "shared-proj",
            "-e",
            "dev",
            "SHARED_SECRET",
        ])
        .success()?;
    assert_eq!(
        bob_read, "alice-initial-value",
        "Bob should read Alice's secret"
    );

    // Bob updates the secret
    bob.exec(&[
        "secret",
        "set",
        "-w",
        "shared-ws",
        "-p",
        "shared-proj",
        "-e",
        "dev",
        "SHARED_SECRET",
        "bob-updated-value",
    ])
    .success()?;

    // Alice reads the updated value
    let alice_read = alice
        .exec(&[
            "secret",
            "get",
            "-w",
            "shared-ws",
            "-p",
            "shared-proj",
            "-e",
            "dev",
            "SHARED_SECRET",
        ])
        .success()?;
    assert_eq!(
        alice_read, "bob-updated-value",
        "Alice should see Bob's update"
    );

    println!("✓ Multi-user secret update test passed");
    Ok(())
}
