//! Audit log E2E tests
//!
//! These tests verify that audit logs are recorded for various operations
//! and can be queried through the CLI.
//!
//! Note: Currently only secret operations (upsert, get, list, delete) are audited.
//! Workspace, project, environment operations are NOT yet audited.

#[macro_use]
mod common;

use common::{BackendConfig, TestHarness};

// ═══════════════════════════════════════════════════════════════════════════
// Audit Log Tests
// ═══════════════════════════════════════════════════════════════════════════

backend_test!(
    test_audit_list_after_operations,
    run_test_audit_list_after_operations
);
backend_test!(test_audit_count, run_test_audit_count);
backend_test!(test_audit_get_by_id, run_test_audit_get_by_id);
backend_test!(test_audit_filter_by_action, run_test_audit_filter_by_action);

// ═══════════════════════════════════════════════════════════════════════════
// Test Implementations
// ═══════════════════════════════════════════════════════════════════════════

async fn run_test_audit_list_after_operations(
    config: BackendConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let harness = TestHarness::new("audit_list", config).await?;

    // Setup: create user, workspace, project, environment
    let invite = harness.create_server_invite()?;
    let alice = harness.create_user("alice");
    alice.join(&invite, &alice.email(), &alice.principal())?;
    alice.exec(&["workspace", "create", "testws"]).success()?;
    alice
        .exec(&["project", "create", "proj", "-w", "testws"])
        .success()?;
    alice
        .exec(&["environment", "create", "dev", "-w", "testws", "-p", "proj"])
        .success()?;

    // Set a secret (this IS audited as secret.create)
    alice
        .exec(&[
            "secret",
            "set",
            "API_KEY",
            "secret123",
            "-w",
            "testws",
            "-p",
            "proj",
            "-e",
            "dev",
        ])
        .success()?;

    // Get the secret (audited as secret.read)
    alice
        .exec(&[
            "secret", "get", "API_KEY", "-w", "testws", "-p", "proj", "-e", "dev",
        ])
        .success()?;

    // List audit logs and verify we have entries
    let output = alice
        .exec(&["audit", "list", "-w", "testws", "--limit", "100"])
        .success()?;

    // Verify audit entries exist (should have at least secret.create and secret.read)
    assert!(
        output.contains("Audit logs") || output.contains("ID:"),
        "Expected audit list output, got: {}",
        output
    );

    println!("test_audit_list_after_operations PASSED");
    Ok(())
}

async fn run_test_audit_count(config: BackendConfig) -> Result<(), Box<dyn std::error::Error>> {
    let harness = TestHarness::new("audit_count", config).await?;

    // Setup: create user, workspace, project, environment
    let invite = harness.create_server_invite()?;
    let alice = harness.create_user("alice");
    alice.join(&invite, &alice.email(), &alice.principal())?;
    alice.exec(&["workspace", "create", "countws"]).success()?;
    alice
        .exec(&["project", "create", "proj", "-w", "countws"])
        .success()?;
    alice
        .exec(&[
            "environment",
            "create",
            "dev",
            "-w",
            "countws",
            "-p",
            "proj",
        ])
        .success()?;

    // Set a secret (this IS audited as secret.create)
    alice
        .exec(&[
            "secret",
            "set",
            "API_KEY",
            "secret123",
            "-w",
            "countws",
            "-p",
            "proj",
            "-e",
            "dev",
        ])
        .success()?;

    // Count audit logs
    let output = alice.exec(&["audit", "count", "-w", "countws"]).success()?;

    // Verify we get a count
    assert!(
        output.contains("Total audit log entries:"),
        "Expected count output, got: {}",
        output
    );

    // The count should be at least 1 (secret upsert creates audit entry)
    if let Some(count_str) = output.split(':').next_back() {
        let count: u64 = count_str.trim().parse().unwrap_or(0);
        assert!(
            count >= 1,
            "Expected at least 1 audit entry, got: {}",
            count
        );
    }

    println!("test_audit_count PASSED");
    Ok(())
}

async fn run_test_audit_get_by_id(config: BackendConfig) -> Result<(), Box<dyn std::error::Error>> {
    let harness = TestHarness::new("audit_get", config).await?;

    // Setup: create user, workspace, project, environment
    let invite = harness.create_server_invite()?;
    let alice = harness.create_user("alice");
    alice.join(&invite, &alice.email(), &alice.principal())?;
    alice.exec(&["workspace", "create", "getws"]).success()?;
    alice
        .exec(&["project", "create", "proj", "-w", "getws"])
        .success()?;
    alice
        .exec(&["environment", "create", "dev", "-w", "getws", "-p", "proj"])
        .success()?;

    // Set a secret (this IS audited as secret.create)
    alice
        .exec(&[
            "secret",
            "set",
            "API_KEY",
            "secret123",
            "-w",
            "getws",
            "-p",
            "proj",
            "-e",
            "dev",
        ])
        .success()?;

    // List audit logs to get an ID
    let list_output = alice
        .exec(&["audit", "list", "-w", "getws", "--limit", "1"])
        .success()?;

    // Extract the ID from the output (look for "ID: <uuid>")
    let id = list_output
        .lines()
        .find(|line| line.starts_with("ID:"))
        .and_then(|line| line.split_whitespace().last())
        .ok_or("Could not find audit log ID in list output")?;

    // Get the specific audit log by ID
    let get_output = alice.exec(&["audit", "get", id, "-w", "getws"]).success()?;

    // Verify the output contains the ID
    assert!(
        get_output.contains(id),
        "Expected audit log with ID {}, got: {}",
        id,
        get_output
    );

    // Verify it contains expected fields
    assert!(
        get_output.contains("Action:"),
        "Expected Action field, got: {}",
        get_output
    );
    assert!(
        get_output.contains("Result:"),
        "Expected Result field, got: {}",
        get_output
    );

    println!("test_audit_get_by_id PASSED");
    Ok(())
}

async fn run_test_audit_filter_by_action(
    config: BackendConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let harness = TestHarness::new("audit_filter", config).await?;

    // Setup: create user, workspace, project, environment
    let invite = harness.create_server_invite()?;
    let alice = harness.create_user("alice");
    alice.join(&invite, &alice.email(), &alice.principal())?;
    alice.exec(&["workspace", "create", "filterws"]).success()?;
    alice
        .exec(&["project", "create", "proj", "-w", "filterws"])
        .success()?;
    alice
        .exec(&[
            "environment",
            "create",
            "dev",
            "-w",
            "filterws",
            "-p",
            "proj",
        ])
        .success()?;

    // Set multiple secrets (audited as secret.create)
    alice
        .exec(&[
            "secret", "set", "KEY1", "value1", "-w", "filterws", "-p", "proj", "-e", "dev",
        ])
        .success()?;
    alice
        .exec(&[
            "secret", "set", "KEY2", "value2", "-w", "filterws", "-p", "proj", "-e", "dev",
        ])
        .success()?;

    // Get a secret (audited as secret.read)
    alice
        .exec(&[
            "secret", "get", "KEY1", "-w", "filterws", "-p", "proj", "-e", "dev",
        ])
        .success()?;

    // Filter by action (secret.create)
    let output = alice
        .exec(&[
            "audit",
            "list",
            "-w",
            "filterws",
            "--action",
            "secret.create",
        ])
        .success()?;

    // Verify we get some output
    assert!(
        !output.is_empty(),
        "Expected some output from filtered audit list"
    );

    // Count filtered results - should be 2 secret.create events
    let count_output = alice
        .exec(&[
            "audit",
            "count",
            "-w",
            "filterws",
            "--action",
            "secret.create",
        ])
        .success()?;

    // Verify we have 2 secret.create events (KEY1 and KEY2)
    if let Some(count_str) = count_output.split(':').next_back() {
        let count: u64 = count_str.trim().parse().unwrap_or(0);
        assert!(
            count >= 2,
            "Expected at least 2 secret.create events (KEY1 and KEY2), got: {}",
            count
        );
    }

    println!("test_audit_filter_by_action PASSED");
    Ok(())
}
