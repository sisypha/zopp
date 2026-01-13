//! Audit log E2E tests
//!
//! Tests audit CLI commands: list, get, count.
//! Audit logs require Admin workspace permission.

#[macro_use]
mod common;

use common::{BackendConfig, TestHarness};

// ═══════════════════════════════════════════════════════════════════════════
// Audit Tests
// ═══════════════════════════════════════════════════════════════════════════

backend_test!(test_audit_list_after_operations, run_test_audit_list);
backend_test!(test_audit_count, run_test_audit_count);
backend_test!(test_audit_get_by_id, run_test_audit_get_by_id);
backend_test!(test_audit_filter_by_action, run_test_audit_filter_by_action);

// ═══════════════════════════════════════════════════════════════════════════
// Test Implementations
// ═══════════════════════════════════════════════════════════════════════════

/// Test that audit logs are recorded for operations and can be listed
async fn run_test_audit_list(config: BackendConfig) -> Result<(), Box<dyn std::error::Error>> {
    let harness = TestHarness::new("audit_list", config).await?;

    // Setup: create user and workspace
    let invite = harness.create_server_invite()?;
    let alice = harness.create_user("alice");
    alice.join(&invite, &alice.email(), &alice.principal())?;
    alice.exec(&["workspace", "create", "testws"]).success()?;
    alice
        .exec(&["project", "create", "api", "-w", "testws"])
        .success()?;
    alice
        .exec(&["environment", "create", "dev", "-w", "testws", "-p", "api"])
        .success()?;

    // Perform some operations that should be recorded in audit logs
    println!("  Test 1: Perform operations to generate audit entries...");
    alice
        .exec(&[
            "secret",
            "set",
            "-w",
            "testws",
            "-p",
            "api",
            "-e",
            "dev",
            "API_KEY",
            "secret123",
        ])
        .success()?;
    alice
        .exec(&[
            "secret", "get", "-w", "testws", "-p", "api", "-e", "dev", "API_KEY",
        ])
        .success()?;
    alice
        .exec(&[
            "secret", "delete", "-w", "testws", "-p", "api", "-e", "dev", "API_KEY",
        ])
        .success()?;

    // Test: List audit logs
    println!("  Test 2: List audit logs...");
    let output = alice
        .exec(&["audit", "list", "-w", "testws", "--limit", "50"])
        .success()?;

    // Should show audit entries (the output includes ID:, Timestamp:, Action:, etc.)
    assert!(
        output.contains("Action:"),
        "Expected audit log entries, got: {}",
        output
    );

    println!("test_audit_list PASSED");
    Ok(())
}

/// Test audit count command
async fn run_test_audit_count(config: BackendConfig) -> Result<(), Box<dyn std::error::Error>> {
    let harness = TestHarness::new("audit_count", config).await?;

    // Setup
    let invite = harness.create_server_invite()?;
    let alice = harness.create_user("alice");
    alice.join(&invite, &alice.email(), &alice.principal())?;
    alice.exec(&["workspace", "create", "testws"]).success()?;
    alice
        .exec(&["project", "create", "api", "-w", "testws"])
        .success()?;
    alice
        .exec(&["environment", "create", "dev", "-w", "testws", "-p", "api"])
        .success()?;

    // Perform operations
    println!("  Test 1: Perform operations...");
    alice
        .exec(&[
            "secret", "set", "-w", "testws", "-p", "api", "-e", "dev", "KEY1", "val1",
        ])
        .success()?;
    alice
        .exec(&[
            "secret", "set", "-w", "testws", "-p", "api", "-e", "dev", "KEY2", "val2",
        ])
        .success()?;

    // Test: Count audit logs
    println!("  Test 2: Count audit logs...");
    let output = alice.exec(&["audit", "count", "-w", "testws"]).success()?;

    // Should show "Total audit log entries: N" where N > 0
    assert!(
        output.contains("Total audit log entries:"),
        "Expected count output, got: {}",
        output
    );

    // Parse the count and verify it's > 0
    let count_str = output.split(':').next_back().map(|s| s.trim()).expect(
        "Failed to parse count from audit output - expected 'Total audit log entries: N' format",
    );
    let count: u32 = count_str
        .parse()
        .expect("Failed to parse audit count as u32");
    assert!(count > 0, "Expected audit count > 0, got: {}", count);

    println!("test_audit_count PASSED");
    Ok(())
}

/// Test getting a specific audit log entry by ID
async fn run_test_audit_get_by_id(config: BackendConfig) -> Result<(), Box<dyn std::error::Error>> {
    let harness = TestHarness::new("audit_get", config).await?;

    // Setup
    let invite = harness.create_server_invite()?;
    let alice = harness.create_user("alice");
    alice.join(&invite, &alice.email(), &alice.principal())?;
    alice.exec(&["workspace", "create", "testws"]).success()?;
    alice
        .exec(&["project", "create", "api", "-w", "testws"])
        .success()?;
    alice
        .exec(&["environment", "create", "dev", "-w", "testws", "-p", "api"])
        .success()?;

    // Perform an operation
    println!("  Test 1: Perform operation...");
    alice
        .exec(&[
            "secret", "set", "-w", "testws", "-p", "api", "-e", "dev", "MY_KEY", "my_value",
        ])
        .success()?;

    // List audit logs to get an ID
    println!("  Test 2: List audit logs to get an ID...");
    let list_output = alice
        .exec(&["audit", "list", "-w", "testws", "--limit", "1"])
        .success()?;

    // Extract the ID from the output (format: "ID:        <uuid>")
    let id = list_output
        .lines()
        .find(|line| line.starts_with("ID:"))
        .and_then(|line| line.split_whitespace().last())
        .ok_or("Failed to extract audit log ID from list output")?;

    // Test: Get the specific audit entry
    println!("  Test 3: Get audit entry by ID {}...", id);
    let output = alice
        .exec(&["audit", "get", "-w", "testws", id])
        .success()?;

    // Should show detailed entry info
    assert!(output.contains("ID:"), "Expected ID in output");
    assert!(
        output.contains("Timestamp:"),
        "Expected Timestamp in output"
    );
    assert!(output.contains("Action:"), "Expected Action in output");
    assert!(output.contains(id), "Expected the requested ID in output");

    println!("test_audit_get_by_id PASSED");
    Ok(())
}

/// Test filtering audit logs by result
async fn run_test_audit_filter_by_action(
    config: BackendConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let harness = TestHarness::new("audit_filter", config).await?;

    // Setup
    let invite = harness.create_server_invite()?;
    let alice = harness.create_user("alice");
    alice.join(&invite, &alice.email(), &alice.principal())?;
    alice.exec(&["workspace", "create", "testws"]).success()?;
    alice
        .exec(&["project", "create", "api", "-w", "testws"])
        .success()?;
    alice
        .exec(&["environment", "create", "dev", "-w", "testws", "-p", "api"])
        .success()?;

    // Perform various operations
    println!("  Test 1: Perform various operations...");
    alice
        .exec(&[
            "secret", "set", "-w", "testws", "-p", "api", "-e", "dev", "KEY1", "val1",
        ])
        .success()?;
    alice
        .exec(&[
            "secret", "get", "-w", "testws", "-p", "api", "-e", "dev", "KEY1",
        ])
        .success()?;
    alice
        .exec(&[
            "secret", "set", "-w", "testws", "-p", "api", "-e", "dev", "KEY2", "val2",
        ])
        .success()?;

    // Test: Filter by result (success)
    println!("  Test 2: Filter audit logs by result 'success'...");
    let output = alice
        .exec(&["audit", "list", "-w", "testws", "--result", "success"])
        .success()?;

    // If there are results, they should all be success
    if output.contains("Result:") {
        for line in output.lines() {
            if line.starts_with("Result:") {
                assert!(
                    line.contains("success"),
                    "Expected only success results when filtering, got: {}",
                    line
                );
            }
        }
    }

    // Test: Count filtered entries
    println!("  Test 3: Count audit logs filtered by result 'success'...");
    let count_output = alice
        .exec(&["audit", "count", "-w", "testws", "--result", "success"])
        .success()?;

    assert!(
        count_output.contains("Total audit log entries:"),
        "Expected count output, got: {}",
        count_output
    );

    println!("test_audit_filter_by_result PASSED");
    Ok(())
}
