//! Environment E2E tests
//!
//! Tests environment CRUD operations: get, delete.
//! Note: create and list are already tested in demo.rs

#[macro_use]
mod common;

use common::{BackendConfig, TestHarness};

// ═══════════════════════════════════════════════════════════════════════════
// Environment Tests
// ═══════════════════════════════════════════════════════════════════════════

backend_test!(test_environment_get, run_test_environment_get);
backend_test!(test_environment_delete, run_test_environment_delete);

// ═══════════════════════════════════════════════════════════════════════════
// Test Implementations
// ═══════════════════════════════════════════════════════════════════════════

/// Test environment get functionality
async fn run_test_environment_get(config: BackendConfig) -> Result<(), Box<dyn std::error::Error>> {
    let harness = TestHarness::new("env_get", config).await?;

    // Setup: create user, workspace, project, and environment
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

    // Test: Get environment details
    println!("  Test 1: Get environment details...");
    let output = alice
        .exec(&["environment", "get", "-w", "testws", "-p", "api", "dev"])
        .success()?;

    // Should show environment info
    assert!(
        output.contains("dev"),
        "Should show environment name, got: {}",
        output
    );

    println!("test_environment_get PASSED");
    Ok(())
}

/// Test environment delete functionality
async fn run_test_environment_delete(
    config: BackendConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let harness = TestHarness::new("env_delete", config).await?;

    // Setup: create user, workspace, project, and environments
    let invite = harness.create_server_invite()?;
    let alice = harness.create_user("alice");
    alice.join(&invite, &alice.email(), &alice.principal())?;
    alice.exec(&["workspace", "create", "delws"]).success()?;
    alice
        .exec(&["project", "create", "api", "-w", "delws"])
        .success()?;
    alice
        .exec(&["environment", "create", "temp", "-w", "delws", "-p", "api"])
        .success()?;
    alice
        .exec(&["environment", "create", "keep", "-w", "delws", "-p", "api"])
        .success()?;

    // Verify both environments exist
    println!("  Test 1: Verify environments exist...");
    let output = alice
        .exec(&["environment", "list", "-w", "delws", "-p", "api"])
        .success()?;
    assert!(output.contains("temp"), "temp environment should exist");
    assert!(output.contains("keep"), "keep environment should exist");

    // Delete the temp environment
    println!("  Test 2: Delete environment...");
    alice
        .exec(&["environment", "delete", "-w", "delws", "-p", "api", "temp"])
        .success()?;

    // Verify temp is deleted but keep still exists
    println!("  Test 3: Verify environment deleted...");
    let output = alice
        .exec(&["environment", "list", "-w", "delws", "-p", "api"])
        .success()?;
    assert!(
        !output.contains("temp"),
        "temp environment should be deleted"
    );
    assert!(
        output.contains("keep"),
        "keep environment should still exist"
    );

    // Verify get on deleted environment fails
    println!("  Test 4: Verify get on deleted environment fails...");
    let result = alice.exec(&["environment", "get", "-w", "delws", "-p", "api", "temp"]);
    assert!(result.failed(), "Should fail to get deleted environment");

    println!("test_environment_delete PASSED");
    Ok(())
}
