//! Project E2E tests
//!
//! Tests project CRUD operations: get, delete.
//! Note: create and list are already tested in demo.rs

#[macro_use]
mod common;

use common::{BackendConfig, TestHarness};

// ═══════════════════════════════════════════════════════════════════════════
// Project Tests
// ═══════════════════════════════════════════════════════════════════════════

backend_test!(test_project_get, run_test_project_get);
backend_test!(test_project_delete, run_test_project_delete);

// ═══════════════════════════════════════════════════════════════════════════
// Test Implementations
// ═══════════════════════════════════════════════════════════════════════════

/// Test project get functionality
async fn run_test_project_get(config: BackendConfig) -> Result<(), Box<dyn std::error::Error>> {
    let harness = TestHarness::new("proj_get", config).await?;

    // Setup: create user, workspace, and project
    let invite = harness.create_server_invite()?;
    let alice = harness.create_user("alice");
    alice.join(&invite, &alice.email(), &alice.principal())?;
    alice.exec(&["workspace", "create", "testws"]).success()?;
    alice
        .exec(&["project", "create", "api", "-w", "testws"])
        .success()?;

    // Test: Get project details
    println!("  Test 1: Get project details...");
    let output = alice
        .exec(&["project", "get", "-w", "testws", "api"])
        .success()?;

    // Should show project info
    assert!(
        output.contains("api"),
        "Should show project name, got: {}",
        output
    );

    println!("test_project_get PASSED");
    Ok(())
}

/// Test project delete functionality
async fn run_test_project_delete(config: BackendConfig) -> Result<(), Box<dyn std::error::Error>> {
    let harness = TestHarness::new("proj_delete", config).await?;

    // Setup: create user, workspace, and projects
    let invite = harness.create_server_invite()?;
    let alice = harness.create_user("alice");
    alice.join(&invite, &alice.email(), &alice.principal())?;
    alice.exec(&["workspace", "create", "delws"]).success()?;
    alice
        .exec(&["project", "create", "temp", "-w", "delws"])
        .success()?;
    alice
        .exec(&["project", "create", "keep", "-w", "delws"])
        .success()?;

    // Verify both projects exist
    println!("  Test 1: Verify projects exist...");
    let output = alice.exec(&["project", "list", "-w", "delws"]).success()?;
    assert!(output.contains("temp"), "temp project should exist");
    assert!(output.contains("keep"), "keep project should exist");

    // Delete the temp project
    println!("  Test 2: Delete project...");
    alice
        .exec(&["project", "delete", "-w", "delws", "temp"])
        .success()?;

    // Verify temp is deleted but keep still exists
    println!("  Test 3: Verify project deleted...");
    let output = alice.exec(&["project", "list", "-w", "delws"]).success()?;
    assert!(!output.contains("temp"), "temp project should be deleted");
    assert!(output.contains("keep"), "keep project should still exist");

    // Verify get on deleted project fails
    println!("  Test 4: Verify get on deleted project fails...");
    let result = alice.exec(&["project", "get", "-w", "delws", "temp"]);
    assert!(result.failed(), "Should fail to get deleted project");

    println!("test_project_delete PASSED");
    Ok(())
}
