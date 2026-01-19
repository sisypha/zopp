//! E2E tests for resource counts
//!
//! Verifies that workspace/project/environment list responses include
//! correct counts for child resources (projects, environments, secrets).

#[macro_use]
mod common;

use common::{BackendConfig, TestHarness};

// ═══════════════════════════════════════════════════════════════════════════
// Count Tests
// ═══════════════════════════════════════════════════════════════════════════

backend_test!(test_workspace_project_count, run_test_workspace_project_count);
backend_test!(test_project_environment_count, run_test_project_environment_count);
backend_test!(test_environment_secret_count, run_test_environment_secret_count);

// ═══════════════════════════════════════════════════════════════════════════
// Test Implementations
// ═══════════════════════════════════════════════════════════════════════════

/// Test that workspace list shows correct project count
async fn run_test_workspace_project_count(
    config: BackendConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let harness = TestHarness::new("ws_proj_count", config).await?;

    // Setup: create user and workspace
    let invite = harness.create_server_invite()?;
    let alice = harness.create_user("alice");
    alice.join(&invite, &alice.email(), &alice.principal())?;

    // Create workspace with no projects
    alice.exec(&["workspace", "create", "test-ws"]).success()?;

    // List workspaces - should show 0 projects
    println!("  Test 1: Empty workspace shows 0 projects...");
    let output = alice.exec(&["workspace", "list"]).success()?;
    assert!(
        output.contains("0 project") || output.contains("(0)"),
        "Workspace list should show 0 projects for empty workspace. Got: {}",
        output
    );

    // Create 2 projects
    println!("  Test 2: Create 2 projects...");
    alice
        .exec(&["project", "create", "proj-1", "-w", "test-ws"])
        .success()?;
    alice
        .exec(&["project", "create", "proj-2", "-w", "test-ws"])
        .success()?;

    // List workspaces - should show 2 projects
    println!("  Test 3: Workspace shows 2 projects...");
    let output = alice.exec(&["workspace", "list"]).success()?;
    assert!(
        output.contains("2 project") || output.contains("(2)"),
        "Workspace list should show 2 projects. Got: {}",
        output
    );

    println!("test_workspace_project_count PASSED");
    Ok(())
}

/// Test that project list shows correct environment count
async fn run_test_project_environment_count(
    config: BackendConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let harness = TestHarness::new("proj_env_count", config).await?;

    // Setup
    let invite = harness.create_server_invite()?;
    let alice = harness.create_user("alice");
    alice.join(&invite, &alice.email(), &alice.principal())?;
    alice.exec(&["workspace", "create", "test-ws"]).success()?;
    alice
        .exec(&["project", "create", "test-proj", "-w", "test-ws"])
        .success()?;

    // List projects - should show 0 environments
    println!("  Test 1: Empty project shows 0 environments...");
    let output = alice.exec(&["project", "list", "-w", "test-ws"]).success()?;
    assert!(
        output.contains("0 environment") || output.contains("(0)"),
        "Project list should show 0 environments for empty project. Got: {}",
        output
    );

    // Create 3 environments
    println!("  Test 2: Create 3 environments...");
    for env in &["dev", "staging", "prod"] {
        alice
            .exec(&[
                "environment",
                "create",
                env,
                "-w",
                "test-ws",
                "-p",
                "test-proj",
            ])
            .success()?;
    }

    // List projects - should show 3 environments
    println!("  Test 3: Project shows 3 environments...");
    let output = alice.exec(&["project", "list", "-w", "test-ws"]).success()?;
    assert!(
        output.contains("3 environment") || output.contains("(3)"),
        "Project list should show 3 environments. Got: {}",
        output
    );

    println!("test_project_environment_count PASSED");
    Ok(())
}

/// Test that environment list shows correct secret count
async fn run_test_environment_secret_count(
    config: BackendConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let harness = TestHarness::new("env_secret_count", config).await?;

    // Setup
    let invite = harness.create_server_invite()?;
    let alice = harness.create_user("alice");
    alice.join(&invite, &alice.email(), &alice.principal())?;
    alice.exec(&["workspace", "create", "test-ws"]).success()?;
    alice
        .exec(&["project", "create", "test-proj", "-w", "test-ws"])
        .success()?;
    alice
        .exec(&[
            "environment",
            "create",
            "dev",
            "-w",
            "test-ws",
            "-p",
            "test-proj",
        ])
        .success()?;

    // List environments - should show 0 secrets
    println!("  Test 1: Empty environment shows 0 secrets...");
    let output = alice
        .exec(&["environment", "list", "-w", "test-ws", "-p", "test-proj"])
        .success()?;
    assert!(
        output.contains("0 secret") || output.contains("(0)"),
        "Environment list should show 0 secrets for empty environment. Got: {}",
        output
    );

    // Create 2 secrets
    println!("  Test 2: Create 2 secrets...");
    alice
        .exec(&[
            "secret",
            "set",
            "API_KEY",
            "secret123",
            "-w",
            "test-ws",
            "-p",
            "test-proj",
            "-e",
            "dev",
        ])
        .success()?;
    alice
        .exec(&[
            "secret",
            "set",
            "DB_URL",
            "postgres://...",
            "-w",
            "test-ws",
            "-p",
            "test-proj",
            "-e",
            "dev",
        ])
        .success()?;

    // List environments - should show 2 secrets
    println!("  Test 3: Environment shows 2 secrets...");
    let output = alice
        .exec(&["environment", "list", "-w", "test-ws", "-p", "test-proj"])
        .success()?;
    assert!(
        output.contains("2 secret") || output.contains("(2)"),
        "Environment list should show 2 secrets. Got: {}",
        output
    );

    println!("test_environment_secret_count PASSED");
    Ok(())
}
