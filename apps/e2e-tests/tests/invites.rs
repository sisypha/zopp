//! Invite E2E tests
//!
//! Tests invite operations: list, revoke.
//! Note: invite create is already tested in demo.rs

#[macro_use]
mod common;

use common::{BackendConfig, TestHarness};

// ═══════════════════════════════════════════════════════════════════════════
// Invite Tests
// ═══════════════════════════════════════════════════════════════════════════

backend_test!(test_invite_list, run_test_invite_list);
backend_test!(test_invite_revoke, run_test_invite_revoke);

// ═══════════════════════════════════════════════════════════════════════════
// Test Implementations
// ═══════════════════════════════════════════════════════════════════════════

/// Test invite list functionality
async fn run_test_invite_list(config: BackendConfig) -> Result<(), Box<dyn std::error::Error>> {
    let harness = TestHarness::new("inv_list", config).await?;

    // Setup: create user and workspace
    let invite = harness.create_server_invite()?;
    let alice = harness.create_user("alice");
    alice.join(&invite, &alice.email(), &alice.principal())?;
    alice.exec(&["workspace", "create", "testws"]).success()?;

    // Create zopp.toml for workspace context (invite list needs it)
    harness.create_zopp_toml("testws", "api", "dev")?;

    // Create a couple of invites
    println!("  Test 1: Create invites...");
    alice
        .exec(&["invite", "create", "-w", "testws", "--plain"])
        .success()?;
    alice
        .exec(&["invite", "create", "-w", "testws", "--plain"])
        .success()?;

    // Test: List invites (uses zopp.toml for workspace context)
    println!("  Test 2: List invites...");
    let output = alice
        .exec_in(harness.test_dir(), &["invite", "list"])
        .success()?;

    // Should show at least 2 invites (each with Token: prefix)
    let invite_count = output.matches("Token:").count();
    assert!(
        invite_count >= 2,
        "Should list at least 2 invites, found: {}",
        invite_count
    );

    println!("test_invite_list PASSED");
    Ok(())
}

/// Test invite revoke functionality
async fn run_test_invite_revoke(config: BackendConfig) -> Result<(), Box<dyn std::error::Error>> {
    let harness = TestHarness::new("inv_revoke", config).await?;

    // Setup: create user and workspace
    let invite = harness.create_server_invite()?;
    let alice = harness.create_user("alice");
    alice.join(&invite, &alice.email(), &alice.principal())?;
    alice.exec(&["workspace", "create", "testws"]).success()?;

    // Create zopp.toml for workspace context (invite list needs it)
    harness.create_zopp_toml("testws", "api", "dev")?;

    // Count initial invites
    println!("  Test 1: Count initial invites...");
    let initial_output = alice
        .exec_in(harness.test_dir(), &["invite", "list"])
        .success()?;
    let initial_count = initial_output.matches("Token:").count();

    // Create an invite
    println!("  Test 2: Create invite...");
    let invite_token = alice
        .exec(&["invite", "create", "-w", "testws", "--plain"])
        .success()?;

    // Verify invite count increased
    // Note: invite list shows the hash token (for server lookup), not the invite code.
    // The full invite code (inv_XXX) is only known to creator and cannot be recovered from list.
    println!("  Test 3: Verify invite count increased...");
    let after_create = alice
        .exec_in(harness.test_dir(), &["invite", "list"])
        .success()?;
    let after_count = after_create.matches("Token:").count();
    assert!(
        after_count > initial_count,
        "Invite count should increase after create: {} -> {}",
        initial_count,
        after_count
    );

    // Revoke the invite using the full invite code
    println!("  Test 4: Revoke invite...");
    alice.exec(&["invite", "revoke", &invite_token]).success()?;

    // Verify revoked invite can't be used
    println!("  Test 5: Verify revoked invite can't be used...");
    let bob = harness.create_user("bob");
    let result = bob.exec(&[
        "join",
        &invite_token,
        &bob.email(),
        "--principal",
        &bob.principal(),
    ]);
    assert!(result.failed(), "Should fail to use revoked invite");

    println!("test_invite_revoke PASSED");
    Ok(())
}
