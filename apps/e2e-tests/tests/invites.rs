//! Invite E2E tests
//!
//! Tests invite list and revoke operations.
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
    let harness = TestHarness::new("invite_list", config).await?;

    // Setup: create user and workspace
    let invite = harness.create_server_invite()?;
    let alice = harness.create_user("alice");
    alice.join(&invite, &alice.email(), &alice.principal())?;
    alice.exec(&["workspace", "create", "testws"]).success()?;

    // Create some invites
    println!("  Test 1: Create invites...");
    alice
        .exec(&["invite", "create", "-w", "testws", "--plain"])
        .success()?;
    alice
        .exec(&["invite", "create", "-w", "testws", "--plain"])
        .success()?;

    // Test: List invites
    println!("  Test 2: List invites...");
    let output = alice.exec(&["invite", "list"]).success()?;

    // Verify invites are listed - each invite shows a "Token:" line
    // We created 2 invites, so expect at least 2 Token entries
    let token_count = output.matches("Token:").count();
    assert!(
        token_count >= 2,
        "Expected at least 2 invites listed (found {} Token: entries), got: {}",
        token_count,
        output
    );

    println!("test_invite_list PASSED");
    Ok(())
}

/// Test invite revoke functionality
async fn run_test_invite_revoke(config: BackendConfig) -> Result<(), Box<dyn std::error::Error>> {
    let harness = TestHarness::new("invite_revoke", config).await?;

    // Setup: create user and workspace
    let invite = harness.create_server_invite()?;
    let alice = harness.create_user("alice");
    alice.join(&invite, &alice.email(), &alice.principal())?;
    alice.exec(&["workspace", "create", "revokews"]).success()?;

    // Create an invite
    println!("  Test 1: Create invite...");
    let invite_code = alice
        .exec(&["invite", "create", "-w", "revokews", "--plain"])
        .success()?;
    let invite_code = invite_code.trim();
    assert!(!invite_code.is_empty(), "Should get non-empty invite code");

    // Verify invite is listed
    println!("  Test 2: Verify invite is listed...");
    let output = alice.exec(&["invite", "list"]).success()?;
    // The list should show at least one invite with a Token: line
    assert!(
        output.contains("Token:"),
        "Expected invite to be listed with Token: field, got: {}",
        output
    );

    // Revoke the invite
    println!("  Test 3: Revoke invite...");
    alice.exec(&["invite", "revoke", invite_code]).success()?;

    // Try to use the revoked invite - should fail
    println!("  Test 4: Verify revoked invite cannot be used...");
    let bob = harness.create_user("bob");
    let result = bob.exec(&["join", invite_code, &bob.email(), &bob.principal()]);
    assert!(
        result.failed(),
        "Should not be able to join with revoked invite"
    );

    println!("test_invite_revoke PASSED");
    Ok(())
}
