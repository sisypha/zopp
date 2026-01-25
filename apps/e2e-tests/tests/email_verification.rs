//! Email Verification E2E tests
//!
//! Tests the email verification flow for new principals.
//!
//! These tests use a mock SMTP server to capture verification emails,
//! allowing us to test the complete flow:
//! 1. Start join (triggers verification email)
//! 2. Extract verification code from captured email
//! 3. Complete join with valid verification code

#[macro_use]
mod common;

use common::{BackendConfig, TestHarness};

// ═══════════════════════════════════════════════════════════════════════════
// Email Verification Tests
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_email_verification_harness_sqlite() -> Result<(), Box<dyn std::error::Error>> {
    run_test_verification_harness(BackendConfig::sqlite_memory()).await
}

#[tokio::test]
async fn test_email_verification_invalid_code_sqlite() -> Result<(), Box<dyn std::error::Error>> {
    run_test_invalid_verification_code(BackendConfig::sqlite_memory()).await
}

#[tokio::test]
async fn test_email_verification_full_flow_sqlite() -> Result<(), Box<dyn std::error::Error>> {
    run_test_full_verification_flow(BackendConfig::sqlite_memory()).await
}

// ═══════════════════════════════════════════════════════════════════════════
// Test Implementations
// ═══════════════════════════════════════════════════════════════════════════

/// Test that the verification-enabled harness works and codes are created
async fn run_test_verification_harness(
    config: BackendConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("  Test: Verification-enabled harness starts correctly...");

    // Create harness with email verification enabled
    let harness = TestHarness::new_with_verification("verify_harness", config).await?;

    // Verify server is running
    let invite = harness.create_server_invite()?;
    assert!(
        invite.starts_with("inv_"),
        "Server should create valid invites"
    );

    println!("  Harness with verification enabled started successfully");
    println!("test_email_verification_harness PASSED");
    Ok(())
}

/// Test that join with invalid verification code fails appropriately
async fn run_test_invalid_verification_code(
    config: BackendConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let harness = TestHarness::new_with_verification("verify_invalid", config).await?;
    let invite = harness.create_server_invite()?;
    let alice = harness.create_user("alice");

    println!("  Test 1: Join with invalid verification code should fail...");

    let result = alice.exec(&[
        "join",
        &invite,
        &alice.email(),
        "--principal",
        &alice.principal(),
        "--verification-code",
        "XXXXXX", // Non-numeric code - guaranteed to be invalid
    ]);

    // Join should fail because verification code is invalid
    assert!(result.failed(), "Join with invalid code should fail");

    let stderr = result.stderr();
    let stdout = result.stdout();
    let output = format!("{}{}", stdout, stderr);

    assert!(
        output.contains("verification")
            || output.contains("Verification")
            || output.contains("Invalid")
            || output.contains("invalid"),
        "Error should mention verification: stdout='{}' stderr='{}'",
        stdout,
        stderr
    );

    println!("  Test 2: Verification email should have been sent...");

    // The join attempt should have sent a verification email
    let code = harness
        .get_verification_code_from_email(&alice.email())
        .await?;
    assert_eq!(code.len(), 6, "Verification code should be 6 digits");
    assert!(
        code.chars().all(|c| c.is_ascii_digit()),
        "Verification code should be all digits: {}",
        code
    );
    println!("    Retrieved verification code from email: {}", code);

    println!(
        "  Test 3: Database should have a verification record (hash stored, not plaintext)..."
    );

    let has_record = harness.has_verification_record(&alice.email())?;
    assert!(
        has_record,
        "Database should have a verification record for the email"
    );
    println!("    Verification record exists in database (code hash stored)");

    println!("test_email_verification_invalid_code PASSED");
    Ok(())
}

/// Test the complete verification flow: request code, receive email, verify
async fn run_test_full_verification_flow(
    config: BackendConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let harness = TestHarness::new_with_verification("verify_full", config).await?;
    let invite = harness.create_server_invite()?;
    let bob = harness.create_user("bob");

    println!("  Test 1: First join attempt triggers verification email...");

    // First attempt with invalid code to trigger email sending
    let result = bob.exec(&[
        "join",
        &invite,
        &bob.email(),
        "--principal",
        &bob.principal(),
        "--verification-code",
        "XXXXXX", // Non-numeric code - guaranteed to be invalid
    ]);
    assert!(result.failed(), "First join should fail with wrong code");

    // Get the verification code from the captured email
    let code = harness
        .get_verification_code_from_email(&bob.email())
        .await?;
    println!("    Received verification code: {}", code);

    println!("  Test 2: Join with correct verification code should succeed...");

    // Now join with the correct code
    bob.join_with_verification(&invite, &bob.email(), &bob.principal(), &code)?;
    println!("    Join succeeded!");

    println!("  Test 3: User should be able to use the CLI after verification...");

    // Verify the user can now create workspaces
    let result = bob.exec(&["workspace", "create", "test-workspace"]);
    let output = result.success()?;
    assert!(
        output.contains("test-workspace") || output.contains("Created"),
        "Should be able to create workspace after verification: {}",
        output
    );
    println!("    Created workspace successfully");

    println!("test_email_verification_full_flow PASSED");
    Ok(())
}
