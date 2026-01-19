//! Keychain storage E2E tests
//!
//! These tests verify that keychain storage works correctly when not using file storage.
//! They are skipped if keychain is not available on the system.

mod common;

use common::harness::{BackendConfig, TestHarness};
use std::process::Command;

/// Helper to check if keychain is available on the system
fn is_keychain_available() -> bool {
    // Try to actually store and delete a test secret to verify keychain works
    #[cfg(target_os = "linux")]
    {
        // On Linux, try to store a secret using secret-tool
        // This verifies D-Bus session and gnome-keyring are working
        let store_result = Command::new("secret-tool")
            .args([
                "store",
                "--label=zopp-test",
                "service",
                "zopp-availability-test",
                "account",
                "test",
            ])
            .stdin(std::process::Stdio::piped())
            .spawn()
            .and_then(|mut child| {
                use std::io::Write;
                // Take stdin to get ownership, write, then drop to send EOF
                if let Some(mut stdin) = child.stdin.take() {
                    stdin.write_all(b"test-secret")?;
                    // stdin is dropped here, sending EOF to secret-tool
                }
                child.wait()
            });

        if store_result.map(|s| s.success()).unwrap_or(false) {
            // Clean up the test secret
            let _ = Command::new("secret-tool")
                .args([
                    "clear",
                    "service",
                    "zopp-availability-test",
                    "account",
                    "test",
                ])
                .status();
            true
        } else {
            false
        }
    }
    #[cfg(target_os = "macos")]
    {
        // On macOS, keychain is always available
        true
    }
    #[cfg(target_os = "windows")]
    {
        // On Windows, credential manager is always available
        true
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        false
    }
}

/// Test that keychain storage works for join/workspace operations
#[tokio::test]
async fn test_keychain_join_and_workspace() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("CI").is_ok() && !is_keychain_available() {
        eprintln!("Skipping keychain test - keychain not available in CI");
        return Ok(());
    }

    let harness = TestHarness::new("keychain_basic", BackendConfig::sqlite_memory()).await?;
    let invite = harness.create_server_invite()?;

    // Create user that will NOT use file storage (default = keychain)
    let alice_home = harness.test_dir().join("alice_keychain");
    std::fs::create_dir_all(&alice_home)?;

    // Join without --use-file-storage (should use keychain)
    let output = Command::new(&harness.zopp_bin)
        .env("HOME", &alice_home)
        .args([
            "--server",
            &harness.server_url,
            "join",
            &invite,
            "alice@example.com",
            "--principal",
            "alice-device",
        ])
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("NotAvailable") {
            eprintln!("Keychain not available on this system, skipping test");
            return Ok(());
        }
        return Err(format!(
            "Join failed: stdout={}, stderr={}",
            String::from_utf8_lossy(&output.stdout),
            stderr
        )
        .into());
    }

    // Verify config file does NOT contain private keys
    let config_path = alice_home.join(".zopp/config.json");
    let config_content = std::fs::read_to_string(&config_path)?;

    // The config should NOT have private_key field (it's stored in keychain)
    assert!(
        !config_content.contains("\"private_key\":"),
        "private_key should NOT be in config file when using keychain"
    );

    // Verify CLI still works (can authenticate using keychain credentials)
    let output = Command::new(&harness.zopp_bin)
        .env("HOME", &alice_home)
        .args([
            "--server",
            &harness.server_url,
            "workspace",
            "create",
            "test-ws",
        ])
        .output()?;

    if !output.status.success() {
        return Err(format!(
            "Workspace create failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }

    // Verify workspace was created
    let output = Command::new(&harness.zopp_bin)
        .env("HOME", &alice_home)
        .args(["--server", &harness.server_url, "workspace", "list"])
        .output()?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("test-ws"), "Workspace should be listed");

    Ok(())
}

/// Test that file storage works as fallback
#[tokio::test]
async fn test_file_storage_fallback() -> Result<(), Box<dyn std::error::Error>> {
    let harness = TestHarness::new("keychain_fallback", BackendConfig::sqlite_memory()).await?;
    let invite = harness.create_server_invite()?;

    // Create user that WILL use file storage
    let bob_home = harness.test_dir().join("bob_file");
    std::fs::create_dir_all(&bob_home)?;

    // Join WITH --use-file-storage
    let output = Command::new(&harness.zopp_bin)
        .env("HOME", &bob_home)
        .args([
            "--server",
            &harness.server_url,
            "--use-file-storage",
            "join",
            &invite,
            "bob@example.com",
            "--principal",
            "bob-device",
        ])
        .output()?;

    if !output.status.success() {
        return Err(format!("Join failed: {}", String::from_utf8_lossy(&output.stderr)).into());
    }

    // Verify config file DOES contain private keys
    let config_path = bob_home.join(".zopp/config.json");
    let config_content = std::fs::read_to_string(&config_path)?;

    // The config SHOULD have private_key field when using file storage
    assert!(
        config_content.contains("\"private_key\":"),
        "private_key SHOULD be in config file when using file storage"
    );
    // use_file_storage should be true (may be serialized as true or the field exists)
    assert!(
        config_content.contains("\"use_file_storage\""),
        "use_file_storage field should be present in config"
    );

    // Verify CLI still works with file storage
    let output = Command::new(&harness.zopp_bin)
        .env("HOME", &bob_home)
        .args([
            "--server",
            &harness.server_url,
            "--use-file-storage",
            "workspace",
            "create",
            "bob-ws",
        ])
        .output()?;

    if !output.status.success() {
        return Err(format!(
            "Workspace create failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }

    Ok(())
}

/// Test principal create with keychain
#[tokio::test]
async fn test_keychain_principal_create() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("CI").is_ok() && !is_keychain_available() {
        eprintln!("Skipping keychain test - keychain not available in CI");
        return Ok(());
    }

    let harness = TestHarness::new("keychain_principal", BackendConfig::sqlite_memory()).await?;
    let invite = harness.create_server_invite()?;

    let alice_home = harness.test_dir().join("alice_principal");
    std::fs::create_dir_all(&alice_home)?;

    // Join without --use-file-storage
    let output = Command::new(&harness.zopp_bin)
        .env("HOME", &alice_home)
        .args([
            "--server",
            &harness.server_url,
            "join",
            &invite,
            "alice@example.com",
            "--principal",
            "alice-laptop",
        ])
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("NotAvailable") {
            eprintln!("Keychain not available, skipping test");
            return Ok(());
        }
        return Err(format!("Join failed: {}", stderr).into());
    }

    // Create another principal (should also use keychain)
    let output = Command::new(&harness.zopp_bin)
        .env("HOME", &alice_home)
        .args([
            "--server",
            &harness.server_url,
            "principal",
            "create",
            "alice-phone",
        ])
        .output()?;

    if !output.status.success() {
        return Err(format!(
            "Principal create failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }

    // List principals - should show both
    let output = Command::new(&harness.zopp_bin)
        .env("HOME", &alice_home)
        .args(["principal", "list"])
        .output()?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("alice-laptop"),
        "First principal should exist"
    );
    assert!(
        stdout.contains("alice-phone"),
        "Second principal should exist"
    );

    // Verify neither principal has private_key in config
    let config_path = alice_home.join(".zopp/config.json");
    let config_content = std::fs::read_to_string(&config_path)?;
    assert!(
        !config_content.contains("\"private_key\":"),
        "No private keys should be in config"
    );

    Ok(())
}

/// Test principal delete cleans up keychain
#[tokio::test]
async fn test_keychain_principal_delete_cleanup() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("CI").is_ok() && !is_keychain_available() {
        eprintln!("Skipping keychain test - keychain not available in CI");
        return Ok(());
    }

    let harness =
        TestHarness::new("keychain_principal_delete", BackendConfig::sqlite_memory()).await?;
    let invite = harness.create_server_invite()?;

    let alice_home = harness.test_dir().join("alice_delete");
    std::fs::create_dir_all(&alice_home)?;

    // Join
    let output = Command::new(&harness.zopp_bin)
        .env("HOME", &alice_home)
        .args([
            "--server",
            &harness.server_url,
            "join",
            &invite,
            "alice@example.com",
            "--principal",
            "alice-main",
        ])
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("NotAvailable") {
            eprintln!("Keychain not available, skipping test");
            return Ok(());
        }
        return Err(format!("Join failed: {}", stderr).into());
    }

    // Create second principal
    let output = Command::new(&harness.zopp_bin)
        .env("HOME", &alice_home)
        .args([
            "--server",
            &harness.server_url,
            "principal",
            "create",
            "alice-temp",
        ])
        .output()?;

    assert!(output.status.success(), "Principal create should succeed");

    // Delete the second principal
    let output = Command::new(&harness.zopp_bin)
        .env("HOME", &alice_home)
        .args(["principal", "delete", "alice-temp"])
        .output()?;

    assert!(output.status.success(), "Principal delete should succeed");

    // Verify only first principal remains
    let output = Command::new(&harness.zopp_bin)
        .env("HOME", &alice_home)
        .args(["principal", "list"])
        .output()?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("alice-main"), "Main principal should exist");
    assert!(
        !stdout.contains("alice-temp"),
        "Deleted principal should not exist"
    );

    Ok(())
}
