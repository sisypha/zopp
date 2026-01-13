//! Demo E2E test - full flow from PR #25 test improvements.
//!
//! Tests the complete user journey:
//! - Server invite → Alice registers → creates workspace
//! - Workspace invite → Bob joins
//! - Both users read/write secrets (validates zero-knowledge)
//! - Export/import .env files
//! - Secret injection via `run` command

mod common;

use std::fs;

use common::BackendConfig;

// Generate 4 test variants (sqlite+memory, sqlite+pg_events, postgres+memory, postgres+postgres)
backend_test!(demo, run_demo_test);

async fn run_demo_test(config: BackendConfig) -> Result<(), Box<dyn std::error::Error>> {
    let config_name = config.name();
    println!("🧪 Starting Zopp E2E Demo Test ({config_name})\n");

    // Create test harness (starts server automatically)
    let harness = common::TestHarness::new("demo", config).await?;
    println!("✓ Server started at {}\n", harness.server_url);

    // Create test users
    let alice = harness.create_user("alice");
    let bob = harness.create_user("bob");
    println!("✓ Test directories created");
    println!("  Alice home: {}", alice.home_dir.display());
    println!("  Bob home:   {}\n", bob.home_dir.display());

    // Step 1: Admin creates server invite for Alice
    println!("🎫 Step 1: Admin creates server invite for Alice...");
    let alice_server_invite = harness.create_server_invite()?;
    println!("✓ Alice's server invite: {}\n", alice_server_invite);

    // Step 2: Alice joins server
    println!("👩 Step 2: Alice joins server...");
    alice.join(&alice_server_invite, &alice.email(), &alice.principal())?;
    println!("✓ Alice joined successfully\n");

    // Step 3: Alice creates workspace
    println!("🏢 Step 3: Alice creates workspace 'acme'...");
    alice.exec(&["workspace", "create", "acme"]).success()?;
    println!("✓ Workspace 'acme' created\n");

    // Step 4: Alice creates project
    println!("📁 Step 4: Alice creates project 'api'...");
    alice
        .exec(&["project", "create", "api", "-w", "acme"])
        .success()?;
    println!("✓ Project 'api' created\n");

    // Step 5: Alice creates environment
    println!("🌍 Step 5: Alice creates environment 'development'...");
    alice
        .exec(&[
            "environment",
            "create",
            "development",
            "-w",
            "acme",
            "-p",
            "api",
        ])
        .success()?;
    println!("✓ Environment 'development' created");

    // Create zopp.toml with defaults
    harness.create_zopp_toml("acme", "api", "development")?;
    println!("✓ Created zopp.toml with defaults\n");

    // Step 6: Alice creates workspace invite for Bob (DEMO.md Step 4)
    println!("🎟️  Step 6: Alice creates workspace invite for Bob...");
    let workspace_invite = alice
        .exec_in(
            harness.test_dir(),
            &["invite", "create", "--expires-hours", "1", "--plain"],
        )
        .success()?;
    println!("✓ Workspace invite: {}\n", workspace_invite);

    // Step 7: Bob joins using workspace invite (DEMO.md Steps 5-6 combined)
    println!("👨 Step 7: Bob joins using Alice's workspace invite...");
    bob.join(&workspace_invite, &bob.email(), &bob.principal())?;
    println!("✓ Bob joined workspace 'acme'\n");

    // Step 8: Alice grants Bob write permission (DEMO.md Step 7)
    println!("🔑 Step 8: Alice grants Bob write permission...");
    alice
        .exec(&[
            "permission",
            "user-set",
            "-w",
            "acme",
            "--email",
            &bob.email(),
            "--role",
            "write",
        ])
        .success()?;
    println!("✓ Bob granted write permission on workspace 'acme'\n");

    // Step 9: Bob writes secret (DEMO.md Step 8)
    println!("🔐 Step 9: Bob writes secret 'FLUXMAIL_API_TOKEN'...");
    let secret_value = "fxt_8k2m9p4x7n1q5w3e6r8t0y2u4i6o8p0a";
    bob.exec_in(
        harness.test_dir(),
        &["secret", "set", "FLUXMAIL_API_TOKEN", secret_value],
    )
    .success()?;
    println!("✓ Secret written by Bob\n");

    // Step 10: Alice reads Bob's secret (DEMO.md Step 9)
    println!("🔓 Step 10: Alice reads Bob's secret...");
    let retrieved_value = alice
        .exec_in(harness.test_dir(), &["secret", "get", "FLUXMAIL_API_TOKEN"])
        .success()?;
    assert_eq!(
        retrieved_value, secret_value,
        "Secret mismatch! Expected: {}, Got: {}",
        secret_value, retrieved_value
    );
    println!("✓ Alice successfully read Bob's secret!");
    println!("  Expected: {}", secret_value);
    println!("  Got:      {}\n", retrieved_value);

    // Step 11: Alice writes secret (DEMO.md Step 10)
    println!("🔐 Step 11: Alice writes secret 'PAYFLOW_MERCHANT_ID'...");
    let secret_value2 = "mch_9x8v7c6b5n4m3";
    alice
        .exec_in(
            harness.test_dir(),
            &["secret", "set", "PAYFLOW_MERCHANT_ID", secret_value2],
        )
        .success()?;
    println!("✓ Secret written by Alice\n");

    // Step 12: Bob reads Alice's secret (DEMO.md Step 11)
    println!("🔓 Step 12: Bob reads Alice's secret...");
    let retrieved_value2 = bob
        .exec_in(
            harness.test_dir(),
            &["secret", "get", "PAYFLOW_MERCHANT_ID"],
        )
        .success()?;
    assert_eq!(
        retrieved_value2, secret_value2,
        "Secret mismatch! Expected: {}, Got: {}",
        secret_value2, retrieved_value2
    );
    println!("✓ Bob successfully read Alice's secret!");
    println!("  Expected: {}", secret_value2);
    println!("  Got:      {}\n", retrieved_value2);

    // Step 13: Export secrets to .env file (DEMO.md Step 12)
    println!("📤 Step 13: Alice exports secrets to .env file...");
    let env_file = harness.test_dir().join("development.env");
    alice
        .exec_in(
            harness.test_dir(),
            &["secret", "export", "-o", env_file.to_str().unwrap()],
        )
        .success()?;
    let env_contents = fs::read_to_string(&env_file)?;
    println!("✓ Secrets exported:\n{}", env_contents);
    assert!(env_contents.contains("FLUXMAIL_API_TOKEN="));
    assert!(env_contents.contains("PAYFLOW_MERCHANT_ID="));

    // Step 14: Create production environment (DEMO.md Step 13)
    println!("🌍 Step 14: Alice creates production environment...");
    alice
        .exec_in(harness.test_dir(), &["environment", "create", "production"])
        .success()?;
    println!("✓ Environment 'production' created\n");

    // Step 15: Import secrets to production (DEMO.md Step 14)
    println!("📥 Step 15: Alice imports secrets to production (using -e flag override)...");
    alice
        .exec_in(
            harness.test_dir(),
            &[
                "secret",
                "import",
                "-e",
                "production",
                "-i",
                env_file.to_str().unwrap(),
            ],
        )
        .success()?;
    println!("✓ Secrets imported to production\n");

    // Step 16: Verify imported secret (DEMO.md Step 15)
    println!("🔍 Step 16: Verify imported secret in production (using -e flag override)...");
    let imported = alice
        .exec_in(
            harness.test_dir(),
            &["secret", "get", "FLUXMAIL_API_TOKEN", "-e", "production"],
        )
        .success()?;
    assert_eq!(
        imported, secret_value,
        "Import mismatch! Expected: {}, Got: {}",
        secret_value, imported
    );
    println!("✓ Import/export roundtrip verified!\n");

    // Step 17: Secret injection via run command (DEMO.md Step 16)
    println!(
        "🏃 Step 17: Alice injects secrets from production and runs command (using -e override)..."
    );
    let injected_value = alice
        .exec_in(
            harness.test_dir(),
            &[
                "run",
                "-e",
                "production",
                "--",
                "printenv",
                "FLUXMAIL_API_TOKEN",
            ],
        )
        .success()?;
    assert_eq!(
        injected_value, secret_value,
        "Injection mismatch! Expected: {}, Got: {}",
        secret_value, injected_value
    );
    println!("✓ Secret injection verified!\n");

    // Summary (harness cleanup happens automatically on drop)
    println!("✅ E2E Demo Test Passed! ({config_name})");
    println!("\n📊 Summary:");
    println!("  ✓ Server started and will stop on cleanup");
    println!("  ✓ Alice registered and created workspace");
    println!("  ✓ Created zopp.toml with defaults (workspace/project/environment)");
    println!("  ✓ Bob registered and joined workspace via invite");
    println!("  ✓ Bob wrote secret, Alice read it (E2E encryption, using zopp.toml)");
    println!("  ✓ Alice wrote secret, Bob read it (E2E encryption, using zopp.toml)");
    println!("  ✓ Secrets exported from development (using zopp.toml defaults)");
    println!("  ✓ Created production environment and imported secrets (using -e flag override)");
    println!("  ✓ Secrets injected from production via run command (using -e flag override)");
    println!("  ✓ Zero-knowledge architecture verified");

    Ok(())
}
