use crate::config::{save_config, store_principal_secrets, CliConfig, PrincipalConfig};
use crate::grpc::connect;
use ed25519_dalek::SigningKey;
use std::io::{self, Write};
use zopp_proto::{JoinRequest, ResendVerificationRequest, VerifyEmailRequest};

/// Principal key material generated during join, kept in memory until verification
struct PrincipalKeys {
    principal_name: String,
    signing_key: SigningKey,
    x25519_keypair: zopp_crypto::Keypair,
    public_key: Vec<u8>,
    x25519_public_key: Vec<u8>,
    ephemeral_pub: Vec<u8>,
    kek_wrapped: Vec<u8>,
    kek_nonce: Vec<u8>,
}

pub async fn cmd_join(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    invite_code: &str,
    email: &str,
    principal_name: Option<&str>,
    use_file_storage: bool,
    verification_code: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Use provided principal name or default to hostname
    let principal_name = match principal_name {
        Some(name) => name.to_string(),
        None => hostname::get()?.to_string_lossy().to_string(),
    };

    let signing_key = SigningKey::generate(&mut rand_core::OsRng);
    let verifying_key = signing_key.verifying_key();
    let public_key = verifying_key.to_bytes().to_vec();

    let x25519_keypair = zopp_crypto::Keypair::generate();
    let x25519_public_bytes = x25519_keypair.public_key_bytes().to_vec();

    let mut client = connect(server, tls_ca_cert).await?;

    // All invites now use inv_ prefix and hash-based lookup
    // The difference is whether the invite has KEK data (workspace invite) or not (bootstrap invite)
    let has_inv_prefix = invite_code.starts_with("inv_");

    // Compute the server token (hash for inv_ prefixed tokens, raw otherwise for legacy)
    let (server_token, invite_secret) = if has_inv_prefix {
        let secret_hex = invite_code
            .strip_prefix("inv_")
            .ok_or("Invalid invite code format")?;
        let invite_secret = hex::decode(secret_hex)?;
        if invite_secret.len() != 32 {
            return Err("Invalid invite code length".into());
        }
        let mut secret_array = [0u8; 32];
        secret_array.copy_from_slice(&invite_secret);
        let secret_hash = zopp_crypto::hash_sha256(&secret_array);
        (hex::encode(secret_hash), Some(secret_array))
    } else {
        // Legacy: use token directly (no hashing)
        (invite_code.to_string(), None)
    };

    // Fetch the invite to check if it has KEK data
    let invite = client
        .get_invite(zopp_proto::GetInviteRequest {
            token: server_token.clone(),
        })
        .await?
        .into_inner();

    // Determine if this is a workspace invite (has KEK) or bootstrap invite (no KEK)
    let (ephemeral_pub, kek_wrapped, kek_nonce) = if !invite.kek_encrypted.is_empty() {
        // Workspace invite: decrypt KEK and re-wrap for our principal
        let secret_array =
            invite_secret.ok_or("Workspace invite requires inv_ prefix with secret")?;

        let dek_for_decryption = zopp_crypto::Dek::from_bytes(&secret_array)?;

        let workspace_id = invite
            .workspace_ids
            .first()
            .ok_or("Invite has no workspace IDs")?;

        let aad = format!("invite:workspace:{}", workspace_id).into_bytes();

        let mut nonce_array = [0u8; 24];
        nonce_array.copy_from_slice(&invite.kek_nonce);
        let nonce = zopp_crypto::Nonce(nonce_array);

        let kek_decrypted =
            zopp_crypto::decrypt(&invite.kek_encrypted, &nonce, &dek_for_decryption, &aad)?;
        let ephemeral_keypair = zopp_crypto::Keypair::generate();
        let my_public = zopp_crypto::public_key_from_bytes(&x25519_keypair.public_key_bytes())?;
        let shared_secret = ephemeral_keypair.shared_secret(&my_public);

        let wrap_aad = format!("workspace:{}", workspace_id).into_bytes();
        let (wrap_nonce, wrapped) =
            zopp_crypto::wrap_key(&kek_decrypted, &shared_secret, &wrap_aad)?;

        (
            ephemeral_keypair.public_key_bytes().to_vec(),
            wrapped.0,
            wrap_nonce.0.to_vec(),
        )
    } else {
        // Bootstrap invite: no KEK to process
        (vec![], vec![], vec![])
    };

    // Store principal key material for use during verification
    let keys = PrincipalKeys {
        principal_name: principal_name.clone(),
        signing_key,
        x25519_keypair,
        public_key: public_key.clone(),
        x25519_public_key: x25519_public_bytes.clone(),
        ephemeral_pub: ephemeral_pub.clone(),
        kek_wrapped: kek_wrapped.clone(),
        kek_nonce: kek_nonce.clone(),
    };

    let response = client
        .join(JoinRequest {
            invite_token: server_token,
            email: email.to_string(),
            principal_name: principal_name.clone(),
            public_key,
            x25519_public_key: x25519_public_bytes,
            ephemeral_pub,
            kek_wrapped,
            kek_nonce,
        })
        .await?
        .into_inner();

    // Determine final principal_id and workspaces based on verification flow
    let (final_principal_id, final_workspaces, final_user_id) = if response.verification_required {
        if let Some(code) = verification_code {
            // Non-interactive: use provided verification code
            let verify_response = client
                .verify_email(VerifyEmailRequest {
                    email: email.to_string(),
                    code: code.to_string(),
                    principal_name: keys.principal_name.clone(),
                    public_key: keys.public_key.clone(),
                    x25519_public_key: keys.x25519_public_key.clone(),
                    ephemeral_pub: keys.ephemeral_pub.clone(),
                    kek_wrapped: keys.kek_wrapped.clone(),
                    kek_nonce: keys.kek_nonce.clone(),
                })
                .await?
                .into_inner();

            if !verify_response.success {
                return Err(
                    format!("Email verification failed: {}", verify_response.message).into(),
                );
            }
            println!("✓ Email verified successfully!\n");
            (
                verify_response.principal_id,
                verify_response.workspaces,
                verify_response.user_id,
            )
        } else {
            // Interactive: prompt for code
            println!("📧 Email verification required.\n");
            println!("A verification code has been sent to: {}", email);
            println!("The code is valid for 15 minutes.\n");

            let verify_response = verify_email_flow(&mut client, email, &keys).await?;
            match verify_response {
                Some(resp) => {
                    println!("✓ Email verified successfully!\n");
                    (resp.principal_id, resp.workspaces, resp.user_id)
                }
                None => {
                    return Err("Email verification failed. Please try joining again.".into());
                }
            }
        }
    } else {
        println!("✓ Joined successfully!\n");
        // No verification needed, principal_id is in the join response
        let principal_id = response
            .principal_id
            .ok_or("Missing principal_id in response")?;
        (principal_id, response.workspaces, response.user_id)
    };

    println!("User ID:      {}", final_user_id);
    println!("Principal ID: {}", final_principal_id);
    println!("Principal:    {}", principal_name);
    println!("\nWorkspaces:");
    for ws in &final_workspaces {
        println!("  - {} ({})", ws.name, ws.id);
    }

    // Store secrets
    let ed25519_private_hex = hex::encode(keys.signing_key.to_bytes());
    let x25519_private_hex = hex::encode(keys.x25519_keypair.secret_key_bytes());

    // Determine where to store private keys
    let (private_key_for_config, x25519_private_for_config) = if use_file_storage {
        // Store in config file
        (
            Some(ed25519_private_hex.clone()),
            Some(x25519_private_hex.clone()),
        )
    } else {
        // Store in keychain
        store_principal_secrets(
            &final_principal_id,
            &ed25519_private_hex,
            Some(&x25519_private_hex),
        )?;
        (None, None)
    };

    // Save config
    let config = CliConfig {
        principals: vec![PrincipalConfig {
            id: final_principal_id,
            name: principal_name.clone(),
            user_id: Some(final_user_id),
            email: Some(email.to_string()),
            private_key: private_key_for_config,
            public_key: hex::encode(keys.signing_key.verifying_key().to_bytes()),
            x25519_private_key: x25519_private_for_config,
            x25519_public_key: Some(hex::encode(keys.x25519_keypair.public_key_bytes())),
        }],
        current_principal: Some(principal_name),
        use_file_storage,
    };
    save_config(&config)?;

    if use_file_storage {
        println!(
            "\nConfig saved to: {}",
            dirs::home_dir()
                .expect("Failed to get home directory")
                .join(".zopp")
                .join("config.json")
                .display()
        );
    } else {
        println!("\nCredentials stored in system keychain.");
        println!(
            "Metadata saved to: {}",
            dirs::home_dir()
                .expect("Failed to get home directory")
                .join(".zopp")
                .join("config.json")
                .display()
        );
    }

    Ok(())
}

/// Successful verification result
struct VerifySuccess {
    principal_id: String,
    user_id: String,
    workspaces: Vec<zopp_proto::Workspace>,
}

/// Handle email verification flow with user input.
/// Returns Some(VerifySuccess) if verification succeeded, None otherwise.
async fn verify_email_flow(
    client: &mut zopp_proto::zopp_service_client::ZoppServiceClient<tonic::transport::Channel>,
    email: &str,
    keys: &PrincipalKeys,
) -> Result<Option<VerifySuccess>, Box<dyn std::error::Error>> {
    // Track if user must resend before trying another code (after server lockout)
    let mut must_resend = false;

    loop {
        // If user must resend, don't allow entering codes until they do
        if must_resend {
            print!("Enter 'r' to request a new code (or 'q' to quit): ");
        } else {
            print!("Enter verification code (or 'r' to resend, 'q' to quit): ");
        }
        io::stdout().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        let input = input.trim();

        // Handle special commands
        if input.eq_ignore_ascii_case("q") || input.eq_ignore_ascii_case("quit") {
            return Ok(None);
        }

        if input.eq_ignore_ascii_case("r") || input.eq_ignore_ascii_case("resend") {
            // Request new code
            let resend_response = client
                .resend_verification(ResendVerificationRequest {
                    email: email.to_string(),
                })
                .await?
                .into_inner();

            if resend_response.success {
                println!("✓ New verification code sent to {}\n", email);
                must_resend = false; // Allow attempts again after successful resend
                continue;
            } else {
                println!("⚠ {}\n", resend_response.message);
                continue;
            }
        }

        // If user must resend but didn't, remind them
        if must_resend {
            println!("⚠ Please request a new code first (enter 'r').\n");
            continue;
        }

        // Validate code format (6 digits)
        if input.len() != 6 || !input.chars().all(|c| c.is_ascii_digit()) {
            println!("⚠ Invalid code format. Please enter the 6-digit code from your email.\n");
            continue;
        }

        // Verify the code, sending principal data to create the principal on success
        let verify_response = client
            .verify_email(VerifyEmailRequest {
                email: email.to_string(),
                code: input.to_string(),
                principal_name: keys.principal_name.clone(),
                public_key: keys.public_key.clone(),
                x25519_public_key: keys.x25519_public_key.clone(),
                ephemeral_pub: keys.ephemeral_pub.clone(),
                kek_wrapped: keys.kek_wrapped.clone(),
                kek_nonce: keys.kek_nonce.clone(),
            })
            .await?
            .into_inner();

        if verify_response.success {
            return Ok(Some(VerifySuccess {
                principal_id: verify_response.principal_id,
                user_id: verify_response.user_id,
                workspaces: verify_response.workspaces,
            }));
        }

        println!("⚠ {}\n", verify_response.message);

        // Check if server says no attempts remaining (server deleted the verification)
        if verify_response.attempts_remaining <= 0 {
            println!("You must request a new verification code.\n");
            must_resend = true;
        }
    }
}
