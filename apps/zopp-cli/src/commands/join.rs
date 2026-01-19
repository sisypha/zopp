use crate::config::{save_config, store_principal_secrets, CliConfig, PrincipalConfig};
use crate::grpc::connect;
use ed25519_dalek::SigningKey;
use zopp_proto::JoinRequest;

pub async fn cmd_join(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    invite_code: &str,
    email: &str,
    principal_name: Option<&str>,
    use_file_storage: bool,
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

    println!("✓ Joined successfully!\n");
    println!("User ID:      {}", response.user_id);
    println!("Principal ID: {}", response.principal_id);
    println!("Principal:    {}", principal_name);
    println!("\nWorkspaces:");
    for ws in &response.workspaces {
        println!("  - {} ({})", ws.name, ws.id);
    }

    // Store secrets
    let ed25519_private_hex = hex::encode(signing_key.to_bytes());
    let x25519_private_hex = hex::encode(x25519_keypair.secret_key_bytes());

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
            &response.principal_id,
            &ed25519_private_hex,
            Some(&x25519_private_hex),
        )?;
        (None, None)
    };

    // Save config
    let config = CliConfig {
        principals: vec![PrincipalConfig {
            id: response.principal_id,
            name: principal_name.clone(),
            user_id: Some(response.user_id),
            email: Some(email.to_string()),
            private_key: private_key_for_config,
            public_key: hex::encode(verifying_key.to_bytes()),
            x25519_private_key: x25519_private_for_config,
            x25519_public_key: Some(hex::encode(x25519_keypair.public_key_bytes())),
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
