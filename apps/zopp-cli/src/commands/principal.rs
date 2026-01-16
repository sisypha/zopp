use crate::config::{get_current_principal, load_config, save_config, PrincipalConfig};
use crate::grpc::{add_auth_metadata, connect};
use ed25519_dalek::SigningKey;
use rand_core::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zopp_proto::{
    ConsumePrincipalExportRequest, CreatePrincipalExportRequest, Empty, GetPrincipalExportRequest,
    GetWorkspaceKeysRequest, GrantPrincipalWorkspaceAccessRequest,
    ListWorkspaceServicePrincipalsRequest, RegisterRequest, RemovePrincipalFromWorkspaceRequest,
    RenamePrincipalRequest, RevokeAllPrincipalPermissionsRequest, Role,
};

/// Exported principal format (JSON before encryption)
#[derive(Serialize, Deserialize)]
struct ExportedPrincipal {
    version: u32,
    server_url: String,
    email: String,
    user_id: String,
    principal: ExportedPrincipalData,
}

#[derive(Serialize, Deserialize)]
struct ExportedPrincipalData {
    id: String,
    name: String,
    private_key: String,
    public_key: String,
    x25519_private_key: Option<String>,
    x25519_public_key: Option<String>,
}

pub async fn cmd_principal_list() -> Result<(), Box<dyn std::error::Error>> {
    let config = load_config()?;
    let current = config
        .current_principal
        .as_deref()
        .or_else(|| config.principals.first().map(|p| p.name.as_str()));

    println!("Principals:");
    for principal in &config.principals {
        let marker = if Some(principal.name.as_str()) == current {
            "*"
        } else {
            " "
        };
        println!("{} {} (ID: {})", marker, principal.name, principal.id);
    }
    Ok(())
}

pub async fn cmd_principal_current() -> Result<(), Box<dyn std::error::Error>> {
    let config = load_config()?;
    let principal = get_current_principal(&config)?;
    println!("{}", principal.name);
    Ok(())
}

pub async fn cmd_principal_create(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    name: &str,
    is_service: bool,
    workspace: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut config = load_config()?;

    // Validate: --service requires --workspace
    if is_service && workspace.is_none() {
        return Err("Service principals require --workspace flag".into());
    }

    // Validate: --workspace without --service is not allowed (for now)
    if !is_service && workspace.is_some() {
        return Err("--workspace flag is only valid with --service".into());
    }

    if config.principals.iter().any(|p| p.name == name) {
        return Err(format!("Principal '{}' already exists", name).into());
    }

    // Generate new principal's keypairs
    let signing_key = SigningKey::generate(&mut rand_core::OsRng);
    let verifying_key = signing_key.verifying_key();
    let public_key = verifying_key.to_bytes().to_vec();

    let new_x25519_keypair = zopp_crypto::Keypair::generate();
    let new_x25519_public_bytes = new_x25519_keypair.public_key_bytes().to_vec();

    let mut client = connect(server, tls_ca_cert).await?;
    let caller_principal = get_current_principal(&config)?.clone();

    // For service principals, wrap KEK for the new principal
    let (ephemeral_pub, kek_wrapped, kek_nonce) = if let Some(ws_name) = workspace {
        // Get caller's wrapped KEK for this workspace
        let mut keys_request = tonic::Request::new(GetWorkspaceKeysRequest {
            workspace_name: ws_name.to_string(),
        });
        add_auth_metadata(
            &mut keys_request,
            &caller_principal,
            "/zopp.ZoppService/GetWorkspaceKeys",
        )?;
        let keys = client.get_workspace_keys(keys_request).await?.into_inner();

        // Unwrap KEK using caller's X25519 private key
        let caller_x25519_private = caller_principal
            .x25519_private_key
            .as_ref()
            .ok_or("Caller principal missing X25519 private key")?;
        let caller_x25519_bytes = hex::decode(caller_x25519_private)?;
        let mut caller_x25519_array = [0u8; 32];
        caller_x25519_array.copy_from_slice(&caller_x25519_bytes);
        let caller_keypair = zopp_crypto::Keypair::from_secret_bytes(&caller_x25519_array);

        let ephemeral_pub_key = zopp_crypto::public_key_from_bytes(&keys.ephemeral_pub)?;
        let shared_secret = caller_keypair.shared_secret(&ephemeral_pub_key);

        let aad = format!("workspace:{}", keys.workspace_id).into_bytes();
        let mut nonce_array = [0u8; 24];
        nonce_array.copy_from_slice(&keys.kek_nonce);
        let nonce = zopp_crypto::Nonce(nonce_array);

        let kek = zopp_crypto::unwrap_key(&keys.kek_wrapped, &nonce, &shared_secret, &aad)?;

        // Wrap KEK for the new service principal's X25519 public key
        let new_ephemeral_keypair = zopp_crypto::Keypair::generate();
        let new_principal_pubkey = zopp_crypto::public_key_from_bytes(&new_x25519_public_bytes)?;
        let new_shared_secret = new_ephemeral_keypair.shared_secret(&new_principal_pubkey);

        let (wrap_nonce, wrapped) = zopp_crypto::wrap_key(&kek, &new_shared_secret, &aad)?;

        (
            Some(new_ephemeral_keypair.public_key_bytes().to_vec()),
            Some(wrapped.0),
            Some(wrap_nonce.0.to_vec()),
        )
    } else {
        (None, None, None)
    };

    let mut request = tonic::Request::new(RegisterRequest {
        email: config.email.clone(),
        principal_name: name.to_string(),
        public_key,
        x25519_public_key: new_x25519_public_bytes.clone(),
        is_service,
        workspace_name: workspace.map(|s| s.to_string()),
        ephemeral_pub,
        kek_wrapped,
        kek_nonce,
    });
    add_auth_metadata(
        &mut request,
        &caller_principal,
        "/zopp.ZoppService/Register",
    )?;

    let response = client.register(request).await?.into_inner();

    let principal_id = response.principal_id.clone();
    config.principals.push(PrincipalConfig {
        id: response.principal_id.clone(),
        name: name.to_string(),
        private_key: hex::encode(signing_key.to_bytes()),
        public_key: hex::encode(verifying_key.to_bytes()),
        x25519_private_key: Some(hex::encode(new_x25519_keypair.secret_key_bytes())),
        x25519_public_key: Some(hex::encode(new_x25519_keypair.public_key_bytes())),
    });
    save_config(&config)?;

    if is_service {
        println!(
            "Service principal '{}' created (ID: {})",
            name, principal_id
        );
        println!("  Added to workspace: {}", workspace.unwrap());
        println!(
            "  Grant permissions with: zopp permission set -w {} --principal {} --role <role>",
            workspace.unwrap(),
            principal_id
        );
    } else {
        println!("Principal '{}' created (ID: {})", name, principal_id);

        // For device principals, grant KEK access to all workspaces the user has access to
        let mut ws_request = tonic::Request::new(Empty {});
        add_auth_metadata(
            &mut ws_request,
            &caller_principal,
            "/zopp.ZoppService/ListWorkspaces",
        )?;
        let workspaces = client
            .list_workspaces(ws_request)
            .await?
            .into_inner()
            .workspaces;

        if !workspaces.is_empty() {
            println!("  Granting access to workspaces...");
            let caller_x25519_private = caller_principal
                .x25519_private_key
                .as_ref()
                .ok_or("Caller principal missing X25519 private key")?;
            let caller_x25519_bytes = hex::decode(caller_x25519_private)?;
            let mut caller_x25519_array = [0u8; 32];
            caller_x25519_array.copy_from_slice(&caller_x25519_bytes);
            let caller_keypair = zopp_crypto::Keypair::from_secret_bytes(&caller_x25519_array);

            for ws in &workspaces {
                // Get caller's wrapped KEK for this workspace
                let mut keys_request = tonic::Request::new(GetWorkspaceKeysRequest {
                    workspace_name: ws.name.clone(),
                });
                add_auth_metadata(
                    &mut keys_request,
                    &caller_principal,
                    "/zopp.ZoppService/GetWorkspaceKeys",
                )?;
                let keys = client.get_workspace_keys(keys_request).await?.into_inner();

                // Unwrap KEK
                let ephemeral_pub_key = zopp_crypto::public_key_from_bytes(&keys.ephemeral_pub)?;
                let shared_secret = caller_keypair.shared_secret(&ephemeral_pub_key);
                let aad = format!("workspace:{}", keys.workspace_id).into_bytes();
                let mut nonce_array = [0u8; 24];
                nonce_array.copy_from_slice(&keys.kek_nonce);
                let nonce = zopp_crypto::Nonce(nonce_array);
                let kek = zopp_crypto::unwrap_key(&keys.kek_wrapped, &nonce, &shared_secret, &aad)?;

                // Wrap KEK for the new device principal
                let new_ephemeral_keypair = zopp_crypto::Keypair::generate();
                let new_principal_pubkey =
                    zopp_crypto::public_key_from_bytes(&new_x25519_public_bytes)?;
                let new_shared_secret = new_ephemeral_keypair.shared_secret(&new_principal_pubkey);
                let (wrap_nonce, wrapped) = zopp_crypto::wrap_key(&kek, &new_shared_secret, &aad)?;

                // Grant access via RPC
                let mut grant_request = tonic::Request::new(GrantPrincipalWorkspaceAccessRequest {
                    workspace_name: ws.name.clone(),
                    principal_id: principal_id.clone(),
                    ephemeral_pub: new_ephemeral_keypair.public_key_bytes().to_vec(),
                    kek_wrapped: wrapped.0,
                    kek_nonce: wrap_nonce.0.to_vec(),
                });
                add_auth_metadata(
                    &mut grant_request,
                    &caller_principal,
                    "/zopp.ZoppService/GrantPrincipalWorkspaceAccess",
                )?;
                client
                    .grant_principal_workspace_access(grant_request)
                    .await?;

                println!("    ✓ {}", ws.name);
            }
        }
    }
    Ok(())
}

pub async fn cmd_principal_use(name: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut config = load_config()?;

    if !config.principals.iter().any(|p| p.name == name) {
        return Err(format!("Principal '{}' not found", name).into());
    }

    config.current_principal = Some(name.to_string());
    save_config(&config)?;

    println!("✓ Switched to principal '{}'", name);
    Ok(())
}

pub async fn cmd_principal_rename(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    name: &str,
    new_name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut config = load_config()?;

    if !config.principals.iter().any(|p| p.name == name) {
        return Err(format!("Principal '{}' not found", name).into());
    }

    if config.principals.iter().any(|p| p.name == new_name) {
        return Err(format!("Principal '{}' already exists", new_name).into());
    }

    let principal = config.principals.iter().find(|p| p.name == name).unwrap();

    let principal_id = principal.id.clone();

    let mut client = connect(server, tls_ca_cert).await?;
    let mut request = tonic::Request::new(RenamePrincipalRequest {
        principal_id: principal_id.clone(),
        new_name: new_name.to_string(),
    });
    add_auth_metadata(&mut request, principal, "/zopp.ZoppService/RenamePrincipal")?;

    client.rename_principal(request).await?;

    let principal = config
        .principals
        .iter_mut()
        .find(|p| p.name == name)
        .unwrap();
    principal.name = new_name.to_string();

    if config.current_principal.as_deref() == Some(name) {
        config.current_principal = Some(new_name.to_string());
    }
    save_config(&config)?;

    println!("✓ Principal renamed from '{}' to '{}'", name, new_name);
    Ok(())
}

pub async fn cmd_principal_delete(name: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut config = load_config()?;

    if config.principals.len() == 1 {
        return Err("Cannot delete the only principal".into());
    }

    let idx = config
        .principals
        .iter()
        .position(|p| p.name == name)
        .ok_or_else(|| format!("Principal '{}' not found", name))?;

    config.principals.remove(idx);

    if config.current_principal.as_deref() == Some(name) {
        config.current_principal = config.principals.first().map(|p| p.name.clone());
    }

    save_config(&config)?;

    println!("✓ Principal '{}' deleted", name);
    if let Some(current) = &config.current_principal {
        println!("Switched to principal '{}'", current);
    }
    Ok(())
}

pub async fn cmd_principal_service_list(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    workspace: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = load_config()?;
    let principal = get_current_principal(&config)?;

    let mut client = connect(server, tls_ca_cert).await?;
    let mut request = tonic::Request::new(ListWorkspaceServicePrincipalsRequest {
        workspace_name: workspace.to_string(),
    });
    add_auth_metadata(
        &mut request,
        principal,
        "/zopp.ZoppService/ListWorkspaceServicePrincipals",
    )?;

    let response = client
        .list_workspace_service_principals(request)
        .await?
        .into_inner();

    if response.service_principals.is_empty() {
        println!("No service principals in workspace '{}'", workspace);
        return Ok(());
    }

    println!("Service principals in workspace '{}':", workspace);
    for sp in response.service_principals {
        println!();
        println!("  {} (ID: {})", sp.name, sp.id);
        println!("    Created: {}", sp.created_at);
        if sp.permissions.is_empty() {
            println!("    Permissions: none");
        } else {
            println!("    Permissions:");
            for perm in sp.permissions {
                let role = match Role::try_from(perm.role) {
                    Ok(Role::Admin) => "admin",
                    Ok(Role::Write) => "write",
                    Ok(Role::Read) => "read",
                    _ => "unknown",
                };
                println!("      {} -> {}", perm.scope, role);
            }
        }
    }
    Ok(())
}

pub async fn cmd_principal_workspace_remove(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    workspace: &str,
    principal_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = load_config()?;
    let principal = get_current_principal(&config)?;

    let mut client = connect(server, tls_ca_cert).await?;
    let mut request = tonic::Request::new(RemovePrincipalFromWorkspaceRequest {
        workspace_name: workspace.to_string(),
        principal_id: principal_id.to_string(),
    });
    add_auth_metadata(
        &mut request,
        principal,
        "/zopp.ZoppService/RemovePrincipalFromWorkspace",
    )?;

    client.remove_principal_from_workspace(request).await?;

    println!(
        "Principal {} removed from workspace '{}'",
        principal_id, workspace
    );
    Ok(())
}

pub async fn cmd_principal_revoke_all(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    workspace: &str,
    principal_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = load_config()?;
    let principal = get_current_principal(&config)?;

    let mut client = connect(server, tls_ca_cert).await?;
    let mut request = tonic::Request::new(RevokeAllPrincipalPermissionsRequest {
        workspace_name: workspace.to_string(),
        principal_id: principal_id.to_string(),
    });
    add_auth_metadata(
        &mut request,
        principal,
        "/zopp.ZoppService/RevokeAllPrincipalPermissions",
    )?;

    let response = client
        .revoke_all_principal_permissions(request)
        .await?
        .into_inner();

    println!(
        "Revoked {} permissions for principal {} in workspace '{}'",
        response.permissions_revoked, principal_id, workspace
    );
    Ok(())
}

/// Export a principal to the server for retrieval on another device.
///
/// Generates a 6-word passphrase from the EFF wordlist, encrypts the principal
/// data with a key derived from the passphrase, and uploads to the server.
/// The passphrase is displayed to the user for use on the importing device.
pub async fn cmd_principal_export(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    name: &str,
    expires_hours: u32,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = load_config()?;
    let caller_principal = get_current_principal(&config)?;

    // Find the principal to export
    let principal = config
        .principals
        .iter()
        .find(|p| p.name == name)
        .ok_or_else(|| format!("Principal '{}' not found", name))?;

    // Generate passphrase (or use env var for testing)
    let passphrase = if let Ok(p) = std::env::var("ZOPP_EXPORT_PASSPHRASE") {
        p
    } else {
        crate::passphrase::generate_passphrase(6)
    };

    // Compute token_hash = hex(SHA256(passphrase)) for server lookup
    let token_hash = hex::encode(Sha256::digest(passphrase.as_bytes()));

    // Create export structure
    let export = ExportedPrincipal {
        version: 1,
        server_url: server.to_string(),
        email: config.email.clone(),
        user_id: config.user_id.clone(),
        principal: ExportedPrincipalData {
            id: principal.id.clone(),
            name: principal.name.clone(),
            private_key: principal.private_key.clone(),
            public_key: principal.public_key.clone(),
            x25519_private_key: principal.x25519_private_key.clone(),
            x25519_public_key: principal.x25519_public_key.clone(),
        },
    };

    // Serialize to JSON
    let json = serde_json::to_string(&export)?;

    // Generate salt and derive encryption key
    let mut salt = [0u8; 16];
    rand_core::OsRng.fill_bytes(&mut salt);

    let key = derive_export_key(&passphrase, &salt)?;
    let dek = zopp_crypto::Dek::from_bytes(&key)?;

    // Encrypt with AEAD
    let aad = b"zopp-principal-export-v2";
    let (nonce, ciphertext) = zopp_crypto::encrypt(json.as_bytes(), &dek, aad)?;

    // Calculate expiration timestamp
    let expires_hours = expires_hours.min(24); // Cap at 24 hours
    let expires_at = chrono::Utc::now().timestamp() + (expires_hours as i64 * 3600);

    // Upload to server
    let mut client = connect(server, tls_ca_cert).await?;
    let mut request = tonic::Request::new(CreatePrincipalExportRequest {
        token_hash: token_hash.clone(),
        encrypted_data: ciphertext.0,
        salt: salt.to_vec(),
        nonce: nonce.0.to_vec(),
        expires_at,
    });
    add_auth_metadata(
        &mut request,
        caller_principal,
        "/zopp.ZoppService/CreatePrincipalExport",
    )?;

    let response = client.create_principal_export(request).await?.into_inner();

    // Display export code and passphrase to user
    println!();
    println!("Principal '{}' export created successfully.", name);
    println!();
    println!("Export code:");
    println!("    {}", response.export_code);
    println!();
    println!("Passphrase (write this down):");
    println!("    {}", passphrase);
    println!();
    println!("This export expires in {} hours.", expires_hours);
    println!("After 3 failed passphrase attempts, the export is permanently deleted.");
    println!();
    println!("On your new device, run:");
    println!("    zopp --server {} principal import", server);
    println!();

    Ok(())
}

/// Import a principal from the server using export code and passphrase.
///
/// Prompts for export code first, then passphrase. Server verifies both
/// before returning encrypted data (prevents offline brute-force).
/// Then decrypts and adds to local configuration.
pub async fn cmd_principal_import(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    export_code_arg: Option<&str>,
    passphrase_arg: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Get export code from arg, env (for testing), or prompt
    let export_code = if let Some(c) = export_code_arg {
        c.to_string()
    } else if let Ok(c) = std::env::var("ZOPP_EXPORT_CODE") {
        c
    } else {
        print!("Enter export code: ");
        std::io::Write::flush(&mut std::io::stdout())?;
        let mut code = String::new();
        std::io::stdin().read_line(&mut code)?;
        code.trim().to_string()
    };

    // Get passphrase from arg, env (for testing), or prompt
    let passphrase = if let Some(p) = passphrase_arg {
        p.to_string()
    } else if let Ok(p) = std::env::var("ZOPP_EXPORT_PASSPHRASE") {
        p
    } else {
        rpassword::prompt_password("Enter passphrase: ")?
    };

    // Compute token_hash to send to server for verification
    // Server verifies BOTH export_code AND token_hash before returning data
    // This prevents offline brute-force - you can't get encrypted data without knowing passphrase
    let token_hash = hex::encode(Sha256::digest(passphrase.as_bytes()));

    // Fetch from server - requires both export_code and correct token_hash
    let mut client = connect(server, tls_ca_cert).await?;
    let request = tonic::Request::new(GetPrincipalExportRequest {
        export_code: export_code.clone(),
        token_hash,
    });

    let response = client
        .get_principal_export(request)
        .await
        .map_err(|e| {
            if e.code() == tonic::Code::NotFound {
                "Export not found - invalid code or expired".to_string()
            } else if e.code() == tonic::Code::PermissionDenied {
                // Server returns detailed message about failed attempts
                e.message().to_string()
            } else {
                format!("Failed to retrieve export: {}", e)
            }
        })?
        .into_inner();

    // Server verified passphrase - now derive key and decrypt
    let key = derive_export_key(&passphrase, &response.salt)?;
    let dek = zopp_crypto::Dek::from_bytes(&key)?;

    let mut nonce_array = [0u8; 24];
    if response.nonce.len() != 24 {
        return Err("Invalid nonce length".into());
    }
    nonce_array.copy_from_slice(&response.nonce);
    let nonce = zopp_crypto::Nonce(nonce_array);

    let aad = b"zopp-principal-export-v2";
    let plaintext = zopp_crypto::decrypt(&response.encrypted_data, &nonce, &dek, aad)
        .map_err(|_| "Decryption failed - wrong passphrase?")?;

    // Parse JSON
    let export: ExportedPrincipal =
        serde_json::from_slice(&plaintext).map_err(|_| "Invalid export format")?;

    if export.version != 1 {
        return Err(format!("Unsupported export version: {}", export.version).into());
    }

    // Load or create config
    let mut config = match load_config() {
        Ok(c) => c,
        Err(_) => {
            // Create new config with this principal
            crate::config::CliConfig {
                user_id: export.user_id.clone(),
                email: export.email.clone(),
                principals: vec![],
                current_principal: None,
            }
        }
    };

    // Check if principal already exists
    if config
        .principals
        .iter()
        .any(|p| p.id == export.principal.id)
    {
        return Err(format!(
            "Principal '{}' (ID: {}) already exists in config",
            export.principal.name, export.principal.id
        )
        .into());
    }

    // Check if name conflicts and find a unique name
    let final_name = if config
        .principals
        .iter()
        .any(|p| p.name == export.principal.name)
    {
        // Find a unique name by appending -imported, -imported-2, etc.
        let base_name = format!("{}-imported", export.principal.name);
        let mut candidate = base_name.clone();
        let mut counter = 2;
        while config.principals.iter().any(|p| p.name == candidate) {
            candidate = format!("{}-{}", base_name, counter);
            counter += 1;
        }
        eprintln!(
            "Note: Principal name '{}' already exists, importing as '{}'",
            export.principal.name, candidate
        );
        candidate
    } else {
        export.principal.name.clone()
    };

    // Add principal
    config.principals.push(PrincipalConfig {
        id: export.principal.id.clone(),
        name: final_name.clone(),
        private_key: export.principal.private_key,
        public_key: export.principal.public_key,
        x25519_private_key: export.principal.x25519_private_key,
        x25519_public_key: export.principal.x25519_public_key,
    });

    // Set as current if it's the only one
    if config.principals.len() == 1 {
        config.current_principal = Some(final_name.clone());
    }

    save_config(&config)?;

    // Mark export as consumed (one-time use) - done after saving config
    // so the user doesn't lose data if consume succeeds but save fails.
    // Retry up to 3 times with backoff for transient network issues.
    for attempt in 1..=3 {
        let consume_request = tonic::Request::new(ConsumePrincipalExportRequest {
            export_id: response.export_id.clone(),
        });
        match client.consume_principal_export(consume_request).await {
            Ok(_) => break,
            Err(_) if attempt < 3 => {
                // Retry after brief delay for transient failures
                tokio::time::sleep(tokio::time::Duration::from_millis(100 * attempt as u64)).await;
                eprintln!("Retrying consume (attempt {}/3)...", attempt + 1);
            }
            Err(e) => {
                // Final attempt failed - warn user prominently
                eprintln!();
                eprintln!(
                    "WARNING: Failed to mark export as consumed after 3 attempts: {}",
                    e
                );
                eprintln!("The export may still be active. For security, you should:");
                eprintln!(
                    "  1. Create a new export with: zopp principal export {}",
                    final_name
                );
                eprintln!("  2. The old export will expire automatically in 24 hours");
                eprintln!();
            }
        }
    }

    println!("Principal '{}' imported successfully.", final_name);
    println!();
    println!("You are now authenticated as:");
    println!("  Email: {}", config.email);
    println!("  Principal: {}", final_name);
    println!();
    println!("Test with: zopp workspace list");

    Ok(())
}

/// Derive encryption key from passphrase using Argon2id
fn derive_export_key(
    passphrase: &str,
    salt: &[u8],
) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    use argon2::{Algorithm, Argon2, Params, Version};

    // Use lighter params for export (still secure, but faster)
    // 64 MiB memory, 3 iterations
    let params =
        Params::new(64 * 1024, 3, 1, Some(32)).map_err(|e| format!("Argon2 params: {}", e))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut key = [0u8; 32];
    argon2
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|e| format!("Key derivation failed: {}", e))?;

    Ok(key)
}
