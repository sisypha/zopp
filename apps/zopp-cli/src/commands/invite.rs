use crate::crypto::unwrap_workspace_kek;
use crate::grpc::{add_auth_metadata, setup_client};

pub async fn cmd_invite_create(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    workspace_name: &str,
    expires_hours: i64,
    plain: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, principal) = setup_client(server, tls_ca_cert).await?;

    let kek = unwrap_workspace_kek(&mut client, &principal, workspace_name).await?;

    let mut invite_secret = [0u8; 32];
    use rand_core::RngCore;
    rand_core::OsRng.fill_bytes(&mut invite_secret);
    let invite_secret_hex = format!("inv_{}", hex::encode(invite_secret));

    // Server never sees the plaintext secret
    let secret_hash = zopp_crypto::hash_sha256(&invite_secret);

    let mut ws_request = tonic::Request::new(zopp_proto::Empty {});
    add_auth_metadata(
        &mut ws_request,
        &principal,
        "/zopp.ZoppService/ListWorkspaces",
    )?;
    let workspaces = client.list_workspaces(ws_request).await?.into_inner();
    let workspace = workspaces
        .workspaces
        .iter()
        .find(|w| w.name == workspace_name)
        .ok_or_else(|| format!("Workspace '{}' not found", workspace_name))?;

    let dek_for_encryption = zopp_crypto::Dek::from_bytes(&invite_secret)?;
    let aad = format!("invite:workspace:{}", workspace.id).into_bytes();
    let (kek_nonce, kek_encrypted) = zopp_crypto::encrypt(&kek, &dek_for_encryption, &aad)?;

    let expires_at = chrono::Utc::now() + chrono::Duration::hours(expires_hours);

    let mut request = tonic::Request::new(zopp_proto::CreateInviteRequest {
        workspace_ids: vec![workspace.id.clone()],
        expires_at: expires_at.timestamp(),
        token: hex::encode(secret_hash), // Hash as token for lookup
        kek_encrypted: kek_encrypted.0,
        kek_nonce: kek_nonce.0.to_vec(),
    });
    add_auth_metadata(&mut request, &principal, "/zopp.ZoppService/CreateInvite")?;

    let _response = client.create_invite(request).await?.into_inner();

    if plain {
        println!("{}", invite_secret_hex);
    } else {
        println!("Workspace invite created!\n");
        println!("Invite code: {}", invite_secret_hex);
        println!("Expires:     {}", expires_at);
        println!("\n⚠️  Share this invite code with the invitee via secure channel");
        println!(
            "   The server does NOT have the plaintext - it's needed to decrypt the workspace key"
        );
    }

    Ok(())
}

/// Create a self-invite for adding a new device.
/// Unlike regular invites:
/// - Only requires any workspace role (read/write/admin), not just admin
/// - Only the same user can consume the invite
pub async fn cmd_invite_create_self(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    workspace_name: &str,
    expires_hours: i64,
    plain: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, principal) = setup_client(server, tls_ca_cert).await?;

    let kek = unwrap_workspace_kek(&mut client, &principal, workspace_name).await?;

    // Get workspace ID for AAD (must match what join expects)
    let mut ws_request = tonic::Request::new(zopp_proto::Empty {});
    add_auth_metadata(
        &mut ws_request,
        &principal,
        "/zopp.ZoppService/ListWorkspaces",
    )?;
    let workspaces = client.list_workspaces(ws_request).await?.into_inner();
    let workspace = workspaces
        .workspaces
        .iter()
        .find(|w| w.name == workspace_name)
        .ok_or_else(|| format!("Workspace '{}' not found", workspace_name))?;

    let mut invite_secret = [0u8; 32];
    use rand_core::RngCore;
    rand_core::OsRng.fill_bytes(&mut invite_secret);
    let invite_secret_hex = format!("inv_{}", hex::encode(invite_secret));

    // Server never sees the plaintext secret
    let secret_hash = zopp_crypto::hash_sha256(&invite_secret);

    // Encrypt the KEK with the invite secret (AAD uses workspace.id to match join)
    let dek_for_encryption = zopp_crypto::Dek::from_bytes(&invite_secret)?;
    let aad = format!("invite:workspace:{}", workspace.id).into_bytes();
    let (kek_nonce, kek_encrypted) = zopp_crypto::encrypt(&kek, &dek_for_encryption, &aad)?;

    let expires_at = chrono::Utc::now() + chrono::Duration::hours(expires_hours);

    let mut request = tonic::Request::new(zopp_proto::CreateSelfInviteRequest {
        workspace_name: workspace_name.to_string(),
        expires_at: expires_at.timestamp(),
        token: hex::encode(secret_hash), // Hash as token for lookup
        kek_encrypted: kek_encrypted.0,
        kek_nonce: kek_nonce.0.to_vec(),
    });
    add_auth_metadata(
        &mut request,
        &principal,
        "/zopp.ZoppService/CreateSelfInvite",
    )?;

    let _response = client.create_self_invite(request).await?.into_inner();

    if plain {
        println!("{}", invite_secret_hex);
    } else {
        println!("Self-invite created!\n");
        println!("Invite code: {}", invite_secret_hex);
        println!("Expires:     {}", expires_at);
        println!("\n⚠️  This invite can ONLY be used by you (same email)");
        println!("   Use it on your new device with: zopp join <code> <your-email>");
    }

    Ok(())
}

pub async fn cmd_invite_list(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, principal) = setup_client(server, tls_ca_cert).await?;

    let mut request = tonic::Request::new(zopp_proto::Empty {});
    add_auth_metadata(&mut request, &principal, "/zopp.ZoppService/ListInvites")?;

    let response = client.list_invites(request).await?.into_inner();

    if response.invites.is_empty() {
        println!("No active invites found.");
    } else {
        println!("Active workspace invites:\n");
        for invite in response.invites {
            println!("ID:      {}", invite.id);
            println!("Token:   {}", invite.token);
            println!(
                "Expires: {}",
                chrono::DateTime::from_timestamp(invite.expires_at, 0)
                    .map(|dt| dt.to_rfc3339())
                    .unwrap_or_else(|| "Unknown".to_string())
            );
            println!();
        }
    }

    Ok(())
}

pub async fn cmd_invite_revoke(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    invite_code: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let secret_hex = invite_code
        .strip_prefix("inv_")
        .ok_or("Invalid invite code format (must start with inv_)")?;
    let invite_secret = hex::decode(secret_hex)?;
    if invite_secret.len() != 32 {
        return Err("Invalid invite code length".into());
    }
    let secret_hash = zopp_crypto::hash_sha256(&invite_secret);
    let token = hex::encode(secret_hash);

    let (mut client, principal) = setup_client(server, tls_ca_cert).await?;

    let mut request = tonic::Request::new(zopp_proto::RevokeInviteRequest { token });
    add_auth_metadata(&mut request, &principal, "/zopp.ZoppService/RevokeInvite")?;

    client.revoke_invite(request).await?;

    println!("Invite revoked");

    Ok(())
}
