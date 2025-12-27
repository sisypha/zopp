use crate::config::{get_current_principal, load_config};
use crate::crypto::unwrap_workspace_kek;
use crate::grpc::sign_request;
use tonic::metadata::MetadataValue;
use zopp_proto::zopp_service_client::ZoppServiceClient;

pub async fn cmd_invite_create(
    server: &str,
    workspace_name: &str,
    expires_hours: i64,
    plain: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = load_config()?;
    let principal = get_current_principal(&config)?;

    let mut client = ZoppServiceClient::connect(server.to_string()).await?;

    // 1. Unwrap the workspace KEK
    let kek = unwrap_workspace_kek(&mut client, principal, workspace_name).await?;

    // 2. Generate random invite secret (32 bytes, displayed as hex with prefix)
    let mut invite_secret = [0u8; 32];
    use rand_core::RngCore;
    rand_core::OsRng.fill_bytes(&mut invite_secret);
    let invite_secret_hex = format!("inv_{}", hex::encode(invite_secret));

    // 3. Hash the secret for server lookup (server never sees plaintext secret)
    let secret_hash = zopp_crypto::hash_sha256(&invite_secret);

    // 4. Get workspace ID first (needed for AAD)
    let (ws_timestamp, ws_signature) = sign_request(&principal.private_key)?;
    let mut ws_request = tonic::Request::new(zopp_proto::Empty {});
    ws_request
        .metadata_mut()
        .insert("principal-id", MetadataValue::try_from(&principal.id)?);
    ws_request.metadata_mut().insert(
        "timestamp",
        MetadataValue::try_from(ws_timestamp.to_string())?,
    );
    ws_request.metadata_mut().insert(
        "signature",
        MetadataValue::try_from(hex::encode(&ws_signature))?,
    );
    let workspaces = client.list_workspaces(ws_request).await?.into_inner();
    let workspace = workspaces
        .workspaces
        .iter()
        .find(|w| w.name == workspace_name)
        .ok_or_else(|| format!("Workspace '{}' not found", workspace_name))?;

    // 5. Encrypt the KEK with the invite secret (using workspace ID in AAD)
    let dek_for_encryption = zopp_crypto::Dek::from_bytes(&invite_secret)?;
    let aad = format!("invite:workspace:{}", workspace.id).into_bytes();
    let (kek_nonce, kek_encrypted) = zopp_crypto::encrypt(&kek, &dek_for_encryption, &aad)?;

    // 6. Calculate expiration time
    let expires_at = chrono::Utc::now() + chrono::Duration::hours(expires_hours);

    // 7. Send invite to server (with hashed secret as token, not plaintext secret)
    let (timestamp, signature) = sign_request(&principal.private_key)?;

    let mut request = tonic::Request::new(zopp_proto::CreateInviteRequest {
        workspace_ids: vec![workspace.id.clone()],
        expires_at: expires_at.timestamp(),
        token: hex::encode(secret_hash), // Hash as token for lookup
        kek_encrypted: kek_encrypted.0,
        kek_nonce: kek_nonce.0.to_vec(),
    });
    request
        .metadata_mut()
        .insert("principal-id", MetadataValue::try_from(&principal.id)?);
    request
        .metadata_mut()
        .insert("timestamp", MetadataValue::try_from(timestamp.to_string())?);
    request.metadata_mut().insert(
        "signature",
        MetadataValue::try_from(hex::encode(&signature))?,
    );

    let _response = client.create_invite(request).await?.into_inner();

    if plain {
        println!("{}", invite_secret_hex);
    } else {
        println!("✓ Workspace invite created!\n");
        println!("Invite code: {}", invite_secret_hex);
        println!("Expires:     {}", expires_at);
        println!("\n⚠️  Share this invite code with the invitee via secure channel");
        println!(
            "   The server does NOT have the plaintext - it's needed to decrypt the workspace key"
        );
    }

    Ok(())
}

pub async fn cmd_invite_list(server: &str) -> Result<(), Box<dyn std::error::Error>> {
    let config = load_config()?;
    let principal = get_current_principal(&config)?;

    let mut client = ZoppServiceClient::connect(server.to_string()).await?;

    let (timestamp, signature) = sign_request(&principal.private_key)?;

    let mut request = tonic::Request::new(zopp_proto::Empty {});
    request
        .metadata_mut()
        .insert("principal-id", MetadataValue::try_from(&principal.id)?);
    request
        .metadata_mut()
        .insert("timestamp", MetadataValue::try_from(timestamp.to_string())?);
    request.metadata_mut().insert(
        "signature",
        MetadataValue::try_from(hex::encode(&signature))?,
    );

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
                chrono::DateTime::from_timestamp(invite.expires_at, 0).unwrap()
            );
            println!();
        }
    }

    Ok(())
}

pub async fn cmd_invite_revoke(
    server: &str,
    invite_code: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = load_config()?;
    let principal = get_current_principal(&config)?;

    let secret_hex = invite_code
        .strip_prefix("inv_")
        .ok_or("Invalid invite code format (must start with inv_)")?;
    let invite_secret = hex::decode(secret_hex)?;
    if invite_secret.len() != 32 {
        return Err("Invalid invite code length".into());
    }
    let secret_hash = zopp_crypto::hash_sha256(&invite_secret);
    let token = hex::encode(secret_hash);

    let mut client = ZoppServiceClient::connect(server.to_string()).await?;

    let (timestamp, signature) = sign_request(&principal.private_key)?;

    let mut request = tonic::Request::new(zopp_proto::RevokeInviteRequest { token });
    request
        .metadata_mut()
        .insert("principal-id", MetadataValue::try_from(&principal.id)?);
    request
        .metadata_mut()
        .insert("timestamp", MetadataValue::try_from(timestamp.to_string())?);
    request.metadata_mut().insert(
        "signature",
        MetadataValue::try_from(hex::encode(&signature))?,
    );

    client.revoke_invite(request).await?;

    println!("✓ Invite revoked");

    Ok(())
}
