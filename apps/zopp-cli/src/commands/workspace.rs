use crate::grpc::{add_auth_metadata, setup_client};
use zopp_proto::{
    CreateWorkspaceRequest, Empty, GetPrincipalRequest, GetWorkspaceKeysRequest,
    GrantPrincipalWorkspaceAccessRequest,
};

pub async fn cmd_workspace_list(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, principal, secrets) = setup_client(server, tls_ca_cert).await?;

    let mut request = tonic::Request::new(Empty {});
    add_auth_metadata(
        &mut request,
        &principal,
        &secrets,
        "/zopp.ZoppService/ListWorkspaces",
    )?;

    let response = client.list_workspaces(request).await?.into_inner();

    if response.workspaces.is_empty() {
        println!("No workspaces found.");
    } else {
        println!("Workspaces:");
        for ws in response.workspaces {
            let project_text = if ws.project_count == 1 {
                "1 project".to_string()
            } else {
                format!("{} projects", ws.project_count)
            };
            println!("  {} ({})", ws.name, project_text);
        }
    }

    Ok(())
}

pub async fn cmd_workspace_create(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, principal, secrets) = setup_client(server, tls_ca_cert).await?;

    use uuid::Uuid;
    let workspace_id = Uuid::now_v7();
    let workspace_id_str = workspace_id.to_string();

    let mut kek = [0u8; 32];
    use rand_core::RngCore;
    rand_core::OsRng.fill_bytes(&mut kek);

    // Get principal's X25519 keypair for wrapping the KEK
    let x25519_private_key = secrets
        .x25519_private_key
        .as_ref()
        .ok_or("Principal missing X25519 private key")?;
    let x25519_private_bytes = hex::decode(x25519_private_key)?;
    let mut x25519_array = [0u8; 32];
    x25519_array.copy_from_slice(&x25519_private_bytes);
    let x25519_keypair = zopp_crypto::Keypair::from_secret_bytes(&x25519_array);

    let ephemeral_keypair = zopp_crypto::Keypair::generate();
    let ephemeral_pub = ephemeral_keypair.public_key_bytes().to_vec();

    let my_public = zopp_crypto::public_key_from_bytes(&x25519_keypair.public_key_bytes())?;
    let shared_secret = ephemeral_keypair.shared_secret(&my_public);

    let aad = format!("workspace:{}", workspace_id_str).into_bytes();
    let (nonce, wrapped) = zopp_crypto::wrap_key(&kek, &shared_secret, &aad)?;

    let mut request = tonic::Request::new(CreateWorkspaceRequest {
        id: workspace_id_str.clone(),
        name: name.to_string(),
        ephemeral_pub,
        kek_wrapped: wrapped.0,
        kek_nonce: nonce.0.to_vec(),
    });
    add_auth_metadata(
        &mut request,
        &principal,
        &secrets,
        "/zopp.ZoppService/CreateWorkspace",
    )?;

    let response = client.create_workspace(request).await?.into_inner();

    println!("Workspace created!\n");
    println!("Name: {}", response.name);
    println!("ID:   {}", response.id);

    Ok(())
}

pub async fn cmd_workspace_grant_principal_access(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    workspace: &str,
    principal_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, caller, caller_secrets) = setup_client(server, tls_ca_cert).await?;

    // Step 1: Get target principal's X25519 public key
    let mut request = tonic::Request::new(GetPrincipalRequest {
        principal_id: principal_id.to_string(),
    });
    add_auth_metadata(
        &mut request,
        &caller,
        &caller_secrets,
        "/zopp.ZoppService/GetPrincipal",
    )?;
    let target_principal = client.get_principal(request).await?.into_inner();

    if target_principal.x25519_public_key.is_empty() {
        return Err("Target principal has no X25519 public key".into());
    }

    // Step 2: Get caller's wrapped KEK for this workspace
    let mut request = tonic::Request::new(GetWorkspaceKeysRequest {
        workspace_name: workspace.to_string(),
    });
    add_auth_metadata(
        &mut request,
        &caller,
        &caller_secrets,
        "/zopp.ZoppService/GetWorkspaceKeys",
    )?;
    let keys = client.get_workspace_keys(request).await?.into_inner();

    // Step 3: Unwrap KEK using caller's X25519 private key
    let caller_x25519_private = caller_secrets
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

    // Step 4: Wrap KEK for target principal's X25519 public key
    let new_ephemeral_keypair = zopp_crypto::Keypair::generate();
    let target_pubkey = zopp_crypto::public_key_from_bytes(&target_principal.x25519_public_key)?;
    let new_shared_secret = new_ephemeral_keypair.shared_secret(&target_pubkey);

    let (wrap_nonce, wrapped) = zopp_crypto::wrap_key(&kek, &new_shared_secret, &aad)?;

    // Step 5: Send to server
    let mut request = tonic::Request::new(GrantPrincipalWorkspaceAccessRequest {
        workspace_name: workspace.to_string(),
        principal_id: principal_id.to_string(),
        ephemeral_pub: new_ephemeral_keypair.public_key_bytes().to_vec(),
        kek_wrapped: wrapped.0,
        kek_nonce: wrap_nonce.0.to_vec(),
    });
    add_auth_metadata(
        &mut request,
        &caller,
        &caller_secrets,
        "/zopp.ZoppService/GrantPrincipalWorkspaceAccess",
    )?;

    client.grant_principal_workspace_access(request).await?;

    println!(
        "Granted workspace '{}' access to principal '{}'",
        workspace, principal_id
    );
    println!("  Principal name: {}", target_principal.name);

    Ok(())
}
