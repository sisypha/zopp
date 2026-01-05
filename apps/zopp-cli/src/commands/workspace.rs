use crate::grpc::{add_auth_metadata, setup_client};
use zopp_proto::{CreateWorkspaceRequest, Empty};

pub async fn cmd_workspace_list(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, principal) = setup_client(server, tls_ca_cert).await?;

    let mut request = tonic::Request::new(Empty {});
    add_auth_metadata(&mut request, &principal)?;

    let response = client.list_workspaces(request).await?.into_inner();

    if response.workspaces.is_empty() {
        println!("No workspaces found.");
    } else {
        println!("Workspaces:");
        for ws in response.workspaces {
            println!("  {}", ws.name);
        }
    }

    Ok(())
}

pub async fn cmd_workspace_create(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, principal) = setup_client(server, tls_ca_cert).await?;

    use uuid::Uuid;
    let workspace_id = Uuid::now_v7();
    let workspace_id_str = workspace_id.to_string();

    let mut kek = [0u8; 32];
    use rand_core::RngCore;
    rand_core::OsRng.fill_bytes(&mut kek);

    // Get principal's X25519 keypair for wrapping the KEK
    let x25519_private_key = principal
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
    add_auth_metadata(&mut request, &principal)?;

    let response = client.create_workspace(request).await?.into_inner();

    println!("✓ Workspace created!\n");
    println!("Name: {}", response.name);
    println!("ID:   {}", response.id);

    Ok(())
}
