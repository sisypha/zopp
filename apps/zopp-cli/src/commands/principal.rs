use crate::config::{get_current_principal, load_config, save_config, PrincipalConfig};
use crate::grpc::{connect, sign_request};
use ed25519_dalek::SigningKey;
use tonic::metadata::MetadataValue;
use zopp_proto::{
    ListWorkspaceServicePrincipalsRequest, RegisterRequest, RemovePrincipalFromWorkspaceRequest,
    RenamePrincipalRequest, RevokeAllPrincipalPermissionsRequest,
};

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
) -> Result<(), Box<dyn std::error::Error>> {
    let mut config = load_config()?;

    if config.principals.iter().any(|p| p.name == name) {
        return Err(format!("Principal '{}' already exists", name).into());
    }

    let signing_key = SigningKey::generate(&mut rand_core::OsRng);
    let verifying_key = signing_key.verifying_key();
    let public_key = verifying_key.to_bytes().to_vec();

    let x25519_keypair = zopp_crypto::Keypair::generate();
    let x25519_public_bytes = x25519_keypair.public_key_bytes().to_vec();

    let mut client = connect(server, tls_ca_cert).await?;
    let principal = get_current_principal(&config)?;
    let (timestamp, signature) = sign_request(&principal.private_key)?;

    let mut request = tonic::Request::new(RegisterRequest {
        email: config.email.clone(),
        principal_name: name.to_string(),
        public_key,
        x25519_public_key: x25519_public_bytes,
        is_service,
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

    let response = client.register(request).await?.into_inner();

    let principal_id = response.principal_id.clone();
    config.principals.push(PrincipalConfig {
        id: response.principal_id,
        name: name.to_string(),
        private_key: hex::encode(signing_key.to_bytes()),
        public_key: hex::encode(verifying_key.to_bytes()),
        x25519_private_key: Some(hex::encode(x25519_keypair.secret_key_bytes())),
        x25519_public_key: Some(hex::encode(x25519_keypair.public_key_bytes())),
    });
    save_config(&config)?;

    if is_service {
        println!("✓ Service principal '{}' created (ID: {})", name, principal_id);
        println!("  Use this ID to grant permissions: zopp permission project-set --principal {}", principal_id);
    } else {
        println!("✓ Principal '{}' created (ID: {})", name, principal_id);
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
    let (timestamp, signature) = sign_request(&principal.private_key)?;

    let mut client = connect(server, tls_ca_cert).await?;
    let mut request = tonic::Request::new(RenamePrincipalRequest {
        principal_id: principal_id.clone(),
        new_name: new_name.to_string(),
    });
    request
        .metadata_mut()
        .insert("principal-id", MetadataValue::try_from(&principal_id)?);
    request
        .metadata_mut()
        .insert("timestamp", MetadataValue::try_from(timestamp.to_string())?);
    request.metadata_mut().insert(
        "signature",
        MetadataValue::try_from(hex::encode(&signature))?,
    );

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
    let (timestamp, signature) = sign_request(&principal.private_key)?;

    let mut client = connect(server, tls_ca_cert).await?;
    let mut request = tonic::Request::new(ListWorkspaceServicePrincipalsRequest {
        workspace_name: workspace.to_string(),
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
                let role = match perm.role {
                    0 => "admin",
                    1 => "write",
                    2 => "read",
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
    let (timestamp, signature) = sign_request(&principal.private_key)?;

    let mut client = connect(server, tls_ca_cert).await?;
    let mut request = tonic::Request::new(RemovePrincipalFromWorkspaceRequest {
        workspace_name: workspace.to_string(),
        principal_id: principal_id.to_string(),
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
    let (timestamp, signature) = sign_request(&principal.private_key)?;

    let mut client = connect(server, tls_ca_cert).await?;
    let mut request = tonic::Request::new(RevokeAllPrincipalPermissionsRequest {
        workspace_name: workspace.to_string(),
        principal_id: principal_id.to_string(),
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
