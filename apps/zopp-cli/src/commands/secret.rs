use crate::crypto::{fetch_and_decrypt_secrets, unwrap_environment_dek, unwrap_workspace_kek};
use crate::grpc::{add_auth_metadata, setup_client};

pub async fn cmd_secret_set(
    server: &str,
    workspace_name: &str,
    project_name: &str,
    environment_name: &str,
    key: &str,
    value: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, principal) = setup_client(server).await?;

    let kek = unwrap_workspace_kek(&mut client, &principal, workspace_name).await?;

    let dek = unwrap_environment_dek(
        &mut client,
        &principal,
        workspace_name,
        project_name,
        environment_name,
        &kek,
    )
    .await?;

    let dek_key = zopp_crypto::Dek::from_bytes(&dek)?;
    let aad = format!(
        "secret:{}:{}:{}:{}",
        workspace_name, project_name, environment_name, key
    )
    .into_bytes();
    let (nonce, ciphertext) = zopp_crypto::encrypt(value.as_bytes(), &dek_key, &aad)?;

    let mut request = tonic::Request::new(zopp_proto::UpsertSecretRequest {
        workspace_name: workspace_name.to_string(),
        project_name: project_name.to_string(),
        environment_name: environment_name.to_string(),
        key: key.to_string(),
        nonce: nonce.0.to_vec(),
        ciphertext: ciphertext.0,
    });
    add_auth_metadata(&mut request, &principal)?;

    client.upsert_secret(request).await?;

    println!("✓ Secret '{}' set", key);

    Ok(())
}

pub async fn cmd_secret_get(
    server: &str,
    workspace_name: &str,
    project_name: &str,
    environment_name: &str,
    key: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, principal) = setup_client(server).await?;

    let mut request = tonic::Request::new(zopp_proto::GetSecretRequest {
        workspace_name: workspace_name.to_string(),
        project_name: project_name.to_string(),
        environment_name: environment_name.to_string(),
        key: key.to_string(),
    });
    add_auth_metadata(&mut request, &principal)?;

    let response = client.get_secret(request).await?.into_inner();

    let kek = unwrap_workspace_kek(&mut client, &principal, workspace_name).await?;

    let dek = unwrap_environment_dek(
        &mut client,
        &principal,
        workspace_name,
        project_name,
        environment_name,
        &kek,
    )
    .await?;

    let dek_key = zopp_crypto::Dek::from_bytes(&dek)?;
    let aad = format!(
        "secret:{}:{}:{}:{}",
        workspace_name, project_name, environment_name, key
    )
    .into_bytes();

    let mut nonce_array = [0u8; 24];
    nonce_array.copy_from_slice(&response.nonce);
    let nonce = zopp_crypto::Nonce(nonce_array);

    let plaintext = zopp_crypto::decrypt(&response.ciphertext, &nonce, &dek_key, &aad)?;
    let value = String::from_utf8(plaintext.to_vec())?;

    println!("{}", value);

    Ok(())
}

pub async fn cmd_secret_list(
    server: &str,
    workspace_name: &str,
    project_name: &str,
    environment_name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, principal) = setup_client(server).await?;

    let mut request = tonic::Request::new(zopp_proto::ListSecretsRequest {
        workspace_name: workspace_name.to_string(),
        project_name: project_name.to_string(),
        environment_name: environment_name.to_string(),
    });
    add_auth_metadata(&mut request, &principal)?;

    let response = client.list_secrets(request).await?.into_inner();

    if response.secrets.is_empty() {
        println!("No secrets found");
    } else {
        println!("Secrets:");
        for secret in response.secrets {
            println!("  {}", secret.key);
        }
    }

    Ok(())
}

pub async fn cmd_secret_delete(
    server: &str,
    workspace_name: &str,
    project_name: &str,
    environment_name: &str,
    key: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, principal) = setup_client(server).await?;

    let mut request = tonic::Request::new(zopp_proto::DeleteSecretRequest {
        workspace_name: workspace_name.to_string(),
        project_name: project_name.to_string(),
        environment_name: environment_name.to_string(),
        key: key.to_string(),
    });
    add_auth_metadata(&mut request, &principal)?;

    client.delete_secret(request).await?;

    println!("✓ Secret '{}' deleted", key);

    Ok(())
}

pub async fn cmd_secret_export(
    server: &str,
    workspace_name: &str,
    project_name: &str,
    environment_name: &str,
    output: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, principal) = setup_client(server).await?;

    // Fetch and decrypt all secrets
    let secret_data = fetch_and_decrypt_secrets(
        &mut client,
        &principal,
        workspace_name,
        project_name,
        environment_name,
    )
    .await?;

    if secret_data.is_empty() {
        return Err("No secrets to export".into());
    }

    // Format as .env (BTreeMap is already sorted)
    let env_content = secret_data
        .iter()
        .map(|(k, v)| format!("{}={}", k, v))
        .collect::<Vec<_>>()
        .join("\n");

    // Write to file or stdout
    if let Some(path) = output {
        std::fs::write(path, env_content)?;
        println!("✓ Exported {} secrets to {}", secret_data.len(), path);
    } else {
        println!("{}", env_content);
    }

    Ok(())
}

pub async fn cmd_secret_import(
    server: &str,
    workspace_name: &str,
    project_name: &str,
    environment_name: &str,
    input: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Read .env content from file or stdin
    let content = if let Some(path) = input {
        std::fs::read_to_string(path)?
    } else {
        use std::io::Read;
        let mut buffer = String::new();
        std::io::stdin().read_to_string(&mut buffer)?;
        buffer
    };

    // Parse .env format (KEY=value, skip comments and empty lines)
    let mut secrets = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((key, value)) = line.split_once('=') {
            secrets.push((key.trim().to_string(), value.trim().to_string()));
        }
    }

    if secrets.is_empty() {
        return Err("No secrets found in input".into());
    }

    // Import each secret using cmd_secret_set logic
    let (mut client, principal) = setup_client(server).await?;

    // Unwrap KEK and DEK once
    let kek = unwrap_workspace_kek(&mut client, &principal, workspace_name).await?;
    let dek = unwrap_environment_dek(
        &mut client,
        &principal,
        workspace_name,
        project_name,
        environment_name,
        &kek,
    )
    .await?;

    for (key, value) in &secrets {
        // Encrypt secret
        let dek_key = zopp_crypto::Dek::from_bytes(&dek)?;
        let aad = format!(
            "secret:{}:{}:{}:{}",
            workspace_name, project_name, environment_name, key
        )
        .into_bytes();

        let (nonce, ciphertext) = zopp_crypto::encrypt(value.as_bytes(), &dek_key, &aad)?;

        // Send to server
        let mut request = tonic::Request::new(zopp_proto::UpsertSecretRequest {
            workspace_name: workspace_name.to_string(),
            project_name: project_name.to_string(),
            environment_name: environment_name.to_string(),
            key: key.clone(),
            nonce: nonce.0.to_vec(),
            ciphertext: ciphertext.0,
        });
        add_auth_metadata(&mut request, &principal)?;

        client.upsert_secret(request).await?;
    }

    println!("✓ Imported {} secrets", secrets.len());

    Ok(())
}

pub async fn cmd_secret_run(
    server: &str,
    workspace_name: &str,
    project_name: &str,
    environment_name: &str,
    command: &[String],
) -> Result<(), Box<dyn std::error::Error>> {
    if command.is_empty() {
        return Err("No command specified".into());
    }

    let (mut client, principal) = setup_client(server).await?;

    // Fetch and decrypt all secrets
    let env_vars = fetch_and_decrypt_secrets(
        &mut client,
        &principal,
        workspace_name,
        project_name,
        environment_name,
    )
    .await?;

    // Execute command with injected environment variables
    let status = std::process::Command::new(&command[0])
        .args(&command[1..])
        .envs(&env_vars)
        .status()?;

    std::process::exit(status.code().unwrap_or(1));
}
