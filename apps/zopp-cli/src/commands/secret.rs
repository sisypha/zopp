use crate::crypto::fetch_and_decrypt_secrets;
use crate::grpc::{add_auth_metadata, setup_client};
use std::collections::BTreeMap;
use std::io::Cursor;
use zopp_secrets::SecretContext;

/// Parse .env content into key-value pairs using dotenvy.
/// Handles quoted values, comments, and edge cases properly.
/// Returns parsed secrets and any parsing errors encountered.
pub fn parse_env_content(content: &str) -> (Vec<(String, String)>, Vec<String>) {
    let mut secrets = Vec::new();
    let mut errors = Vec::new();

    for result in dotenvy::from_read_iter(Cursor::new(content)) {
        match result {
            Ok((key, value)) => secrets.push((key, value)),
            Err(e) => errors.push(e.to_string()),
        }
    }

    (secrets, errors)
}

/// Format secrets as .env content (KEY=value, one per line).
pub fn format_env_content(secrets: &BTreeMap<String, String>) -> String {
    secrets
        .iter()
        .map(|(k, v)| format!("{}={}", k, v))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Helper to create a SecretContext for a given environment
async fn create_secret_context(
    client: &mut zopp_proto::zopp_service_client::ZoppServiceClient<tonic::transport::Channel>,
    principal: &crate::config::PrincipalConfig,
    workspace_name: &str,
    project_name: &str,
    environment_name: &str,
) -> Result<SecretContext, Box<dyn std::error::Error>> {
    // Get workspace keys
    let mut request = tonic::Request::new(zopp_proto::GetWorkspaceKeysRequest {
        workspace_name: workspace_name.to_string(),
    });
    add_auth_metadata(
        &mut request,
        principal,
        "/zopp.ZoppService/GetWorkspaceKeys",
    )?;
    let workspace_keys = client.get_workspace_keys(request).await?.into_inner();

    // Get environment
    let mut request = tonic::Request::new(zopp_proto::GetEnvironmentRequest {
        workspace_name: workspace_name.to_string(),
        project_name: project_name.to_string(),
        environment_name: environment_name.to_string(),
    });
    add_auth_metadata(&mut request, principal, "/zopp.ZoppService/GetEnvironment")?;
    let environment = client.get_environment(request).await?.into_inner();

    // Extract X25519 private key
    let x25519_private_key = principal
        .x25519_private_key
        .as_ref()
        .ok_or("Principal missing X25519 private key")?;
    let x25519_private_bytes = hex::decode(x25519_private_key)?;
    let mut x25519_array = [0u8; 32];
    x25519_array.copy_from_slice(&x25519_private_bytes);

    // Create SecretContext
    Ok(SecretContext::new(
        x25519_array,
        workspace_keys,
        environment,
        workspace_name.to_string(),
        project_name.to_string(),
        environment_name.to_string(),
    )?)
}

pub async fn cmd_secret_set(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    workspace_name: &str,
    project_name: &str,
    environment_name: &str,
    key: &str,
    value: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, principal) = setup_client(server, tls_ca_cert).await?;

    let ctx = create_secret_context(
        &mut client,
        &principal,
        workspace_name,
        project_name,
        environment_name,
    )
    .await?;

    let encrypted = ctx.encrypt_secret(key, value)?;

    let mut request = tonic::Request::new(zopp_proto::UpsertSecretRequest {
        workspace_name: workspace_name.to_string(),
        project_name: project_name.to_string(),
        environment_name: environment_name.to_string(),
        key: key.to_string(),
        nonce: encrypted.nonce,
        ciphertext: encrypted.ciphertext,
    });
    add_auth_metadata(&mut request, &principal, "/zopp.ZoppService/UpsertSecret")?;

    client.upsert_secret(request).await?;

    println!("Secret '{}' set", key);

    Ok(())
}

pub async fn cmd_secret_get(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    workspace_name: &str,
    project_name: &str,
    environment_name: &str,
    key: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, principal) = setup_client(server, tls_ca_cert).await?;

    let mut request = tonic::Request::new(zopp_proto::GetSecretRequest {
        workspace_name: workspace_name.to_string(),
        project_name: project_name.to_string(),
        environment_name: environment_name.to_string(),
        key: key.to_string(),
    });
    add_auth_metadata(&mut request, &principal, "/zopp.ZoppService/GetSecret")?;

    let response = client.get_secret(request).await?.into_inner();

    let ctx = create_secret_context(
        &mut client,
        &principal,
        workspace_name,
        project_name,
        environment_name,
    )
    .await?;

    let value = ctx.decrypt_secret(&response)?;

    println!("{}", value);

    Ok(())
}

pub async fn cmd_secret_list(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    workspace_name: &str,
    project_name: &str,
    environment_name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, principal) = setup_client(server, tls_ca_cert).await?;

    let mut request = tonic::Request::new(zopp_proto::ListSecretsRequest {
        workspace_name: workspace_name.to_string(),
        project_name: project_name.to_string(),
        environment_name: environment_name.to_string(),
    });
    add_auth_metadata(&mut request, &principal, "/zopp.ZoppService/ListSecrets")?;

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
    tls_ca_cert: Option<&std::path::Path>,
    workspace_name: &str,
    project_name: &str,
    environment_name: &str,
    key: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, principal) = setup_client(server, tls_ca_cert).await?;

    let mut request = tonic::Request::new(zopp_proto::DeleteSecretRequest {
        workspace_name: workspace_name.to_string(),
        project_name: project_name.to_string(),
        environment_name: environment_name.to_string(),
        key: key.to_string(),
    });
    add_auth_metadata(&mut request, &principal, "/zopp.ZoppService/DeleteSecret")?;

    client.delete_secret(request).await?;

    println!("Secret '{}' deleted", key);

    Ok(())
}

pub async fn cmd_secret_export(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    workspace_name: &str,
    project_name: &str,
    environment_name: &str,
    output: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, principal) = setup_client(server, tls_ca_cert).await?;

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
    let env_content = format_env_content(&secret_data);

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
    tls_ca_cert: Option<&std::path::Path>,
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
    let (secrets, errors) = parse_env_content(&content);

    // Report any parsing errors to stderr
    for error in &errors {
        eprintln!("Warning: failed to parse {}", error);
    }

    if secrets.is_empty() {
        return Err("No secrets found in input".into());
    }

    let (mut client, principal) = setup_client(server, tls_ca_cert).await?;

    // Create SecretContext once
    let ctx = create_secret_context(
        &mut client,
        &principal,
        workspace_name,
        project_name,
        environment_name,
    )
    .await?;

    for (key, value) in &secrets {
        let encrypted = ctx.encrypt_secret(key, value)?;

        let mut request = tonic::Request::new(zopp_proto::UpsertSecretRequest {
            workspace_name: workspace_name.to_string(),
            project_name: project_name.to_string(),
            environment_name: environment_name.to_string(),
            key: key.clone(),
            nonce: encrypted.nonce,
            ciphertext: encrypted.ciphertext,
        });
        add_auth_metadata(&mut request, &principal, "/zopp.ZoppService/UpsertSecret")?;

        client.upsert_secret(request).await?;
    }

    println!("Imported {} secrets", secrets.len());

    Ok(())
}

pub async fn cmd_secret_run(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    workspace_name: &str,
    project_name: &str,
    environment_name: &str,
    command: &[String],
) -> Result<(), Box<dyn std::error::Error>> {
    if command.is_empty() {
        return Err("No command specified".into());
    }

    let (mut client, principal) = setup_client(server, tls_ca_cert).await?;

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_env_content_simple() {
        let content = "API_KEY=secret123\nDB_PASSWORD=pass456";
        let (secrets, errors) = parse_env_content(content);
        assert!(errors.is_empty());
        assert_eq!(secrets.len(), 2);
        assert_eq!(secrets[0], ("API_KEY".to_string(), "secret123".to_string()));
        assert_eq!(
            secrets[1],
            ("DB_PASSWORD".to_string(), "pass456".to_string())
        );
    }

    #[test]
    fn test_parse_env_content_with_comments() {
        let content = "# Comment\nAPI_KEY=secret\n# Another\nDB=pass";
        let (secrets, errors) = parse_env_content(content);
        assert!(errors.is_empty());
        assert_eq!(secrets.len(), 2);
    }

    #[test]
    fn test_parse_env_content_with_empty_lines() {
        let content = "API_KEY=secret\n\n\nDB=pass\n";
        let (secrets, errors) = parse_env_content(content);
        assert!(errors.is_empty());
        assert_eq!(secrets.len(), 2);
    }

    #[test]
    fn test_parse_env_content_empty() {
        let (secrets, errors) = parse_env_content("");
        assert!(secrets.is_empty());
        assert!(errors.is_empty());

        let (secrets, errors) = parse_env_content("# only comments");
        assert!(secrets.is_empty());
        assert!(errors.is_empty());
    }

    #[test]
    fn test_parse_env_content_value_with_equals() {
        let content = "URL=postgres://user:pass@host/db?ssl=true";
        let (secrets, errors) = parse_env_content(content);
        assert!(errors.is_empty());
        assert_eq!(secrets.len(), 1);
        assert_eq!(secrets[0].1, "postgres://user:pass@host/db?ssl=true");
    }

    #[test]
    fn test_parse_env_content_quoted_with_whitespace() {
        // dotenvy preserves whitespace inside quoted values
        let content = r#"API_KEY=" secret with spaces ""#;
        let (secrets, errors) = parse_env_content(content);
        assert!(errors.is_empty());
        assert_eq!(secrets.len(), 1);
        assert_eq!(secrets[0].1, " secret with spaces ");
    }

    #[test]
    fn test_parse_env_content_reports_errors() {
        // Unclosed quote should result in a parsing error
        let content = "VALID=value\nINVALID=\"unclosed";
        let (secrets, errors) = parse_env_content(content);
        assert_eq!(secrets.len(), 1);
        assert_eq!(secrets[0].0, "VALID");
        assert_eq!(errors.len(), 1);
        // dotenvy reports parsing errors with context
        assert!(!errors[0].is_empty());
    }

    #[test]
    fn test_format_env_content() {
        let mut secrets = BTreeMap::new();
        secrets.insert("API_KEY".to_string(), "secret123".to_string());
        secrets.insert("DB_PASSWORD".to_string(), "pass456".to_string());
        let content = format_env_content(&secrets);
        assert_eq!(content, "API_KEY=secret123\nDB_PASSWORD=pass456");
    }

    #[test]
    fn test_format_env_content_empty() {
        let secrets = BTreeMap::new();
        assert_eq!(format_env_content(&secrets), "");
    }
}
