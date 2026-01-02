use crate::config::{get_current_principal, load_config, PrincipalConfig};
use chrono::Utc;
use ed25519_dalek::{Signer, SigningKey};
use tonic::metadata::MetadataValue;
use tonic::transport::Channel;
use zopp_proto::zopp_service_client::ZoppServiceClient;

pub async fn connect(
    server: &str,
) -> Result<ZoppServiceClient<Channel>, Box<dyn std::error::Error>> {
    let endpoint = Channel::from_shared(server.to_string())?;

    let endpoint = if server.starts_with("https://") {
        let tls_config = tonic::transport::ClientTlsConfig::new();
        endpoint.tls_config(tls_config)?
    } else {
        endpoint
    };

    let channel = endpoint.connect().await?;
    let client = ZoppServiceClient::new(channel);
    Ok(client)
}

pub fn sign_request(private_key_hex: &str) -> Result<(i64, Vec<u8>), Box<dyn std::error::Error>> {
    let timestamp = Utc::now().timestamp();
    let private_key_bytes = hex::decode(private_key_hex)?;
    let signing_key = SigningKey::from_bytes(
        private_key_bytes
            .as_slice()
            .try_into()
            .map_err(|_| "Invalid private key length")?,
    );
    let signature = signing_key.sign(&timestamp.to_le_bytes());
    Ok((timestamp, signature.to_bytes().to_vec()))
}

/// Setup authenticated client: load config, get principal, connect to server
pub async fn setup_client(
    server: &str,
) -> Result<(ZoppServiceClient<Channel>, PrincipalConfig), Box<dyn std::error::Error>> {
    let config = load_config()?;
    let principal = get_current_principal(&config)?;
    let client = connect(server).await?;
    Ok((client, principal.clone()))
}

/// Add authentication metadata (principal-id, timestamp, signature) to a request
pub fn add_auth_metadata<T>(
    request: &mut tonic::Request<T>,
    principal: &PrincipalConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let (timestamp, signature) = sign_request(&principal.private_key)?;

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

    Ok(())
}
