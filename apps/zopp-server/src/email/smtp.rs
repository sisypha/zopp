//! SMTP email provider implementation.

use super::{EmailError, EmailProvider, VerificationEmailContent};
use async_trait::async_trait;
use lettre::{
    message::{header::ContentType, MultiPart, SinglePart},
    transport::smtp::{
        authentication::Credentials,
        client::{Tls, TlsParameters},
    },
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
};

/// SMTP email provider.
pub struct SmtpProvider {
    transport: AsyncSmtpTransport<Tokio1Executor>,
}

impl SmtpProvider {
    /// Create a new SMTP provider.
    pub fn new(
        host: String,
        port: u16,
        username: Option<String>,
        password: Option<String>,
        use_tls: bool,
    ) -> Result<Self, EmailError> {
        let mut builder = if use_tls {
            let tls_params = TlsParameters::new(host.clone()).map_err(|e| {
                EmailError::InvalidConfig(format!("TLS configuration error: {}", e))
            })?;

            // Port 465 uses implicit TLS (SMTPS), other ports use STARTTLS
            if port == 465 {
                AsyncSmtpTransport::<Tokio1Executor>::relay(&host)
                    .map_err(|e| EmailError::InvalidConfig(format!("SMTP relay error: {}", e)))?
                    .port(port)
                    .tls(Tls::Wrapper(tls_params))
            } else {
                AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&host)
                    .map_err(|e| EmailError::InvalidConfig(format!("SMTP relay error: {}", e)))?
                    .port(port)
                    .tls(Tls::Required(tls_params))
            }
        } else {
            AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&host).port(port)
        };

        if let (Some(user), Some(pass)) = (username, password) {
            builder = builder.credentials(Credentials::new(user, pass));
        }

        let transport = builder.build();

        Ok(Self { transport })
    }
}

#[async_trait]
impl EmailProvider for SmtpProvider {
    async fn send_verification(
        &self,
        to: &str,
        code: &str,
        from_address: &str,
        from_name: Option<&str>,
    ) -> Result<(), EmailError> {
        let content = VerificationEmailContent::new(code);

        let from = match from_name {
            Some(name) => format!("{} <{}>", name, from_address),
            None => from_address.to_string(),
        };

        let message =
            Message::builder()
                .from(from.parse().map_err(|e| {
                    EmailError::InvalidConfig(format!("Invalid from address: {}", e))
                })?)
                .to(to
                    .parse()
                    .map_err(|e| EmailError::InvalidConfig(format!("Invalid to address: {}", e)))?)
                .subject(content.subject)
                .multipart(
                    MultiPart::alternative()
                        .singlepart(
                            SinglePart::builder()
                                .header(ContentType::TEXT_PLAIN)
                                .body(content.text),
                        )
                        .singlepart(
                            SinglePart::builder()
                                .header(ContentType::TEXT_HTML)
                                .body(content.html),
                        ),
                )
                .map_err(|e| EmailError::SendFailed(format!("Failed to build email: {}", e)))?;

        self.transport
            .send(message)
            .await
            .map_err(|e| EmailError::SendFailed(e.to_string()))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_provider_creation_no_tls() {
        let provider = SmtpProvider::new("localhost".to_string(), 25, None, None, false);
        assert!(provider.is_ok());
    }

    #[test]
    fn test_provider_creation_with_credentials() {
        let provider = SmtpProvider::new(
            "localhost".to_string(),
            587,
            Some("user".to_string()),
            Some("pass".to_string()),
            false,
        );
        assert!(provider.is_ok());
    }
}
