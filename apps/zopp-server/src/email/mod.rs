//! Email module for verification.
//!
//! This module provides email sending capabilities for the verification flow.

mod code;
#[cfg(feature = "email-resend")]
mod resend;
#[cfg(feature = "email-smtp")]
mod smtp;
mod templates;

pub use code::generate_verification_code;
pub use templates::VerificationEmailContent;

use crate::config::{EmailConfig, EmailProviderConfig};
use async_trait::async_trait;
use thiserror::Error;

/// Email sending error
#[derive(Debug, Error)]
pub enum EmailError {
    #[error("Failed to send email: {0}")]
    SendFailed(String),

    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),

    #[error("Provider not available: {0}")]
    ProviderNotAvailable(String),
}

/// Trait for email providers
#[async_trait]
pub trait EmailProvider: Send + Sync {
    /// Send a verification email
    async fn send_verification(
        &self,
        to: &str,
        code: &str,
        from_address: &str,
        from_name: Option<&str>,
    ) -> Result<(), EmailError>;
}

/// Create an email provider from configuration
pub fn create_provider(config: &EmailConfig) -> Result<Box<dyn EmailProvider>, EmailError> {
    match &config.provider {
        #[cfg(feature = "email-resend")]
        EmailProviderConfig::Resend { api_key } => {
            Ok(Box::new(resend::ResendProvider::new(api_key.clone())))
        }
        #[cfg(not(feature = "email-resend"))]
        EmailProviderConfig::Resend { .. } => Err(EmailError::ProviderNotAvailable(
            "Resend support not compiled in. Enable the 'email-resend' feature.".to_string(),
        )),
        #[cfg(feature = "email-smtp")]
        EmailProviderConfig::Smtp {
            host,
            port,
            username,
            password,
            use_tls,
        } => {
            let provider = smtp::SmtpProvider::new(
                host.clone(),
                *port,
                username.clone(),
                password.clone(),
                *use_tls,
            )?;
            Ok(Box::new(provider))
        }
        #[cfg(not(feature = "email-smtp"))]
        EmailProviderConfig::Smtp { .. } => Err(EmailError::ProviderNotAvailable(
            "SMTP support not compiled in. Enable the 'email-smtp' feature.".to_string(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verification_code_format() {
        let code = generate_verification_code();
        assert_eq!(code.len(), 6);
        assert!(code.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn test_verification_code_uniqueness() {
        // Generate 100 codes and ensure they're not all the same
        let codes: Vec<String> = (0..100).map(|_| generate_verification_code()).collect();
        let unique_codes: std::collections::HashSet<_> = codes.iter().collect();
        // With 1M possible codes, we should get mostly unique values
        assert!(unique_codes.len() > 90);
    }
}
