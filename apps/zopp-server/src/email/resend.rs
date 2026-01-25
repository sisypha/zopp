//! Resend email provider implementation.

use super::{EmailError, EmailProvider, VerificationEmailContent};
use async_trait::async_trait;
use resend_rs::{types::CreateEmailBaseOptions, Resend};

/// Resend email provider.
pub struct ResendProvider {
    client: Resend,
}

impl ResendProvider {
    /// Create a new Resend provider with the given API key.
    pub fn new(api_key: String) -> Self {
        Self {
            client: Resend::new(&api_key),
        }
    }
}

#[async_trait]
impl EmailProvider for ResendProvider {
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

        let email = CreateEmailBaseOptions::new(from, vec![to.to_string()], content.subject)
            .with_text(&content.text)
            .with_html(&content.html);

        self.client
            .emails
            .send(email)
            .await
            .map_err(|e| EmailError::SendFailed(e.to_string()))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_provider_creation() {
        let provider = ResendProvider::new("re_test_key".to_string());
        // Just verify it creates without panicking
        assert!(std::mem::size_of_val(&provider) > 0);
    }
}
