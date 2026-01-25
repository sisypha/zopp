//! MailHog client for E2E testing email verification.
//!
//! MailHog is a mock SMTP server with an HTTP API for retrieving captured emails.
//! This module provides a client to interact with MailHog's API.
//!
//! Start MailHog: docker compose -f docker/docker-compose.test.yaml up -d

use regex::Regex;
use serde::Deserialize;

/// MailHog API response for messages
#[derive(Debug, Deserialize)]
#[allow(dead_code)] // Fields needed for deserialization but not all are read
pub struct MailHogMessages {
    pub total: u32,
    pub count: u32,
    pub start: u32,
    pub items: Vec<MailHogMessage>,
}

/// A single message from MailHog
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct MailHogMessage {
    #[serde(rename = "ID")]
    pub id: String,
    #[serde(rename = "From")]
    pub from: MailHogAddress,
    #[serde(rename = "To")]
    pub to: Vec<MailHogAddress>,
    #[serde(rename = "Content")]
    pub content: MailHogContent,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct MailHogAddress {
    #[serde(rename = "Mailbox")]
    pub mailbox: String,
    #[serde(rename = "Domain")]
    pub domain: String,
}

impl MailHogAddress {
    pub fn email(&self) -> String {
        format!("{}@{}", self.mailbox, self.domain)
    }
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct MailHogContent {
    #[serde(rename = "Headers")]
    pub headers: std::collections::HashMap<String, Vec<String>>,
    #[serde(rename = "Body")]
    pub body: String,
}

/// MailHog client for retrieving captured emails
pub struct MailHogClient {
    api_url: String,
    client: reqwest::Client,
}

impl MailHogClient {
    /// Create a new MailHog client
    pub fn new(host: &str, port: u16) -> Self {
        Self {
            api_url: format!("http://{}:{}/api/v2", host, port),
            client: reqwest::Client::new(),
        }
    }

    /// Create from environment variables or defaults
    /// Uses MAILHOG_HOST (default: 127.0.0.1) and MAILHOG_API_PORT (default: 8025)
    pub fn from_env() -> Self {
        let host = std::env::var("MAILHOG_HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
        let port: u16 = std::env::var("MAILHOG_API_PORT")
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(8025);
        Self::new(&host, port)
    }

    /// Check if MailHog is available
    pub async fn is_available(&self) -> bool {
        self.client
            .get(format!("{}/messages", self.api_url))
            .timeout(std::time::Duration::from_secs(2))
            .send()
            .await
            .map(|r| r.status().is_success())
            .unwrap_or(false)
    }

    /// Get all messages
    pub async fn get_messages(&self) -> Result<MailHogMessages, Box<dyn std::error::Error>> {
        let response = self
            .client
            .get(format!("{}/messages", self.api_url))
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(format!("MailHog API error: {}", response.status()).into());
        }

        Ok(response.json().await?)
    }

    /// Get the latest email sent to a specific address
    pub async fn get_email_for(
        &self,
        to_email: &str,
    ) -> Result<Option<MailHogMessage>, Box<dyn std::error::Error>> {
        let messages = self.get_messages().await?;

        Ok(messages.items.into_iter().rev().find(|msg| {
            msg.to
                .iter()
                .any(|addr| addr.email().to_lowercase() == to_email.to_lowercase())
        }))
    }

    /// Extract verification code from the latest email to an address.
    /// Looks for a 6-digit code in the email body.
    pub async fn get_verification_code(
        &self,
        to_email: &str,
    ) -> Result<Option<String>, Box<dyn std::error::Error>> {
        let email = self.get_email_for(to_email).await?;

        Ok(email.and_then(|msg| {
            let re = Regex::new(r"\b(\d{6})\b").ok()?;
            re.captures(&msg.content.body)
                .and_then(|cap| cap.get(1))
                .map(|m| m.as_str().to_string())
        }))
    }

    /// Clear all messages
    pub async fn clear(&self) -> Result<(), Box<dyn std::error::Error>> {
        // MailHog delete endpoint is on v1, not v2
        let delete_url = self.api_url.replace("/api/v2", "/api/v1/messages");
        self.client.delete(&delete_url).send().await?;
        Ok(())
    }

    /// Wait for an email to arrive (with timeout)
    pub async fn wait_for_email(
        &self,
        to_email: &str,
        timeout_ms: u64,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        let start = std::time::Instant::now();
        let timeout = std::time::Duration::from_millis(timeout_ms);

        while start.elapsed() < timeout {
            if self.get_email_for(to_email).await?.is_some() {
                return Ok(true);
            }
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        }
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn test_mailhog_client_creation() {
        let client = super::MailHogClient::new("localhost", 8025);
        assert!(client.api_url.contains("localhost:8025"));
    }
}
