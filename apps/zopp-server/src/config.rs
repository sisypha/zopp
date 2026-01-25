//! Server configuration module for email verification.
//!
//! Supports configuration via environment variables:
//!
//! ```bash
//! # Core settings
//! ZOPP_EMAIL_VERIFICATION_REQUIRED=true  # enabled by default
//!
//! # Provider: Resend
//! ZOPP_EMAIL_PROVIDER=resend
//! RESEND_API_KEY=re_...
//!
//! # Provider: SMTP
//! ZOPP_EMAIL_PROVIDER=smtp
//! SMTP_HOST=smtp.gmail.com
//! SMTP_PORT=587
//! SMTP_USERNAME=user@example.com
//! SMTP_PASSWORD=app_password
//! SMTP_USE_TLS=true
//!
//! # Sender config
//! ZOPP_EMAIL_FROM=noreply@zopp.dev
//! ZOPP_EMAIL_FROM_NAME="Zopp Security"
//! ```

use std::env;
use thiserror::Error;

/// Server configuration
#[derive(Debug, Clone, Default)]
pub struct ServerConfig {
    pub email: Option<EmailConfig>,
}

/// Email configuration for verification
#[derive(Debug, Clone)]
pub struct EmailConfig {
    /// Whether email verification is required for new principals
    pub verification_required: bool,
    /// Email provider configuration
    pub provider: EmailProviderConfig,
    /// From email address
    pub from_address: String,
    /// Optional from name
    pub from_name: Option<String>,
}

/// Email provider configuration
#[derive(Debug, Clone)]
pub enum EmailProviderConfig {
    /// Resend email provider
    Resend {
        /// Resend API key
        #[allow(dead_code)] // Used when email-resend feature is enabled
        api_key: String,
    },
    /// SMTP email provider
    Smtp {
        /// SMTP host
        host: String,
        /// SMTP port
        port: u16,
        /// Optional username
        username: Option<String>,
        /// Optional password
        password: Option<String>,
        /// Whether to use TLS
        use_tls: bool,
    },
}

/// Configuration errors
#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("Email verification is enabled but no email provider is configured")]
    VerificationEnabledWithoutProvider,

    #[error("Invalid email provider: {0}. Expected 'resend' or 'smtp'")]
    InvalidProvider(String),

    #[error("Missing required environment variable: {0}")]
    MissingEnvVar(String),

    #[error("Invalid port number: {0}")]
    InvalidPort(String),

    #[error("Missing from address: ZOPP_EMAIL_FROM is required when email is configured")]
    MissingFromAddress,

    #[error("SMTP provider requires SMTP_HOST")]
    SmtpMissingHost,
}

impl ServerConfig {
    /// Load configuration from environment variables
    pub fn from_env() -> Result<Self, ConfigError> {
        let verification_required = env::var("ZOPP_EMAIL_VERIFICATION_REQUIRED")
            .map(|v| v.to_lowercase() == "true" || v == "1")
            .unwrap_or(true); // Enabled by default

        let provider_type = env::var("ZOPP_EMAIL_PROVIDER").ok();

        // If no provider is configured
        if provider_type.is_none() {
            if verification_required {
                // Check if there's an explicit setting for verification
                if env::var("ZOPP_EMAIL_VERIFICATION_REQUIRED").is_ok() {
                    return Err(ConfigError::VerificationEnabledWithoutProvider);
                }
                // If verification_required is just the default, silently disable email
                return Ok(Self { email: None });
            }
            return Ok(Self { email: None });
        }

        let provider_type = provider_type.unwrap();
        let provider = match provider_type.to_lowercase().as_str() {
            "resend" => {
                let api_key = env::var("RESEND_API_KEY")
                    .map_err(|_| ConfigError::MissingEnvVar("RESEND_API_KEY".to_string()))?;
                EmailProviderConfig::Resend { api_key }
            }
            "smtp" => {
                let host = env::var("SMTP_HOST").map_err(|_| ConfigError::SmtpMissingHost)?;
                let port = env::var("SMTP_PORT")
                    .unwrap_or_else(|_| "587".to_string())
                    .parse::<u16>()
                    .map_err(|_| {
                        ConfigError::InvalidPort(
                            env::var("SMTP_PORT").unwrap_or_else(|_| "invalid".to_string()),
                        )
                    })?;
                let username = env::var("SMTP_USERNAME").ok();
                let password = env::var("SMTP_PASSWORD").ok();
                let use_tls = env::var("SMTP_USE_TLS")
                    .map(|v| v.to_lowercase() == "true" || v == "1")
                    .unwrap_or(true); // TLS by default

                EmailProviderConfig::Smtp {
                    host,
                    port,
                    username,
                    password,
                    use_tls,
                }
            }
            other => return Err(ConfigError::InvalidProvider(other.to_string())),
        };

        let from_address =
            env::var("ZOPP_EMAIL_FROM").map_err(|_| ConfigError::MissingFromAddress)?;
        let from_name = env::var("ZOPP_EMAIL_FROM_NAME").ok();

        Ok(Self {
            email: Some(EmailConfig {
                verification_required,
                provider,
                from_address,
                from_name,
            }),
        })
    }

    /// Check if email verification is required
    pub fn is_verification_required(&self) -> bool {
        self.email
            .as_ref()
            .map(|e| e.verification_required)
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::sync::Mutex;

    // Mutex to serialize tests that modify environment variables
    static ENV_MUTEX: Mutex<()> = Mutex::new(());

    // All env vars we touch in tests - cleared before each test
    const ENV_VARS: &[&str] = &[
        "ZOPP_EMAIL_VERIFICATION_REQUIRED",
        "ZOPP_EMAIL_PROVIDER",
        "RESEND_API_KEY",
        "SMTP_HOST",
        "SMTP_PORT",
        "SMTP_USERNAME",
        "SMTP_PASSWORD",
        "SMTP_USE_TLS",
        "ZOPP_EMAIL_FROM",
        "ZOPP_EMAIL_FROM_NAME",
    ];

    // Helper to clean up env vars - holds mutex lock
    struct EnvGuard<'a> {
        _lock: std::sync::MutexGuard<'a, ()>,
    }

    impl<'a> EnvGuard<'a> {
        fn new() -> Self {
            let lock = ENV_MUTEX.lock().unwrap();
            // Clear all env vars at start
            for var in ENV_VARS {
                env::remove_var(var);
            }
            Self { _lock: lock }
        }

        fn set(&self, key: &str, value: &str) {
            env::set_var(key, value);
        }

        #[allow(dead_code)]
        fn remove(&self, key: &str) {
            env::remove_var(key);
        }
    }

    impl<'a> Drop for EnvGuard<'a> {
        fn drop(&mut self) {
            // Clear all env vars on drop
            for var in ENV_VARS {
                env::remove_var(var);
            }
        }
    }

    #[test]
    fn test_default_config_no_email() {
        let _guard = EnvGuard::new();
        // No env vars set, so email should be None

        let config = ServerConfig::from_env().unwrap();
        assert!(config.email.is_none());
        assert!(!config.is_verification_required());
    }

    #[test]
    fn test_verification_enabled_without_provider_explicit() {
        let guard = EnvGuard::new();
        guard.set("ZOPP_EMAIL_VERIFICATION_REQUIRED", "true");
        guard.remove("ZOPP_EMAIL_PROVIDER");

        let result = ServerConfig::from_env();
        assert!(matches!(
            result,
            Err(ConfigError::VerificationEnabledWithoutProvider)
        ));
    }

    #[test]
    fn test_resend_provider_config() {
        let guard = EnvGuard::new();
        guard.set("ZOPP_EMAIL_PROVIDER", "resend");
        guard.set("RESEND_API_KEY", "re_test_key");
        guard.set("ZOPP_EMAIL_FROM", "test@example.com");
        guard.set("ZOPP_EMAIL_FROM_NAME", "Test Sender");
        guard.set("ZOPP_EMAIL_VERIFICATION_REQUIRED", "true");

        let config = ServerConfig::from_env().unwrap();
        let email = config.email.unwrap();
        assert!(email.verification_required);
        assert_eq!(email.from_address, "test@example.com");
        assert_eq!(email.from_name, Some("Test Sender".to_string()));

        match email.provider {
            EmailProviderConfig::Resend { api_key } => {
                assert_eq!(api_key, "re_test_key");
            }
            _ => panic!("Expected Resend provider"),
        }
    }

    #[test]
    fn test_resend_missing_api_key() {
        let guard = EnvGuard::new();
        guard.set("ZOPP_EMAIL_PROVIDER", "resend");
        guard.remove("RESEND_API_KEY");
        guard.set("ZOPP_EMAIL_FROM", "test@example.com");

        let result = ServerConfig::from_env();
        assert!(matches!(result, Err(ConfigError::MissingEnvVar(_))));
    }

    #[test]
    fn test_smtp_provider_config() {
        let guard = EnvGuard::new();
        guard.set("ZOPP_EMAIL_PROVIDER", "smtp");
        guard.set("SMTP_HOST", "smtp.example.com");
        guard.set("SMTP_PORT", "465");
        guard.set("SMTP_USERNAME", "user@example.com");
        guard.set("SMTP_PASSWORD", "secret");
        guard.set("SMTP_USE_TLS", "true");
        guard.set("ZOPP_EMAIL_FROM", "test@example.com");
        guard.set("ZOPP_EMAIL_VERIFICATION_REQUIRED", "true");

        let config = ServerConfig::from_env().unwrap();
        let email = config.email.unwrap();

        match email.provider {
            EmailProviderConfig::Smtp {
                host,
                port,
                username,
                password,
                use_tls,
            } => {
                assert_eq!(host, "smtp.example.com");
                assert_eq!(port, 465);
                assert_eq!(username, Some("user@example.com".to_string()));
                assert_eq!(password, Some("secret".to_string()));
                assert!(use_tls);
            }
            _ => panic!("Expected SMTP provider"),
        }
    }

    #[test]
    fn test_smtp_defaults() {
        let guard = EnvGuard::new();
        guard.set("ZOPP_EMAIL_PROVIDER", "smtp");
        guard.set("SMTP_HOST", "smtp.example.com");
        guard.remove("SMTP_PORT"); // Should default to 587
        guard.remove("SMTP_USERNAME");
        guard.remove("SMTP_PASSWORD");
        guard.remove("SMTP_USE_TLS"); // Should default to true
        guard.set("ZOPP_EMAIL_FROM", "test@example.com");
        guard.set("ZOPP_EMAIL_VERIFICATION_REQUIRED", "true");

        let config = ServerConfig::from_env().unwrap();
        let email = config.email.unwrap();

        match email.provider {
            EmailProviderConfig::Smtp {
                port,
                username,
                password,
                use_tls,
                ..
            } => {
                assert_eq!(port, 587);
                assert!(username.is_none());
                assert!(password.is_none());
                assert!(use_tls);
            }
            _ => panic!("Expected SMTP provider"),
        }
    }

    #[test]
    fn test_smtp_missing_host() {
        let guard = EnvGuard::new();
        guard.set("ZOPP_EMAIL_PROVIDER", "smtp");
        guard.remove("SMTP_HOST");
        guard.set("ZOPP_EMAIL_FROM", "test@example.com");

        let result = ServerConfig::from_env();
        assert!(matches!(result, Err(ConfigError::SmtpMissingHost)));
    }

    #[test]
    fn test_invalid_port() {
        let guard = EnvGuard::new();
        guard.set("ZOPP_EMAIL_PROVIDER", "smtp");
        guard.set("SMTP_HOST", "smtp.example.com");
        guard.set("SMTP_PORT", "not_a_number");
        guard.set("ZOPP_EMAIL_FROM", "test@example.com");

        let result = ServerConfig::from_env();
        assert!(matches!(result, Err(ConfigError::InvalidPort(_))));
    }

    #[test]
    fn test_invalid_provider() {
        let guard = EnvGuard::new();
        guard.set("ZOPP_EMAIL_PROVIDER", "mailgun");
        guard.set("ZOPP_EMAIL_FROM", "test@example.com");

        let result = ServerConfig::from_env();
        assert!(matches!(result, Err(ConfigError::InvalidProvider(_))));
    }

    #[test]
    fn test_missing_from_address() {
        let guard = EnvGuard::new();
        guard.set("ZOPP_EMAIL_PROVIDER", "resend");
        guard.set("RESEND_API_KEY", "re_test_key");
        guard.remove("ZOPP_EMAIL_FROM");

        let result = ServerConfig::from_env();
        assert!(matches!(result, Err(ConfigError::MissingFromAddress)));
    }

    #[test]
    fn test_verification_disabled() {
        let guard = EnvGuard::new();
        guard.set("ZOPP_EMAIL_PROVIDER", "resend");
        guard.set("RESEND_API_KEY", "re_test_key");
        guard.set("ZOPP_EMAIL_FROM", "test@example.com");
        guard.set("ZOPP_EMAIL_VERIFICATION_REQUIRED", "false");

        let config = ServerConfig::from_env().unwrap();
        assert!(!config.is_verification_required());
        let email = config.email.unwrap();
        assert!(!email.verification_required);
    }

    #[test]
    fn test_provider_case_insensitive() {
        let guard = EnvGuard::new();
        guard.set("ZOPP_EMAIL_PROVIDER", "RESEND");
        guard.set("RESEND_API_KEY", "re_test_key");
        guard.set("ZOPP_EMAIL_FROM", "test@example.com");

        let config = ServerConfig::from_env().unwrap();
        assert!(config.email.is_some());
        match config.email.unwrap().provider {
            EmailProviderConfig::Resend { .. } => {}
            _ => panic!("Expected Resend provider"),
        }
    }
}
