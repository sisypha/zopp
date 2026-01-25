//! Email templates for verification.

/// Content for verification emails.
pub struct VerificationEmailContent {
    pub subject: String,
    pub text: String,
    pub html: String,
}

impl VerificationEmailContent {
    /// Create verification email content with the given code.
    pub fn new(code: &str) -> Self {
        Self {
            subject: "Your Zopp verification code".to_string(),
            text: Self::text_template(code),
            html: Self::html_template(code),
        }
    }

    fn text_template(code: &str) -> String {
        format!(
            r#"Welcome to Zopp!

Your verification code is: {}

This code will expire in 15 minutes.

If you didn't request this code, please ignore this email.

--
Zopp Security Team"#,
            code
        )
    }

    fn html_template(code: &str) -> String {
        format!(
            r#"<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif; line-height: 1.6; color: #333; margin: 0; padding: 0; background: #f5f5f5; }}
        .container {{ max-width: 600px; margin: 0 auto; padding: 40px 20px; }}
        .card {{ background: white; border-radius: 8px; padding: 40px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        h1 {{ color: #1a1a1a; margin-top: 0; font-size: 24px; }}
        .code {{ font-size: 36px; font-weight: bold; letter-spacing: 8px; color: #2563eb; text-align: center; padding: 24px; background: #f0f7ff; border-radius: 8px; margin: 24px 0; font-family: 'SF Mono', Monaco, monospace; }}
        .expires {{ color: #666; font-size: 14px; text-align: center; }}
        .footer {{ margin-top: 32px; padding-top: 20px; border-top: 1px solid #eee; color: #888; font-size: 12px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="card">
            <h1>Welcome to Zopp!</h1>
            <p>Your verification code is:</p>
            <div class="code">{}</div>
            <p class="expires">This code will expire in 15 minutes.</p>
            <div class="footer">
                <p>If you didn't request this code, please ignore this email.</p>
                <p>— Zopp Security Team</p>
            </div>
        </div>
    </div>
</body>
</html>"#,
            code
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_email_content_contains_code() {
        let code = "123456";
        let content = VerificationEmailContent::new(code);

        assert!(content.text.contains(code));
        assert!(content.html.contains(code));
    }

    #[test]
    fn test_email_subject() {
        let content = VerificationEmailContent::new("123456");
        assert_eq!(content.subject, "Your Zopp verification code");
    }

    #[test]
    fn test_text_template_format() {
        let content = VerificationEmailContent::new("654321");

        assert!(content.text.contains("Welcome to Zopp!"));
        assert!(content.text.contains("654321"));
        assert!(content.text.contains("15 minutes"));
        assert!(content.text.contains("Zopp Security Team"));
    }

    #[test]
    fn test_html_template_format() {
        let content = VerificationEmailContent::new("999999");

        assert!(content.html.contains("<!DOCTYPE html>"));
        assert!(content.html.contains("999999"));
        assert!(content.html.contains("15 minutes"));
        assert!(content.html.contains("Zopp Security Team"));
    }
}
