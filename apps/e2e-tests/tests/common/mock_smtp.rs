//! Mock SMTP server for E2E testing email verification.
//!
//! Uses mailin-embedded to create a real SMTP server that captures emails,
//! allowing tests to retrieve verification codes from the email body.
//!
//! Note: This module is kept for potential future use but currently tests use
//! MailHog (via docker-compose.test.yaml) for email capture.

#![allow(dead_code)]

use mailin_embedded::response::{OK, START_DATA};
use mailin_embedded::{Handler, Response, Server};
use regex::Regex;
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::thread;

/// Captured email data
#[derive(Debug, Clone)]
pub struct CapturedEmail {
    pub from: String,
    pub to: Vec<String>,
    pub data: String,
}

/// Handler that captures emails
#[derive(Clone)]
struct EmailCapture {
    emails: Arc<Mutex<Vec<CapturedEmail>>>,
    current_from: Arc<Mutex<String>>,
    current_to: Arc<Mutex<Vec<String>>>,
    current_data: Arc<Mutex<Vec<u8>>>,
}

impl Handler for EmailCapture {
    fn helo(&mut self, _ip: std::net::IpAddr, _domain: &str) -> Response {
        OK
    }

    fn mail(&mut self, _ip: std::net::IpAddr, _domain: &str, from: &str) -> Response {
        *self.current_from.lock().unwrap() = from.to_string();
        self.current_to.lock().unwrap().clear();
        self.current_data.lock().unwrap().clear();
        OK
    }

    fn rcpt(&mut self, to: &str) -> Response {
        self.current_to.lock().unwrap().push(to.to_string());
        OK
    }

    fn data_start(
        &mut self,
        _domain: &str,
        _from: &str,
        _is8bit: bool,
        _to: &[String],
    ) -> Response {
        START_DATA
    }

    fn data(&mut self, buf: &[u8]) -> std::io::Result<()> {
        // Accumulate data chunks - email content comes in multiple calls
        self.current_data.lock().unwrap().extend_from_slice(buf);
        Ok(())
    }

    fn data_end(&mut self) -> Response {
        // Now we have the complete email, store it
        let data = String::from_utf8_lossy(&self.current_data.lock().unwrap()).to_string();
        let from = self.current_from.lock().unwrap().clone();
        let to = self.current_to.lock().unwrap().clone();

        self.emails
            .lock()
            .unwrap()
            .push(CapturedEmail { from, to, data });

        // Clear for next email
        self.current_data.lock().unwrap().clear();

        OK
    }
}

/// Mock SMTP server that captures emails for testing
pub struct MockSmtpServer {
    port: u16,
    emails: Arc<Mutex<Vec<CapturedEmail>>>,
    shutdown_handle: Option<thread::JoinHandle<()>>,
}

impl MockSmtpServer {
    /// Start a new mock SMTP server on a random available port
    pub fn start() -> Result<Self, Box<dyn std::error::Error>> {
        // Find an available port
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let port = listener.local_addr()?.port();
        drop(listener); // Release the port so mailin can use it

        let emails: Arc<Mutex<Vec<CapturedEmail>>> = Arc::new(Mutex::new(Vec::new()));
        let emails_clone = emails.clone();

        let handle = thread::spawn(move || {
            let handler = EmailCapture {
                emails: emails_clone,
                current_from: Arc::new(Mutex::new(String::new())),
                current_to: Arc::new(Mutex::new(Vec::new())),
                current_data: Arc::new(Mutex::new(Vec::new())),
            };

            let mut server = Server::new(handler);
            server
                .with_addr(format!("127.0.0.1:{}", port))
                .expect("Failed to set server address");

            // This blocks until the server is stopped
            // For tests, the server will be dropped when the test ends
            let _ = server.serve();
        });

        // Give the server a moment to start
        std::thread::sleep(std::time::Duration::from_millis(100));

        Ok(Self {
            port,
            emails,
            shutdown_handle: Some(handle),
        })
    }

    /// Get the port the server is listening on
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Get all captured emails
    pub fn get_emails(&self) -> Vec<CapturedEmail> {
        self.emails.lock().unwrap().clone()
    }

    /// Get the latest email sent to a specific address
    pub fn get_email_for(&self, to_email: &str) -> Option<CapturedEmail> {
        self.emails
            .lock()
            .unwrap()
            .iter()
            .rev()
            .find(|e| e.to.iter().any(|t| t.contains(to_email)))
            .cloned()
    }

    /// Extract verification code from the latest email to an address.
    /// Looks for a 6-digit code in the email body.
    pub fn get_verification_code(&self, to_email: &str) -> Option<String> {
        let email = self.get_email_for(to_email)?;

        // Look for 6-digit code in the email body
        let re = Regex::new(r"\b(\d{6})\b").ok()?;
        re.captures(&email.data)
            .and_then(|cap| cap.get(1))
            .map(|m| m.as_str().to_string())
    }

    /// Clear all captured emails
    pub fn clear(&self) {
        self.emails.lock().unwrap().clear();
    }

    /// Wait for at least one email to arrive (with timeout)
    pub fn wait_for_email(&self, timeout_ms: u64) -> bool {
        let start = std::time::Instant::now();
        let timeout = std::time::Duration::from_millis(timeout_ms);

        while start.elapsed() < timeout {
            if !self.emails.lock().unwrap().is_empty() {
                return true;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        false
    }
}

impl Drop for MockSmtpServer {
    fn drop(&mut self) {
        // The server thread will end when the test process ends
        // We don't need to explicitly stop it for tests
        if let Some(handle) = self.shutdown_handle.take() {
            // Don't wait for the thread - it's blocking on accept()
            drop(handle);
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_mock_smtp_starts() {
        let server = super::MockSmtpServer::start().expect("Failed to start mock SMTP");
        assert!(server.port() > 0);
    }
}
