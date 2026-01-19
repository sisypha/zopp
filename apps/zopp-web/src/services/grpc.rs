//! gRPC-web client service
//!
//! This module handles communication with the zopp-server via gRPC-web.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum GrpcError {
    #[error("Network error: {0}")]
    Network(String),
    #[error("Server error: {0}")]
    Server(String),
    #[error("Authentication error: {0}")]
    Auth(String),
}

/// gRPC-web client configuration
#[derive(Clone)]
pub struct GrpcConfig {
    pub server_url: String,
}

impl Default for GrpcConfig {
    fn default() -> Self {
        Self {
            server_url: super::config::get_server_url(),
        }
    }
}

/// gRPC-web client for zopp
pub struct ZoppClient {
    config: GrpcConfig,
}

impl ZoppClient {
    pub fn new(config: GrpcConfig) -> Self {
        Self { config }
    }

    pub fn server_url(&self) -> &str {
        &self.config.server_url
    }

    // TODO: Implement gRPC-web methods using fetch API
    // Each method will:
    // 1. Serialize request to protobuf
    // 2. Add auth metadata (using crypto service for signing)
    // 3. Make HTTP POST to gRPC-web endpoint
    // 4. Deserialize response
}

impl Default for ZoppClient {
    fn default() -> Self {
        Self::new(GrpcConfig::default())
    }
}
