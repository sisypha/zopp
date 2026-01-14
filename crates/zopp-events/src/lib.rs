//! Event bus abstraction for zopp secret change notifications.
//!
//! This crate defines the EventBus trait that allows different implementations
//! for event broadcasting across server replicas:
//! - Memory (single server, tokio broadcast channels)
//! - Redis (multi-server, Redis pub/sub)
//! - Postgres (multi-server, PostgreSQL LISTEN/NOTIFY)

use async_trait::async_trait;
use futures::Stream;
use serde::{Deserialize, Serialize};
use std::pin::Pin;
use thiserror::Error;
use zopp_storage::EnvironmentId;

/// Type of secret change event
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum EventType {
    Created,
    Updated,
    Deleted,
}

/// Event representing a change to a secret in an environment
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SecretChangeEvent {
    pub event_type: EventType,
    pub key: String,
    pub version: i64,
    pub timestamp: i64,
}

/// Error type for event bus operations
#[derive(Debug, Error)]
pub enum EventBusError {
    #[error("backend error: {0}")]
    Backend(String),
}

/// Stream of secret change events
pub type EventStream = Pin<Box<dyn Stream<Item = SecretChangeEvent> + Send>>;

/// Event bus trait for publishing and subscribing to secret change events.
///
/// Implementations can be:
/// - In-memory (single server): tokio broadcast channels
/// - Redis: Redis pub/sub
/// - Postgres: PostgreSQL LISTEN/NOTIFY
#[async_trait]
pub trait EventBus: Send + Sync {
    /// Publish a secret change event to all watchers of this environment.
    ///
    /// This is called after a secret is created, updated, or deleted.
    /// The event is broadcast to all active subscribers for this environment.
    async fn publish(
        &self,
        env_id: &EnvironmentId,
        event: SecretChangeEvent,
    ) -> Result<(), EventBusError>;

    /// Subscribe to secret change events for an environment.
    ///
    /// Returns a stream that yields events as they occur.
    /// The stream will continue until dropped or the connection is closed.
    async fn subscribe(&self, env_id: &EnvironmentId) -> Result<EventStream, EventBusError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_type_equality() {
        assert_eq!(EventType::Created, EventType::Created);
        assert_eq!(EventType::Updated, EventType::Updated);
        assert_eq!(EventType::Deleted, EventType::Deleted);
        assert_ne!(EventType::Created, EventType::Updated);
        assert_ne!(EventType::Updated, EventType::Deleted);
    }

    #[test]
    fn test_event_type_clone() {
        let event_type = EventType::Created;
        let cloned = event_type.clone();
        assert_eq!(event_type, cloned);
    }

    #[test]
    fn test_event_type_debug() {
        assert!(format!("{:?}", EventType::Created).contains("Created"));
        assert!(format!("{:?}", EventType::Updated).contains("Updated"));
        assert!(format!("{:?}", EventType::Deleted).contains("Deleted"));
    }

    #[test]
    fn test_secret_change_event_serialization() {
        let event = SecretChangeEvent {
            event_type: EventType::Created,
            key: "API_KEY".to_string(),
            version: 42,
            timestamp: 1234567890,
        };

        let json = serde_json::to_string(&event).unwrap();
        let deserialized: SecretChangeEvent = serde_json::from_str(&json).unwrap();

        assert_eq!(event.event_type, deserialized.event_type);
        assert_eq!(event.key, deserialized.key);
        assert_eq!(event.version, deserialized.version);
        assert_eq!(event.timestamp, deserialized.timestamp);
    }

    #[test]
    fn test_secret_change_event_clone() {
        let event = SecretChangeEvent {
            event_type: EventType::Updated,
            key: "SECRET".to_string(),
            version: 1,
            timestamp: 999,
        };

        let cloned = event.clone();
        assert_eq!(event.key, cloned.key);
        assert_eq!(event.version, cloned.version);
    }

    #[test]
    fn test_secret_change_event_debug() {
        let event = SecretChangeEvent {
            event_type: EventType::Deleted,
            key: "TO_DELETE".to_string(),
            version: 3,
            timestamp: 111,
        };

        let debug_str = format!("{:?}", event);
        assert!(debug_str.contains("TO_DELETE"));
        assert!(debug_str.contains("Deleted"));
    }

    #[test]
    fn test_event_bus_error_display() {
        let error = EventBusError::Backend("connection failed".to_string());
        let display = error.to_string();
        assert!(display.contains("backend error"));
        assert!(display.contains("connection failed"));
    }

    #[test]
    fn test_event_bus_error_debug() {
        let error = EventBusError::Backend("test error".to_string());
        let debug_str = format!("{:?}", error);
        assert!(debug_str.contains("Backend"));
        assert!(debug_str.contains("test error"));
    }
}
