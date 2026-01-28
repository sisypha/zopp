//! Server unit and integration tests.
//!
//! Tests are organized into modules by feature area:
//! - `common` - Shared test helpers and utilities
//! - `auth` - Authentication and signature verification tests
//! - `permissions` - Permission checking unit tests
//! - `join_flow` - Join and invite flow tests
//! - `store_backend` - Storage backend abstraction tests
//! - `handlers` - gRPC handler integration tests

pub mod common;

mod auth;
mod handlers;
mod join_flow;
mod permissions;
mod store_backend;
