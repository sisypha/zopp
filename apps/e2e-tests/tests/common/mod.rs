//! Shared test utilities for e2e tests.
//!
//! Not all exports are used by all tests, so we allow unused imports.

#![allow(unused_imports)]

pub mod harness;
pub mod utils;

// Re-export commonly used items
pub use harness::{BackendConfig, TestHarness, TestUser};
pub use utils::{get_binary_paths, graceful_shutdown, parse_principal_id};
