//! Common utilities for E2E tests.

pub mod harness;
pub mod mailhog;
pub mod utils;

// Re-export for tests that use the new infrastructure
// Note: rbac.rs doesn't use harness, so allow unused imports there
#[allow(unused_imports)]
pub use harness::*;
#[allow(unused_imports)]
pub use mailhog::*;
#[allow(unused_imports)]
pub use utils::*;
