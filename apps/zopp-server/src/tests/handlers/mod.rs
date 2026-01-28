//! gRPC handler integration tests.
//!
//! These tests call the actual gRPC service methods through the ZoppService trait.
//! They are organized by feature area.

mod audit;
mod auth;
mod effective_permissions;
mod environments;
mod groups;
mod invites;
mod permissions;
mod principals;
mod projects;
mod rbac;
mod secrets;
mod service_accounts;
mod verification;
mod workspaces;
