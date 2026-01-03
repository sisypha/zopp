# Development Guide

## Prerequisites

- Rust 1.65+ (stable)
- Docker (optional, for integration tests)
- PostgreSQL (optional, for Postgres backend development)

## Building and Testing

```bash
# Build all crates
cargo build --workspace

# Run tests
cargo test --workspace

# Format and lint
cargo fmt --all
cargo clippy --workspace --all-targets --all-features

# Build Docker images
docker build -f server.Dockerfile -t zopp-server .
docker build -f operator.Dockerfile -t zopp-operator .
docker build -f cli.Dockerfile -t zopp-cli .
```

## Running Locally

### Server (SQLite)
```bash
cargo run --bin zopp-server serve
```

### Server (PostgreSQL)
```bash
# Start PostgreSQL
docker run --name zopp-pg -e POSTGRES_PASSWORD=postgres -p 5432:5432 -d postgres:16

# Run server
DATABASE_URL=postgres://postgres:postgres@localhost/postgres cargo run --bin zopp-server serve
```

### CLI
```bash
# After server is running
cargo run --bin zopp -- workspace create acme
cargo run --bin zopp -- secret set FOO bar
```

## Storage Backends

Each storage backend lives in its own crate and implements the `Store` trait from `zopp-storage`. See individual crate READMEs for backend-specific details:

- `crates/zopp-store-sqlite/` - SQLite implementation

### Adding a Storage Backend

Create a new crate that implements the `Store` trait. The implementation can use any approach - SQL database, key-value store, file system, etc.

```rust
use zopp_storage::Store;

pub struct MyStore { /* ... */ }

#[async_trait::async_trait]
impl Store for MyStore {
    // Implement required methods
}
```
