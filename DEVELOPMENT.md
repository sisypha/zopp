# Development Guide

## Building and Testing

```bash
cargo build
cargo test
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
