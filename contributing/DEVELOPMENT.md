# Development Guide

## Prerequisites

- Rust 1.90+ (stable)
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

### Web UI

The web UI requires additional tooling and runs alongside the server.

#### Prerequisites
```bash
# Install trunk (Rust WASM bundler)
cargo install trunk

# Install wasm-pack
cargo install wasm-pack

# Add WASM target
rustup target add wasm32-unknown-unknown

# Install node dependencies (for Tailwind/DaisyUI)
cd apps/zopp-web && npm install
```

#### Option 1: Docker Compose (Easiest)
```bash
# Terminal 1: Start server + Envoy proxy
cd docker
docker-compose -f docker-compose.web-dev.yaml up

# Terminal 2: Build WASM crypto module (one-time)
wasm-pack build --target web --out-dir apps/zopp-web/pkg crates/zopp-crypto-wasm

# Terminal 3: Start web UI
cd apps/zopp-web
trunk serve
```

#### Option 2: Run Everything Locally
```bash
# Terminal 1: Start zopp-server
cargo run --bin zopp-server serve

# Terminal 2: Start Envoy (needed for gRPC-web translation)
docker run -v $(pwd)/docker/envoy-grpc-web.yaml:/etc/envoy/envoy.yaml \
  --add-host=host.docker.internal:host-gateway \
  -p 8080:8080 envoyproxy/envoy:v1.28-latest

# Terminal 3: Build WASM crypto (one-time, rebuild after changes to zopp-crypto)
wasm-pack build --target web --out-dir apps/zopp-web/pkg crates/zopp-crypto-wasm

# Terminal 4: Start web UI with hot reload
cd apps/zopp-web
trunk serve
```

The web UI will be available at http://localhost:3000

#### Testing a User Flow

To test the UI, you need an invite token:
```bash
# Create a workspace and invite via CLI
cargo run --bin zopp -- workspace create my-workspace
cargo run --bin zopp -- invite create -w my-workspace
# Copy the inv_xxxx token and use it at http://localhost:3000/register
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
