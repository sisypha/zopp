# Web UI Development Dockerfile
# Provides a complete environment for running the Leptos web app with hot reloading

# Use latest stable Rust to match workspace rust-version requirement
FROM rust:bookworm

# Install Node.js (for tailwindcss) and other dependencies
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - && \
    apt-get update && \
    apt-get install -y nodejs protobuf-compiler && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install wasm target and tools
RUN rustup target add wasm32-unknown-unknown && \
    cargo install trunk wasm-bindgen-cli wasm-pack

# Set up working directory
WORKDIR /app

# Expose the trunk dev server port
EXPOSE 3000

# Startup script that builds WASM/CSS then runs trunk
# Source is mounted at runtime via docker-compose volumes
CMD ["sh", "-c", "cd apps/zopp-web && npm install && cd ../../crates/zopp-crypto-wasm && wasm-pack build --target web --dev --out-dir ../../apps/zopp-web/pkg && cd ../../apps/zopp-web && npx tailwindcss -i ./style/input.css -o ./style/output.css && trunk serve --address 0.0.0.0 --port 3000"]
