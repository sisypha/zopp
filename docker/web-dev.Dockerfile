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

# Copy Cargo workspace files first for better layer caching
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY apps ./apps

# Install npm dependencies
RUN cd apps/zopp-web && npm install

# Build the WASM crypto package
RUN cd crates/zopp-crypto-wasm && \
    wasm-pack build --target web --dev --out-dir ../../apps/zopp-web/pkg

# Build Tailwind CSS
RUN cd apps/zopp-web && \
    npx tailwindcss -i ./style/input.css -o ./style/output.css

# Expose the trunk dev server port
EXPOSE 3000

# Set working directory to web app
WORKDIR /app/apps/zopp-web

# Run trunk serve with watch mode
# --address 0.0.0.0 to allow connections from outside the container
# --proxy-backend for API calls to envoy
CMD ["trunk", "serve", "--address", "0.0.0.0", "--port", "3000"]
