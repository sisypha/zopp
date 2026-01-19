# Server Development Dockerfile
# Provides a Rust environment with cargo-watch for hot reloading

# Use latest stable Rust to match workspace rust-version requirement
FROM rust:bookworm

# Install cargo-watch for hot reloading
RUN cargo install cargo-watch

# Install protobuf compiler for proto compilation
RUN apt-get update && \
    apt-get install -y protobuf-compiler && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Set up working directory
WORKDIR /app

# Expose gRPC port
EXPOSE 50051

# Default command (can be overridden)
CMD ["cargo", "watch", "-x", "run --bin zopp-server -- serve"]
