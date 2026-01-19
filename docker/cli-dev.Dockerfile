# CLI Development Dockerfile
# Provides a Rust environment for running zopp CLI commands

# Use latest stable Rust to match workspace rust-version requirement
FROM rust:bookworm

# Install protobuf compiler for proto compilation
RUN apt-get update && \
    apt-get install -y protobuf-compiler && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Set up working directory
WORKDIR /app

# Keep container running
CMD ["tail", "-f", "/dev/null"]
