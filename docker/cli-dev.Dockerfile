# CLI Development Dockerfile
# Provides a Rust environment for running zopp CLI commands

FROM rust:1.83-bookworm

# Install protobuf compiler for proto compilation
RUN apt-get update && \
    apt-get install -y protobuf-compiler && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create non-root user for CLI
RUN useradd -m -s /bin/bash zopp

# Set up working directory
WORKDIR /app

# Build the CLI binary once (will be rebuilt on source changes)
# This is done at runtime via the helper script

USER zopp

# Keep container running
CMD ["tail", "-f", "/dev/null"]
