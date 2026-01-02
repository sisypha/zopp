# Build stage
FROM rust:1.90-slim AS builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

# Copy workspace files
COPY Cargo.toml Cargo.lock ./
COPY apps/ apps/
COPY crates/ crates/
COPY xtask/ xtask/

# Build release binary (offline mode for sqlx)
ENV SQLX_OFFLINE=true
RUN cargo build --release --bin zopp-operator

# Runtime stage
FROM debian:sid-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -u 1000 -s /bin/false zopp

# Copy binary from builder
COPY --from=builder /build/target/release/zopp-operator /usr/local/bin/zopp-operator

# Set ownership
RUN chown zopp:zopp /usr/local/bin/zopp-operator

USER zopp

# Note: No ports exposed - operator only makes outbound connections
ENTRYPOINT ["/usr/local/bin/zopp-operator"]
