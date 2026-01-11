#!/bin/bash
set -e

echo "=== E2E Test Coverage Collection ==="

# Check if cargo-llvm-cov is installed
if ! command -v cargo-llvm-cov &> /dev/null; then
    echo "cargo-llvm-cov is not installed. Install with: cargo install cargo-llvm-cov"
    exit 1
fi

# Setup coverage environment
echo "Setting up coverage environment..."
source <(cargo llvm-cov show-env --export-prefix)

# Clean previous coverage data
echo "Cleaning previous coverage data..."
cargo llvm-cov clean --workspace

# Build all binaries with instrumentation
echo "Building instrumented binaries..."
cargo build --workspace --bins

# Run unit tests
echo "Running unit tests..."
cargo test --workspace --all-features

# Run E2E tests (spawned binaries inherit coverage env)
echo "Running E2E tests..."
cargo test --package e2e-tests -- --test-threads=1

# Generate reports
echo "Generating coverage reports..."
mkdir -p target/coverage
cargo llvm-cov report --lcov --output-path target/coverage/e2e-coverage.lcov
cargo llvm-cov report --html --output-dir target/coverage/html
cargo llvm-cov report

echo ""
echo "=== Coverage reports generated ==="
echo "  LCOV: target/coverage/e2e-coverage.lcov"
echo "  HTML: target/coverage/html/index.html"
