#!/bin/bash
set -e

echo "=== Test Coverage Collection ==="

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

# Run E2E tests (spawned binaries inherit coverage env)
echo "Running E2E tests..."
cargo test --package e2e-tests -- --test-threads=1

# Generate reports
echo "Generating coverage reports..."
mkdir -p coverage
cargo llvm-cov report --lcov --output-path coverage/lcov.info
cargo llvm-cov report --html --output-dir coverage/html
cargo llvm-cov report | tee coverage/summary.txt

echo ""
echo "=== Coverage reports generated ==="
echo "  LCOV: coverage/lcov.info"
echo "  HTML: coverage/html/index.html"
echo "  Summary: coverage/summary.txt"
