#!/bin/bash
set -eo pipefail

echo "=== Unit Test Coverage ==="

if ! command -v cargo-llvm-cov &> /dev/null; then
    echo "cargo-llvm-cov is not installed. Install with: cargo install cargo-llvm-cov"
    exit 1
fi

# Clean previous coverage data
echo "Cleaning previous coverage data..."
cargo llvm-cov clean --workspace

mkdir -p coverage

# Exclude e2e-tests and xtask from coverage measurement
IGNORE="(xtask/|e2e-tests/)"

echo "Running unit tests with coverage..."

# Generate LCOV report (exclude e2e-tests and xtask from test run)
cargo llvm-cov --workspace --all-features \
    --exclude e2e-tests --exclude xtask \
    --ignore-filename-regex "$IGNORE" \
    --lcov --output-path coverage/lcov.info

# Generate HTML report
cargo llvm-cov --workspace --all-features \
    --exclude e2e-tests --exclude xtask \
    --ignore-filename-regex "$IGNORE" \
    --html --output-dir coverage/html

# Generate summary
cargo llvm-cov --workspace --all-features \
    --exclude e2e-tests --exclude xtask \
    --ignore-filename-regex "$IGNORE" \
    | tee coverage/summary.txt

echo ""
echo "=== Coverage reports generated ==="
echo "  LCOV: coverage/lcov.info"
echo "  HTML: coverage/html/index.html"
echo "  Summary: coverage/summary.txt"
