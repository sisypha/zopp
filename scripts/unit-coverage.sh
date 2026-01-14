#!/usr/bin/env bash
set -euo pipefail

# Unit test coverage script for crates only
# Apps (CLI, server, operator) are tested via E2E - crates should have 100% coverage
# Requires: cargo-llvm-cov (install with: cargo install cargo-llvm-cov)

mkdir -p coverage

echo "Running unit tests with coverage (crates only, target: 100%)..."

# Dynamically find all crates in the crates/ directory
PACKAGE_FLAGS=""
for crate_dir in crates/*/; do
    if [ -f "${crate_dir}Cargo.toml" ]; then
        crate_name=$(basename "$crate_dir")
        PACKAGE_FLAGS="$PACKAGE_FLAGS --package $crate_name"
    fi
done

echo "Measuring coverage for:$PACKAGE_FLAGS"
echo ""

# Run unit tests with coverage for crates only
cargo llvm-cov \
    $PACKAGE_FLAGS \
    --all-features \
    --html \
    --output-dir coverage/html

# Generate text summary for CI parsing
cargo llvm-cov \
    $PACKAGE_FLAGS \
    --all-features \
    --no-run \
    > coverage/summary.txt

echo ""
echo "Coverage report generated (crates only):"
echo "  HTML: coverage/html/index.html"
echo "  Summary: coverage/summary.txt"
echo ""
cat coverage/summary.txt
