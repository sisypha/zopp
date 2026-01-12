#!/bin/bash
set -e

echo "=== Test Coverage Collection ==="

# Check if cargo-llvm-cov is installed
if ! command -v cargo-llvm-cov &> /dev/null; then
    echo "cargo-llvm-cov is not installed. Install with: cargo install cargo-llvm-cov"
    exit 1
fi

# The challenge with E2E coverage:
# - E2E tests spawn separate zopp binaries (zopp-server, zopp)
# - These spawned binaries need to be instrumented and write profraw files
#
# Our approach:
# 1. Use cargo llvm-cov to build instrumented binaries with show-env
# 2. Run tests which spawn those binaries (binaries inherit LLVM_PROFILE_FILE)
# 3. Generate report from profraw files

# Clean previous coverage data
echo "Cleaning previous coverage data..."
cargo llvm-cov clean --workspace

# Get llvm-cov environment variables and export them
echo "Setting up coverage environment..."
eval $(cargo llvm-cov show-env --export-prefix)
export LLVM_PROFILE_FILE="$PWD/target/llvm-cov-target/zopp-%p-%m.profraw"

# Build instrumented binaries to the llvm-cov-target directory
# Tests look for binaries in target/llvm-cov-target/debug
echo "Building instrumented binaries..."
cargo build --workspace --bins --target-dir target/llvm-cov-target

# Run E2E tests (spawned binaries inherit coverage env)
echo "Running E2E tests..."

# Run core tests in parallel
cargo test --package e2e-tests --test demo --test rbac --test principals --test audit --test groups --test invites --test projects --test environments --test user_permissions --no-fail-fast -- --test-threads=4

# Run K8s tests (require Docker and kind, run sequentially)
# Skip only if SKIP_K8S_TESTS=1 is set
if [[ "${SKIP_K8S_TESTS:-}" == "1" ]]; then
    echo "Skipping K8s tests (SKIP_K8S_TESTS=1)"
else
    echo "Running K8s tests..."
    cargo test --package e2e-tests --test k8s --no-fail-fast -- --test-threads=1
fi

# Generate reports (exclude xtask - dev tooling not part of runtime)
echo "Generating coverage reports..."
mkdir -p coverage
IGNORE_REGEX="xtask/"
cargo llvm-cov report --ignore-filename-regex "$IGNORE_REGEX" --lcov --output-path coverage/lcov.info
cargo llvm-cov report --ignore-filename-regex "$IGNORE_REGEX" --html --output-dir coverage/html
cargo llvm-cov report --ignore-filename-regex "$IGNORE_REGEX" | tee coverage/summary.txt

echo ""
echo "=== Coverage reports generated ==="
echo "  LCOV: coverage/lcov.info"
echo "  HTML: coverage/html/index.html"
echo "  Summary: coverage/summary.txt"
