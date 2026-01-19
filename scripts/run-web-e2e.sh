#!/bin/bash
# Run web UI E2E tests
#
# Prerequisites:
#   1. Build the CLI and server: cargo build --bins
#   2. Start backend services: docker compose -f docker/docker-compose.web-dev.yaml up -d
#
# Usage:
#   ./scripts/run-web-e2e.sh

set -e

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "Running zopp web UI E2E tests..."

# Check if backend services are running
echo -n "Checking if Envoy proxy is running on port 8080... "
if curl -s -o /dev/null -w "" http://localhost:8080 2>/dev/null || curl -s -o /dev/null -w "" --head http://localhost:8080 2>/dev/null; then
    echo -e "${GREEN}OK${NC}"
else
    echo -e "${RED}FAILED${NC}"
    echo ""
    echo "Backend services are not running. Start them with:"
    echo "  docker compose -f docker/docker-compose.web-dev.yaml up -d"
    exit 1
fi

echo -n "Checking if zopp-server is running on port 50051... "
if nc -z localhost 50051 2>/dev/null; then
    echo -e "${GREEN}OK${NC}"
else
    echo -e "${RED}FAILED${NC}"
    echo ""
    echo "zopp-server is not running. Start it with:"
    echo "  docker compose -f docker/docker-compose.web-dev.yaml up -d"
    exit 1
fi

# Check if CLI binary exists
CLI_BIN="$PROJECT_ROOT/target/debug/zopp"
if [ ! -f "$CLI_BIN" ]; then
    CLI_BIN="$PROJECT_ROOT/target/release/zopp"
fi
if [ ! -f "$CLI_BIN" ]; then
    echo -e "${RED}Error: zopp CLI not found. Run 'cargo build --bins' first.${NC}"
    exit 1
fi

# Check if server binary exists (needed for creating invites)
SERVER_BIN="$PROJECT_ROOT/target/debug/zopp-server"
if [ ! -f "$SERVER_BIN" ]; then
    SERVER_BIN="$PROJECT_ROOT/target/release/zopp-server"
fi

# If no ZOPP_TEST_INVITE is set, try to create one
if [ -z "$ZOPP_TEST_INVITE" ]; then
    echo -e "${YELLOW}Note: ZOPP_TEST_INVITE not set.${NC}"

    # Try to create an invite if we have database access
    if [ -n "$DATABASE_URL" ] && [ -f "$SERVER_BIN" ]; then
        echo "Creating test invite via DATABASE_URL..."
        ZOPP_TEST_INVITE=$("$SERVER_BIN" invite create --expires-hours 1 --plain 2>/dev/null) || true
        if [ -n "$ZOPP_TEST_INVITE" ]; then
            export ZOPP_TEST_INVITE
            echo -e "${GREEN}Created test invite${NC}"
        fi
    fi

    if [ -z "$ZOPP_TEST_INVITE" ]; then
        echo ""
        echo "To run tests, set ZOPP_TEST_INVITE or DATABASE_URL:"
        echo "  export ZOPP_TEST_INVITE=\$(zopp-server invite create --plain)"
        echo "  # or"
        echo "  export DATABASE_URL=sqlite:///path/to/zopp.db"
        echo ""
        echo "If using docker-compose, you can exec into the container:"
        echo "  docker compose -f docker/docker-compose.web-dev.yaml exec zopp-server zopp-server invite create --plain"
        exit 1
    fi
fi

# Change to web app directory and run tests
cd apps/zopp-web

# Install dependencies if needed
if [ ! -d "node_modules" ]; then
    echo "Installing npm dependencies..."
    npm install
fi

# Install Playwright browsers if needed
if ! npx playwright --version > /dev/null 2>&1; then
    echo "Installing Playwright..."
    npx playwright install chromium
fi

echo ""
echo "Running Playwright tests..."
npm run test:e2e -- "$@"
