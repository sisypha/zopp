#!/bin/bash
# Helper script to run zopp CLI commands via Docker
#
# Usage:
#   ./docker/zopp-cli.sh <command> [args...]
#
# Examples:
#   ./docker/zopp-cli.sh workspace list
#   ./docker/zopp-cli.sh workspace create my-workspace
#   ./docker/zopp-cli.sh project create -w my-workspace my-project
#   ./docker/zopp-cli.sh secret set -w ws -p proj -e env MY_SECRET value
#   ./docker/zopp-cli.sh secret get -w ws -p proj -e env MY_SECRET
#
# The CLI automatically connects to the zopp-server container.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Check if docker compose is running
if ! docker compose -f "$SCRIPT_DIR/docker-compose.dev.yaml" ps --status running cli >/dev/null 2>&1; then
    echo "Error: Development containers are not running."
    echo "Start them with: docker compose -f docker/docker-compose.dev.yaml up -d"
    exit 1
fi

# Run the CLI command in the container
# First build the CLI if not already built, then run the command
# Use -- to separate docker args from the command, and pass args as separate strings
docker compose -f "$SCRIPT_DIR/docker-compose.dev.yaml" exec cli \
    bash -c 'cargo build --bin zopp --release 2>/dev/null && ./target/release/zopp --server http://zopp-server:50051 --use-file-storage "$@"' -- "$@"
