---
sidebar_position: 3
title: Docker Installation
description: Run zopp server and CLI using Docker.
---

# Docker Installation

Docker provides an easy way to run the zopp server without installing dependencies. All zopp images are available on GitHub Container Registry.

## Images

| Image | Description |
|-------|-------------|
| `ghcr.io/faiscadev/zopp-server` | The zopp gRPC server |
| `ghcr.io/faiscadev/zopp-operator` | Kubernetes operator for syncing secrets |
| `ghcr.io/faiscadev/zopp-cli` | The zopp CLI |

All images support `linux/amd64` and `linux/arm64`.

## Running the Server

### Quick Start (SQLite)

```bash
docker run -d \
  --name zopp-server \
  -p 50051:50051 \
  -v zopp-data:/data \
  ghcr.io/faiscadev/zopp-server:latest
```

This starts the server with SQLite storage at `/data/zopp.db`.

### With PostgreSQL

```bash
docker run -d \
  --name zopp-server \
  -p 50051:50051 \
  -e DATABASE_URL=postgres://user:password@host:5432/zopp \
  ghcr.io/faiscadev/zopp-server:latest
```

### With TLS

```bash
docker run -d \
  --name zopp-server \
  -p 50051:50051 \
  -v /path/to/certs:/certs:ro \
  -v zopp-data:/data \
  ghcr.io/faiscadev/zopp-server:latest \
  serve --tls-cert /certs/server.crt --tls-key /certs/server.key
```

## Docker Compose

A complete setup with PostgreSQL:

```yaml
# docker-compose.yaml
version: '3.8'

services:
  postgres:
    image: postgres:16
    environment:
      POSTGRES_USER: zopp
      POSTGRES_PASSWORD: zopp
      POSTGRES_DB: zopp
    volumes:
      - postgres-data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U zopp"]
      interval: 5s
      timeout: 5s
      retries: 5

  zopp-server:
    image: ghcr.io/faiscadev/zopp-server:latest
    ports:
      - "50051:50051"
    environment:
      DATABASE_URL: postgres://zopp:zopp@postgres:5432/zopp
    depends_on:
      postgres:
        condition: service_healthy

volumes:
  postgres-data:
```

Start with:

```bash
docker compose up -d
```

## Using the CLI via Docker

If you don't want to install the CLI locally, you can use the Docker image:

```bash
# Create an alias for convenience
alias zopp='docker run --rm -v ~/.zopp:/home/zopp/.zopp ghcr.io/faiscadev/zopp-cli:latest'

# Now use normally
zopp workspace list
```

:::note
The `-v ~/.zopp:/home/zopp/.zopp` mount ensures your credentials persist between runs.
:::

### Connecting to Host Network

To connect the CLI to a server running on your host machine:

```bash
# Linux
docker run --rm \
  --network host \
  -v ~/.zopp:/home/zopp/.zopp \
  ghcr.io/faiscadev/zopp-cli:latest \
  --server http://127.0.0.1:50051 \
  workspace list

# macOS/Windows
docker run --rm \
  -v ~/.zopp:/home/zopp/.zopp \
  ghcr.io/faiscadev/zopp-cli:latest \
  --server http://host.docker.internal:50051 \
  workspace list
```

## Creating Server Invites

To create the first user invite, you need to run the server command with database access:

```bash
# SQLite
docker run --rm \
  -v zopp-data:/data \
  ghcr.io/faiscadev/zopp-server:latest \
  invite create --expires-hours 48 --db /data/zopp.db

# PostgreSQL
docker run --rm \
  -e DATABASE_URL=postgres://zopp:zopp@host.docker.internal:5432/zopp \
  ghcr.io/faiscadev/zopp-server:latest \
  invite create --expires-hours 48
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `DATABASE_URL` | Database connection string | SQLite at `/data/zopp.db` |
| `ZOPP_TLS_CERT` | Path to TLS certificate | None |
| `ZOPP_TLS_KEY` | Path to TLS private key | None |
| `ZOPP_TLS_CLIENT_CA` | Path to client CA for mTLS | None |

## Health Checks

The server exposes health endpoints on port 8080:

```bash
# Liveness
curl http://localhost:8080/healthz

# Readiness
curl http://localhost:8080/readyz
```

## Next Steps

- [Kubernetes Installation](/zopp/installation/kubernetes) - Deploy to Kubernetes with Helm
- [Self-Hosting Guide](/zopp/self-hosting) - Complete deployment guide
- [TLS Configuration](/zopp/self-hosting/tls) - Secure your deployment
