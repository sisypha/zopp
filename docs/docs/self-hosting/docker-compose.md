---
sidebar_position: 4
title: Docker Compose
description: Deploy zopp with Docker Compose for non-Kubernetes environments.
---

# Docker Compose Deployment

This guide shows how to deploy zopp with Docker Compose—ideal for teams not using Kubernetes.

## Quick Start

```bash
# Clone and start
git clone https://github.com/faiscadev/zopp.git
cd zopp/examples/docker-compose
docker compose up -d

# Create first user invite
docker compose exec zopp-server zopp-server invite create --expires-hours 48
```

Your zopp server is now running at `localhost:50051`.

## Development Setup

The basic `docker-compose.yml` includes:
- zopp server on port 50051
- PostgreSQL 16 with persistent storage
- Health checks for both services

```yaml
services:
  zopp-server:
    image: ghcr.io/faiscadev/zopp-server:latest
    ports:
      - "50051:50051"
      - "8080:8080"
    environment:
      DATABASE_URL: postgres://zopp:zopp@postgres:5432/zopp
    depends_on:
      postgres:
        condition: service_healthy

  postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_USER: zopp
      POSTGRES_PASSWORD: zopp
      POSTGRES_DB: zopp
    volumes:
      - postgres-data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U zopp -d zopp"]
      interval: 5s
      timeout: 5s
      retries: 5

volumes:
  postgres-data:
```

## Production Setup

For production, use `docker-compose.production.yml` which adds:
- TLS encryption
- Resource limits
- Environment-based password configuration

### 1. Generate TLS Certificates

```bash
mkdir -p certs

# Option A: Self-signed (testing only)
openssl req -x509 -newkey rsa:4096 \
  -keyout certs/server.key -out certs/server.crt \
  -days 365 -nodes -subj "/CN=zopp.example.com"

# Option B: Let's Encrypt (production)
# Use certbot or your preferred ACME client
```

### 2. Set a Secure Password

```bash
export POSTGRES_PASSWORD=$(openssl rand -base64 32)
echo "Save this password: $POSTGRES_PASSWORD"
```

### 3. Start the Stack

```bash
docker compose -f docker-compose.production.yml up -d
```

### 4. Create First User

```bash
docker compose -f docker-compose.production.yml exec zopp-server \
  zopp-server invite create --expires-hours 48
```

## Connecting Clients

Configure the CLI to connect to your server:

```bash
# Development (no TLS)
zopp --server http://localhost:50051 join <token> you@example.com

# Production (TLS)
zopp --server https://zopp.example.com:50051 join <token> you@example.com
```

Or set defaults in `~/.zopp/config.json`:

```json
{
  "server_url": "https://zopp.example.com:50051"
}
```

## Operations

### View Logs

```bash
docker compose logs -f zopp-server
```

### Backup Database

```bash
docker compose exec postgres pg_dump -U zopp zopp > backup-$(date +%Y%m%d).sql
```

### Restore Database

```bash
cat backup.sql | docker compose exec -T postgres psql -U zopp zopp
```

### Update zopp

```bash
docker compose pull
docker compose up -d
```

### Create Additional Invites

```bash
docker compose exec zopp-server zopp-server invite create --expires-hours 48
```

## Health Checks

The server exposes health endpoints on port 8080:

```bash
# Liveness (server is running)
curl http://localhost:8080/healthz

# Readiness (server can handle requests)
curl http://localhost:8080/readyz
```

## Troubleshooting

### Connection Refused

Check that both services are running:

```bash
docker compose ps
docker compose logs zopp-server
```

### Database Connection Errors

Wait for PostgreSQL to be ready:

```bash
docker compose logs postgres
```

The zopp server waits for the `postgres` health check before starting.

### TLS Certificate Errors

Verify certificate paths and permissions:

```bash
ls -la certs/
docker compose exec zopp-server ls -la /certs/
```

## Next Steps

- [Server Deployment](/self-hosting/server) - Other deployment options
- [TLS Configuration](/self-hosting/tls) - Advanced TLS setup
- [Team Collaboration](/guides/team-collaboration) - Invite your team
