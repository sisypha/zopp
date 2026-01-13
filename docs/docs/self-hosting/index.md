---
sidebar_position: 1
title: Self-Hosting
description: Deploy your own zopp server.
---

# Self-Hosting

zopp is designed to be self-hosted. You maintain full control over your secrets infrastructure—no third-party access, no vendor lock-in.

## Deployment Options

- [Server Deployment](/zopp/self-hosting/server) - Deploy the zopp server as a standalone binary or container
- [Database Setup](/zopp/self-hosting/database) - Choose between SQLite (simple) and PostgreSQL (production)
- [TLS Configuration](/zopp/self-hosting/tls) - Secure your deployment with TLS and optional mutual TLS

## Quick Start

### Single Server (SQLite)

The simplest deployment for small teams:

```bash
# Download binary
curl -fsSL https://github.com/faiscadev/zopp/releases/latest/download/zopp-server-linux-amd64 -o zopp-server
chmod +x zopp-server

# Start server
./zopp-server serve --db /var/lib/zopp/zopp.db

# Create first user invite
./zopp-server invite create --expires-hours 48 --db /var/lib/zopp/zopp.db
```

### Production (PostgreSQL + TLS)

For production deployments:

```bash
# With Docker
docker run -d \
  --name zopp-server \
  -p 50051:50051 \
  -e DATABASE_URL=postgres://user:pass@postgres:5432/zopp \
  -v /path/to/certs:/certs:ro \
  ghcr.io/faiscadev/zopp-server:latest \
  serve --tls-cert /certs/server.crt --tls-key /certs/server.key
```

### Kubernetes

For Kubernetes deployments, use the Helm chart:

```bash
helm install zopp oci://ghcr.io/faiscadev/charts/zopp
```

See [Kubernetes Installation](/zopp/installation/kubernetes) for details.

## Architecture

```
                              Clients
       +-----------+  +-----------+  +------------+  +-----------+
       |    CLI    |  |    CLI    |  |  Operator  |  |    CLI    |
       |  (Alice)  |  |   (Bob)   |  |   (K8s)    |  |   (CI)    |
       +-----+-----+  +-----+-----+  +------+-----+  +-----+-----+
             |              |               |              |
             +-------+------+-------+-------+------+-------+
                                    |               
                              gRPC (TLS)
                                    |
                                    v
       +------------------------------------------------------------+
       |                       zopp Server                          |
       |                                                            |
       |   +----------------------------------------------------+   |
       |   |                   gRPC Service                     |   |
       |   |   - Authentication (Ed25519 signatures)            |   |
       |   |   - Authorization (RBAC)                           |   |
       |   |   - Audit logging                                  |   |
       |   +----------------------------------------------------+   |
       |                            |                               |
       |                            v                               |
       |   +----------------------------------------------------+   |
       |   |                  Storage Layer                     |   |
       |   |   - SQLite (development / small teams)             |   |
       |   |   - PostgreSQL (production)                        |   |
       |   +----------------------------------------------------+   |
       |                                                            |
       |   Server stores ONLY:          Server NEVER sees:          |
       |   - Wrapped keys (encrypted)   - Plaintext secrets         |
       |   - Encrypted secrets          - Unwrapped keys            |
       |   - User/principal metadata                                |
       |   - Audit logs                                             |
       +------------------------------------------------------------+
```

## Requirements

### Hardware

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| CPU | 1 core | 2+ cores |
| Memory | 256 MB | 512 MB+ |
| Storage | 100 MB + data | SSD recommended |

### Network

| Port | Protocol | Description |
|------|----------|-------------|
| 50051 | gRPC | API endpoint |
| 8080 | HTTP | Health checks |

:::tip
zopp is lightweight—a single server can handle thousands of secrets and many concurrent clients.
:::

## Next Steps

- [Server Deployment](/zopp/self-hosting/server) - Detailed deployment guide
- [Database Setup](/zopp/self-hosting/database) - SQLite vs PostgreSQL
- [TLS Configuration](/zopp/self-hosting/tls) - Secure your deployment
