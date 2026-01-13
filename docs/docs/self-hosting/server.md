---
sidebar_position: 2
title: Server Deployment
description: Deploy the zopp server.
---

# Server Deployment

This guide covers deploying the zopp server in various environments.

## Binary Installation

Download and run the server binary:

```bash
# Download
curl -fsSL https://github.com/faiscadev/zopp/releases/latest/download/zopp-server-linux-amd64 -o zopp-server
chmod +x zopp-server

# Run with SQLite (default)
./zopp-server serve

# Run with custom database path
./zopp-server serve --db /var/lib/zopp/zopp.db

# Run with PostgreSQL
DATABASE_URL=postgres://user:pass@localhost/zopp ./zopp-server serve

# Run with TLS
./zopp-server serve \
  --tls-cert /path/to/server.crt \
  --tls-key /path/to/server.key
```

## Docker Deployment

```bash
# SQLite
docker run -d \
  --name zopp-server \
  -p 50051:50051 \
  -v zopp-data:/data \
  ghcr.io/faiscadev/zopp-server:latest

# PostgreSQL
docker run -d \
  --name zopp-server \
  -p 50051:50051 \
  -e DATABASE_URL=postgres://user:pass@host:5432/zopp \
  ghcr.io/faiscadev/zopp-server:latest

# With TLS
docker run -d \
  --name zopp-server \
  -p 50051:50051 \
  -v /path/to/certs:/certs:ro \
  ghcr.io/faiscadev/zopp-server:latest \
  serve --tls-cert /certs/server.crt --tls-key /certs/server.key
```

## Systemd Service

For production Linux deployments:

```ini
# /etc/systemd/system/zopp.service
[Unit]
Description=zopp Secrets Manager
After=network.target

[Service]
Type=simple
User=zopp
ExecStart=/usr/local/bin/zopp-server serve --db /var/lib/zopp/zopp.db
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable zopp
sudo systemctl start zopp
```

## Creating Invites

To bootstrap the first user:

```bash
# SQLite
./zopp-server invite create --expires-hours 48 --db /var/lib/zopp/zopp.db

# PostgreSQL
DATABASE_URL=postgres://user:pass@localhost/zopp ./zopp-server invite create --expires-hours 48

# Docker
docker exec zopp-server zopp-server invite create --expires-hours 48
```

## Health Checks

The server exposes health endpoints on port 8080:

```bash
# Liveness
curl http://localhost:8080/healthz

# Readiness
curl http://localhost:8080/readyz
```

## Next Steps

- [Database Setup](/zopp/self-hosting/database) - Configure SQLite or PostgreSQL
- [TLS Configuration](/zopp/self-hosting/tls) - Secure your deployment
